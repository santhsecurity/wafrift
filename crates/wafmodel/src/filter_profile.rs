//! Filter characterization — learn WHICH attack tokens a live WAF actually
//! policies, by *differential* probing.
//!
//! The bypass-discovery method a human uses is not "encode everything and
//! pray" — it is "find out what the filter blocks, then target the gap." A
//! solver that knows the WAF blocks `<script` but lets `<svg` through, or
//! policies `onerror=` but not `onpointerenter=`, spends its (expensive,
//! lossy) encoding budget only where it must and uses cheaper plaintext
//! everywhere else. This module is the reconnaissance step the
//! [`solve`](crate::solve) stage consumes.
//!
//! # Differential isolation
//!
//! Sending one dangerous token and observing [`Outcome::Block`] proves
//! nothing on its own: the carrier context, the special characters (`<`, `=`,
//! `:`), or the value length could be the cause. Each probe therefore carries
//! a **benign twin** — the same shape with the signature broken
//! (`<script`→`<scrupt`, `onerror=`→`onerrxr=`) — and we compare the two:
//!
//! | dangerous | benign twin | verdict          | meaning for the solver                       |
//! |-----------|-------------|------------------|----------------------------------------------|
//! | Block     | Pass        | `Policed`      | the rule keys on THIS token — must encode it  |
//! | Pass      | Pass        | `Unpoliced`    | token reaches the sink raw — no work needed   |
//! | Block     | Block       | `CarrierGate`  | not the keyword; the chars/len/context gate   |
//! | Pass      | Block       | `Inconclusive` | contradictory (oracle noise) — never guessed  |
//!
//! `Policed`(Verdict::Policed) and `CarrierGate`(Verdict::CarrierGate)
//! both inform the solver; `Unpoliced`(Verdict::Unpoliced) is the prize
//! (use the token in plaintext); `Inconclusive`(Verdict::Inconclusive) is
//! discarded, never turned into a guess (anti-rig — the same discipline the
//! learner applies to `ServerError`).
//!
//! Cost is exactly **two** membership queries per probe. The battery is
//! Tier-B *data* ([`default_battery`]); extend it by appending [`TokenProbe`]s,
//! not by editing code.

use crate::ensemble_dilution::RuleGroup;
use crate::error::{Result, WafModelError};
use crate::oracle::WafOracle;
use crate::outcome::Outcome;
use crate::solve::preimage_for;
use crate::transduce::{Pipeline, Stage};
use wafrift_types::Request;

/// One differential probe: a dangerous attack token paired with a
/// structurally identical **benign twin** that breaks the token's signature.
///
/// Invariant the battery must uphold: `benign_twin` shares `token`'s length,
/// leading/trailing structural punctuation, and character classes, but
/// contains **no** rule-keyword substring — so any difference in the two
/// outcomes is attributable to the keyword alone, not to shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenProbe {
    /// The dangerous token whose policing we are measuring (e.g. `"<script"`).
    pub token: String,
    /// Signature-broken twin of identical shape (e.g. `"<scrupt"`).
    pub benign_twin: String,
    /// Which attack class this token belongs to.
    pub class: RuleGroup,
}

impl TokenProbe {
    /// Construct a probe.
    pub fn new(token: impl Into<String>, benign_twin: impl Into<String>, class: RuleGroup) -> Self {
        Self {
            token: token.into(),
            benign_twin: benign_twin.into(),
            class,
        }
    }

    /// Tier-B integrity: a sound twin changes ONLY ASCII letters, never the
    /// length or the non-letter skeleton (punctuation, digits, spaces), and is
    /// not identical to the token. Any outcome difference is then attributable
    /// to the keyword, not to shape. Returns the reason on violation.
    fn validate(&self) -> std::result::Result<(), String> {
        if self.token.len() != self.benign_twin.len() {
            return Err(format!(
                "twin {:?} must match token {:?} byte length",
                self.benign_twin, self.token
            ));
        }
        if self.token == self.benign_twin {
            return Err(format!("twin must differ from token {:?}", self.token));
        }
        for (i, (tb, wb)) in self.token.bytes().zip(self.benign_twin.bytes()).enumerate() {
            if tb != wb && !(tb.is_ascii_alphabetic() && wb.is_ascii_alphabetic()) {
                return Err(format!(
                    "at index {i}, twin {:?} differs from {:?} on a non-letter byte — that \
                     perturbs the structural skeleton",
                    self.benign_twin, self.token
                ));
            }
        }
        Ok(())
    }
}

/// What the differential told us about one token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Dangerous blocked, twin passed → the WAF rules on this exact token.
    /// The solver MUST transform it (encode / homoglyph / case) to bypass.
    Policed,
    /// Both passed → the token reaches the sink verbatim. The solver can use
    /// it in plaintext and spend no encoding budget on it. The prize.
    Unpoliced,
    /// Both blocked → the keyword is not the gate; the surrounding characters,
    /// length, or context is. Encoding the keyword alone will not help — the
    /// solver must address the structural element instead.
    CarrierGate,
    /// Dangerous passed while the (less-suspicious) twin blocked — a
    /// contradiction that means oracle noise. Recorded, never acted on.
    Inconclusive,
}

impl Verdict {
    /// Project a (dangerous, twin) outcome pair onto the differential verdict.
    #[must_use]
    pub fn from_outcomes(dangerous: Outcome, twin: Outcome) -> Self {
        match (dangerous, twin) {
            (Outcome::Block, Outcome::Pass) => Verdict::Policed,
            (Outcome::Pass, Outcome::Pass) => Verdict::Unpoliced,
            (Outcome::Block, Outcome::Block) => Verdict::CarrierGate,
            (Outcome::Pass, Outcome::Block) => Verdict::Inconclusive,
        }
    }
}

/// What characterization concluded about one probed token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenFinding {
    /// The dangerous token that was probed.
    pub token: String,
    /// Its attack class.
    pub class: RuleGroup,
    /// The differential verdict.
    pub verdict: Verdict,
}

/// The differential filter profile: per-token verdicts plus the cost paid.
#[derive(Debug, Clone, Default)]
pub struct FilterProfile {
    /// One finding per probe, in battery order.
    pub findings: Vec<TokenFinding>,
    /// Membership queries spent (two per probe, fewer if the oracle erred).
    pub queries: u64,
    /// Probes whose verdict is [`Verdict::Inconclusive`] *because the oracle
    /// returned a transport error* (as opposed to a genuine Pass/Block
    /// contradiction). Surfaced so a caller can distinguish "the WAF is
    /// confusing" from "the network is down".
    pub transport_errors: u64,
}

impl FilterProfile {
    /// Tokens the WAF policies by keyword — the solver must transform these.
    pub fn policed(&self) -> impl Iterator<Item = &TokenFinding> {
        self.findings
            .iter()
            .filter(|f| f.verdict == Verdict::Policed)
    }

    /// Tokens that reach the sink in plaintext — free for the solver to use.
    pub fn unpoliced(&self) -> impl Iterator<Item = &TokenFinding> {
        self.findings
            .iter()
            .filter(|f| f.verdict == Verdict::Unpoliced)
    }

    /// Tokens whose *carrier* (chars/length/context), not the keyword, is the
    /// gate — encoding the keyword alone will not bypass these.
    pub fn carrier_gated(&self) -> impl Iterator<Item = &TokenFinding> {
        self.findings
            .iter()
            .filter(|f| f.verdict == Verdict::CarrierGate)
    }

    /// Is this exact token policed by keyword?
    #[must_use]
    pub fn is_policed(&self, token: &str) -> bool {
        self.findings
            .iter()
            .any(|f| f.token == token && f.verdict == Verdict::Policed)
    }
}

/// Characterize a live WAF's block surface by running each [`TokenProbe`] in
/// `battery` through `oracle`, carrying the probe value into a request via
/// `carrier` (the caller owns the injection point — query arg, body field,
/// header — so this crate takes no HTTP stack).
///
/// Best-effort and total: a transport error on either half of a probe yields
/// an `Inconclusive`(Verdict::Inconclusive) finding (and increments
/// [`FilterProfile::transport_errors`]) rather than aborting the whole sweep —
/// one flaky probe must not discard the intelligence from the rest.
pub fn characterize<O, F>(
    oracle: &mut O,
    battery: &[TokenProbe],
    carrier: F,
) -> Result<FilterProfile>
where
    O: WafOracle,
    F: Fn(&str) -> Request,
{
    let mut findings = Vec::with_capacity(battery.len());
    let mut transport_errors = 0u64;
    let before = oracle.queries();

    for probe in battery {
        let dangerous = oracle.classify(&carrier(&probe.token));
        let twin = oracle.classify(&carrier(&probe.benign_twin));
        let verdict = match (dangerous, twin) {
            (Ok(d), Ok(t)) => Verdict::from_outcomes(d, t),
            _ => {
                transport_errors += 1;
                Verdict::Inconclusive
            }
        };
        findings.push(TokenFinding {
            token: probe.token.clone(),
            class: probe.class,
            verdict,
        });
    }

    Ok(FilterProfile {
        findings,
        queries: oracle.queries().saturating_sub(before),
        transport_errors,
    })
}

/// One WAF **decode-gap**: a single origin-style transform whose structural
/// preimage of a policed token *passes* the WAF, revealing that the WAF does
/// not apply that transform before matching.
///
/// This is **necessary but not sufficient** for a bypass: it proves only the
/// WAF-side half (the WAF's literal match is defeated by this encoding). To
/// *exploit* it the origin must actually apply the transform — confirm origin
/// behaviour with the reflection fingerprint ([`scan_origin`](crate::scan_origin)).
/// Reported as a candidate, never as a confirmed bypass (no fabrication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeGap {
    /// The policed token this gap defeats the WAF match for.
    pub token: String,
    /// Label of the origin transform the WAF fails to replicate (e.g.
    /// `"url_decode"`, `"nfkc_normalize"`, `"base64_decode"`).
    pub stage: &'static str,
    /// The structural preimage actually sent (the encoded form that passed).
    pub encoded_preimage: Vec<u8>,
}

/// The single-stage origin transforms a WAF may or may not replicate before
/// matching. Each is probed as `preimage_for(token, [stage], encode_all)` —
/// reusing the canonical solver encoder, so no encoding logic is duplicated.
fn decode_probe_stages() -> Vec<(&'static str, Stage)> {
    vec![
        (
            "url_decode",
            Stage::UrlDecode {
                plus_is_space: false,
            },
        ),
        ("double_url_decode", Stage::DoubleUrlDecode),
        ("html_entity_decode", Stage::HtmlEntityDecode),
        ("nfkc_normalize", Stage::NfkcNormalize),
        ("bestfit_downconvert", Stage::BestFitDownconvert),
        ("base64_decode", Stage::Base64Decode),
        ("hex_decode", Stage::HexDecode),
    ]
}

/// For each **policed** token in `profile`, probe whether the structural
/// preimage of each origin transform in `decode_probe_stages` passes the
/// WAF — surfacing the specific encodings that defeat the WAF's literal match.
///
/// Sound by construction: every candidate preimage genuinely differs from the
/// raw token (skipped otherwise) and is verified to *pass* the live oracle
/// before being recorded; the raw token was already proven blocked (it is
/// `Policed`). The result is the WAF-decode-gap set — the encodings a solver
/// should try first against a confirmed-decoding origin. Cost is
/// `|policed| × stages` membership queries; run after [`characterize`] so it
/// probes only the (usually few) tokens worth deepening.
pub fn probe_decode_gaps<O, F>(
    oracle: &mut O,
    profile: &FilterProfile,
    carrier: F,
) -> Result<Vec<DecodeGap>>
where
    O: WafOracle,
    F: Fn(&str) -> Request,
{
    let stages = decode_probe_stages();
    let mut gaps = Vec::new();
    for finding in profile.policed() {
        for (label, stage) in &stages {
            let sink = Pipeline(vec![stage.clone()]);
            // encode_all: rewrite the WHOLE token so no literal substring of the
            // WAF rule survives — a pass then unambiguously means "the WAF did
            // not apply this decode", not "the rule happened not to match".
            let encoded = preimage_for(finding.token.as_bytes(), &sink, true);
            if encoded == finding.token.as_bytes() {
                continue; // transform is a no-op for this token — not a probe
            }
            let value = String::from_utf8_lossy(&encoded).into_owned();
            if matches!(oracle.classify(&carrier(&value))?, Outcome::Pass) {
                gaps.push(DecodeGap {
                    token: finding.token.clone(),
                    stage: label,
                    encoded_preimage: encoded,
                });
            }
        }
    }
    Ok(gaps)
}

/// The embedded Tier-B default battery — the single source of the default
/// probes is the data file, not a hardcoded `vec!`. Override per-run with
/// [`battery_from_toml`].
const DEFAULT_BATTERY_TOML: &str = include_str!("../rules/filter/tokens.toml");

/// The default differential battery, parsed from the embedded Tier-B data file
/// `DEFAULT_BATTERY_TOML`. Extend coverage by editing that file (or shipping
/// your own and passing it to [`battery_from_toml`]) — never by branching in
/// code. The embedded data is validated by the same loader and pinned by tests.
#[must_use]
pub fn default_battery() -> Vec<TokenProbe> {
    battery_from_toml(DEFAULT_BATTERY_TOML)
        .expect("embedded default filter battery must be valid (asserted in tests)")
}

/// Deserialize a Tier-B filter-probe battery from TOML. The schema is a list of
/// `[[probe]]` tables, each `{ token, benign_twin, class }` where `class` is one
/// of the [`RuleGroup`] names (`xss`, `sqli`, `lfi_rfi`, `rce`, `protocol`,
/// `scanner`). Every probe is validated against the structural twin invariant
/// (`TokenProbe::validate`) at load — the loader **fails closed** on a
/// malformed twin, an unknown class, or an empty battery, so bad data can never
/// silently weaken the differential.
pub fn battery_from_toml(src: &str) -> Result<Vec<TokenProbe>> {
    #[derive(serde::Deserialize)]
    struct ProbeFile {
        #[serde(default)]
        probe: Vec<ProbeRow>,
    }
    #[derive(serde::Deserialize)]
    struct ProbeRow {
        token: String,
        benign_twin: String,
        class: String,
    }

    let parsed: ProbeFile = toml::from_str(src)
        .map_err(|e| WafModelError::Artifact(format!("parsing filter battery TOML: {e}")))?;
    if parsed.probe.is_empty() {
        return Err(WafModelError::Artifact(
            "filter battery has no [[probe]] entries".into(),
        ));
    }
    let mut out = Vec::with_capacity(parsed.probe.len());
    for row in parsed.probe {
        let class = RuleGroup::ALL
            .iter()
            .copied()
            .find(|g| g.name() == row.class)
            .ok_or_else(|| {
                WafModelError::Artifact(format!(
                    "unknown probe class {:?} (expected one of {:?})",
                    row.class,
                    RuleGroup::ALL.iter().map(|g| g.name()).collect::<Vec<_>>(),
                ))
            })?;
        let probe = TokenProbe::new(row.token, row.benign_twin, class);
        probe
            .validate()
            .map_err(|why| WafModelError::Artifact(format!("invalid filter probe: {why}")))?;
        out.push(probe);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::FnOracle;

    /// An oracle that blocks any request whose URL contains one of `policed`
    /// (case-sensitive substring) — a faithful stand-in for a literal-token
    /// WAF rule. Everything else passes.
    fn literal_token_waf(
        policed: &'static [&'static str],
    ) -> FnOracle<impl FnMut(&Request) -> Result<Outcome>> {
        FnOracle::new(move |req: &Request| {
            let url = req.url();
            let blocked = policed.iter().any(|tok| url.contains(tok));
            Ok(if blocked {
                Outcome::Block
            } else {
                Outcome::Pass
            })
        })
    }

    /// Carrier: drop the raw value into a query parameter of a fixed URL. The
    /// benign carrier text is identical for every probe, so only the value
    /// differs between the two halves of a differential.
    fn query_carrier(value: &str) -> Request {
        Request::get(format!("https://target.test/search?q=lookup-{value}-end"))
    }

    #[test]
    fn policed_token_is_isolated_from_its_benign_twin() {
        // The WAF blocks exactly "<script>"; the twin "<scrupt>" is not a rule
        // keyword, so it passes → the differential must read Policed.
        let mut waf = literal_token_waf(&["<script>"]);
        let battery = [TokenProbe::new(
            "<script>",
            "<scrupt>",
            RuleGroup::CrossSiteScripting,
        )];
        let profile = characterize(&mut waf, &battery, query_carrier).unwrap();

        assert_eq!(
            profile.queries, 2,
            "exactly two membership queries per probe"
        );
        assert_eq!(profile.transport_errors, 0);
        assert!(profile.is_policed("<script>"));
        let policed: Vec<_> = profile.policed().map(|f| f.token.as_str()).collect();
        assert_eq!(policed, vec!["<script>"]);
    }

    #[test]
    fn unpoliced_token_is_the_prize() {
        // The WAF policies SQLi only; an XSS tag sails through with its twin →
        // Unpoliced, and the solver learns it needs no encoding for it.
        let mut waf = literal_token_waf(&["union select"]);
        let battery = [TokenProbe::new(
            "<svg onload=",
            "<svq onloxd=",
            RuleGroup::CrossSiteScripting,
        )];
        let profile = characterize(&mut waf, &battery, query_carrier).unwrap();

        assert!(!profile.is_policed("<svg onload="));
        let unpoliced: Vec<_> = profile.unpoliced().map(|f| f.token.as_str()).collect();
        assert_eq!(
            unpoliced,
            vec!["<svg onload="],
            "an unpoliced token must be surfaced"
        );
    }

    #[test]
    fn carrier_gate_when_both_halves_block() {
        // The WAF blocks the structural prefix "<" itself (an over-broad rule),
        // so BOTH the dangerous token and its twin block → CarrierGate, telling
        // the solver the keyword is not the gate.
        let mut waf = literal_token_waf(&["<"]);
        let battery = [TokenProbe::new(
            "<script>",
            "<scrupt>",
            RuleGroup::CrossSiteScripting,
        )];
        let profile = characterize(&mut waf, &battery, query_carrier).unwrap();

        assert!(
            !profile.is_policed("<script>"),
            "both-block must NOT read as Policed"
        );
        let gated: Vec<_> = profile.carrier_gated().map(|f| f.token.as_str()).collect();
        assert_eq!(gated, vec!["<script>"]);
    }

    #[test]
    fn transport_error_is_inconclusive_not_a_guess() {
        // An oracle that always errors must yield Inconclusive findings and a
        // transport-error count — never a fabricated Pass/Block verdict.
        let mut waf =
            FnOracle::new(|_req: &Request| Err(crate::error::WafModelError::Oracle("down".into())));
        let battery = default_battery();
        let n = battery.len();
        let profile = characterize(&mut waf, &battery, query_carrier).unwrap();

        assert_eq!(profile.transport_errors, n as u64, "every probe erred");
        assert!(profile.policed().next().is_none());
        assert!(profile.unpoliced().next().is_none());
        assert!(
            profile
                .findings
                .iter()
                .all(|f| f.verdict == Verdict::Inconclusive),
            "transport failure must never produce an actionable verdict"
        );
    }

    #[test]
    fn from_outcomes_truth_table_is_exhaustive() {
        assert_eq!(
            Verdict::from_outcomes(Outcome::Block, Outcome::Pass),
            Verdict::Policed
        );
        assert_eq!(
            Verdict::from_outcomes(Outcome::Pass, Outcome::Pass),
            Verdict::Unpoliced
        );
        assert_eq!(
            Verdict::from_outcomes(Outcome::Block, Outcome::Block),
            Verdict::CarrierGate
        );
        assert_eq!(
            Verdict::from_outcomes(Outcome::Pass, Outcome::Block),
            Verdict::Inconclusive
        );
    }

    #[test]
    fn default_battery_twins_preserve_structure_and_only_swap_letters() {
        // Tier-B integrity: a sound twin changes ONLY ASCII letters, never the
        // length or the non-letter skeleton (punctuation, digits, spaces) — so
        // any outcome difference between token and twin is attributable to the
        // keyword, not to length, character-class, or structural-byte filters.
        for p in default_battery() {
            assert_eq!(
                p.benign_twin.len(),
                p.token.len(),
                "twin {:?} must match token {:?} byte length",
                p.benign_twin,
                p.token
            );
            assert_ne!(p.token, p.benign_twin, "twin must differ from the token");
            for (i, (tb, wb)) in p.token.bytes().zip(p.benign_twin.bytes()).enumerate() {
                if tb != wb {
                    assert!(
                        tb.is_ascii_alphabetic() && wb.is_ascii_alphabetic(),
                        "at index {i}, twin {:?} differs from {:?} on a NON-letter byte \
                         ({tb:#x} vs {wb:#x}) — that perturbs the structural skeleton",
                        p.benign_twin,
                        p.token
                    );
                }
            }
        }
    }

    #[test]
    fn embedded_default_battery_parses_and_is_non_trivial() {
        // The shipped Tier-B data file must load through the real loader (so the
        // validate() contract is exercised on it) and cover every rule group.
        let battery = default_battery();
        assert!(battery.len() >= 10, "default battery unexpectedly small");
        let classes: std::collections::HashSet<RuleGroup> =
            battery.iter().map(|p| p.class).collect();
        for required in [
            RuleGroup::CrossSiteScripting,
            RuleGroup::SqlInjection,
            RuleGroup::FileInclusion,
            RuleGroup::RemoteCodeExecution,
        ] {
            assert!(
                classes.contains(&required),
                "default battery missing class {required:?}"
            );
        }
    }

    #[test]
    fn battery_from_toml_round_trips_a_minimal_file() {
        let src = r#"
            [[probe]]
            token = "<script>"
            benign_twin = "<scrupt>"
            class = "xss"
        "#;
        let battery = battery_from_toml(src).expect("valid battery");
        assert_eq!(battery.len(), 1);
        assert_eq!(battery[0].token, "<script>");
        assert_eq!(battery[0].class, RuleGroup::CrossSiteScripting);
    }

    #[test]
    fn battery_from_toml_fails_closed_on_a_structurally_invalid_twin() {
        // A twin that changes a NON-letter byte (here the trailing `>` → `x`)
        // perturbs the skeleton and must be rejected at load, not silently used.
        let src = r#"
            [[probe]]
            token = "<script>"
            benign_twin = "<scrupx"
            class = "xss"
        "#;
        let err = battery_from_toml(src).expect_err("must reject a bad twin");
        assert!(
            format!("{err}").contains("invalid filter probe"),
            "got: {err}"
        );
    }

    #[test]
    fn battery_from_toml_rejects_unknown_class_and_empty_file() {
        let bad_class = r#"
            [[probe]]
            token = "system("
            benign_twin = "systxm("
            class = "totally-made-up"
        "#;
        assert!(
            battery_from_toml(bad_class).is_err(),
            "unknown class must be rejected"
        );
        assert!(
            battery_from_toml("# nothing here\n").is_err(),
            "empty battery must be rejected"
        );
    }

    /// One-pass percent-decode for the decode-gap test WAFs.
    fn pct_decode_once(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                let hi = (b[i + 1] as char).to_digit(16);
                let lo = (b[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn policed_script_profile() -> FilterProfile {
        FilterProfile {
            findings: vec![TokenFinding {
                token: "<script>".to_string(),
                class: RuleGroup::CrossSiteScripting,
                verdict: Verdict::Policed,
            }],
            queries: 0,
            transport_errors: 0,
        }
    }

    #[test]
    fn decode_gap_probe_finds_every_gap_against_a_no_decode_literal_waf() {
        // A WAF that matches the raw bytes and decodes NOTHING: every encoded
        // preimage of `<script>` differs from the literal, so every stage is a
        // decode-gap.
        let mut waf = literal_token_waf(&["<script>"]);
        let gaps = probe_decode_gaps(&mut waf, &policed_script_profile(), query_carrier).unwrap();
        let stages: std::collections::HashSet<&str> = gaps.iter().map(|g| g.stage).collect();
        assert!(
            stages.contains("url_decode"),
            "a no-decode WAF must expose the url_decode gap"
        );
        assert!(stages.contains("base64_decode"));
        assert!(
            gaps.iter().all(|g| g.token == "<script>"),
            "every gap must be attributed to the policed token"
        );
    }

    #[test]
    fn decode_gap_probe_omits_the_transform_the_waf_actually_replicates() {
        // A WAF that url-decodes ONCE before matching: the url_decode preimage
        // decodes back to `<script>` and is blocked → NOT a gap. The forms it
        // does not decode (double-url, base64) still pass → gaps. This is the
        // discriminating test: the probe must distinguish what the WAF decodes
        // from what it does not.
        let mut waf = FnOracle::new(|req: &Request| {
            let decoded = pct_decode_once(req.url());
            Ok(if decoded.contains("<script>") {
                Outcome::Block
            } else {
                Outcome::Pass
            })
        });
        let gaps = probe_decode_gaps(&mut waf, &policed_script_profile(), query_carrier).unwrap();
        let stages: std::collections::HashSet<&str> = gaps.iter().map(|g| g.stage).collect();
        assert!(
            !stages.contains("url_decode"),
            "the WAF replicates url-decode, so it must NOT be reported as a gap: {stages:?}"
        );
        assert!(
            stages.contains("double_url_decode"),
            "the WAF does not double-url-decode → that IS a gap: {stages:?}"
        );
        assert!(
            stages.contains("base64_decode"),
            "the WAF does not base64-decode → that IS a gap: {stages:?}"
        );
    }

    #[test]
    fn decode_gap_probe_is_empty_when_no_token_is_policed() {
        // No policed tokens → nothing to deepen → no gaps, no queries wasted.
        let mut waf = literal_token_waf(&["<script>"]);
        let empty = FilterProfile::default();
        let gaps = probe_decode_gaps(&mut waf, &empty, query_carrier).unwrap();
        assert!(gaps.is_empty());
        assert_eq!(
            waf.queries(),
            0,
            "no policed token ⇒ no decode-gap probes sent"
        );
    }

    #[test]
    fn full_default_battery_classifies_a_mixed_waf_end_to_end() {
        // A WAF that policies a representative token from three classes but not
        // the fourth (RCE). Characterization must surface exactly the policed
        // set and leave the RCE tokens unpoliced.
        let mut waf = literal_token_waf(&["<script>", "union select", "/etc/passwd"]);
        let profile = characterize(&mut waf, &default_battery(), query_carrier).unwrap();

        assert!(profile.is_policed("<script>"));
        assert!(profile.is_policed("union select"));
        assert!(profile.is_policed("/etc/passwd"));
        // RCE tokens were never policed → must be reported unpoliced.
        let unpoliced: std::collections::HashSet<_> =
            profile.unpoliced().map(|f| f.token.as_str()).collect();
        assert!(
            unpoliced.contains("system("),
            "unpoliced RCE token must be surfaced"
        );
        assert!(unpoliced.contains(";bash -i"));
        assert_eq!(profile.transport_errors, 0);
        assert_eq!(profile.queries, default_battery().len() as u64 * 2);
    }
}
