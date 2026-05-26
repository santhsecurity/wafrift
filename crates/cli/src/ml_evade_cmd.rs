//! `wafrift ml-evade` — wrap `wafrift_strategy::evade_ml_backed` as
//! an operator-facing subcommand.
//!
//! Closes the production-caller gap for `apply_ml_evasion_if_applicable`
//! and `evade_ml_backed` from `wafrift_strategy`. The functions had
//! tests but no shipped binary ever called them; the `MlEvasion`
//! technique variant existed in `wafrift_types::Technique` with no
//! code path that could produce it.
//!
//! ## What this does
//!
//! Given an attack payload, a target URL, and a declared WAF name
//! (AWS Bot Control, Cloudflare Bot Management, Akamai Bot Manager,
//! Datadome — the four ML-backed classes in `WafClass::is_ml_backed`),
//! runs `evade_ml_backed` which routes the body through
//! `ml_evasion_candidates` (gradient-aware mutations + manifold
//! check). Emits the resulting `EvasionResult` describing the
//! mutated request and which techniques were applied.
//!
//! Non-ML-backed WAFs (`Cloudflare WAF`, `AWS Core Rule Set`, plain
//! ModSecurity, etc.) get `Ok(None)` — the function is honest about
//! its applicability and never fabricates an evasion for WAFs whose
//! ML model it can't reason about.

use std::process::ExitCode;

use clap::Args;
use serde::Serialize;
use wafrift_strategy::{DEFAULT_ML_BUDGET, evade_ml_backed};
use wafrift_types::{Request, Technique};

#[derive(Args, Debug)]
pub struct MlEvadeArgs {
    /// Target URL — used only as the destination on the mutated
    /// request. The function does NOT probe the target; this
    /// subcommand is offline and emits the mutated request for an
    /// operator to inspect or replay through a separate sender.
    #[arg(long, value_name = "URL")]
    pub target: String,

    /// Attack payload bytes (UTF-8). Will be placed in the request
    /// body. ML evasion is body-only — empty bodies short-circuit
    /// with no mutation.
    #[arg(long, value_name = "ATTACK")]
    pub attack: String,

    /// Declared WAF identity — must be an ML-backed class for the
    /// function to produce a mutation. Strings matched
    /// case-insensitively via `WafClass::from_waf_name`:
    /// "AWS Bot Control", "Cloudflare Bot Management",
    /// "Akamai Bot Manager", "Datadome".
    #[arg(long, value_name = "NAME")]
    pub waf_name: String,

    /// Search budget for `ml_evasion_candidates`. Higher = more
    /// gradient steps explored. Default: `DEFAULT_ML_BUDGET`.
    #[arg(long)]
    pub budget: Option<u64>,

    /// Deterministic seed for the mutation RNG. Default: derived
    /// FNV-1a from `(target, attack, waf_name)` so the same inputs
    /// always produce the same mutation.
    #[arg(long)]
    pub seed: Option<u64>,

    /// Content-Type to set on the synthesized request. Defaults to
    /// `application/x-www-form-urlencoded` — the most common body
    /// shape ML bot-management products score against.
    #[arg(long, default_value = "application/x-www-form-urlencoded")]
    pub content_type: String,

    /// Output format: `text` (default) or `json`. JSON emits a
    /// stable-schema envelope downstream tools can diff against.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

#[derive(Serialize)]
struct MlEvadeOutput {
    schema_version: u32,
    target: String,
    waf_name: String,
    is_ml_backed: bool,
    attack: String,
    found_evasion: bool,
    techniques: Vec<String>,
    description: String,
    /// Final body bytes (lossy UTF-8) after ML mutation. None when
    /// `found_evasion=false`.
    mutated_body: Option<String>,
    confidence: f64,
}

const SCHEMA_VERSION: u32 = 1;

pub fn run_ml_evade(args: MlEvadeArgs) -> ExitCode {
    let seed = args.seed.unwrap_or_else(|| {
        fnv1a_64_combine(&[
            args.target.as_bytes(),
            args.attack.as_bytes(),
            args.waf_name.as_bytes(),
        ])
    });
    let budget = args.budget.unwrap_or(DEFAULT_ML_BUDGET);
    let req = Request::post(args.target.clone(), args.attack.clone().into_bytes())
        .header("Content-Type", &args.content_type);
    let result = evade_ml_backed(&req, &args.waf_name, budget, seed);

    let is_ml_backed = result.is_some()
        || ml_class_check(&args.waf_name);
    let json_mode = args.format == "json";
    if json_mode {
        let envelope = render_json(&args, is_ml_backed, result.as_ref());
        match serde_json::to_string_pretty(&envelope) {
            Ok(s) => {
                println!("{s}");
            }
            Err(e) => {
                eprintln!("error: json render: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        print_text(&args, is_ml_backed, result.as_ref());
    }
    // Exit codes:
    //   0 = mutation produced (ML-backed + body + manifold accepted).
    //   3 = waf is not ML-backed (vacuous request, nothing to do).
    //   4 = ML-backed but manifold rejected every candidate.
    match (is_ml_backed, result.is_some()) {
        (true, true) => ExitCode::SUCCESS,
        (false, _) => ExitCode::from(3),
        (true, false) => ExitCode::from(4),
    }
}

fn render_json(
    args: &MlEvadeArgs,
    is_ml_backed: bool,
    result: Option<&wafrift_types::EvasionResult>,
) -> MlEvadeOutput {
    MlEvadeOutput {
        schema_version: SCHEMA_VERSION,
        target: args.target.clone(),
        waf_name: args.waf_name.clone(),
        is_ml_backed,
        attack: args.attack.clone(),
        found_evasion: result.is_some(),
        techniques: result
            .map(|r| r.techniques.iter().map(format_technique).collect())
            .unwrap_or_default(),
        description: result
            .map(|r| r.description.clone())
            .unwrap_or_default(),
        mutated_body: result.and_then(|r| {
            r.request
                .body_bytes()
                .map(|b| String::from_utf8_lossy(b).into_owned())
        }),
        confidence: result.map(|r| r.confidence).unwrap_or(0.0),
    }
}

fn print_text(
    args: &MlEvadeArgs,
    is_ml_backed: bool,
    result: Option<&wafrift_types::EvasionResult>,
) {
    println!("Target   : {}", args.target);
    println!("WAF      : {} (ml-backed: {is_ml_backed})", args.waf_name);
    println!("Attack   : {}", args.attack);
    match result {
        Some(r) => {
            println!(
                "Evasion  : FOUND — {} technique(s), confidence {:.2}",
                r.techniques.len(),
                r.confidence
            );
            println!("Desc     : {}", r.description);
            for t in &r.techniques {
                println!("  - {}", format_technique(t));
            }
            if let Some(body) = r.request.body_bytes() {
                println!(
                    "Mutated  : {:?}",
                    String::from_utf8_lossy(body)
                );
            }
        }
        None if !is_ml_backed => {
            println!("Evasion  : skipped — '{}' is not an ML-backed WAF", args.waf_name);
        }
        None => {
            println!(
                "Evasion  : ML-backed WAF but the manifold check rejected every mutation \
                 candidate. Try a larger --budget or a different seed."
            );
        }
    }
}

fn format_technique(t: &Technique) -> String {
    format!("{t:?}")
}

/// Cheap check: does the waf_name route to an `is_ml_backed` class?
/// Used by the exit-code branch and by the JSON envelope's
/// `is_ml_backed` field so operators can see why an exit-3 happened.
fn ml_class_check(waf_name: &str) -> bool {
    wafrift_types::WafClass::from_waf_name(waf_name).is_ml_backed()
}

/// FNV-1a 64 over a concatenation of byte slices — deterministic
/// seed when the operator hasn't passed `--seed`.
fn fnv1a_64_combine(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for part in parts {
        for &b in *part {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x100000001b3);
        }
        // Domain separator between parts so (a,bc) doesn't collide
        // with (ab,c).
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(waf: &str) -> MlEvadeArgs {
        MlEvadeArgs {
            target: "https://target.example/".into(),
            attack: "q=' OR 1=1--".into(),
            waf_name: waf.into(),
            budget: Some(32),
            seed: Some(42),
            content_type: "application/x-www-form-urlencoded".into(),
            format: "json".into(),
        }
    }

    #[test]
    fn non_ml_waf_returns_exit_3() {
        let code = run_ml_evade(args("ModSecurity"));
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(3)),
            "non-ML WAF must short-circuit with exit 3"
        );
    }

    #[test]
    fn empty_waf_name_returns_exit_3() {
        let code = run_ml_evade(args(""));
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(3)));
    }

    #[test]
    fn ml_backed_waf_returns_zero_or_four_never_panics() {
        // AWS Bot Control is ML-backed. The manifold check is
        // probabilistic — the function may produce a mutation (exit 0)
        // or reject every candidate (exit 4). Both are acceptable;
        // the contract is "never panic".
        let code = run_ml_evade(args("AWS Bot Control"));
        let s = format!("{code:?}");
        assert!(
            s.contains("(0)") || s.contains("(4)"),
            "ML-backed WAF must exit 0 or 4, got {s}"
        );
    }

    #[test]
    fn ml_class_check_matches_strategy_crate_semantics() {
        // Pin: the four ML-backed classes the strategy crate
        // recognises. If a new class is added, this test catches it
        // and forces a CLI surface update (e.g. flag docs).
        assert!(ml_class_check("AWS Bot Control"));
        assert!(ml_class_check("Cloudflare Bot Management"));
        assert!(ml_class_check("Akamai Bot Manager"));
        assert!(ml_class_check("Datadome"));
        // Negatives: ensemble or rule-based products.
        assert!(!ml_class_check("Cloudflare WAF"));
        assert!(!ml_class_check("ModSecurity"));
        assert!(!ml_class_check(""));
    }

    #[test]
    fn fnv1a_64_combine_distinguishes_part_boundaries() {
        // The domain separator means (a, bc) and (ab, c) must hash
        // differently — otherwise an attacker controlling part of
        // the seed input could force a collision.
        let a = fnv1a_64_combine(&[b"a", b"bc"]);
        let b = fnv1a_64_combine(&[b"ab", b"c"]);
        assert_ne!(a, b, "boundary-separator must change the hash");
    }

    #[test]
    fn fnv1a_64_combine_is_deterministic_for_same_input() {
        let a = fnv1a_64_combine(&[b"hello", b"world"]);
        let b = fnv1a_64_combine(&[b"hello", b"world"]);
        assert_eq!(a, b);
    }

    #[test]
    fn render_json_emits_complete_envelope_on_no_result() {
        let a = args("ModSecurity");
        let env = render_json(&a, false, None);
        assert_eq!(env.schema_version, SCHEMA_VERSION);
        assert!(!env.is_ml_backed);
        assert!(!env.found_evasion);
        assert!(env.techniques.is_empty());
        assert_eq!(env.mutated_body, None);
        assert!((env.confidence - 0.0).abs() < 1e-9);
    }

    // ─── ADVERSARIAL: input boundaries ────────────────────────────

    #[test]
    fn empty_attack_does_not_panic() {
        let mut a = args("AWS Bot Control");
        a.attack = String::new();
        // Empty body short-circuits inside the function. Must not
        // panic; exit-code defined per (is_ml_backed, mutation_found).
        let code = run_ml_evade(a);
        let s = format!("{code:?}");
        assert!(s.contains("(0)") || s.contains("(3)") || s.contains("(4)"));
    }

    #[test]
    fn ten_megabyte_attack_does_not_panic() {
        let mut a = args("AWS Bot Control");
        a.attack = "x".repeat(10 * 1024 * 1024);
        let code = run_ml_evade(a);
        let s = format!("{code:?}");
        assert!(
            s.contains("(0)") || s.contains("(3)") || s.contains("(4)"),
            "10 MiB attack must produce a defined exit: {s}"
        );
    }

    #[test]
    fn attack_with_null_bytes_no_panic() {
        let mut a = args("AWS Bot Control");
        a.attack = "\0\0\0attack\0".into();
        let _ = run_ml_evade(a);
    }

    #[test]
    fn attack_with_invalid_utf8_via_unicode_replacement() {
        // CLI arg is String so can't carry raw 0xFE/0xFF — but
        // multi-byte unicode + lone surrogates should still pass
        // through without panic.
        let mut a = args("AWS Bot Control");
        a.attack = "пëîçÿ\u{FFFD}".into();
        let _ = run_ml_evade(a);
    }

    #[test]
    fn budget_zero_does_not_underflow() {
        let mut a = args("AWS Bot Control");
        a.budget = Some(0);
        let code = run_ml_evade(a);
        let s = format!("{code:?}");
        assert!(s.contains("(0)") || s.contains("(4)"));
    }

    #[test]
    fn budget_u64_max_does_not_overflow() {
        let mut a = args("AWS Bot Control");
        a.budget = Some(u64::MAX);
        // Must terminate in bounded time despite the huge budget —
        // the underlying search has its own caps.
        let start = std::time::Instant::now();
        let _ = run_ml_evade(a);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(30),
            "u64::MAX budget must terminate in <30s"
        );
    }

    // ─── ADVERSARIAL: waf_name parsing ─────────────────────────────

    #[test]
    fn waf_name_with_surrounding_whitespace() {
        // Pin current behavior: WafClass::from_waf_name does NOT
        // trim whitespace, so `"  AWS Bot Control  "` may NOT be
        // recognized. If the function is updated to trim, this test
        // catches it and forces a docs/test update.
        let mut a = args("  AWS Bot Control  ");
        a.format = "json".into();
        let code = run_ml_evade(a);
        let s = format!("{code:?}");
        // Both behaviors are acceptable; assert non-panic + defined
        // exit code only.
        assert!(s.contains("(0)") || s.contains("(3)") || s.contains("(4)"));
    }

    #[test]
    fn waf_name_unicode_does_not_panic() {
        // Two separate runs so we don't need Clone on the args.
        let code = run_ml_evade(args("Унікнул Кловдфлоер"));
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(3)),
            "unrecognized WAF name (unicode garbage) must exit 3 vacuously"
        );
        let mut a2 = args("Унікнул Кловдфлоер");
        a2.attack = String::new();
        let _ = run_ml_evade(a2);
    }

    #[test]
    fn waf_name_extremely_long() {
        let code = run_ml_evade(args(&"X".repeat(10_000)));
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(3)),
            "long unrecognized waf name must short-circuit to exit 3"
        );
    }

    #[test]
    fn waf_name_with_null_byte() {
        let code = run_ml_evade(args("AWS Bot\0Control"));
        // Embedded null breaks the match; expect exit 3.
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(3))
        );
    }

    // ─── ADVERSARIAL: content-type passthrough ─────────────────────

    #[test]
    fn empty_content_type_does_not_panic() {
        let mut a = args("AWS Bot Control");
        a.content_type = String::new();
        let _ = run_ml_evade(a);
    }

    #[test]
    fn content_type_with_semicolons_and_charset() {
        let mut a = args("AWS Bot Control");
        a.content_type = "application/json; charset=utf-8; boundary=foo".into();
        let _ = run_ml_evade(a);
    }

    #[test]
    fn content_type_with_newline_does_not_panic() {
        // Header injection probe. The wafrift_types::Request header
        // setter should at minimum not panic; whether it sanitizes
        // is a separate question.
        let mut a = args("AWS Bot Control");
        a.content_type = "application/json\r\nX-Smuggle: yes".into();
        let _ = run_ml_evade(a);
    }

    // ─── ADVERSARIAL: seed determinism ─────────────────────────────

    #[test]
    fn explicit_seed_is_deterministic_across_runs() {
        // Repeated runs with the SAME explicit seed must produce
        // identical exit codes (the underlying mutation search is
        // seeded deterministic).
        let a1 = args("AWS Bot Control");
        let a2 = args("AWS Bot Control");
        let c1 = run_ml_evade(a1);
        let c2 = run_ml_evade(a2);
        assert_eq!(format!("{c1:?}"), format!("{c2:?}"));
    }

    #[test]
    fn fnv1a_combine_treats_split_inputs_as_different() {
        // Stronger version of the existing boundary test: two
        // structurally different splits must hash differently
        // across many cases.
        for (a, b) in [
            (vec![&b""[..], b"abc"], vec![&b"a"[..], b"bc"]),
            (vec![&b"abc"[..]], vec![&b"a"[..], b"bc"]),
            (vec![&b"a"[..], b"b", b"c"], vec![&b"ab"[..], b"c"]),
        ] {
            assert_ne!(
                fnv1a_64_combine(&a),
                fnv1a_64_combine(&b),
                "split boundaries must distinguish: {a:?} vs {b:?}"
            );
        }
    }

    // ─── ADVERSARIAL: ml_class_check robustness ────────────────────

    #[test]
    fn ml_class_check_partial_substrings_negative() {
        // "AWS" alone (no "Bot Control") must not match.
        assert!(!ml_class_check("AWS"));
        assert!(!ml_class_check("Cloudflare"));
        assert!(!ml_class_check("Akamai"));
    }

    #[test]
    fn ml_class_check_lowercase_variants() {
        // The classifier uses substring matching internally; pin
        // current behavior. If matching is case-sensitive, lowercase
        // names won't match.
        // (Whichever way it works, the test docs the contract.)
        let lower = ml_class_check("aws bot control");
        let upper = ml_class_check("AWS Bot Control");
        assert!(upper, "canonical name must match");
        // Both true OR both false are acceptable; mixed = bug.
        if lower != upper {
            panic!(
                "case-sensitivity mismatch: ml_class_check is inconsistent \
                 (lower={lower}, upper={upper})"
            );
        }
    }
}
