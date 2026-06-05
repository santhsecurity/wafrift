//! Compare two `bench-waf --output JSON` blobs and gate on regression.
//!
//! Implements the regression rules from `wafrift-bench/methodology.md`:
//!   - bypass-rate drop >= --bypass-drop-pp percentage points → regression
//!   - raw-block-rate drop below --raw-block-floor → WAF stack changed,
//!     not wafrift; emits a warning (stack mismatch ≠ wafrift bug).
//!
//! Used as a CI gate: exit 3 means "wafrift got worse vs baseline".

use std::path::PathBuf;
use std::process::ExitCode;

/// `bench-waf --output` JSON blobs in CI are a few MiB for ~1k cases
/// today; growth headroom is fine. 64 MiB catches `/dev/zero`,
/// hostile symlinks, and accidental log-file aliasing without
/// rejecting any legitimate bench output we've ever shipped.
const BENCH_DIFF_INPUT_MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, clap::Args)]
pub(crate) struct BenchDiffArgs {
    /// R48-I8 fix (dogfood pass 9): operator muscle memory expects
    /// `wafrift bench-diff <CURRENT> <BASELINE>` to work positional.
    /// Long-form flags retained for backwards-compat. Either form
    /// works; mixing them errors via clap's overrides_with.
    #[arg(value_name = "CURRENT", conflicts_with = "current")]
    pub current_positional: Option<PathBuf>,

    #[arg(value_name = "BASELINE", conflicts_with = "baseline")]
    pub baseline_positional: Option<PathBuf>,

    /// JSON output from the new bench-waf run.
    #[arg(long, required_unless_present = "current_positional")]
    pub current: Option<PathBuf>,

    /// JSON output from the prior baseline run.
    #[arg(long, required_unless_present = "baseline_positional")]
    pub baseline: Option<PathBuf>,

    /// Regression threshold: a drop of this many percentage points in
    /// `evaded_summary.overall_bypass_rate` triggers exit 3. Default 2pp
    /// matches the methodology.md rule.
    #[arg(long, default_value_t = 2.0)]
    pub bypass_drop_pp: f64,

    /// Stack-mismatch threshold: if `raw_block_rate` falls below this,
    /// the WAF target itself changed (not wafrift). Default 0.95 per
    /// methodology.md.
    #[arg(long, default_value_t = 0.95)]
    pub raw_block_floor: f64,

    /// Output format. `text` (default) prints the human-readable
    /// table; `json` emits a structured blob with all rates,
    /// drop_pp, regression flag, and any stack-mismatch warning
    /// so CI can act on the result without parsing stderr.
    /// R46-I2 / R46-I8 fix (dogfood pass 7): pre-fix --quiet
    /// emitted the human text table; consumers piping to jq broke.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

pub(crate) fn run_bench_diff(args: BenchDiffArgs) -> ExitCode {
    // R48-I8: resolve positional vs --long-flag forms. clap
    // guarantees exactly one of each via `required_unless_present`
    // + `conflicts_with`, so both `or` paths are reachable.
    let current_path = match args.current.as_ref().or(args.current_positional.as_ref()) {
        Some(p) => p.clone(),
        None => unreachable!("clap guarantees one of current / current_positional"),
    };
    let baseline_path = match args.baseline.as_ref().or(args.baseline_positional.as_ref()) {
        Some(p) => p.clone(),
        None => unreachable!("clap guarantees one of baseline / baseline_positional"),
    };
    let cur = match load(&current_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: read {}: {e}", current_path.display());
            return ExitCode::from(1);
        }
    };
    let base = match load(&baseline_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: read {}: {e}", baseline_path.display());
            return ExitCode::from(1);
        }
    };

    // Detect files that are clearly not bench-waf outputs — warn before
    // comparing so the operator knows they're comparing garbage.
    // A legitimate bench-waf file always has at least one of: raw_block_rate,
    // evade_mode, or results. Two missing = almost certainly the wrong file.
    let looks_like_bench = |v: &serde_json::Value| -> bool {
        v.get("raw_block_rate").is_some()
            || v.get("evade_mode").is_some()
            || v.get("results").is_some()
    };
    // R45-tail fix (dogfood): if BOTH inputs lack the bench-waf
    // shape, the comparison is definitely meaningless. Exit 2
    // instead of issuing a warning and proceeding to print zeroes
    // — a CI gate using bench-diff exit code as the regression
    // signal was passing on totally bogus files.
    let cur_ok = looks_like_bench(&cur);
    let base_ok = looks_like_bench(&base);
    if !cur_ok && !base_ok {
        eprintln!(
            "error: neither {} nor {} looks like a bench-waf --output file \
             (both missing raw_block_rate / evade_mode / results). Refusing \
             to print a zero diff for non-bench inputs.",
            current_path.display(),
            baseline_path.display()
        );
        return ExitCode::from(2);
    }
    if !cur_ok {
        eprintln!(
            "WARNING: {} does not look like a bench-waf --output file (missing raw_block_rate / evade_mode / results). Comparison may be meaningless.",
            current_path.display()
        );
    }
    if !base_ok {
        eprintln!(
            "WARNING: {} does not look like a bench-waf --output file (missing raw_block_rate / evade_mode / results). Comparison may be meaningless.",
            baseline_path.display()
        );
    }

    // Catch the foot-gun where one side ran with --evade and the other
    // didn't. The bypass-rate column only exists in evade mode, and a
    // missing field reads as 0 — silent comparison would either show a
    // huge drop (regression alarm) or a huge climb (false reassurance).
    let cur_evade = evade_mode(&cur);
    let base_evade = evade_mode(&base);
    if cur_evade != base_evade {
        eprintln!(
            "WARNING: mode mismatch — baseline evade_mode={base_evade}, current evade_mode={cur_evade}. \
             Bypass-rate comparison is meaningless when only one side ran the evasion engine."
        );
    }

    let cur_bypass = bypass_rate(&cur);
    let base_bypass = bypass_rate(&base);
    let cur_raw = raw_block_rate(&cur);
    let base_raw = raw_block_rate(&base);
    let drop_pp = (base_bypass - cur_bypass) * 100.0;

    let mut regression = false;
    let stack_mismatch = cur_raw < args.raw_block_floor;

    if args.format == "text" {
        println!("baseline overall bypass: {:.2}%", base_bypass * 100.0);
        println!("current  overall bypass: {:.2}%", cur_bypass * 100.0);
        println!("delta:                   {:+.2}pp", -drop_pp);
        println!("baseline raw-block:      {:.2}%", base_raw * 100.0);
        println!("current  raw-block:      {:.2}%", cur_raw * 100.0);
    }

    if drop_pp > args.bypass_drop_pp {
        if args.format == "text" {
            eprintln!(
                "REGRESSION: bypass rate fell {:.2}pp (threshold {:.2}pp).",
                drop_pp, args.bypass_drop_pp
            );
        }
        regression = true;
    }

    if stack_mismatch && args.format == "text" {
        eprintln!(
            "WARNING: current raw-block-rate {:.2}% < floor {:.2}% — \
             the WAF stack itself may have changed (not a wafrift bug).",
            cur_raw * 100.0,
            args.raw_block_floor * 100.0
        );
    }

    if args.format == "json" {
        // R46-I8 fix: everything the operator might check goes into
        // ONE structured object on stdout so CI can `| jq` without
        // also tee'ing stderr.
        let obj = serde_json::json!({
            "schema_version": 1,
            "baseline_bypass_rate": base_bypass,
            "current_bypass_rate": cur_bypass,
            "delta_pp": -drop_pp,
            "baseline_raw_block_rate": base_raw,
            "current_raw_block_rate": cur_raw,
            "bypass_drop_pp_threshold": args.bypass_drop_pp,
            "raw_block_floor": args.raw_block_floor,
            "regression": regression,
            "stack_mismatch_warning": stack_mismatch,
        });
        println!("{}", serde_json::to_string(&obj).unwrap_or_default());
    }

    if regression {
        ExitCode::from(3)
    } else {
        println!("OK: no regression vs baseline.");
        ExitCode::SUCCESS
    }
}

fn load(path: &std::path::Path) -> Result<serde_json::Value, String> {
    let s = crate::safe_body::read_bounded_text_file(path, BENCH_DIFF_INPUT_MAX_BYTES)
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

fn bypass_rate(v: &serde_json::Value) -> f64 {
    v.pointer("/evaded_summary/overall_bypass_rate")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0)
}

fn raw_block_rate(v: &serde_json::Value) -> f64 {
    v.pointer("/raw_block_rate")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0)
}

fn evade_mode(v: &serde_json::Value) -> bool {
    v.pointer("/evade_mode")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &std::path::Path, body: &str) {
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn regression_when_bypass_falls_more_than_threshold() {
        let dir = std::env::temp_dir().join("wafrift_bench_diff_test_regress");
        let _ = std::fs::create_dir_all(&dir);
        let cur = dir.join("cur.json");
        let base = dir.join("base.json");
        write(
            &base,
            r#"{"raw_block_rate":1.0,"evaded_summary":{"overall_bypass_rate":0.50}}"#,
        );
        write(
            &cur,
            r#"{"raw_block_rate":1.0,"evaded_summary":{"overall_bypass_rate":0.40}}"#,
        );
        let code = run_bench_diff(BenchDiffArgs {
            current_positional: None,
            baseline_positional: None,
            current: Some(cur),
            baseline: Some(base),
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
            format: "text".into(),
        });
        // ExitCode does not impl PartialEq; canonicalize via debug.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(3)));
    }

    #[test]
    fn ok_when_bypass_within_threshold() {
        let dir = std::env::temp_dir().join("wafrift_bench_diff_test_ok");
        let _ = std::fs::create_dir_all(&dir);
        let cur = dir.join("cur.json");
        let base = dir.join("base.json");
        write(
            &base,
            r#"{"raw_block_rate":1.0,"evaded_summary":{"overall_bypass_rate":0.50}}"#,
        );
        write(
            &cur,
            r#"{"raw_block_rate":1.0,"evaded_summary":{"overall_bypass_rate":0.49}}"#,
        );
        let code = run_bench_diff(BenchDiffArgs {
            current_positional: None,
            baseline_positional: None,
            current: Some(cur),
            baseline: Some(base),
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
            format: "text".into(),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn raw_block_floor_warns_but_does_not_fail() {
        // Stack-mismatch path: bypass rate unchanged, but raw_block_rate
        // dropped below the floor. Per methodology this is a "stack
        // changed", NOT a wafrift regression — exit must stay 0.
        let dir = std::env::temp_dir().join("wafrift_bench_diff_test_floor");
        let _ = std::fs::create_dir_all(&dir);
        let cur = dir.join("cur.json");
        let base = dir.join("base.json");
        write(
            &base,
            r#"{"raw_block_rate":1.0,"evaded_summary":{"overall_bypass_rate":0.50}}"#,
        );
        write(
            &cur,
            r#"{"raw_block_rate":0.80,"evaded_summary":{"overall_bypass_rate":0.50}}"#,
        );
        let code = run_bench_diff(BenchDiffArgs {
            current_positional: None,
            baseline_positional: None,
            current: Some(cur),
            baseline: Some(base),
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
            format: "text".into(),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn malformed_baseline_json_returns_exit_1() {
        let dir = std::env::temp_dir().join("wafrift_bench_diff_test_malformed");
        let _ = std::fs::create_dir_all(&dir);
        let cur = dir.join("cur.json");
        let base = dir.join("base.json");
        write(
            &cur,
            r#"{"raw_block_rate":1.0,"evaded_summary":{"overall_bypass_rate":0.5}}"#,
        );
        write(&base, "not json at all");
        let code = run_bench_diff(BenchDiffArgs {
            current_positional: None,
            baseline_positional: None,
            current: Some(cur),
            baseline: Some(base),
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
            format: "text".into(),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
    }

    #[test]
    fn missing_baseline_file_returns_exit_1() {
        let dir = std::env::temp_dir().join("wafrift_bench_diff_test_missing");
        let _ = std::fs::create_dir_all(&dir);
        let cur = dir.join("cur.json");
        write(
            &cur,
            r#"{"raw_block_rate":1.0,"evaded_summary":{"overall_bypass_rate":0.5}}"#,
        );
        let code = run_bench_diff(BenchDiffArgs {
            current_positional: None,
            baseline_positional: None,
            current: Some(cur),
            baseline: Some(dir.join("does-not-exist.json")),
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
            format: "text".into(),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
    }

    #[test]
    fn evade_mode_mismatch_warns_but_does_not_fail() {
        // Comparing a no-evade baseline against a with-evade current is a
        // foot-gun. We warn but don't fail (the operator may know exactly
        // what they're doing).
        let dir = std::env::temp_dir().join("wafrift_bench_diff_test_mode_mismatch");
        let _ = std::fs::create_dir_all(&dir);
        let cur = dir.join("cur.json");
        let base = dir.join("base.json");
        write(&base, r#"{"raw_block_rate":1.0,"evade_mode":false}"#);
        write(
            &cur,
            r#"{"raw_block_rate":1.0,"evade_mode":true,"evaded_summary":{"overall_bypass_rate":0.10}}"#,
        );
        let code = run_bench_diff(BenchDiffArgs {
            current_positional: None,
            baseline_positional: None,
            current: Some(cur),
            baseline: Some(base),
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
            format: "text".into(),
        });
        // base_bypass=0, cur_bypass=0.10 → drop_pp negative → no regression.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn non_bench_files_are_rejected_not_silently_zero_diffed() {
        // Both files are valid JSON but lack every bench-waf field.
        // Pre-hardening this silently returned a 0% diff; that turned
        // `wafrift bench-diff` into a CI green stamp for any unrelated
        // JSON pair. New contract: refuse with exit 2 (bad-input) so
        // the gate can never be tricked by malformed artifacts.
        let dir = std::env::temp_dir().join("wafrift_bench_diff_test_non_bench");
        let _ = std::fs::create_dir_all(&dir);
        let cur = dir.join("cur.json");
        let base = dir.join("base.json");
        write(&cur, r#"{"completely":"unrelated","data":42}"#);
        write(&base, r#"{"also":"unrelated"}"#);
        let code = run_bench_diff(BenchDiffArgs {
            current_positional: None,
            baseline_positional: None,
            current: Some(cur),
            baseline: Some(base),
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
            format: "text".into(),
        });
        // Bad-input exit code (anti-rig: never silently 0).
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(2)));
    }

    #[test]
    fn empty_evaded_summary_treats_as_zero_bypass() {
        // Defensive: an old-schema baseline that lacks evaded_summary
        // should not be mis-read as 0% bypass and trigger a phantom
        // regression. Currently bypass_rate() returns 0 on missing
        // pointer — that means base_bypass=0, cur_bypass=anything
        // gives drop_pp <= 0, so no regression. Pin this with a test.
        let dir = std::env::temp_dir().join("wafrift_bench_diff_test_old_schema");
        let _ = std::fs::create_dir_all(&dir);
        let cur = dir.join("cur.json");
        let base = dir.join("base.json");
        write(
            &cur,
            r#"{"raw_block_rate":1.0,"evaded_summary":{"overall_bypass_rate":0.30}}"#,
        );
        write(&base, r#"{"raw_block_rate":1.0}"#); // no evaded_summary
        let code = run_bench_diff(BenchDiffArgs {
            current_positional: None,
            baseline_positional: None,
            current: Some(cur),
            baseline: Some(base),
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
            format: "text".into(),
        });
        // base_bypass = 0 (missing), cur_bypass = 0.30 → no regression.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    // ── Round 18: bounded bench-diff input reads ─────────────────────
    //
    // `bench-diff --current` / `--baseline` previously slurped via
    // std::fs::read_to_string and OOMed on /dev/zero / multi-GB
    // symlinks. Must go through safe_body::read_bounded_text_file
    // with BENCH_DIFF_INPUT_MAX_BYTES.

    #[test]
    fn bench_diff_input_load_is_bounded() {
        let src = include_str!("bench_diff.rs");
        let needle = "safe_body::read_bounded_text_file(path, BENCH_DIFF_INPUT_MAX_BYTES)";
        assert!(
            src.contains(needle),
            "bench_diff.rs `load` must use bounded reader with BENCH_DIFF_INPUT_MAX_BYTES"
        );
        let banned = concat!(
            "std::fs::",
            "read_to_",
            "string(path).map_err(|e| e.to_string())"
        );
        assert!(
            !src.contains(banned),
            "raw unbounded fs read of bench-diff input path reintroduced — OOM regression"
        );
    }

    #[test]
    fn bench_diff_cap_is_sane() {
        assert!(
            super::BENCH_DIFF_INPUT_MAX_BYTES >= 16 * 1024 * 1024,
            "BENCH_DIFF_INPUT_MAX_BYTES tightened below 16 MiB — could reject legitimate bench outputs"
        );
    }
}
