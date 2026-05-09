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

#[derive(Debug, clap::Args)]
pub struct BenchDiffArgs {
    /// JSON output from the new bench-waf run.
    #[arg(long)]
    pub current: PathBuf,

    /// JSON output from the prior baseline run.
    #[arg(long)]
    pub baseline: PathBuf,

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
}

pub fn run_bench_diff(args: BenchDiffArgs) -> ExitCode {
    let cur = match load(&args.current) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: read {}: {e}", args.current.display());
            return ExitCode::from(1);
        }
    };
    let base = match load(&args.baseline) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: read {}: {e}", args.baseline.display());
            return ExitCode::from(1);
        }
    };

    let cur_bypass = bypass_rate(&cur);
    let base_bypass = bypass_rate(&base);
    let cur_raw = raw_block_rate(&cur);
    let base_raw = raw_block_rate(&base);
    let drop_pp = (base_bypass - cur_bypass) * 100.0;

    let mut regression = false;

    println!("baseline overall bypass: {:.2}%", base_bypass * 100.0);
    println!("current  overall bypass: {:.2}%", cur_bypass * 100.0);
    println!("delta:                   {:+.2}pp", -drop_pp);
    println!("baseline raw-block:      {:.2}%", base_raw * 100.0);
    println!("current  raw-block:      {:.2}%", cur_raw * 100.0);

    if drop_pp >= args.bypass_drop_pp {
        eprintln!(
            "REGRESSION: bypass rate fell {:.2}pp (threshold {:.2}pp).",
            drop_pp, args.bypass_drop_pp
        );
        regression = true;
    }

    if cur_raw < args.raw_block_floor {
        eprintln!(
            "WARNING: current raw-block-rate {:.2}% < floor {:.2}% — \
             the WAF stack itself may have changed (not a wafrift bug).",
            cur_raw * 100.0,
            args.raw_block_floor * 100.0
        );
    }

    if regression {
        ExitCode::from(3)
    } else {
        println!("OK: no regression vs baseline.");
        ExitCode::SUCCESS
    }
}

fn load(path: &std::path::Path) -> Result<serde_json::Value, String> {
    let s = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

fn bypass_rate(v: &serde_json::Value) -> f64 {
    v.pointer("/evaded_summary/overall_bypass_rate")
        .and_then(|x| x.as_f64())
        .unwrap_or(0.0)
}

fn raw_block_rate(v: &serde_json::Value) -> f64 {
    v.pointer("/raw_block_rate").and_then(|x| x.as_f64()).unwrap_or(0.0)
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
            current: cur,
            baseline: base,
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
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
            current: cur,
            baseline: base,
            bypass_drop_pp: 2.0,
            raw_block_floor: 0.95,
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }
}
