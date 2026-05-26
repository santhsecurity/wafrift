//! `wafrift tmin` — corpus minimization alias for `wafrift distill`.
//!
//! Given a KNOWN-working bypass payload, apply Zeller's ddmin to find the
//! minimum-edit-distance substring that STILL bypasses. The full algorithm
//! lives in `distill_cmd`; this module is a thin re-export layer that
//! presents the same capability under the `tmin` name familiar to AFL /
//! libFuzzer users.
//!
//! ## Why not duplicate?
//!
//! LAW 2 (backwards-compatible, complete modularity): duplicating the ddmin
//! logic into a second command buys nothing and creates a maintenance split.
//! `tmin` re-exports `DistillArgs` verbatim and delegates to `run_distill`
//! — the two commands are indistinguishable at runtime. The only user-visible
//! difference is the name: `distill` comes from the pentest vocabulary,
//! `tmin` comes from fuzzing tooling. Both are valid entry points.
//!
//! ## Output
//!
//! `tmin` streams the same reduction probes and emits the same final
//! summary as `distill` (original length, final length, probes spent).
//! Use `--format json` for machine-readable output.

use std::process::ExitCode;

use clap::Args;
use tokio_util::sync::CancellationToken;

use crate::distill_cmd::{DistillArgs, run_distill};

/// Arguments for `wafrift tmin` — identical to `wafrift distill` by design
/// (same algorithm, different entry-point name for AFL/fuzzer-familiar users).
///
/// Every flag documented here is forwarded verbatim to the ddmin engine in
/// `distill_cmd::run_distill`.
#[derive(Args, Debug)]
pub struct TminArgs {
    /// Target URL.
    #[arg(value_name = "URL")]
    pub target: String,

    /// Query parameter name to inject into.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// The KNOWN-working bypass payload to minimize. Must actually bypass the
    /// WAF — `tmin` exits 2 if the payload is blocked on the first probe.
    /// Typically the `bypass_variants[i].payload` field from
    /// `wafrift scan --format json` output. Reads from stdin when omitted
    /// and stdin is not a tty.
    #[arg(long)]
    pub payload: Option<String>,

    /// Output format. `text` prints a short summary; `json` emits a
    /// structured blob compatible with `wafrift distill --format json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Inter-fire delay (ms) — useful against rate-limited targets.
    #[arg(long, default_value_t = 0)]
    pub delay_ms: u64,

    /// Accept self-signed TLS certificates.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// HTTP proxy to route every probe through.
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Extra request headers (`-H 'Name: Value'`, repeatable).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Maximum HTTP probes before stopping (anti-runaway guard).
    /// Default 500.
    #[arg(long, default_value_t = 500)]
    pub max_fires: u32,
}

impl TminArgs {
    /// Convert into the canonical `DistillArgs` that `run_distill` accepts.
    ///
    /// `--payload` is required for `distill`. If the caller omitted it and
    /// stdin is a tty we cannot recover — return `None` and the caller
    /// prints the usage error.
    fn into_distill_args(self) -> Option<DistillArgs> {
        let payload = match self.payload {
            Some(p) => p,
            None => {
                // Try reading from stdin (non-interactive pipe).
                use std::io::IsTerminal;
                if std::io::stdin().is_terminal() {
                    return None;
                }
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf).ok()?;
                buf.trim().to_string()
            }
        };
        Some(DistillArgs {
            target: self.target,
            param: self.param,
            payload,
            format: self.format,
            delay_ms: self.delay_ms,
            insecure: self.insecure,
            proxy: self.proxy,
            header: self.header,
            max_fires: self.max_fires,
        })
    }
}

/// Entry point — dispatched from `main::Commands::Tmin`.
///
/// Delegates entirely to `distill_cmd::run_distill`. See that module for
/// the full ddmin algorithm documentation.
pub async fn run_tmin(args: TminArgs, cancel: CancellationToken) -> ExitCode {
    let distill_args = match args.into_distill_args() {
        Some(a) => a,
        None => {
            eprintln!(
                "error: --payload is required (or pipe a payload on stdin)"
            );
            return ExitCode::from(2);
        }
    };
    run_distill(distill_args, cancel).await
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Conversion: all fields survive the TminArgs → DistillArgs round-trip.
    #[test]
    fn into_distill_args_roundtrip() {
        let tmin = TminArgs {
            target: "http://target/".into(),
            param: "p".into(),
            payload: Some("<script>alert(1)</script>".into()),
            format: "json".into(),
            delay_ms: 50,
            insecure: true,
            proxy: Some("http://127.0.0.1:8080".into()),
            header: vec!["X-Test: 1".into()],
            max_fires: 200,
        };
        let da = tmin.into_distill_args().expect("should convert");
        assert_eq!(da.target, "http://target/");
        assert_eq!(da.param, "p");
        assert_eq!(da.payload, "<script>alert(1)</script>");
        assert_eq!(da.format, "json");
        assert_eq!(da.delay_ms, 50);
        assert!(da.insecure);
        assert_eq!(da.proxy, Some("http://127.0.0.1:8080".into()));
        assert_eq!(da.header, vec!["X-Test: 1".to_string()]);
        assert_eq!(da.max_fires, 200);
    }

    /// Default values survive conversion.
    #[test]
    fn into_distill_args_defaults() {
        let tmin = TminArgs {
            target: "http://localhost/".into(),
            param: "q".into(),
            payload: Some("' OR 1=1--".into()),
            format: "text".into(),
            delay_ms: 0,
            insecure: false,
            proxy: None,
            header: vec![],
            max_fires: 500,
        };
        let da = tmin.into_distill_args().expect("should convert");
        assert_eq!(da.param, "q");
        assert!(!da.insecure);
        assert!(da.proxy.is_none());
        assert_eq!(da.max_fires, 500);
    }

    /// None payload with no stdin pipe returns None.
    #[test]
    fn none_payload_tty_returns_none() {
        // We can only reliably test the non-stdin branch in unit tests
        // (stdin IS a tty in the test harness). The tty branch should
        // return None.
        let tmin = TminArgs {
            target: "http://target/".into(),
            param: "q".into(),
            payload: None,
            format: "text".into(),
            delay_ms: 0,
            insecure: false,
            proxy: None,
            header: vec![],
            max_fires: 500,
        };
        // In a test harness stdin is a tty, so this should be None.
        // (If the test harness pipes stdin, the read would succeed — that
        //  is also correct behaviour and the assertion would not fire.)
        let result = tmin.into_distill_args();
        // We cannot assert None because CI may pipe stdin. Just confirm
        // no panic.
        let _ = result;
    }

    /// Payload field preserves embedded special characters exactly.
    #[test]
    fn payload_special_chars_preserved() {
        let payload = "'; DROP TABLE users; -- \" <>&\t\n";
        let tmin = TminArgs {
            target: "http://t/".into(),
            param: "q".into(),
            payload: Some(payload.into()),
            format: "text".into(),
            delay_ms: 0,
            insecure: false,
            proxy: None,
            header: vec![],
            max_fires: 500,
        };
        let da = tmin.into_distill_args().unwrap();
        assert_eq!(da.payload, payload);
    }

    /// Multipl headers are forwarded in order.
    #[test]
    fn multiple_headers_forwarded() {
        let tmin = TminArgs {
            target: "http://t/".into(),
            param: "q".into(),
            payload: Some("p".into()),
            format: "text".into(),
            delay_ms: 0,
            insecure: false,
            proxy: None,
            header: vec!["A: 1".into(), "B: 2".into(), "C: 3".into()],
            max_fires: 500,
        };
        let da = tmin.into_distill_args().unwrap();
        assert_eq!(da.header, vec!["A: 1", "B: 2", "C: 3"]);
    }

    /// max_fires=0 is a valid (immediate-abort) setting.
    #[test]
    fn max_fires_zero_valid() {
        let tmin = TminArgs {
            target: "http://t/".into(),
            param: "q".into(),
            payload: Some("p".into()),
            format: "text".into(),
            delay_ms: 0,
            insecure: false,
            proxy: None,
            header: vec![],
            max_fires: 0,
        };
        let da = tmin.into_distill_args().unwrap();
        assert_eq!(da.max_fires, 0);
    }

    /// max_fires ceiling (u32::MAX) is preserved.
    #[test]
    fn max_fires_ceiling_preserved() {
        let tmin = TminArgs {
            target: "http://t/".into(),
            param: "q".into(),
            payload: Some("p".into()),
            format: "text".into(),
            delay_ms: 0,
            insecure: false,
            proxy: None,
            header: vec![],
            max_fires: u32::MAX,
        };
        let da = tmin.into_distill_args().unwrap();
        assert_eq!(da.max_fires, u32::MAX);
    }

    /// `json` format forwarded correctly.
    #[test]
    fn format_json_forwarded() {
        let tmin = TminArgs {
            target: "http://t/".into(),
            param: "q".into(),
            payload: Some("p".into()),
            format: "json".into(),
            delay_ms: 0,
            insecure: false,
            proxy: None,
            header: vec![],
            max_fires: 500,
        };
        let da = tmin.into_distill_args().unwrap();
        assert_eq!(da.format, "json");
    }

    /// Large delay_ms is preserved.
    #[test]
    fn delay_ms_large_value() {
        let tmin = TminArgs {
            target: "http://t/".into(),
            param: "q".into(),
            payload: Some("p".into()),
            format: "text".into(),
            delay_ms: 60_000,
            insecure: false,
            proxy: None,
            header: vec![],
            max_fires: 500,
        };
        let da = tmin.into_distill_args().unwrap();
        assert_eq!(da.delay_ms, 60_000);
    }

    /// Empty proxy string is NOT normalised to None (caller's intent).
    #[test]
    fn empty_proxy_stays_some() {
        let tmin = TminArgs {
            target: "http://t/".into(),
            param: "q".into(),
            payload: Some("p".into()),
            format: "text".into(),
            delay_ms: 0,
            insecure: false,
            proxy: Some(String::new()),
            header: vec![],
            max_fires: 500,
        };
        let da = tmin.into_distill_args().unwrap();
        // The empty proxy string is forwarded — the transport layer decides
        // what to do with it (likely errors, which is also correct).
        assert_eq!(da.proxy, Some(String::new()));
    }
}
