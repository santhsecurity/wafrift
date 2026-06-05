//! Print ready-to-merge `EvasionConfig` snippets for common egress presets.

use serde_json::json;
use std::process::ExitCode;

#[derive(Debug, clap::Args)]
pub(crate) struct EgressExampleArgs {
    /// Preset name: `tor` (`SOCKS5h` to local Tor).
    #[arg(long, default_value = "tor", value_parser = ["tor"])]
    pub preset: String,
    /// Output format. `json` (default) emits only the bare JSON
    /// snippet — clean for piping into `jq` or merging into a config
    /// file. `human` adds the explanatory comment header on stderr
    /// for interactive use. Per dogfood B8: pre-fix the comment was
    /// unconditionally emitted to stderr, polluting `2>&1` capture of
    /// callers that expected pure JSON.
    #[arg(long, default_value = "json", value_parser = ["json", "human"])]
    pub format: String,
}

pub(crate) fn run_egress_example(args: EgressExampleArgs) -> ExitCode {
    let (snippet, comment) = match args.preset.as_str() {
        "tor" => (
            json!({
                "proxies": ["socks5h://127.0.0.1:9050"],
            }),
            "# Tor: start a local Tor SOCKS listener (default 9050). `socks5h` resolves DNS via Tor.",
        ),
        other => {
            eprintln!(
                "unknown egress preset {other:?}. Available: tor. \
                 (Run `wafrift egress-example --help` for the canonical list.)"
            );
            return ExitCode::from(2);
        }
    };
    if args.format == "human" {
        eprintln!("{comment}");
    }
    match serde_json::to_string_pretty(&snippet) {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
