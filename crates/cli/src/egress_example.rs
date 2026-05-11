//! Print ready-to-merge `EvasionConfig` snippets for common egress presets.

use serde_json::json;
use std::process::ExitCode;

#[derive(Debug, clap::Args)]
pub struct EgressExampleArgs {
    /// Preset name: `tor` (`SOCKS5h` to local Tor).
    #[arg(long, default_value = "tor", value_parser = ["tor"])]
    pub preset: String,
}

pub fn run_egress_example(args: EgressExampleArgs) -> ExitCode {
    let snippet = match args.preset.as_str() {
        "tor" => {
            eprintln!(
                "# Tor: start a local Tor SOCKS listener (default 9050). `socks5h` resolves DNS via Tor."
            );
            json!({
                "proxies": ["socks5h://127.0.0.1:9050"],
            })
        }
        other => {
            eprintln!(
                "unknown egress preset {other:?}. Available: tor. \
                 (Run `wafrift egress-example --help` for the canonical list.)"
            );
            return ExitCode::from(2);
        }
    };
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
