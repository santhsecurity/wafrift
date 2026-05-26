//! `wafrift init` — scaffold a commented `.wafrift.toml` so first-run
//! is something other than `--help` archaeology.
//!
//! All keys are commented out so the unmodified file behaves like
//! "all defaults" — operators uncomment what they need. This avoids
//! the surprise where a scaffolded config silently changes behaviour
//! the user didn't ask for.

use clap::Args;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Output path for the scaffold. Defaults to `./.wafrift.toml`.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Overwrite the file if it already exists. Without this flag, init
    /// refuses to clobber an existing config — operators have no
    /// expectation that `wafrift init` would destroy in-flight tuning.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Suppress all human-readable output — only errors are emitted.
    /// The success confirmation ("wrote scaffold … bytes") and the
    /// "Next steps" advisory are silenced so `wafrift init` can be
    /// called from scripts without polluting their output.
    #[arg(short, long)]
    pub quiet: bool,
}

pub fn run_init(args: InitArgs, quiet: bool) -> ExitCode {
    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(".wafrift.toml"));

    if out_path.exists() && !args.force {
        eprintln!(
            "error: {} already exists; pass --force to overwrite",
            out_path.display()
        );
        return ExitCode::from(1);
    }

    if let Err(e) = fs::write(&out_path, SCAFFOLD) {
        eprintln!("error: write {}: {e}. Fix: verify the directory is writable.", out_path.display());
        return ExitCode::from(1);
    }

    if !quiet {
        eprintln!(
            "wrote scaffold ({} bytes) → {}",
            SCAFFOLD.len(),
            out_path.display()
        );
        eprintln!("Next steps:");
        eprintln!("  1. Edit the file — uncomment the keys you want to override.");
        eprintln!("  2. Run `wafrift-proxy --listen 127.0.0.1:8080 --mitm` and point your client at it.");
        eprintln!("  3. Run `wafrift report` after you have findings.");
    }
    ExitCode::SUCCESS
}

/// Best-effort lookup of the `wafrift-proxy` binary so `init` can give
/// accurate next-steps instead of telling the operator to run a command
/// that may not exist. Checks each `$PATH` entry plus the directory of
/// the current executable (the common `cargo build` side-by-side case).
fn locate_proxy() -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        "wafrift-proxy.exe"
    } else {
        "wafrift-proxy"
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    if let Ok(cur) = std::env::current_exe()
        && let Some(parent) = cur.parent()
    {
        dirs.push(parent.to_path_buf());
    }
    dirs.into_iter().map(|d| d.join(exe)).find(|p| p.is_file())
}

const SCAFFOLD: &str = r#"# .wafrift.toml — wafrift configuration scaffold.
#
# This file is parsed by wafrift CLI subcommands that consult it.
# Every key below is commented out, so an unmodified file behaves
# identically to the compiled defaults — uncomment what you need.
#
# NOTE: `wafrift scan` does not yet auto-load this file. The `[scan]`
# section below documents the keys that match `ScanArgs` flags; they
# must be passed as CLI flags until the config-integration pass wires
# `WafRiftConfig::load()` into the scan command.
#
# wafrift-proxy is configured via CLI flags, not this file. The values
# below mirror the proxy flag names so you can copy-paste them into a
# wrapper script.

# ── scan defaults (matches `wafrift scan` CLI flags) ──
[scan]
# Default evasion intensity: "light" | "medium" | "heavy".
# level = "heavy"

# Inter-request delay in milliseconds. Bump if the target rate-limits.
# delay_ms = 50

# Default output format: "text" | "json".
# format = "text"

# ── proxy hints (NOT auto-loaded — use these as a `wafrift-proxy` flag reference) ──
# wafrift-proxy --listen 127.0.0.1:8080 \
#   --mitm \
#   --max-rps-per-host 5 \
#   --only-host '*.example.com' \
#   --skip-path '/static/*,/oauth/*,/favicon.ico,/healthz' \
#   --only-method 'POST,PUT,DELETE'
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_round_trips_as_valid_toml() {
        let parsed: toml::Value = toml::from_str(SCAFFOLD).expect("scaffold must be valid TOML");
        // The body should expose at least the [scan] table even though
        // every value is commented out — otherwise we silently shipped
        // a config the parser can't open.
        assert!(parsed.get("scan").is_some(), "[scan] section missing");
    }

    #[test]
    fn scaffold_keys_are_commented_out() {
        // Every key inside [scan] must be commented so the file is a
        // pure no-op. Catch the regression where someone uncomments
        // a default and accidentally ships an opinion.
        for line in SCAFFOLD.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            // Section headers are allowed; key=value lines are not.
            assert!(
                trimmed.starts_with('[') && trimmed.ends_with(']'),
                "uncommented non-section line in scaffold: {line:?}"
            );
        }
    }
}
