//! `wafrift man` — emit the troff(1) man page for the CLI.
//!
//! The page is generated from the live clap command tree by
//! `clap_mangen`, so adding a new subcommand automatically extends
//! the page without a manual edit. The `manpage_in_sync.rs`
//! integration test gates the shipped `docs/man/wafrift.1` against
//! this emitter so a docs drift fails CI.

use clap::{Args, CommandFactory};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::Cli;

#[derive(Args, Debug)]
pub(crate) struct ManArgs {
    /// Subcommand to render. Default: render the top-level `wafrift`
    /// page. Pass `all` to emit a concatenated stream covering every
    /// subcommand (one page per `\n.SH` section).
    #[arg(long)]
    pub sub: Option<String>,

    /// Write to this file instead of stdout. Conventional install path
    /// is `/usr/local/share/man/man1/wafrift.1`.
    #[arg(long, short)]
    pub output: Option<PathBuf>,
}

/// Entry point.
pub(crate) fn run_man(args: ManArgs) -> ExitCode {
    let cmd = Cli::command();
    let parent_version = env!("CARGO_PKG_VERSION");
    let mut buf: Vec<u8> = Vec::new();

    // Issue-3 fix (dogfood R43 cohort): `--sub all` previously
    // emitted ONLY the top-level page (one .TH header, 168 lines).
    // The advertised behaviour is concat every subcommand's page.
    // Walk get_subcommands() and emit each one's troff after the
    // top-level header.
    //
    // Issue-4 fix (same cohort): per-subcommand pages had an empty
    // version string in their .TH header (`.TH evade 1 "evade "`).
    // clap_mangen inherits the bin name from the Command we pass
    // it; the version on a sub-Command is empty unless we re-stamp
    // it. Use `.version()` to apply the workspace package version
    // to every page.
    let render_one = |buf: &mut Vec<u8>, c: clap::Command| -> Result<(), std::io::Error> {
        let c = c.version(parent_version);
        let man = clap_mangen::Man::new(c);
        man.render(buf)
    };

    let target_cmd = match args.sub.as_deref() {
        None | Some("wafrift") => Some(cmd),
        Some("all") => {
            let top = cmd.clone();
            if let Err(e) = render_one(&mut buf, top) {
                eprintln!("error: render top-level man page: {e}");
                return ExitCode::from(1);
            }
            for sub in cmd.get_subcommands() {
                // Troff comment separator between subcommand pages
                // (`.\"` is troff's comment-to-end-of-line).
                buf.extend_from_slice(b"\n.\\\" ---- subcommand: ");
                buf.extend_from_slice(sub.get_name().as_bytes());
                buf.extend_from_slice(b" ----\n");
                if let Err(e) = render_one(&mut buf, sub.clone()) {
                    eprintln!("error: render man page for `{}`: {e}", sub.get_name());
                    return ExitCode::from(1);
                }
            }
            None
        }
        Some(name) => match cmd
            .get_subcommands()
            .find(|c| c.get_name() == name)
            .cloned()
        {
            Some(c) => Some(c),
            None => {
                let cmd = Cli::command();
                let names: Vec<&str> = cmd.get_subcommands().map(clap::Command::get_name).collect();
                eprintln!("error: unknown subcommand {name:?}. Available: {names:?}");
                return ExitCode::from(1);
            }
        },
    };
    if let Some(c) = target_cmd
        && let Err(e) = render_one(&mut buf, c)
    {
        eprintln!("error: render man page: {e}");
        return ExitCode::from(1);
    }
    match args.output {
        Some(p) => {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&p, &buf) {
                eprintln!("error: write {}: {e}", p.display());
                return ExitCode::from(1);
            }
            eprintln!("wrote man page ({} bytes) → {}", buf.len(), p.display());
        }
        None => {
            use std::io::Write;
            if let Err(e) = std::io::stdout().write_all(&buf) {
                eprintln!("error: write stdout: {e}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_man_with_unknown_subcommand_returns_error() {
        let args = ManArgs {
            sub: Some("never-existed".into()),
            output: None,
        };
        // Drives the full command tree validation; expected exit
        // code 1 on the unknown-subcommand path.
        let code = run_man(args);
        // ExitCode doesn't expose its numeric value publicly, but
        // the test compiles only if the function returns ExitCode.
        // Use the Debug repr smoke: a SUCCESS value would print
        // "ExitCode(unix_exit_status(0))"; a 1 prints "(1)".
        let s = format!("{code:?}");
        assert!(s.contains("1"), "unknown subcommand should exit 1, got {s}");
    }
}
