//! `wafrift probe` — emit the differential analysis probe set as
//! NDJSON. Each line is one canonical probe shape (a payload + the
//! WAF feature it tests + whether a well-behaved WAF should block
//! it). Useful as a sanity oracle for hand-built rules.

use clap::Args;
use colored::Colorize;
use serde_json::json;
use wafrift_evolution::differential;

use crate::helpers::probe_target_label;

#[derive(Args, Debug)]
pub(crate) struct ProbeArgs {
    /// Generate a smaller probe set.
    #[arg(long)]
    pub quick: bool,
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn run_probe(args: ProbeArgs) {
    let probes = if args.quick {
        differential::generate_quick_probes()
    } else {
        differential::generate_probes()
    };

    for probe in probes {
        let line = json!({
            "payload": probe.payload,
            "tests": probe_target_label(&probe.tests),
            "description": probe.description,
            "expected_blocked": probe.expected_blocked,
        });
        println!("{}", line.to_string().blue());
    }
}
