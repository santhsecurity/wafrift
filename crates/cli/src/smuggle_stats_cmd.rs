//! `wafrift smuggle-stats` — operator-facing probe-budget snapshot.
//!
//! Counts every probe wafrift can emit across the 9 smuggle
//! families, broken down by family and artifact kind, and reports
//! the wire-byte budget. Operators run this before firing a scan to
//! decide whether they need to subsample.
//!
//! Output is structured JSON, suitable for piping into `jq`, CI
//! gates, or shell variables. Example:
//!
//! ```json
//! {
//!   "total_probes": 61,
//!   "per_family": {"cookie": 7, "auth": 8, ...},
//!   "per_kind": {"headers": 33, "body": 16, "frames": 12},
//!   "total_wire_bytes": 12345,
//!   "avg_wire_bytes": 202,
//!   "max_wire_bytes": 1200,
//!   "max_technique": "compression.bomb"
//! }
//! ```

use clap::Parser;
use std::collections::BTreeMap;
use std::io::Write;
use std::process::ExitCode;

use wafrift_core::probe_aggregator::{ProbeSeeds, all_probes};

#[derive(Debug, Parser)]
pub struct SmuggleStatsArgs {
    /// Cookie / Authorization name seed.
    #[arg(long, default_value = "session")]
    pub cookie_name: String,

    /// Credential value seed.
    #[arg(long, default_value = "wafrift-test-token")]
    pub credential: String,

    /// Opaque payload seed.
    #[arg(long, default_value = "wafrift-smuggle-payload")]
    pub payload: String,

    /// Form params for multipart / JSON smuggle.
    #[arg(long, default_value = "user=admin&token=wafrift-test-token")]
    pub form: String,

    /// Protected path seed for path-normalize probes.
    #[arg(long, default_value = "/admin")]
    pub protected_path: String,

    /// Protected hostname seed for host-header probes.
    #[arg(long, default_value = "admin.example.com")]
    pub protected_host: String,

    /// Pretty-print the JSON output.
    #[arg(long)]
    pub pretty: bool,

    /// Optional family prefix to drill down on — when set, stats
    /// are computed only over probes whose technique starts with
    /// this prefix. Empty (default) = all families.
    #[arg(long, default_value = "")]
    pub family: String,
}

#[derive(serde::Serialize)]
struct StatsReport {
    total_probes: usize,
    per_family: BTreeMap<String, usize>,
    per_kind: BTreeMap<String, usize>,
    total_wire_bytes: usize,
    avg_wire_bytes: usize,
    max_wire_bytes: usize,
    max_technique: String,
}

pub fn run_smuggle_stats(args: SmuggleStatsArgs) -> ExitCode {
    let form_params = crate::helpers::parse_form_pairs(&args.form);
    let seeds = ProbeSeeds {
        cookie_name: &args.cookie_name,
        credential_value: &args.credential,
        form_params,
        payload: args.payload.as_bytes().to_vec(),
        protected_path: &args.protected_path,
        protected_host: &args.protected_host,
    };
    let probes: Vec<_> = all_probes(&seeds)
        .into_iter()
        .filter(|p| args.family.is_empty() || p.technique().starts_with(&args.family))
        .collect();

    if probes.is_empty() {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-stats: family filter {:?} matched zero probes",
            args.family
        );
        return ExitCode::from(2);
    }

    let mut per_family: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_wire_bytes: usize = 0;
    let mut max_wire_bytes: usize = 0;
    let mut max_technique = String::new();

    for p in &probes {
        let tech = p.technique();
        let family = tech.split('.').next().unwrap_or("").to_string();
        *per_family.entry(family).or_insert(0) += 1;

        let artifact = p.artifact();
        let kind = match &artifact {
            wafrift_types::probe::SmuggleArtifact::Headers(_) => "headers",
            wafrift_types::probe::SmuggleArtifact::BodyWithContentType { .. } => "body",
            wafrift_types::probe::SmuggleArtifact::Frames(_) => "frames",
        };
        *per_kind.entry(kind.to_string()).or_insert(0) += 1;

        let bytes = artifact.wire_byte_count();
        total_wire_bytes += bytes;
        if bytes > max_wire_bytes {
            max_wire_bytes = bytes;
            max_technique = tech;
        }
    }

    let avg_wire_bytes = if probes.is_empty() {
        0
    } else {
        total_wire_bytes / probes.len()
    };

    let report = StatsReport {
        total_probes: probes.len(),
        per_family,
        per_kind,
        total_wire_bytes,
        avg_wire_bytes,
        max_wire_bytes,
        max_technique,
    };

    let json = if args.pretty {
        serde_json::to_string_pretty(&report)
    } else {
        serde_json::to_string(&report)
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match json {
        Ok(s) => {
            let _ = writeln!(out, "{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "serialize error: {e}");
            ExitCode::from(1)
        }
    }
}
