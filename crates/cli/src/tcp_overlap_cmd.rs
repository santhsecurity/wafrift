//! `wafrift tcp-overlap` — plan a target-based TCP sequence-overlap desync.
//!
//! Emits overlapping TCP segment plans that a WAF/IDS reassembles to a **benign**
//! byte stream while the origin behind it reassembles to the **attack** — the
//! classic Ptacek-Newsham evasion, with every plan self-verified by simulating
//! both reassembly policies before it is printed. This command plans and prints
//! the segments (sequence number + bytes); a raw-socket sender delivers them.

use std::process::ExitCode;

use clap::Args;

use wafrift_tcpoverlap::{
    DifferentialPlan, ReassemblyPolicy, differential_matrix, differential_plan,
};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyArg {
    First,
    Last,
    Bsd,
    Linux,
}

impl From<PolicyArg> for ReassemblyPolicy {
    fn from(p: PolicyArg) -> Self {
        match p {
            PolicyArg::First => ReassemblyPolicy::First,
            PolicyArg::Last => ReassemblyPolicy::Last,
            PolicyArg::Bsd => ReassemblyPolicy::Bsd,
            PolicyArg::Linux => ReassemblyPolicy::Linux,
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct TcpOverlapArgs {
    /// The benign byte stream the WAF should reassemble (what it inspects).
    #[arg(long)]
    pub benign: String,
    /// The attack byte stream the origin should reassemble (what it executes).
    /// Must be the same length as `--benign` for a clean full-overlap split.
    #[arg(long)]
    pub attack: String,
    /// Target a specific WAF reassembly policy (requires `--origin-policy`). When
    /// omitted, every disagreeing policy pair is enumerated.
    #[arg(long, value_enum, requires = "origin_policy")]
    pub waf_policy: Option<PolicyArg>,
    /// Target a specific origin reassembly policy (requires `--waf-policy`).
    #[arg(long, value_enum, requires = "waf_policy")]
    pub origin_policy: Option<PolicyArg>,
    /// Output format.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
}

pub(crate) fn run_tcp_overlap(args: TcpOverlapArgs) -> ExitCode {
    ExitCode::from(run_inner(&args))
}

fn run_inner(args: &TcpOverlapArgs) -> u8 {
    let benign = args.benign.as_bytes();
    let attack = args.attack.as_bytes();

    let plans: Vec<DifferentialPlan> = match (args.waf_policy, args.origin_policy) {
        (Some(w), Some(o)) => differential_plan(benign, attack, w.into(), o.into())
            .into_iter()
            .collect(),
        _ => differential_matrix(benign, attack),
    };

    if args.format == "json" {
        println!("{}", report_json(args, &plans));
    } else {
        print_human(args, &plans);
    }

    // 0 = at least one verified differential; 4 = none possible for these inputs.
    if plans.is_empty() { 4 } else { 0 }
}

fn plan_json(plan: &DifferentialPlan) -> serde_json::Value {
    let segs: Vec<serde_json::Value> = plan
        .segments
        .iter()
        .map(|s| {
            serde_json::json!({
                "seq": s.seq,
                "data_hex": s.data.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "data_utf8_lossy": String::from_utf8_lossy(&s.data),
            })
        })
        .collect();
    serde_json::json!({
        "waf_policy": plan.waf_policy.label(),
        "origin_policy": plan.origin_policy.label(),
        "waf_view": String::from_utf8_lossy(&plan.waf_view),
        "origin_view": String::from_utf8_lossy(&plan.origin_view),
        "segments": segs,
    })
}

fn report_json(args: &TcpOverlapArgs, plans: &[DifferentialPlan]) -> serde_json::Value {
    serde_json::json!({
        "schema": "wafrift.tcp_overlap.v1",
        "benign": args.benign,
        "attack": args.attack,
        "differentials": plans.iter().map(plan_json).collect::<Vec<_>>(),
        "note": "each plan is self-verified: simulating the WAF policy yields benign, the origin \
                 policy yields attack. Deliver the segments with a raw-socket sender.",
    })
}

fn print_human(args: &TcpOverlapArgs, plans: &[DifferentialPlan]) {
    println!("wafrift tcp-overlap — target-based TCP reassembly desync");
    println!("benign (WAF view) : {}", args.benign);
    println!("attack (origin)   : {}", args.attack);
    if plans.is_empty() {
        if args.benign.len() != args.attack.len() {
            println!(
                "\nNo differential: --benign and --attack must be equal length for a clean \
                 full-overlap split ({} vs {} bytes).",
                args.benign.len(),
                args.attack.len()
            );
        } else {
            println!("\nNo differential found for the requested policy pairing.");
        }
        return;
    }
    println!("\n{} verified policy differential(s):", plans.len());
    for plan in plans {
        println!(
            "\n  WAF={} ⟶ benign   |   origin={} ⟶ attack",
            plan.waf_policy.label(),
            plan.origin_policy.label()
        );
        for (i, s) in plan.segments.iter().enumerate() {
            println!(
                "    seg{i}: seq={} bytes={:?}",
                s.seq,
                String::from_utf8_lossy(&s.data)
            );
        }
    }
}
