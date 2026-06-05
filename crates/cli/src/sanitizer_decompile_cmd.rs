//! `wafrift sanitizer-decompile` — decompile a client-side HTML sanitizer.
//!
//! The DOM-XSS counterpart to `wafrift fingerprint`/`audit`: where those
//! decompile a server WAF, this recovers the **client sanitizer** from a shipped
//! JS source map (or raw JS), extracts its allow/deny model, and L*/SFA-mines the
//! XSS vectors that survive it. Every reported bypass is re-verified against the
//! extracted model and flagged for live scald DOM confirmation — proposed by the
//! model, never asserted as executed here.

use std::process::ExitCode;

use clap::Args;

use wafrift_sanitizer::{
    MineResult, SanitizerModel, SourceMap, decompile_and_mine, extract_sanitizer, mxss_candidates,
};

/// 32 MiB caps any legitimate bundle/source-map while catching `/dev/zero` and
/// accidental log aliasing.
const SOURCE_FILE_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Args, Debug)]
pub(crate) struct SanitizerDecompileArgs {
    /// Path to a JavaScript **source map** (`*.map`). Its embedded
    /// `sourcesContent` is the readable sanitizer source to decompile. Mutually
    /// exclusive with `--js`.
    #[arg(long, conflicts_with = "js")]
    pub source_map: Option<String>,
    /// Path to a raw JavaScript file (already-readable source — e.g. an
    /// un-minified bundle). Mutually exclusive with `--source-map`.
    #[arg(long)]
    pub js: Option<String>,
    /// Maximum number of L*/SFA-deduced bypass candidates to mine.
    #[arg(long, default_value_t = 128)]
    pub max_mine: usize,
    /// Maximum length of a mined candidate.
    #[arg(long, default_value_t = 24)]
    pub max_len: usize,
    /// Equivalence-oracle search depth (deeper = a more faithful learned model,
    /// more membership queries against the in-process sanitizer oracle).
    #[arg(long, default_value_t = 6)]
    pub eq_depth: usize,
    /// Output format.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
}

pub(crate) fn run_sanitizer_decompile(args: SanitizerDecompileArgs) -> ExitCode {
    ExitCode::from(run_inner(args))
}

fn run_inner(args: SanitizerDecompileArgs) -> u8 {
    // Resolve the source to scan: a source map's recovered content, or raw JS.
    let source = match (&args.source_map, &args.js) {
        (Some(map_path), None) => match read_source_map(map_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        },
        (None, Some(js_path)) => match read_text(js_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        },
        _ => {
            eprintln!("error: exactly one of --source-map or --js is required");
            return 2;
        }
    };

    let model = extract_sanitizer(&source);
    if model.is_empty() {
        let json = args.format == "json";
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "schema": "wafrift.sanitizer_decompile.v1",
                    "sanitizer_detected": false,
                    "bypasses": [],
                })
            );
        } else {
            println!("No client-side sanitizer recognised in the recovered source.");
        }
        return 6; // no sanitizer in play (mirrors scan's "no WAF" exit 6)
    }

    let result = decompile_and_mine(model, args.max_mine, args.max_len, args.eq_depth);
    let has_bypass = !result.bypasses.is_empty();

    if args.format == "json" {
        println!("{}", report_json(&result));
    } else {
        print_human(&result);
    }

    if has_bypass { 0 } else { 4 }
}

/// Read a source map and recover its embedded original source.
fn read_source_map(path: &str) -> Result<String, String> {
    let raw = read_text(path)?;
    let map = SourceMap::parse(&raw).map_err(|e| format!("parsing source map {path}: {e}"))?;
    let content = map.recovered_content();
    if content.trim().is_empty() {
        return Err(format!(
            "source map {path} has no embedded `sourcesContent` to decompile (only position \
             mappings were present)"
        ));
    }
    Ok(content)
}

fn read_text(path: &str) -> Result<String, String> {
    crate::safe_body::read_bounded_text_file(std::path::Path::new(path), SOURCE_FILE_MAX_BYTES)
        .map_err(|e| format!("reading {path}: {e}"))
}

fn model_json(m: &SanitizerModel) -> serde_json::Value {
    serde_json::json!({
        "kind": m.kind.label(),
        "allowed_tags": m.allowed_tags,
        "forbidden_tags": m.forbidden_tags,
        "forbidden_attrs": m.forbidden_attrs,
        "strips_event_handlers": m.strips_event_handlers,
        "blocked_schemes": m.blocked_schemes,
        "strip_patterns": m.strip_patterns,
        "evidence": m.evidence,
    })
}

fn report_json(result: &MineResult) -> serde_json::Value {
    serde_json::json!({
        "schema": "wafrift.sanitizer_decompile.v1",
        "sanitizer_detected": true,
        "model": model_json(&result.model),
        "membership_queries": result.membership_queries,
        "equivalence_rounds": result.equivalence_rounds,
        "mined_before_verify": result.mined_before_verify,
        "bypasses": result.bypasses,
        "mxss_candidates": mxss_candidates(&result.model),
        "note": "each bypass survives the extracted model; confirm DOM execution in a real \
                 browser (scald) — not asserted as executed here. mxss_candidates are reachable \
                 mutation-XSS trigger pairs the in-model check cannot prove — confirm in a live DOM.",
    })
}

fn print_human(result: &MineResult) {
    let m = &result.model;
    println!("wafrift sanitizer-decompile — client sanitizer X-ray");
    println!("detected sanitizer : {}", m.kind.label());
    if let Some(allow) = &m.allowed_tags {
        println!("allowed tags       : [{}]", allow.join(", "));
    }
    if !m.forbidden_tags.is_empty() {
        println!("forbidden tags     : [{}]", m.forbidden_tags.join(", "));
    }
    println!(
        "strips handlers    : {}",
        if m.strips_event_handlers { "yes" } else { "NO (event-handler vectors survive)" }
    );
    if !m.blocked_schemes.is_empty() {
        println!("blocked schemes    : [{}]", m.blocked_schemes.join(", "));
    }
    if !m.strip_patterns.is_empty() {
        println!("strip patterns     : {}", m.strip_patterns.len());
    }
    println!(
        "\nDecompiled via L*/SFA: {} membership queries, {} equivalence rounds, {} candidates mined.",
        result.membership_queries, result.equivalence_rounds, result.mined_before_verify
    );
    if result.bypasses.is_empty() {
        println!("\nNo executable vector survives this sanitizer config (model-proven).");
    } else {
        println!("\n{} bypass(es) survive the sanitizer (confirm in a real browser via scald):", result.bypasses.len());
        for b in &result.bypasses {
            println!("  [{}] {}", b.vector, b.payload);
        }
    }
    let mxss = mxss_candidates(&result.model);
    if !mxss.is_empty() {
        println!(
            "\n{} mutation-XSS candidate(s) — reachable trigger pairs the in-model check cannot \
             prove; confirm in a live DOM (scald):",
            mxss.len()
        );
        for c in &mxss {
            println!("  <{}><{}> ({})", c.root, c.child, c.class);
        }
    }
}
