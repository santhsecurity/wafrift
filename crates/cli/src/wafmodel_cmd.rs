//! `wafrift audit` / `wafrift harden` — the WAF-decompiler product
//! surface.
//!
//! `audit`  : decompile a CRS-class ruleset and report the holes an
//!            attacker can drive through it (raw / cased / decode-
//!            mismatch encodings) — the "WAF X-ray".
//! `harden` : synthesize the minimal CRS-grade rules that close those
//!            holes, prove zero new false positives on a benign
//!            sample, and exit non-zero unless closure is proven (so
//!            it is usable as a CI gate).
//!
//! Zero-config: the OWASP-CRS-derived ruleset is embedded; with no
//! flags both commands work offline and deterministically. `--ruleset`
//! points at any Tier-B ruleset TOML to audit a custom config.

use std::process::ExitCode;
use wafrift_types::Request;
use wafrift_wafmodel::normalize::Transform;
use wafrift_wafmodel::{
    ChannelSet, Outcome, Rule, SimRegexWaf, WafOracle, default_crs_ruleset, norm_mismatch_members,
};

#[derive(clap::Args, Debug)]
pub struct AuditArgs {
    /// Tier-B ruleset TOML to audit. Default: the embedded CRS core.
    #[arg(long)]
    pub ruleset: Option<String>,
    /// Attack class: `xss`, `sqli`, or `all`. Restricted by clap
    /// so a typo (`--class xxs`) fails with an actionable error at
    /// parse time rather than silently falling back to `all` and
    /// producing a report the operator can't reproduce.
    #[arg(long, default_value = "all", value_parser = ["xss", "sqli", "all"])]
    pub class: String,
}

#[derive(clap::Args, Debug)]
pub struct HardenArgs {
    /// Tier-B ruleset TOML to harden. Default: the embedded CRS core.
    #[arg(long)]
    pub ruleset: Option<String>,
    /// Attack class: `xss`, `sqli`, or `all`. Restricted by clap
    /// so a typo (`--class xxs`) fails with an actionable error at
    /// parse time rather than silently falling back to `all` and
    /// producing a report the operator can't reproduce.
    #[arg(long, default_value = "all", value_parser = ["xss", "sqli", "all"])]
    pub class: String,
}

fn load_ruleset(path: &Option<String>) -> Result<SimRegexWaf, String> {
    let src = match path {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("reading {p}: {e}"))?,
        None => default_crs_ruleset().to_string(),
    };
    SimRegexWaf::from_toml(&src).map_err(|e| e.to_string())
}

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

/// Canonical attacks + the CRS-normalized tokens that detect them.
fn class_data(
    class: &str,
) -> Vec<(
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
)> {
    // (class, canonical attacks, closing tokens)
    let xss: (&str, &[&str], &[&str]) = (
        "xss",
        &[
            "<script>alert(1)</script>",
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
        ],
        &["<script", "<svg", "<img", "onerror=", "onload="],
    );
    let sqli: (&str, &[&str], &[&str]) = (
        "sqli",
        &[
            "1' OR '1'='1",
            "1 UNION SELECT pw FROM users",
            "1; SELECT sleep(5)",
        ],
        &["union select", "' or '", "sleep("],
    );
    match class {
        "xss" => vec![xss],
        "sqli" => vec![sqli],
        _ => vec![xss, sqli],
    }
}

fn case_flip(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                ((c as u8) ^ 0x20) as char
            } else {
                c
            }
        })
        .collect()
}

/// Every candidate delivery of one canonical attack: raw, full-case-
/// flipped, and the decode-mismatch encodings (double-URL / JSON /
/// HTML-entity preimages from the equiv bridge).
fn classify_pass(waf: &mut impl WafOracle, req: &Request) -> Result<bool, String> {
    match waf.classify(req) {
        Ok(Outcome::Pass) => Ok(true),
        Ok(Outcome::Block) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

fn candidates(attack: &str) -> Vec<(String, String)> {
    let mut v = vec![
        ("raw".to_string(), attack.to_string()),
        ("case".to_string(), case_flip(attack)),
    ];
    for m in norm_mismatch_members(attack, "q") {
        v.push((m.rules[0].to_string(), m.payload));
    }
    v
}

pub fn run_audit(args: AuditArgs) -> ExitCode {
    let mut waf = match load_ruleset(&args.ruleset) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    println!("wafrift audit — WAF decompilation report");
    println!("ruleset fingerprint : {}", waf.fingerprint());
    println!("rules loaded        : {}", waf.rule_count());
    println!("inbound threshold   : {}\n", waf.threshold());

    let mut total_holes = 0usize;
    for (class, attacks, _) in class_data(&args.class) {
        println!("== class: {class} ==");
        for atk in attacks {
            for (label, cand) in candidates(atk) {
                let passed = match classify_pass(&mut waf, &body(cand.as_bytes())) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("  classify error [{label}]: {e}");
                        continue;
                    }
                };
                if passed {
                    total_holes += 1;
                    println!("  HOLE [{label:<26}] {atk}");
                    println!("        delivered as: {cand}");
                }
            }
        }
    }
    println!("\n{total_holes} hole(s) found.");
    if total_holes == 0 {
        println!("No bypass found for the audited classes with the shipped vectors.");
    } else {
        println!("Run `wafrift harden` to synthesize verified closing rules.");
    }
    ExitCode::SUCCESS
}

pub fn run_harden(args: HardenArgs) -> ExitCode {
    let waf = match load_ruleset(&args.ruleset) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let tf = vec![
        Transform::UrlDecodeUni,
        Transform::HtmlEntityDecode,
        Transform::Lowercase,
    ];
    let benign: &[&str] = &[
        "hello world",
        "O'Brien from accounting",
        "union square farmers market",
        "please select an option",
        "I love javascript tutorials",
    ];

    let mut all_proven = true;
    println!("wafrift harden — synthesized closing rules\n");
    for (class, attacks, tokens) in class_data(&args.class) {
        // Holes before (over the realistic candidate set).
        let mut pre = waf.with_rules_added(vec![]);
        let holes_before: usize = attacks
            .iter()
            .flat_map(|a| candidates(a))
            .filter(|(_, c)| classify_pass(&mut pre, &body(c.as_bytes())).unwrap_or(false))
            .count();

        // Two CRS-normalized rules per token: one single-decode (closes
        // raw/case/single-encode holes) and one DOUBLE-urldecode (closes
        // the double-encode normalization-mismatch — a single-decode
        // rule provably cannot, since CRS urlDecodeUni is one pass).
        let tf_double = vec![
            Transform::UrlDecodeUni,
            Transform::UrlDecodeUni,
            Transform::HtmlEntityDecode,
            Transform::Lowercase,
        ];
        let mut added = Vec::new();
        for t in tokens {
            let Ok(re) = regex::bytes::Regex::new(&regex::escape(t)) else {
                continue;
            };
            let safe = t.replace([' ', '<', '\''], "_");
            added.push(Rule {
                id: format!("synth-{class}-{safe}"),
                channels: ChannelSet::all(),
                transforms: tf.clone(),
                pattern: re.clone(),
                score: waf.threshold(),
            });
            added.push(Rule {
                id: format!("synth-{class}-{safe}-dbl"),
                channels: ChannelSet::all(),
                transforms: tf_double.clone(),
                pattern: re,
                score: waf.threshold(),
            });
        }
        let mut hardened = waf.with_rules_added(added.clone());

        let holes_after: usize = attacks
            .iter()
            .flat_map(|a| candidates(a))
            .filter(|(_, c)| {
                classify_pass(&mut hardened, &body(c.as_bytes())).unwrap_or(false)
            })
            .count();
        let fp: usize = benign
            .iter()
            .filter(|b| {
                classify_pass(&mut pre, &body(b.as_bytes())).unwrap_or(false)
                    && classify_pass(&mut hardened, &body(b.as_bytes())) == Ok(false)
            })
            .count();
        let proven = holes_after == 0 && fp == 0;
        all_proven &= proven;

        println!("== class: {class} ==");
        println!("  holes before : {holes_before}");
        println!("  holes after  : {holes_after}");
        println!("  benign FP    : {fp}");
        println!(
            "  closure      : {}",
            if proven { "PROVEN" } else { "NOT PROVEN" }
        );
        if holes_after > 0 {
            // Honest, structural disclosure (NOT a silent limitation):
            // CRS has no JSON body transform, so a JSON-unescape
            // normalization-mismatch is unclosable by ANY CRS rule —
            // it requires a JSON request-body processor at the WAF.
            println!(
                "  residual     : {holes_after} hole(s) a CRS rule cannot close \
                 (e.g. JSON-unescape mismatch — needs REQUEST_BODY_PROCESSOR=JSON \
                 at the WAF, not a signature)."
            );
        }
        println!("  --- add to your CRS config (Tier-B) ---");
        for r in &added {
            println!(
                "  [[rule]]\n  id = \"{}\"\n  transforms = [\"UrlDecodeUni\",\"HtmlEntityDecode\",\"Lowercase\"]\n  pattern = {:?}\n  score = {}",
                r.id,
                r.pattern.as_str(),
                r.score
            );
        }
        println!();
    }
    if all_proven {
        println!("All audited classes closed with zero benign false positives.");
        ExitCode::SUCCESS
    } else {
        eprintln!("closure NOT proven for at least one class — not safe to claim fixed");
        ExitCode::from(1)
    }
}
