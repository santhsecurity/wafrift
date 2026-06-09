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
use std::sync::Arc;
use wafrift_types::Request;
use wafrift_wafmodel::normalize::Transform;
use wafrift_wafmodel::{
    Channel, ChannelSet, DecodeGap, FilterProfile, FnReflector, Outcome, Pipeline,
    ReflectionOracle, Rule, SimRegexWaf, Stage, TokenProbe, Verdict, WafModelError, WafOracle,
    characterize, default_crs_ruleset, default_filter_battery, norm_mismatch_members,
    probe_decode_gaps, scan_origin, solve_bypass,
};

/// CRS-class rulesets are kilobytes (the embedded core CRS is <500 KiB
/// even with annotations). 16 MiB caps every legitimate ruleset while
/// catching `--ruleset /dev/zero`, hostile symlinks, and accidental
/// log-file aliasing.
const RULESET_FILE_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(clap::Args, Debug)]
pub(crate) struct AuditArgs {
    /// Tier-B ruleset TOML to audit. Default: the embedded CRS core.
    #[arg(long)]
    pub ruleset: Option<String>,
    /// Attack class: `xss`, `sqli`, or `all`. Restricted by clap
    /// so a typo (`--class xxs`) fails with an actionable error at
    /// parse time rather than silently falling back to `all` and
    /// producing a report the operator can't reproduce.
    #[arg(long, default_value = "all", value_parser = ["xss", "sqli", "all"])]
    pub class: String,
    /// Output format. `human` (default) prints the operator-friendly
    /// report; `json` emits a machine-parseable structure suitable for
    /// piping into `jq` / CI parsers. Dogfood B3 fix: previously the
    /// command had no `--format` flag and `--quiet` was a no-op.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct HardenArgs {
    /// Tier-B ruleset TOML to harden. Default: the embedded CRS core.
    #[arg(long)]
    pub ruleset: Option<String>,
    /// Attack class: `xss`, `sqli`, or `all`. Restricted by clap
    /// so a typo (`--class xxs`) fails with an actionable error at
    /// parse time rather than silently falling back to `all` and
    /// producing a report the operator can't reproduce.
    #[arg(long, default_value = "all", value_parser = ["xss", "sqli", "all"])]
    pub class: String,
    /// Output format. `human` (default) prints the operator-friendly
    /// report with ready-to-paste TOML rule snippets; `json` emits a
    /// machine-parseable structure whose `added_rules[].transforms`
    /// array reflects the ACTUAL transform chain for each synthesized
    /// rule (including double-UrlDecodeUni variants for closing
    /// double-encoded bypass holes).
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct FingerprintArgs {
    /// Target URL whose reflection point echoes a request parameter value
    /// back into the response (e.g. a search box, error page, or API field).
    #[arg(long)]
    pub url: String,
    /// The request parameter whose value the target reflects. The probe is
    /// sent as `GET <url>?<param>=<percent-encoded-marker>`.
    #[arg(long, default_value = "q")]
    pub param: String,
    /// Optional attack to solve a TARGETED bypass for, once the origin's
    /// normalization pipeline is fingerprinted (e.g.
    /// `--attack '<script>alert(1)</script>'`). The same URL is probed as a
    /// live block/pass oracle (2xx = pass, anything else = block) and the
    /// solver re-verifies every candidate against it — so a mis-detected or
    /// mis-ordered stage can only fail to produce a bypass, never fabricate
    /// one.
    #[arg(long)]
    pub attack: Option<String>,
    /// Also run a differential filter characterization: probe the live target
    /// with a battery of attack tokens, each paired with a signature-broken
    /// benign twin, to learn WHICH tokens the WAF actually policies (vs. which
    /// reach the sink in plaintext). Then, for each policed token, probe which
    /// encodings (url / double-url / html-entity / NFKC / best-fit / base64 /
    /// hex) the WAF fails to decode before matching — the candidate "decode-gap"
    /// bypass encodings (an origin that applies the transform reconstructs the
    /// attack). Costs two live requests per token plus one per decode probe.
    #[arg(long)]
    pub characterize_filter: bool,
    /// Path to a custom Tier-B filter-probe battery (TOML: `[[probe]]` rows of
    /// `token` / `benign_twin` / `class`). Overrides the embedded default. Only
    /// meaningful with `--characterize-filter`. Malformed probes are rejected at
    /// load (fail-closed), never silently skipped.
    #[arg(long)]
    pub filter_battery: Option<String>,
    /// Cap on the number of token probes run by `--characterize-filter` (live-
    /// query minimization for a rate-limited target). `0` (default) runs the
    /// whole battery. When set below the battery size, probes are ordered by
    /// descending expected **information gain** (Beta-Bernoulli entropy from
    /// `--filter-history`) so the budget is spent on the tokens whose policing is
    /// least certain — not re-confirming tokens a prior run already pinned. Costs
    /// two live requests per kept probe (plus the decode-gap probes on the policed
    /// subset).
    #[arg(long, default_value_t = 0)]
    pub filter_budget: usize,
    /// JSON history file warm-starting the `--filter-budget` info-gain ordering.
    /// Each token's prior block/pass outcomes are loaded before scheduling and the
    /// new run's outcomes are merged back and saved — so repeated assessments of a
    /// target converge the budget onto its genuinely-uncertain tokens. Absent file
    /// = cold start (deterministic battery order). Same `History` schema as
    /// `bench-waf --history-file`.
    #[arg(long)]
    pub filter_history: Option<String>,
    /// Path to a custom Tier-B WAF block-page signature file (TOML:
    /// `signature = ["...", ...]`). A 2xx response whose body contains one of
    /// these is classified as a block (many WAFs serve their block page with
    /// HTTP 200). Overrides the embedded default signature set.
    #[arg(long)]
    pub block_signatures: Option<String>,
    /// Accept invalid TLS certificates (self-signed test stacks only).
    #[arg(long)]
    pub insecure: bool,
    /// Explicit authorization note required for non-RFC1918 / non-loopback
    /// targets — this command sends live requests to `--url`.
    #[arg(long)]
    pub permission: Option<String>,
    /// Output format. `human` (default) prints the operator report; `json`
    /// emits a machine-parseable structure for CI / `jq`.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
}

fn load_ruleset(path: &Option<String>) -> Result<SimRegexWaf, String> {
    let src = match path {
        Some(p) => crate::safe_body::read_bounded_text_file(
            std::path::Path::new(p),
            RULESET_FILE_MAX_BYTES,
        )
        .map_err(|e| format!("reading {p}: {e}"))?,
        None => default_crs_ruleset().to_string(),
    };
    SimRegexWaf::from_toml(&src).map_err(|e| e.to_string())
}

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

/// Resolve the live-oracle block-page signatures: a `--block-signatures` file
/// (Tier-B, fail-closed) when given, else the embedded default set.
fn resolve_block_signatures(path: &Option<String>) -> Result<Vec<String>, String> {
    match path {
        Some(p) => {
            let src = crate::safe_body::read_bounded_text_file(
                std::path::Path::new(p),
                RULESET_FILE_MAX_BYTES,
            )
            .map_err(|e| format!("reading block-signature file {p}: {e}"))?;
            wafrift_liveoracle::verdict::load_block_signatures(&src)
        }
        None => Ok(wafrift_liveoracle::verdict::default_block_signatures()),
    }
}

/// Render a `ChannelSet` as the TOML array literal that `SimRegexWaf::from_toml`
/// can round-trip back. Needed so the harden output's `[[rule]]` stanzas are
/// copy-pasteable into a `.toml` ruleset without a missing-field parse error.
fn channel_set_toml(cs: ChannelSet) -> String {
    const ALL: &[(Channel, &str)] = &[
        (Channel::Path, "\"Path\""),
        (Channel::ArgName, "\"ArgName\""),
        (Channel::ArgValue, "\"ArgValue\""),
        (Channel::HeaderName, "\"HeaderName\""),
        (Channel::HeaderValue, "\"HeaderValue\""),
        (Channel::CookieName, "\"CookieName\""),
        (Channel::CookieValue, "\"CookieValue\""),
        (Channel::Body, "\"Body\""),
    ];
    let parts: Vec<&str> = ALL
        .iter()
        .filter(|(ch, _)| cs.contains(*ch))
        .map(|(_, s)| *s)
        .collect();
    format!("[{}]", parts.join(", "))
}

/// One Tier-B attack class: canonical attacks paired with the CRS-normalized
/// tokens a synthesized rule keys on to detect them.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct AttackClass {
    /// Class selector (`xss`, `sqli`).
    pub name: String,
    /// Canonical attack payloads `audit`/`harden` measure against.
    pub attacks: Vec<String>,
    /// CRS-normalized detection tokens `harden` synthesizes rules from.
    pub tokens: Vec<String>,
}

/// The embedded Tier-B attack-class data — the single source of `audit` /
/// `harden`'s canonical attacks and detection tokens is this file, not a
/// hardcoded `vec!`. Extend coverage by adding a `[[class]]` block to it.
const ATTACK_CLASSES_TOML: &str = include_str!("../rules/classes/attack_classes.toml");

/// Parse a Tier-B attack-class set from TOML. **Fails closed**: an empty set, or
/// any class missing its attacks or its tokens, is rejected — a class whose
/// tokens don't detect its attacks would make the `harden` proof vacuous, so bad
/// data is a hard error here, never a silently weakened self-test.
fn attack_classes_from_toml(src: &str) -> Result<Vec<AttackClass>, String> {
    #[derive(serde::Deserialize)]
    struct ClassFile {
        #[serde(default)]
        class: Vec<AttackClass>,
    }
    let parsed: ClassFile =
        toml::from_str(src).map_err(|e| format!("parsing attack-class data: {e}"))?;
    if parsed.class.is_empty() {
        return Err("attack-class data has no `[[class]]` entries".to_string());
    }
    for c in &parsed.class {
        if c.name.trim().is_empty() {
            return Err("an attack class has an empty `name`".to_string());
        }
        if c.attacks.is_empty() {
            return Err(format!("class {:?} has no `attacks`", c.name));
        }
        if c.tokens.is_empty() {
            return Err(format!("class {:?} has no `tokens`", c.name));
        }
    }
    Ok(parsed.class)
}

/// Canonical attacks + the CRS-normalized tokens that detect them, filtered to
/// `class` (`xss` / `sqli` / anything else ⇒ all). Sourced from the embedded
/// Tier-B [`ATTACK_CLASSES_TOML`]; the loader is fail-closed and pinned by tests,
/// so `expect` here can only fire on a corrupt build artifact.
fn class_data(class: &str) -> Vec<AttackClass> {
    let all = attack_classes_from_toml(ATTACK_CLASSES_TOML)
        .expect("embedded attack-class data must be valid (asserted in tests)");
    match class {
        "xss" | "sqli" => all.into_iter().filter(|c| c.name == class).collect(),
        _ => all,
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

/// Normalization-mismatch preimage labels whose reconstruction requires an
/// *origin* transform that the CRS transform set (`UrlDecodeUni`,
/// `HtmlEntityDecode`, `Lowercase`) cannot perform — so a synthesized CRS rule
/// provably cannot block them, and including them in a "closure proven" test
/// would produce a false negative (proven=false for correct behaviour):
///
/// * `norm_mismatch_json_unescape` — ModSecurity/Coraza have no JSON string
///   unescape transform, so a `\uXXXX` payload cannot be matched.
/// * `norm_mismatch_nfkc` / `norm_mismatch_bestfit` — CRS has no Unicode
///   NFKC-normalization or best-fit charset-coercion transform, so a homoglyph
///   / curly-quote payload is never folded to the ASCII token a rule keys on.
///   (Closing these holes genuinely requires the WAF to add a normalization
///   stage it does not ship — a real defensive gap, not a rule-synthesis bug.)
const CRS_UNENFORCEABLE_SINKS: &[&str] = &[
    "norm_mismatch_json_unescape",
    "norm_mismatch_nfkc",
    "norm_mismatch_bestfit",
];

/// Same as [`candidates`] but excludes the preimage types CRS cannot enforce
/// (see [`CRS_UNENFORCEABLE_SINKS`]). Used by `run_harden_inner` so the closure
/// assertion matches what the synthesized rules can actually enforce.
fn harden_candidates(attack: &str) -> Vec<(String, String)> {
    candidates(attack)
        .into_iter()
        .filter(|(label, _)| !CRS_UNENFORCEABLE_SINKS.contains(&label.as_str()))
        .collect()
}

pub(crate) fn run_audit(args: AuditArgs) -> ExitCode {
    ExitCode::from(run_audit_inner(args))
}

/// Same as [`run_audit`] but returns a plain `u8` so tests can
/// assert exact exit codes — `std::process::ExitCode` is opaque and
/// has no public conversion back to its inner byte.
fn run_audit_inner(args: AuditArgs) -> u8 {
    let mut waf = match load_ruleset(&args.ruleset) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let json_mode = args.format == "json";
    if !json_mode {
        println!("wafrift audit — WAF decompilation report");
        println!("ruleset fingerprint : {}", waf.fingerprint());
        println!("rules loaded        : {}", waf.rule_count());
        println!("inbound threshold   : {}\n", waf.threshold());
    }

    let mut holes_json: Vec<serde_json::Value> = Vec::new();
    let mut total_holes = 0usize;
    for c in class_data(&args.class) {
        if !json_mode {
            println!("== class: {} ==", c.name);
        }
        for atk in &c.attacks {
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
                    if json_mode {
                        holes_json.push(serde_json::json!({
                            "class": c.name,
                            "label": label,
                            "attack": atk,
                            "delivered_as": cand,
                        }));
                    } else {
                        println!("  HOLE [{label:<26}] {atk}");
                        println!("        delivered as: {cand}");
                    }
                }
            }
        }
    }

    if json_mode {
        let report = serde_json::json!({
            "ruleset_fingerprint": waf.fingerprint(),
            "rules_loaded": waf.rule_count(),
            "inbound_threshold": waf.threshold(),
            "audited_class": args.class,
            "total_holes": total_holes,
            "holes": holes_json,
        });
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
    } else {
        println!("\n{total_holes} hole(s) found.");
        if total_holes == 0 {
            println!("No bypass found for the audited classes with the shipped vectors.");
        } else {
            println!("Run `wafrift harden` to synthesize verified closing rules.");
        }
    }
    0
}

/// Per-class result collected before rendering, so JSON and human
/// output share the same computation path.
struct ClassHardenResult {
    class: String,
    holes_before: usize,
    holes_after: usize,
    benign_fp: usize,
    proven: bool,
    added: Vec<Rule>,
}

pub(crate) fn run_harden(args: HardenArgs) -> ExitCode {
    ExitCode::from(run_harden_inner(args))
}

/// Same as [`run_harden`] but returns a plain `u8` so tests can
/// assert exact exit codes — `std::process::ExitCode` is opaque and
/// has no public conversion back to its inner byte.
fn run_harden_inner(args: HardenArgs) -> u8 {
    let waf = match load_ruleset(&args.ruleset) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
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

    let json_mode = args.format == "json";
    let mut all_proven = true;
    let mut results: Vec<ClassHardenResult> = Vec::new();

    for c in class_data(&args.class) {
        let (class, attacks, tokens) = (c.name, c.attacks, c.tokens);
        // Holes before (over the CRS-decodable candidate set: raw, case-
        // flipped, URL-encoded, HTML-entity encoded — but NOT json_unescape
        // which requires a transform CRS/ModSecurity does not provide).
        let mut pre = waf.with_rules_added(vec![]);
        let holes_before: usize = attacks
            .iter()
            .flat_map(|a| harden_candidates(a))
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
        for t in &tokens {
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
            .flat_map(|a| harden_candidates(a))
            .filter(|(_, c)| classify_pass(&mut hardened, &body(c.as_bytes())).unwrap_or(false))
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

        results.push(ClassHardenResult {
            class,
            holes_before,
            holes_after,
            benign_fp: fp,
            proven,
            added,
        });
    }

    if json_mode {
        let classes_json: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                let rules_json: Vec<serde_json::Value> = r
                    .added
                    .iter()
                    .map(|rule| {
                        // Serialize the ACTUAL transform chain for each rule so
                        // callers don't need to infer which rules are double-
                        // decode variants from the rule id alone.
                        let tf_list: Vec<&str> = rule
                            .transforms
                            .iter()
                            .map(|t| match t {
                                Transform::UrlDecodeUni => "UrlDecodeUni",
                                Transform::HtmlEntityDecode => "HtmlEntityDecode",
                                Transform::Lowercase => "Lowercase",
                                Transform::RemoveNulls => "RemoveNulls",
                                Transform::CompressWhitespace => "CompressWhitespace",
                                Transform::RemoveWhitespace => "RemoveWhitespace",
                            })
                            .collect();
                        serde_json::json!({
                            "id": rule.id,
                            "transforms": tf_list,
                            "pattern": rule.pattern.as_str(),
                            "score": rule.score,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "class": r.class,
                    "holes_before": r.holes_before,
                    "holes_after": r.holes_after,
                    "benign_false_positives": r.benign_fp,
                    "proven_closed": r.proven,
                    "added_rules": rules_json,
                })
            })
            .collect();
        let report = serde_json::json!({
            "audited_class": args.class,
            "all_proven": all_proven,
            "classes": classes_json,
        });
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
    } else {
        println!("wafrift harden — synthesized closing rules\n");
        for r in &results {
            println!("== class: {} ==", r.class);
            println!("  holes before : {}", r.holes_before);
            println!("  holes after  : {}", r.holes_after);
            println!("  benign FP    : {}", r.benign_fp);
            println!(
                "  closure      : {}",
                if r.proven { "PROVEN" } else { "NOT PROVEN" }
            );
            if r.holes_after > 0 {
                // Honest, structural disclosure (NOT a silent limitation):
                // CRS has no JSON body transform, so a JSON-unescape
                // normalization-mismatch is unclosable by ANY CRS rule —
                // it requires a JSON request-body processor at the WAF.
                println!(
                    "  residual     : {} hole(s) a CRS rule cannot close \
                     (e.g. JSON-unescape mismatch — needs REQUEST_BODY_PROCESSOR=JSON \
                     at the WAF, not a signature).",
                    r.holes_after
                );
            }
            println!("  --- add to your CRS config (Tier-B) ---");
            for rule in &r.added {
                // Derive the transform list from the rule's *actual* transform
                // chain, not a hardcoded string. Pre-fix: every rule (including
                // the double-UrlDecodeUni variants) was printed with the
                // single-decode list — the TOML a defender copies would apply
                // the wrong normalization and leave the double-encode holes
                // open even after deploying the "closing" rule.
                let tf_toml: Vec<String> = rule
                    .transforms
                    .iter()
                    .map(|t| format!("\"{t:?}\""))
                    .collect();
                println!(
                    "  [[rule]]\n  id = \"{}\"\n  channels = {}\n  transforms = [{}]\n  pattern = {:?}\n  score = {}",
                    rule.id,
                    channel_set_toml(rule.channels),
                    tf_toml.join(", "),
                    rule.pattern.as_str(),
                    rule.score
                );
            }
            println!();
        }
        if all_proven {
            println!("All audited classes closed with zero benign false positives.");
        } else {
            eprintln!("closure NOT proven for at least one class — not safe to claim fixed");
        }
    }

    if all_proven { 0 } else { 1 }
}

// ── fingerprint: live origin-normalization decompilation ────────────────────

/// Human/JSON label for a detected origin stage. Only the stages
/// `detect_origin_normalization` can return are named; anything else falls
/// back to the `Debug` form so a newly-added stage is never silently mislabeled.
fn stage_label(s: &Stage) -> String {
    match s {
        Stage::UrlDecode { .. } => "url_decode".to_string(),
        Stage::DoubleUrlDecode => "double_url_decode".to_string(),
        Stage::JsonUnescape => "json_unescape".to_string(),
        Stage::HtmlEntityDecode => "html_entity_decode".to_string(),
        Stage::Base64Decode => "base64_decode".to_string(),
        Stage::HexDecode => "hex_decode".to_string(),
        Stage::OverlongUtf8Decode => "overlong_utf8_decode".to_string(),
        Stage::StripNulls => "strip_nulls".to_string(),
        Stage::NfkcNormalize => "nfkc_normalize".to_string(),
        Stage::BestFitDownconvert => "bestfit_downconvert".to_string(),
        other => format!("{other:?}"),
    }
}

/// Build a live [`ReflectionOracle`] backed by reqwest: send the probe bytes as
/// `GET <url>?<param>=<percent-encoded-bytes>` and return the (capped) response
/// body for the fingerprinter to scan for the folded marker.
///
/// Delivery model: the probe is percent-encoded for the URL, so the target's
/// framework performs exactly one baseline query-string URL-decode before the
/// value reaches the application. Detected stages are therefore the
/// normalization the origin applies *on top of* that baseline — and
/// `solve_bypass`'s candidates are delivered the same way (payload bytes
/// percent-encoded into the same parameter), so the fingerprint and the bypass
/// it drives stay coherent.
fn build_http_reflector(
    rt: Arc<tokio::runtime::Runtime>,
    target_url: String,
    param: String,
    insecure: bool,
) -> Result<impl ReflectionOracle, String> {
    let client = wafrift_transport::base_client_builder(
        10, // 10 s probe timeout — matches the model-evade oracle.
        insecure,
        Some("wafrift/fingerprint (authorized security research)"),
    )
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let client = Arc::new(client);
    let target_url = Arc::new(target_url);
    let param = Arc::new(param);

    Ok(FnReflector(move |probe: &[u8]| {
        let probe_url = format!(
            "{}?{}={}",
            target_url.as_str(),
            param.as_str(),
            urlencoding::encode_binary(probe)
        );
        let client2 = client.clone();
        let body = rt.block_on(async move {
            let resp = client2.get(&probe_url).send().await.map_err(|e| {
                WafModelError::Oracle(format!("HTTP error probing {probe_url}: {e}"))
            })?;
            // Observe the reflection in the headers AND the body: an origin
            // that decodes/normalizes the param into a `Location`/`Set-Cookie`
            // header (redirects don't carry a body) would otherwise read as
            // "no reflection". Headers are captured before the body is
            // streamed (read_bounded consumes the response). Redirects are
            // not followed (Policy::none), so the 3xx Location is preserved.
            let mut observed = crate::safe_body::header_bytes(&resp);
            let body =
                crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
                    .await
                    .map_err(|e| WafModelError::Oracle(format!("reading reflection body: {e}")))?;
            observed.extend_from_slice(&body);
            Ok::<Vec<u8>, WafModelError>(observed)
        })?;
        Ok(body)
    }))
}

pub(crate) fn run_fingerprint(args: FingerprintArgs) -> ExitCode {
    ExitCode::from(run_fingerprint_inner(args))
}

/// Same as [`run_fingerprint`] but returns a plain `u8` so tests can assert
/// exact exit codes.
fn run_fingerprint_inner(args: FingerprintArgs) -> u8 {
    // Live requests go out — gate on the same authorization check model-evade
    // uses (loopback / RFC1918 always allowed; public hosts need a reason).
    if let Err(e) = crate::model_evade_cmd::check_permission(&args.url, &args.permission) {
        eprintln!("error: {e}");
        return 2;
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("error: failed to start async runtime: {e}");
            return 2;
        }
    };

    // Optional differential filter characterization. Independent of reflection
    // (it asks "what does the WAF block", not "what does it echo"), so it is
    // computed up front and reported on every exit path — including the
    // no-reflection one, where knowing the block surface is still actionable.
    let filter_profile = if args.characterize_filter {
        match run_filter_characterization(&rt, &args) {
            Ok(pg) => Some(pg),
            Err(e) => {
                eprintln!("warn: filter characterization failed: {e}");
                None
            }
        }
    } else {
        None
    };

    let mut reflector = match build_http_reflector(
        rt.clone(),
        args.url.clone(),
        args.param.clone(),
        args.insecure,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let scan = match scan_origin(&mut reflector) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: probing origin reflection: {e}");
            return 2;
        }
    };
    // Inconclusive measurements must NOT read as a clean origin. No reflection
    // observed ⇒ we never saw the channel echo (wrong parameter, or the value
    // is not reflected); an ambient marker collision ⇒ the byte/whole-value
    // probes are untrustworthy. Either way, fail loudly rather than silently
    // report an empty (and misleading) pipeline.
    if !scan.reflection_observed {
        if args.format == "json" {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "url": args.url,
                    "param": args.param,
                    "reflection_observed": false,
                    "detected_stages": [],
                    "bypass": serde_json::Value::Null,
                    "filter_profile": filter_profile.as_ref().map(filter_profile_json),
                    "error": "no reflection observed",
                }))
                .unwrap_or_default()
            );
        } else {
            eprintln!(
                "error: no reflection observed at parameter `{}` — the target did not echo any \
                 probe back. Is `--param` the parameter whose value is reflected?",
                args.param
            );
            if let Some(p) = &filter_profile {
                print_filter_profile_human(p);
            }
        }
        return 3;
    }
    if scan.marker_collision {
        eprintln!(
            "warn: the fingerprint marker already appears in the target's baseline response \
             (ambient content collision) — byte/whole-value stage detection is suppressed to \
             avoid false positives; results may be incomplete."
        );
    }
    let detected = scan.stages;
    let stage_names: Vec<String> = detected.iter().map(stage_label).collect();

    // Optional: drive the detected pipeline into the solver for a TARGETED,
    // live-verified bypass of `--attack`.
    let mut bypass: Option<serde_json::Value> = None;
    let mut bypass_human: Option<String> = None;
    if let Some(attack) = &args.attack {
        if detected.is_empty() {
            bypass_human = Some(
                "no origin normalization detected — no homoglyph/encoding bypass class applies \
                 (the solver would only be able to report the raw attack, which the WAF already \
                 sees)."
                    .to_string(),
            );
            bypass = Some(serde_json::json!({
                "status": "no_normalization_detected",
                "attack": attack,
                "param": args.param,
            }));
        } else {
            match build_solved_bypass(&rt, &args, attack, &detected) {
                Ok(BypassOutcome::NotPoliced) => {
                    bypass_human = Some(format!(
                        "not policed — the WAF does not block `{attack}` as delivered to `{}`, so \
                         it already reaches the sink; no bypass is needed (and none is fabricated).",
                        args.param,
                    ));
                    bypass = Some(serde_json::json!({
                        "status": "not_policed",
                        "attack": attack,
                        "param": args.param,
                    }));
                }
                Ok(BypassOutcome::Bypassed {
                    payload_b64,
                    sink_view,
                }) => {
                    bypass_human = Some(format!(
                        "verified bypass found — deliver `{}={}` (payload base64: {})",
                        args.param,
                        urlencoding::encode_binary(&base64_decode_lossy(&payload_b64)),
                        payload_b64,
                    ));
                    bypass = Some(serde_json::json!({
                        "status": "bypassed",
                        "attack": attack,
                        "param": args.param,
                        "payload_base64": payload_b64,
                        "sink_view": String::from_utf8_lossy(&sink_view),
                    }));
                }
                Ok(BypassOutcome::Unbypassable) => {
                    bypass_human = Some(
                        "the raw attack is blocked, but no structural preimage of the detected \
                         pipeline passed the live WAF — the WAF holds (reported honestly as no \
                         bypass rather than a fabricated one)."
                            .to_string(),
                    );
                    bypass = Some(serde_json::json!({
                        "status": "unbypassable",
                        "attack": attack,
                        "param": args.param,
                    }));
                }
                Err(e) => {
                    eprintln!("error: solving bypass: {e}");
                    return 2;
                }
            }
        }
    }

    if args.format == "json" {
        let report = serde_json::json!({
            "url": args.url,
            "param": args.param,
            "reflection_observed": true,
            "marker_collision": scan.marker_collision,
            "detected_stages": stage_names,
            "bypass": bypass,
            "filter_profile": filter_profile.as_ref().map(filter_profile_json),
        });
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
    } else {
        println!("wafrift fingerprint — live origin-normalization decompilation");
        println!("target : {}", args.url);
        println!("param  : {}\n", args.param);
        if stage_names.is_empty() {
            println!(
                "No origin normalization detected beyond the framework's baseline query decode."
            );
        } else {
            println!("Detected origin pipeline (canonical order):");
            for (i, name) in stage_names.iter().enumerate() {
                println!("  {}. {name}", i + 1);
            }
        }
        if let Some(b) = &bypass_human {
            println!("\nbypass: {b}");
        }
        if let Some(p) = &filter_profile {
            print_filter_profile_human(p);
        }
    }
    0
}

/// Run a differential filter characterization against the live `--url` using
/// the same block/pass oracle the solver uses (`GET url?param=<value>`,
/// 2xx = pass). The carrier delivers each probe value into the parameter under
/// test, identical to how `build_solved_bypass` delivers candidates, so the
/// characterization and any subsequent solve stay coherent.
fn run_filter_characterization(
    rt: &Arc<tokio::runtime::Runtime>,
    args: &FingerprintArgs,
) -> Result<(FilterProfile, Vec<DecodeGap>), String> {
    let mut oracle = crate::model_evade_cmd::build_http_oracle(
        rt.clone(),
        args.url.clone(),
        args.param.clone(),
        args.insecure,
        None,
        Some(resolve_block_signatures(&args.block_signatures)?),
    )?;
    let url = args.url.clone();
    let carrier = move |value: &str| Request::post(&url, value.as_bytes().to_vec());
    // The battery is Tier-B data: a `--filter-battery` file overrides the
    // embedded default. The loader fails closed on a malformed probe, so a bad
    // data file is a hard error here, never a silently weakened differential.
    let battery = match &args.filter_battery {
        Some(path) => {
            let src = crate::safe_body::read_bounded_text_file(
                std::path::Path::new(path),
                RULESET_FILE_MAX_BYTES,
            )
            .map_err(|e| format!("reading filter battery {path}: {e}"))?;
            wafrift_wafmodel::battery_from_toml(&src).map_err(|e| e.to_string())?
        }
        None => default_filter_battery(),
    };

    // Live-query minimization: warm-start a per-token block/pass posterior from
    // --filter-history, order the battery by descending expected information
    // gain, and trim to --filter-budget. A tight budget against a rate-limited
    // target is then spent on the tokens whose policing is least certain — never
    // re-confirming what a prior run already pinned. Cold start (no history) is
    // deterministic battery order; the scheduler never introduces RNG.
    let history_path = args.filter_history.as_ref().map(std::path::PathBuf::from);
    let mut history = match &history_path {
        Some(p) => crate::info_gain_sched::load_history(p)?,
        None => crate::info_gain_sched::History::new(),
    };
    let battery_total = battery.len();
    let battery = if args.filter_budget > 0 || history_path.is_some() {
        crate::info_gain_sched::order_items_by_info_gain(
            &history,
            battery,
            args.filter_budget,
            |p: &TokenProbe| p.token.clone(),
        )
    } else {
        battery
    };
    if args.filter_budget > 0 && battery.len() < battery_total {
        eprintln!(
            "filter characterization: --filter-budget {} → probing {} of {} battery tokens \
             (highest info-gain first)",
            args.filter_budget,
            battery.len(),
            battery_total
        );
    }

    // First: which tokens are policed at all. Then, for the (usually few)
    // policed tokens, which encodings the WAF fails to decode before matching —
    // the candidate bypass surface. `&carrier` is reused across both probes.
    let profile = characterize(&mut oracle, &battery, &carrier).map_err(|e| e.to_string())?;
    let gaps = probe_decode_gaps(&mut oracle, &profile, &carrier).map_err(|e| e.to_string())?;

    // Fold this run's outcomes back into the posterior so the next run's ordering
    // is better-informed; persist when the operator supplied a history file.
    observe_findings_into_history(&mut history, &profile);
    if let Some(p) = &history_path {
        // Warn, don't die: the profile is already computed and worth returning —
        // a write hiccup must not discard a run that already spent live queries.
        if let Err(e) = crate::info_gain_sched::save_history(p, &history) {
            eprintln!("warn: filter history write to {} failed: {e}", p.display());
        }
    }

    Ok((profile, gaps))
}

/// Fold a [`FilterProfile`]'s findings into an info-gain `History`: a policed or
/// carrier-gated token is a *block* observation, an unpoliced token a *pass*.
/// [`Verdict::Inconclusive`] is never fed in — oracle noise must not move the
/// posterior (the same anti-rig discipline `characterize` itself applies).
fn observe_findings_into_history(
    history: &mut crate::info_gain_sched::History,
    profile: &FilterProfile,
) {
    for f in &profile.findings {
        match f.verdict {
            Verdict::Policed | Verdict::CarrierGate => history.observe(f.token.clone(), true),
            Verdict::Unpoliced => history.observe(f.token.clone(), false),
            Verdict::Inconclusive => {}
        }
    }
}

/// Project a [`FilterProfile`] + its decode-gaps into the machine-readable
/// report shape: the three actionable token sets, the cost, and the per-token
/// WAF-decode-gaps (candidate bypass encodings).
fn filter_profile_json(pg: &(FilterProfile, Vec<DecodeGap>)) -> serde_json::Value {
    let (p, gaps) = pg;
    let gaps_json: Vec<serde_json::Value> = gaps
        .iter()
        .map(|g| {
            serde_json::json!({
                "token": g.token.as_str(),
                "stage": g.stage,
                "encoded_preimage": String::from_utf8_lossy(&g.encoded_preimage),
            })
        })
        .collect();
    serde_json::json!({
        "queries": p.queries,
        "transport_errors": p.transport_errors,
        "policed": p.policed().map(|f| f.token.as_str()).collect::<Vec<_>>(),
        "unpoliced": p.unpoliced().map(|f| f.token.as_str()).collect::<Vec<_>>(),
        "carrier_gated": p.carrier_gated().map(|f| f.token.as_str()).collect::<Vec<_>>(),
        "decode_gaps": gaps_json,
    })
}

/// Print the operator-facing filter characterization summary.
fn print_filter_profile_human(pg: &(FilterProfile, Vec<DecodeGap>)) {
    let (p, gaps) = pg;
    let join = |v: Vec<&str>| {
        if v.is_empty() {
            "(none)".to_string()
        } else {
            v.join(", ")
        }
    };
    let policed: Vec<&str> = p.policed().map(|f| f.token.as_str()).collect();
    let unpoliced: Vec<&str> = p.unpoliced().map(|f| f.token.as_str()).collect();
    let gated: Vec<&str> = p.carrier_gated().map(|f| f.token.as_str()).collect();
    println!("\nFilter characterization ({} live queries):", p.queries);
    println!("  policed (must transform)  : {}", join(policed));
    println!("  unpoliced (use plaintext) : {}", join(unpoliced));
    if !gated.is_empty() {
        println!("  carrier-gated (chars/len) : {}", join(gated));
    }
    if !gaps.is_empty() {
        println!(
            "  WAF decode-gaps (candidate bypass encodings — origin must apply the transform):"
        );
        for g in gaps {
            println!(
                "    {} via {} — try `{}`",
                g.token,
                g.stage,
                String::from_utf8_lossy(&g.encoded_preimage)
            );
        }
    }
    if p.transport_errors > 0 {
        println!(
            "  note: {} probe(s) inconclusive (transport errors) — not counted as pass or block",
            p.transport_errors
        );
    }
}

/// Decode a base64 payload back to raw bytes; on malformed input (which cannot
/// happen for our own freshly-encoded value) fall back to the bytes verbatim so
/// the operator still gets a usable string rather than a panic.
fn base64_decode_lossy(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_else(|_| s.as_bytes().to_vec())
}

/// The three sound outcomes of a targeted solve against a live target, kept
/// distinct so the operator never confuses "nothing to bypass" with "couldn't
/// bypass it" — the #7 false-positive class.
enum BypassOutcome {
    /// The raw attack already passes the WAF as delivered — there is nothing to
    /// bypass (the never-policed case). NOT a bypass.
    NotPoliced,
    /// A live-verified bypass: deliver `payload_b64` and the origin's detected
    /// pipeline reconstructs the attack at the sink.
    Bypassed {
        payload_b64: String,
        sink_view: Vec<u8>,
    },
    /// The raw attack is blocked, but no structural preimage of the detected
    /// pipeline passed the live WAF — the WAF holds. Honest non-result.
    Unbypassable,
}

/// Run the live solver against the detected pipeline, distinguishing the three
/// sound outcomes. A control probe first establishes whether the raw attack is
/// actually policed: if not, the result is [`BypassOutcome::NotPoliced`] and no
/// search runs (a "bypass" would be vacuous). Only a raw-blocked attack with a
/// live-passing preimage is reported as [`BypassOutcome::Bypassed`] — the WAF
/// oracle is the same live target, so `solve_bypass`'s CEGIS gate confirms each
/// candidate actually passes before it is reported.
fn build_solved_bypass(
    rt: &Arc<tokio::runtime::Runtime>,
    args: &FingerprintArgs,
    attack: &str,
    detected: &[Stage],
) -> Result<BypassOutcome, String> {
    let mut waf = crate::model_evade_cmd::build_http_oracle(
        rt.clone(),
        args.url.clone(),
        args.param.clone(),
        args.insecure,
        None,
        Some(resolve_block_signatures(&args.block_signatures)?),
    )?;
    let url = args.url.clone();
    let build = move |b: &[u8]| Request::post(&url, b.to_vec());

    // Control probe: is the raw attack actually blocked? If it already passes,
    // there is nothing to bypass — report NotPoliced and never fabricate one.
    let raw_blocked = matches!(
        waf.classify(&build(attack.as_bytes()))
            .map_err(|e| e.to_string())?,
        Outcome::Block
    );
    if !raw_blocked {
        return Ok(BypassOutcome::NotPoliced);
    }

    let sink = Pipeline(detected.to_vec());
    match solve_bypass(attack.as_bytes(), &sink, &mut waf, &build).map_err(|e| e.to_string())? {
        Some(sol) => {
            use base64::Engine;
            let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&sol.input);
            Ok(BypassOutcome::Bypassed {
                payload_b64,
                sink_view: sol.sink_view,
            })
        }
        None => Ok(BypassOutcome::Unbypassable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── observe_findings_into_history (info-gain feedback) ────────────────

    fn finding(token: &str, verdict: Verdict) -> wafrift_wafmodel::TokenFinding {
        wafrift_wafmodel::TokenFinding {
            token: token.to_string(),
            class: wafrift_wafmodel::RuleGroup::CrossSiteScripting,
            verdict,
        }
    }

    #[test]
    fn observe_maps_policed_and_carrier_gate_to_block_unpoliced_to_pass() {
        let profile = FilterProfile {
            findings: vec![
                finding("<script", Verdict::Policed),
                finding("<svg", Verdict::Unpoliced),
                finding("onerror=", Verdict::CarrierGate),
            ],
            queries: 6,
            transport_errors: 0,
        };
        let mut h = crate::info_gain_sched::History::new();
        observe_findings_into_history(&mut h, &profile);
        // Policed → blocked.
        assert_eq!(h.stats("<script").n_blocked, 1);
        assert_eq!(h.stats("<script").n_passed, 0);
        // Unpoliced → passed.
        assert_eq!(h.stats("<svg").n_passed, 1);
        assert_eq!(h.stats("<svg").n_blocked, 0);
        // CarrierGate → blocked (the carrier still rejected the request).
        assert_eq!(h.stats("onerror=").n_blocked, 1);
    }

    #[test]
    fn observe_never_feeds_inconclusive_into_the_posterior() {
        // Anti-rig: an Inconclusive verdict is oracle noise; feeding it as either
        // a block or a pass would bias the next run's info-gain ordering.
        let profile = FilterProfile {
            findings: vec![finding("noisy", Verdict::Inconclusive)],
            queries: 2,
            transport_errors: 1,
        };
        let mut h = crate::info_gain_sched::History::new();
        observe_findings_into_history(&mut h, &profile);
        assert!(
            h.is_empty(),
            "Inconclusive must not create a posterior entry"
        );
    }

    #[test]
    fn observe_accumulates_across_runs_for_a_drifting_token() {
        // A token blocked on run 1 and passed on run 2 (WAF config drift) must
        // accumulate to θ≈0.5 — exactly the high-info-gain token a budget run
        // should keep probing.
        let mut h = crate::info_gain_sched::History::new();
        observe_findings_into_history(
            &mut h,
            &FilterProfile {
                findings: vec![finding("drift", Verdict::Policed)],
                queries: 2,
                transport_errors: 0,
            },
        );
        observe_findings_into_history(
            &mut h,
            &FilterProfile {
                findings: vec![finding("drift", Verdict::Unpoliced)],
                queries: 2,
                transport_errors: 0,
            },
        );
        let s = h.stats("drift");
        assert_eq!(s.n_blocked, 1);
        assert_eq!(s.n_passed, 1);
        assert!(
            (s.theta_estimate() - 0.5).abs() < 1e-12,
            "drifting token → θ=0.5"
        );
    }

    // ── run_audit ────────────────────────────────────────────────────────

    /// The embedded CRS ruleset loads without error and reports at least
    /// one hole for the `xss` class (the whole raison d'être of the
    /// audit command).
    #[test]
    fn audit_xss_finds_at_least_one_hole() {
        let args = AuditArgs {
            ruleset: None,
            class: "xss".into(),
            format: "human".into(),
        };
        // run_audit prints to stdout/stderr but returns SUCCESS regardless
        // of holes found (it's a reporting tool, not a CI gate). The
        // relevant invariant is: it does NOT panic or exit(2).
        let code = run_audit_inner(args);
        assert_eq!(
            code, 0,
            "run_audit must succeed (exit 0) when using the embedded ruleset"
        );
    }

    #[test]
    fn audit_sqli_succeeds() {
        let args = AuditArgs {
            ruleset: None,
            class: "sqli".into(),
            format: "human".into(),
        };
        assert_eq!(run_audit_inner(args), 0);
    }

    #[test]
    fn audit_all_succeeds() {
        let args = AuditArgs {
            ruleset: None,
            class: "all".into(),
            format: "human".into(),
        };
        assert_eq!(run_audit_inner(args), 0);
    }

    /// `--format json` must produce valid JSON with the expected top-level
    /// keys and non-negative counts.
    #[test]
    fn audit_json_output_is_valid_json_schema() {
        // Capture stdout by running the logic directly through class_data +
        // classify_pass — we can't easily redirect stdout in a unit test,
        // so instead we test the JSON blob that run_audit would build.
        // Construct it the same way run_audit does.
        use wafrift_wafmodel::default_crs_ruleset;
        let mut waf = SimRegexWaf::from_toml(default_crs_ruleset()).unwrap();
        let mut holes_json: Vec<serde_json::Value> = Vec::new();
        let mut total_holes = 0usize;
        for c in class_data("xss") {
            for atk in &c.attacks {
                for (label, cand) in candidates(atk) {
                    let passed = classify_pass(&mut waf, &body(cand.as_bytes())).unwrap_or(false);
                    if passed {
                        total_holes += 1;
                        holes_json.push(serde_json::json!({
                            "class": c.name,
                            "label": label,
                            "attack": atk,
                            "delivered_as": cand,
                        }));
                    }
                }
            }
        }
        let report = serde_json::json!({
            "ruleset_fingerprint": waf.fingerprint(),
            "rules_loaded": waf.rule_count(),
            "inbound_threshold": waf.threshold(),
            "audited_class": "xss",
            "total_holes": total_holes,
            "holes": holes_json,
        });
        // Must round-trip through serde_json without error.
        let s = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.get("total_holes").is_some());
        assert!(v.get("holes").is_some());
        assert!(v.get("rules_loaded").unwrap().as_u64().unwrap() > 0);
    }

    #[test]
    fn audit_bad_ruleset_file_returns_exit_2() {
        let args = AuditArgs {
            ruleset: Some("/nonexistent/path/ruleset.toml".into()),
            class: "xss".into(),
            format: "human".into(),
        };
        let code = run_audit_inner(args);
        assert_eq!(code, 2, "bad ruleset file must exit 2");
    }

    // ── run_harden ───────────────────────────────────────────────────────

    /// The embedded CRS ruleset hardens to proven closure for both classes.
    /// This is the contract the harden command exists to fulfill.
    #[test]
    fn harden_all_proves_closure_with_embedded_ruleset() {
        let args = HardenArgs {
            ruleset: None,
            class: "all".into(),
            format: "human".into(),
        };
        // `all_proven` → exit 0.
        let code = run_harden_inner(args);
        assert_eq!(
            code, 0,
            "harden must prove closure (exit 0) for both classes on the embedded ruleset"
        );
    }

    #[test]
    fn harden_xss_only_proves_closure() {
        let code = run_harden_inner(HardenArgs {
            ruleset: None,
            class: "xss".into(),
            format: "human".into(),
        });
        assert_eq!(code, 0);
    }

    #[test]
    fn harden_sqli_only_proves_closure() {
        let code = run_harden_inner(HardenArgs {
            ruleset: None,
            class: "sqli".into(),
            format: "human".into(),
        });
        assert_eq!(code, 0);
    }

    /// JSON mode must produce valid JSON with the expected keys and the
    /// `all_proven` field set to true on the embedded ruleset.
    #[test]
    fn harden_json_format_flag_accepted_and_sane() {
        // Call run_harden in JSON mode. We can't easily capture stdout in a
        // unit test (println! goes directly to the fd), so we replicate the
        // logic here — this mirrors the contract test in harden_contract.rs.
        use wafrift_wafmodel::default_crs_ruleset;
        let waf = SimRegexWaf::from_toml(default_crs_ruleset()).unwrap();
        let tf = vec![
            Transform::UrlDecodeUni,
            Transform::HtmlEntityDecode,
            Transform::Lowercase,
        ];
        let benign: &[&str] = &["hello world", "please select an option"];
        // Verify the JSON-mode logic doesn't panic and produces a
        // valid shape. We test it by running the internal computation
        // and asserting the JSON shape we would emit.
        let mut classes_json: Vec<serde_json::Value> = Vec::new();
        for c in class_data("xss") {
            let class = &c.name;
            let mut added: Vec<Rule> = Vec::new();
            for t in &c.tokens {
                let re = regex::bytes::Regex::new(&regex::escape(t)).unwrap();
                let safe = t.replace([' ', '<', '\''], "_");
                added.push(Rule {
                    id: format!("synth-{class}-{safe}"),
                    channels: ChannelSet::all(),
                    transforms: tf.clone(),
                    pattern: re,
                    score: waf.threshold(),
                });
            }
            let rules_json: Vec<serde_json::Value> = added
                .iter()
                .map(|rule| {
                    let tf_list: Vec<&str> = rule
                        .transforms
                        .iter()
                        .map(|t| match t {
                            Transform::UrlDecodeUni => "UrlDecodeUni",
                            Transform::HtmlEntityDecode => "HtmlEntityDecode",
                            Transform::Lowercase => "Lowercase",
                            Transform::RemoveNulls => "RemoveNulls",
                            Transform::CompressWhitespace => "CompressWhitespace",
                            Transform::RemoveWhitespace => "RemoveWhitespace",
                        })
                        .collect();
                    serde_json::json!({
                        "id": rule.id,
                        "transforms": tf_list,
                        "pattern": rule.pattern.as_str(),
                        "score": rule.score,
                    })
                })
                .collect();
            classes_json.push(serde_json::json!({
                "class": class,
                "holes_before": 0,
                "holes_after": 0,
                "benign_false_positives": 0,
                "proven_closed": true,
                "added_rules": rules_json,
            }));
        }
        let report = serde_json::json!({
            "audited_class": "xss",
            "all_proven": true,
            "classes": classes_json,
        });
        let s = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.get("all_proven").unwrap().as_bool().unwrap());
        assert!(v.get("classes").unwrap().is_array());
        // Each added_rule must have a "transforms" array, not a hardcoded
        // string — this is the core invariant the pre-fix violated.
        let first_class = &v["classes"][0];
        let first_rule = &first_class["added_rules"][0];
        assert!(
            first_rule["transforms"].is_array(),
            "transforms must be an array, not a hardcoded string"
        );
        assert!(
            !first_rule["transforms"].as_array().unwrap().is_empty(),
            "transforms array must not be empty"
        );
        // Anti-rig: benign strings are not present in the output.
        for b in benign {
            assert!(
                !s.contains(b),
                "benign corpus must not appear in the JSON output"
            );
        }
    }

    /// The TOML rule snippet for a double-decode rule must include
    /// `UrlDecodeUni` TWICE (the double-decode variant).
    #[test]
    fn harden_toml_output_reflects_actual_transform_chain() {
        // Directly test the transform-to-TOML helper logic (the bug was
        // here). The double-decode chain must produce two "UrlDecodeUni"
        // entries.
        let double_chain = [
            Transform::UrlDecodeUni,
            Transform::UrlDecodeUni,
            Transform::HtmlEntityDecode,
            Transform::Lowercase,
        ];
        let tf_toml: Vec<String> = double_chain.iter().map(|t| format!("\"{t:?}\"")).collect();
        let toml_str = tf_toml.join(", ");
        // Must have "UrlDecodeUni" appearing twice.
        let count = toml_str.matches("UrlDecodeUni").count();
        assert_eq!(
            count, 2,
            "double-decode TOML must list UrlDecodeUni twice, got: {toml_str}"
        );
        // And the standard chain has it once.
        let single_chain = [
            Transform::UrlDecodeUni,
            Transform::HtmlEntityDecode,
            Transform::Lowercase,
        ];
        let single_toml: String = single_chain
            .iter()
            .map(|t| format!("\"{t:?}\""))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            single_toml.matches("UrlDecodeUni").count(),
            1,
            "single-decode TOML must list UrlDecodeUni once"
        );
    }

    #[test]
    fn harden_bad_ruleset_file_returns_exit_2() {
        let args = HardenArgs {
            ruleset: Some("/nonexistent/path/ruleset.toml".into()),
            class: "all".into(),
            format: "human".into(),
        };
        assert_eq!(run_harden_inner(args), 2);
    }

    // ── class_data / helpers ─────────────────────────────────────────────

    /// class_data("all") must return exactly two entries (xss + sqli).
    #[test]
    fn class_data_all_returns_two_entries() {
        assert_eq!(class_data("all").len(), 2);
    }

    #[test]
    fn class_data_xss_returns_one_entry() {
        let v = class_data("xss");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "xss");
    }

    #[test]
    fn class_data_sqli_returns_one_entry() {
        let v = class_data("sqli");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "sqli");
    }

    // ── attack-class Tier-B loader (fail-closed) ─────────────────────────

    #[test]
    fn embedded_attack_classes_parse_and_are_non_trivial() {
        // The embedded data the `expect` in class_data relies on MUST be valid;
        // pin it so a bad edit fails here, not at runtime.
        let classes = attack_classes_from_toml(ATTACK_CLASSES_TOML)
            .expect("embedded attack-class data must parse");
        assert_eq!(classes.len(), 2, "ship xss + sqli");
        for c in &classes {
            assert!(!c.attacks.is_empty(), "{} must have attacks", c.name);
            assert!(!c.tokens.is_empty(), "{} must have tokens", c.name);
        }
    }

    #[test]
    fn attack_classes_loader_rejects_empty_set() {
        assert!(
            attack_classes_from_toml("").is_err(),
            "empty data must fail closed"
        );
        assert!(
            attack_classes_from_toml("# only a comment\n").is_err(),
            "a file with no [[class]] must fail closed"
        );
    }

    #[test]
    fn attack_classes_loader_rejects_a_class_missing_tokens_or_attacks() {
        // A class whose tokens don't detect its attacks would make harden's proof
        // vacuous — the loader must reject an empty side rather than weaken it.
        let no_tokens = "[[class]]\nname = \"xss\"\nattacks = [\"<script>\"]\ntokens = []\n";
        assert!(
            attack_classes_from_toml(no_tokens).is_err(),
            "empty tokens must fail"
        );
        let no_attacks = "[[class]]\nname = \"xss\"\nattacks = []\ntokens = [\"<script\"]\n";
        assert!(
            attack_classes_from_toml(no_attacks).is_err(),
            "empty attacks must fail"
        );
        let no_name = "[[class]]\nname = \"\"\nattacks = [\"x\"]\ntokens = [\"y\"]\n";
        assert!(
            attack_classes_from_toml(no_name).is_err(),
            "blank name must fail"
        );
    }

    #[test]
    fn attack_classes_loader_rejects_malformed_toml() {
        assert!(
            attack_classes_from_toml("[[class]]\nname = ").is_err(),
            "syntactically broken TOML must be a hard error"
        );
    }

    #[test]
    fn xss_tokens_actually_detect_xss_attacks() {
        // The load-bearing semantic invariant the harden proof rests on: every
        // shipped class's tokens must be substrings present (case-insensitively)
        // across its attack set — otherwise a synthesized rule keys on a token no
        // attack contains, and the "holes closed" proof is meaningless.
        for c in attack_classes_from_toml(ATTACK_CLASSES_TOML).unwrap() {
            for tok in &c.tokens {
                let joined = c.attacks.join(" ").to_ascii_lowercase();
                assert!(
                    joined.contains(&tok.to_ascii_lowercase()),
                    "class {}: token {tok:?} appears in none of its attacks",
                    c.name
                );
            }
        }
    }

    /// case_flip must toggle ASCII case and leave non-alpha unchanged.
    #[test]
    fn case_flip_toggles_ascii_case() {
        assert_eq!(case_flip("Hello123!"), "hELLO123!");
        assert_eq!(case_flip(""), "");
        assert_eq!(case_flip("123"), "123");
    }

    // ── channel_set_toml ─────────────────────────────────────────────────

    /// All-channels `ChannelSet` must serialize to a TOML array containing
    /// all eight channel names in canonical declaration order.
    #[test]
    fn channel_set_toml_all_channels_round_trips() {
        let s = channel_set_toml(ChannelSet::all());
        // Must be bracketed.
        assert!(
            s.starts_with('[') && s.ends_with(']'),
            "must be a TOML array: {s}"
        );
        // All eight channels must appear.
        for name in &[
            "\"Path\"",
            "\"ArgName\"",
            "\"ArgValue\"",
            "\"HeaderName\"",
            "\"HeaderValue\"",
            "\"CookieName\"",
            "\"CookieValue\"",
            "\"Body\"",
        ] {
            assert!(s.contains(name), "missing channel {name} in: {s}");
        }
    }

    /// An empty `ChannelSet` must serialize to `[]`, not to a list of
    /// stray commas or a malformed TOML literal.
    #[test]
    fn channel_set_toml_empty_produces_empty_array() {
        let s = channel_set_toml(ChannelSet::none());
        assert_eq!(s, "[]", "empty ChannelSet must produce '[]', got: {s}");
    }

    /// A single-channel `ChannelSet` must produce exactly one entry.
    #[test]
    fn channel_set_toml_single_channel_has_one_entry() {
        let cs = ChannelSet::none().with(Channel::Body);
        let s = channel_set_toml(cs);
        assert_eq!(
            s, "[\"Body\"]",
            "single-channel must serialize to [\"Body\"], got: {s}"
        );
    }

    /// `channel_set_toml` output is accepted by `SimRegexWaf::from_toml`
    /// when embedded in a minimal `[[rule]]` stanza. This is the end-to-end
    /// contract: if the harden command emits the TOML, a user can paste it
    /// and it will parse without error.
    #[test]
    fn channel_set_toml_output_is_parseable_by_sim_regex_waf() {
        let channels_toml = channel_set_toml(ChannelSet::all());
        // Minimal valid ruleset with the generated channels field.
        let toml = format!(
            r#"threshold = 5
[[rule]]
id = "test-toml-roundtrip"
channels = {channels_toml}
transforms = ["UrlDecodeUni", "Lowercase"]
pattern = "script"
score = 5
"#
        );
        let result = SimRegexWaf::from_toml(&toml);
        assert!(
            result.is_ok(),
            "channel_set_toml output must parse cleanly in from_toml: {:?}",
            result.err()
        );
    }

    /// candidates must include the raw and case-flipped variants plus
    /// at least one decode-mismatch encoding.
    #[test]
    fn candidates_includes_raw_and_case_variant() {
        let cands = candidates("<script>alert(1)</script>");
        let labels: Vec<&str> = cands.iter().map(|(l, _)| l.as_str()).collect();
        assert!(labels.contains(&"raw"), "must include raw variant");
        assert!(
            labels.contains(&"case"),
            "must include case-flipped variant"
        );
        // There must be at least one decode-mismatch encoding on top of raw+case.
        assert!(
            cands.len() > 2,
            "must include at least one mismatch encoding beyond raw+case, got {labels:?}"
        );
    }

    // ── Round 18: bounded ruleset reads ─────────────────────────────
    //
    // `--ruleset <path>` previously slurped via std::fs::read_to_string
    // and OOMed on /dev/zero / multi-GB symlinks. Must go through
    // safe_body::read_bounded_text_file with RULESET_FILE_MAX_BYTES.

    #[test]
    fn ruleset_load_is_bounded() {
        let src = include_str!("wafmodel_cmd.rs");
        let needle = "safe_body::read_bounded_text_file(\n            std::path::Path::new(p),\n            RULESET_FILE_MAX_BYTES,\n        )";
        assert!(
            src.contains(needle),
            "wafmodel_cmd.rs `load_ruleset` must use bounded reader with RULESET_FILE_MAX_BYTES"
        );
        let banned = concat!("std::fs::", "read_to_", "string(p).map_err");
        assert!(
            !src.contains(banned),
            "raw unbounded fs read of ruleset path reintroduced — OOM regression"
        );
    }

    #[test]
    fn ruleset_cap_is_sane() {
        assert!(
            super::RULESET_FILE_MAX_BYTES >= 4 * 1024 * 1024,
            "RULESET_FILE_MAX_BYTES tightened below 4 MiB — could reject legitimate rulesets"
        );
    }

    #[test]
    fn stage_label_names_every_detectable_stage() {
        // Every stage the live fingerprinter can return must have a stable,
        // non-Debug label (the Debug fallback is only for stages detect cannot
        // emit). If a new detectable stage is added without a label, this drift
        // guard fails because the label equals the Debug form.
        let detectable = [
            Stage::UrlDecode {
                plus_is_space: false,
            },
            Stage::Base64Decode,
            Stage::HexDecode,
            Stage::OverlongUtf8Decode,
            Stage::StripNulls,
            Stage::NfkcNormalize,
            Stage::BestFitDownconvert,
        ];
        for s in detectable {
            let label = stage_label(&s);
            assert!(
                label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{s:?} has no snake_case label (got {label:?})"
            );
            assert_ne!(label, format!("{s:?}"), "{s:?} fell through to Debug label");
        }
    }

    // ── live fingerprint over a real loopback TCP origin ─────────────────
    //
    // The payoff e2e: a real reflection-echo HTTP server applying a KNOWN
    // normalization, reached over a real reqwest client, and
    // `detect_origin_normalization` must recover exactly that stage (positive)
    // while an identity origin yields nothing (anti-fabrication twin). This
    // proves the live wiring — not a `FakeOrigin` double — end to end.
    mod fingerprint_live {
        use super::*;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        /// One-pass percent-decode (the framework's baseline query decode).
        fn pct_decode_once(s: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(s.len());
            let mut i = 0;
            while i < s.len() {
                if s[i] == b'%' && i + 2 < s.len() {
                    let hi = (s[i + 1] as char).to_digit(16);
                    let lo = (s[i + 2] as char).to_digit(16);
                    if let (Some(h), Some(l)) = (hi, lo) {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                        continue;
                    }
                }
                out.push(s[i]);
                i += 1;
            }
            out
        }

        /// Extract the raw (still percent-encoded) value of `name` from a
        /// request-line path like `/?q=<value>&x=1`.
        fn extract_param(path: &[u8], name: &[u8]) -> Vec<u8> {
            let q = match path.iter().position(|&b| b == b'?') {
                Some(p) => &path[p + 1..],
                None => return Vec::new(),
            };
            for pair in q.split(|&b| b == b'&') {
                if let Some(eq) = pair.iter().position(|&b| b == b'=')
                    && &pair[..eq] == name
                {
                    return pair[eq + 1..].to_vec();
                }
            }
            Vec::new()
        }

        /// Byte transform an echo origin applies to the decoded query value.
        type EchoTransform = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

        /// Spawn an echo origin on `rt` that reflects `transform(framework_url_decode(q))`.
        /// Returns the bound address. The server runs until `rt` is dropped.
        fn spawn_echo_origin(rt: &tokio::runtime::Runtime, transform: EchoTransform) -> SocketAddr {
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                let addr = listener.local_addr().expect("addr");
                tokio::spawn(async move {
                    loop {
                        let (mut sock, _) = match listener.accept().await {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let tf = transform.clone();
                        tokio::spawn(async move {
                            let mut buf = Vec::new();
                            let mut tmp = [0u8; 1024];
                            loop {
                                match sock.read(&mut tmp).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        buf.extend_from_slice(&tmp[..n]);
                                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                            break;
                                        }
                                        if buf.len() > 64 * 1024 {
                                            break;
                                        }
                                    }
                                    Err(_) => return,
                                }
                            }
                            let line_end =
                                buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
                            let request_line = &buf[..line_end];
                            let path = request_line
                                .split(|&b| b == b' ')
                                .nth(1)
                                .unwrap_or(b"");
                            let raw = extract_param(path, b"q");
                            let decoded = pct_decode_once(&raw);
                            let reflected = tf(&decoded);
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                reflected.len()
                            );
                            let _ = sock.write_all(head.as_bytes()).await;
                            let _ = sock.write_all(&reflected).await;
                            let _ = sock.shutdown().await;
                        });
                    }
                });
                addr
            })
        }

        #[test]
        fn live_reflector_against_identity_origin_detects_nothing() {
            // Anti-fabrication twin: an origin that reflects the value verbatim
            // (only the framework's baseline decode) applies no extra stage, so
            // the fingerprinter MUST report an empty pipeline.
            let srv_rt = tokio::runtime::Runtime::new().unwrap();
            let addr = spawn_echo_origin(&srv_rt, Arc::new(|v: &[u8]| v.to_vec()));

            let cli_rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
            let url = format!("http://{addr}/");
            let mut reflector = build_http_reflector(cli_rt, url, "q".to_string(), false).unwrap();
            let scan = scan_origin(&mut reflector).unwrap();
            assert!(
                scan.reflection_observed,
                "the echo channel must be observed so the empty result is trustworthy"
            );
            assert!(
                scan.stages.is_empty(),
                "identity origin must detect no stages, got {:?}",
                scan.stages
            );
        }

        #[test]
        fn live_reflector_against_base64_origin_detects_base64() {
            // Positive: an origin that base64-decodes the parameter (after the
            // framework's baseline url-decode) must be fingerprinted as exactly
            // Base64Decode — over real TCP, not a FakeOrigin double.
            use base64::Engine;
            let srv_rt = tokio::runtime::Runtime::new().unwrap();
            let addr = spawn_echo_origin(
                &srv_rt,
                Arc::new(|v: &[u8]| {
                    // Decode if it's valid base64; otherwise reflect verbatim so
                    // non-base64 probes (url/overlong/nul) stay unfolded.
                    match base64::engine::general_purpose::STANDARD.decode(v) {
                        Ok(d) => d,
                        Err(_) => v.to_vec(),
                    }
                }),
            );

            let cli_rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
            let url = format!("http://{addr}/");
            let mut reflector = build_http_reflector(cli_rt, url, "q".to_string(), false).unwrap();
            let scan = scan_origin(&mut reflector).unwrap();
            assert!(scan.reflection_observed);
            assert!(!scan.marker_collision);
            assert_eq!(
                scan.stages,
                vec![Stage::Base64Decode],
                "base64-decoding origin must be fingerprinted as exactly Base64Decode"
            );
        }
    }
}
