//! `wafrift harvest` + `wafrift submit` — turn a hunt/bench bypass
//! corpus into review-ready HackerOne reports, then (separately, one at
//! a time, only with `--confirm`) file a single reviewed report.
//!
//! ## Two commands, one hard rule: NEVER auto-submit
//!
//! Mass-filing machine-generated reports at a bounty program is the
//! fastest way to get the account banned. So the pipeline is split:
//!
//! - `harvest` is READ + RE-VERIFY + WRITE-TO-DISK only. It never talks
//!   to HackerOne. It reads the rule-bypass corpus a `hunt` /
//!   `bench-waf --corpus-out` run produced, drops duplicates and
//!   already-handled bypasses, re-fires each unique candidate at the
//!   LIVE target to confirm it STILL works and capture fresh
//!   request+response proof (a stale "it bypassed last week" is not
//!   submittable), and writes one Markdown report per still-working
//!   bypass.
//!
//! - `submit` files exactly ONE report, and only when `--confirm` is
//!   passed. Without `--confirm` it is a dry run that prints what would
//!   be sent. There is no batch mode and no automatic path: the operator
//!   reviews each report by hand and submits the good ones individually.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

use wafrift_evolution::rule_corpus::{RecordedBypass, RuleBypassCorpus, SubmissionStatus};
use wafrift_grammar::grammar::equiv::DeliveryShape;

use crate::bench_waf::build_request_for_payload;
use crate::equiv_engine::{
    ProbeEnvelope, build_request_for_delivery, differential_confirmed, send_with_envelope,
    verified_bypass,
};

/// Tier-B per-class "policing probe" table — an un-evaded canonical attack per
/// class that a competent WAF should block. Used by the differential-baseline
/// gate to tell a genuine evasion from a never-policed sink (see
/// [`differential_credits`]).
const POLICING_PROBES_TOML: &str = include_str!("../rules/policing_probes.toml");

/// Parse the Tier-B policing-probe table: `[[probe]] class=.. payload=..`.
/// Fails closed on an empty table or an empty payload.
fn load_policing_probes(src: &str) -> Result<std::collections::HashMap<String, String>, String> {
    #[derive(serde::Deserialize)]
    struct Row {
        class: String,
        payload: String,
    }
    #[derive(serde::Deserialize)]
    struct Table {
        #[serde(default)]
        probe: Vec<Row>,
    }
    let table: Table =
        toml::from_str(src).map_err(|e| format!("parsing policing-probe TOML: {e}"))?;
    if table.probe.is_empty() {
        return Err("policing-probe file has no `[[probe]]` entries".into());
    }
    let mut map = std::collections::HashMap::new();
    for r in table.probe {
        if r.payload.trim().is_empty() {
            return Err(format!("policing probe for class `{}` is empty", r.class));
        }
        map.insert(r.class, r.payload);
    }
    Ok(map)
}

/// The embedded policing-probe table (parsed once). Panics only if the shipped
/// data file is malformed (asserted by tests).
fn policing_probes() -> &'static std::collections::HashMap<String, String> {
    static MAP: std::sync::OnceLock<std::collections::HashMap<String, String>> =
        std::sync::OnceLock::new();
    MAP.get_or_init(|| {
        load_policing_probes(POLICING_PROBES_TOML)
            .expect("embedded policing-probe data file must be valid (asserted in tests)")
    })
}

/// The un-evaded policing probe for `class`, if the Tier-B table lists one.
fn class_policing_probe(class: &str) -> Option<&'static str> {
    policing_probes().get(class).map(String::as_str)
}

/// Decide whether a confirmed candidate should be CREDITED as a real bypass
/// under the active differential-baseline policy.
///
/// - Differential OFF → always `true` (legacy crediting; the headline metric is
///   byte-for-byte unchanged).
/// - Differential ON → fire the class's un-evaded policing probe through the
///   SAME delivery (`build_control`) and credit only if the WAF BLOCKED it
///   (`base_blocked`). A probe that sails through means the sink was never
///   policed for this class, so the recorded "bypass" reaching the app is a
///   false positive (no evasion occurred) — drop it. When no probe exists for
///   the class, the differential cannot be evaluated, so credit is withheld
///   (`base_blocked = false`) rather than inflating the count.
async fn differential_credits<F>(
    client: &reqwest::Client,
    class: &str,
    timeout_secs: u64,
    build_control: F,
) -> bool
where
    F: FnOnce(&str) -> wafrift_types::Request,
{
    let differential = crate::config::differential_enabled();
    if !differential {
        return differential_confirmed(true, false, true);
    }
    let base_blocked = match class_policing_probe(class) {
        Some(probe) => {
            let control = build_control(probe);
            matches!(
                send_with_envelope(client, &control, timeout_secs).await,
                Ok(env) if env.blocked
            )
        }
        None => false,
    };
    differential_confirmed(true, differential, base_blocked)
}

/// Cloudflare's public WAF-bypass bounty surface — the `--target
/// cumulusfire` preset for both `hunt` and `harvest`.
const CUMULUSFIRE_BASE_URL: &str = "https://waf.cumulusfire.net";
const CUMULUSFIRE_PERMISSION: &str =
    "CumulusFire public bug bounty scope — wafrift harvest --target cumulusfire";
const CUMULUSFIRE_TEAM: &str = "cumulusfire";

/// Fallback delivery shapes tried during re-verify, in order. Used ONLY
/// when the corpus has no recorded delivery shape for a bypass (a
/// pre-delivery-capture corpus, or a payload-mutation strategy that has
/// no equivalence shape). When the corpus DOES carry the shape,
/// [`reverify_one`] re-fires that exact shape first (faithful re-fire)
/// and only falls back to these standard shapes if it no longer
/// reproduces. The first shape that still bypasses doubles as a clean,
/// concrete reproduction.
const REVERIFY_MODES: &[(&str, &str)] = &[
    (
        "body_form_q",
        "POST /post  (application/x-www-form-urlencoded, q=<payload>)",
    ),
    ("url_query_q", "GET /get?q=<payload>"),
    ("raw_body", "POST /post  (text/plain, raw body)"),
];

/// Map an attack class to its primary CWE (HackerOne `weakness_id`).
/// Data-driven so a new class is one row, never a scattered literal.
fn weakness_id_for_class(class: &str) -> u32 {
    match class {
        "sql" => 89,        // CWE-89  SQL Injection
        "xss" => 79,        // CWE-79  Cross-site Scripting
        "cmdi" => 78,       // CWE-78  OS Command Injection
        "path" => 22,       // CWE-22  Path Traversal
        "ssti" => 1336,     // CWE-1336 Server-Side Template Injection
        "ldap" => 90,       // CWE-90  LDAP Injection
        "ssrf" => 918,      // CWE-918 SSRF
        "nosql" => 943,     // CWE-943 Improper Neutralization in a Data Query
        "xxe" => 611,       // CWE-611 XXE
        "log4shell" => 502, // CWE-502 Deserialization of Untrusted Data
        _ => 20,            // CWE-20  Improper Input Validation (generic)
    }
}

// ─── harvest ───────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub(crate) struct HarvestArgs {
    /// Live target to RE-VERIFY each candidate bypass against. Re-firing
    /// confirms the bypass still works today and captures fresh
    /// request+response proof for the report. Overridden by
    /// `--target cumulusfire`.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Named target preset. Currently only `cumulusfire` — pre-fills
    /// `--base-url`, the permission reason, and the H1 team for
    /// Cloudflare's public WAF bounty surface.
    #[arg(long, value_name = "PRESET", value_parser = ["cumulusfire"])]
    pub target: Option<String>,

    /// Path to the rule-bypass corpus JSON. Defaults to the per-target
    /// file a `hunt` campaign writes (`~/.wafrift/corpus-<target>.json`).
    #[arg(long)]
    pub corpus: Option<PathBuf>,

    /// Directory to write review-ready Markdown reports into. Defaults
    /// to `~/.wafrift/harvest-<target>/`. (`--out` is kept as an alias
    /// for the name harvest shipped with in 0.3.0.)
    #[arg(long = "output", visible_alias = "out", value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// HackerOne team handle embedded in each report (used by
    /// `wafrift submit`). Defaults to `cumulusfire`.
    #[arg(long, default_value = "cumulusfire")]
    pub h1_team: String,

    /// Authorization statement, required for any target outside
    /// localhost / RFC1918 / the built-in allowlist (unless
    /// `--target cumulusfire`, which carries a built-in reason).
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// Cap the number of candidate bypasses re-verified (0 = no cap).
    #[arg(long, default_value_t = 0)]
    pub limit: usize,

    /// Per-probe timeout for the re-verify requests (seconds).
    #[arg(long, default_value_t = 15)]
    pub timeout_secs: u64,

    /// Delay between re-verify probes (milliseconds) — be polite to the
    /// live target.
    #[arg(long, default_value_t = 250)]
    pub delay_ms: u64,

    /// Skip the live re-verify step and emit reports straight from the
    /// corpus (offline triage). Reports are marked UNVERIFIED — do not
    /// submit one without re-verifying it first.
    #[arg(long)]
    pub no_reverify: bool,

    /// Collapse candidates to ONE per root cause `(class × technique)` before
    /// re-verify, keeping the shortest (minimal) payload as the canonical.
    /// A hunt records hundreds of near-duplicate variants of the same
    /// evasion mechanism (e.g. 210 `inet_aton_form` SSRF variants); filing
    /// them as separate reports is the bounty-program-ban risk this tool
    /// otherwise warns about. With this flag a 895-variant corpus harvests as
    /// ~42 submittable root-cause reports. Default off (exact-payload dedup)
    /// for backwards-compatibility.
    #[arg(long = "root-cause", visible_alias = "by-root-cause")]
    pub root_cause: bool,

    /// After confirming a bypass still reaches origin, PROVE it executes by
    /// detonating the response through the external `detonate` tool — elevating
    /// a reflected XSS bypass to a confirmed `alert(1)`-class exploit. Requires
    /// the `detonate` binary on PATH (or `$WAFRIFT_DETONATE_BIN`); when absent,
    /// harvest warns once and proceeds without execution proof.
    #[arg(long = "prove-execution")]
    pub prove_execution: bool,
}

pub(crate) fn run_harvest(args: HarvestArgs) -> ExitCode {
    ExitCode::from(run_harvest_inner(args))
}

/// Resolve the `--target cumulusfire` preset into (base_url, permission,
/// team), or fall back to the explicit flags. Returns `Err(code)` if no
/// target could be determined.
fn resolve_target(args: &HarvestArgs) -> Result<(String, Option<String>, String), u8> {
    if args.target.as_deref() == Some("cumulusfire") {
        let base = args
            .base_url
            .clone()
            .unwrap_or_else(|| CUMULUSFIRE_BASE_URL.to_string());
        let perm = Some(
            args.i_have_permission
                .clone()
                .unwrap_or_else(|| CUMULUSFIRE_PERMISSION.to_string()),
        );
        return Ok((base, perm, CUMULUSFIRE_TEAM.to_string()));
    }
    match args.base_url.clone() {
        Some(u) => Ok((u, args.i_have_permission.clone(), args.h1_team.clone())),
        None => {
            eprintln!(
                "error: --base-url (or --target cumulusfire) is required so harvest \
                 knows where to re-verify each bypass."
            );
            Err(2)
        }
    }
}

fn run_harvest_inner(args: HarvestArgs) -> u8 {
    let (base_url, permission, team) = match resolve_target(&args) {
        Ok(t) => t,
        Err(code) => return code,
    };

    // Gate on the same allowlist / --i-have-permission contract bench &
    // hunt use (exits 2 on refusal). Always — not just when re-verifying:
    // every report embeds the target host and a curl reproduction aimed at
    // it, so generating attack reports for a host the operator hasn't
    // asserted permission to target is refused even under --no-reverify.
    crate::permission::assert_permitted(&base_url, permission.as_deref());

    let corpus_path = args
        .corpus
        .clone()
        .unwrap_or_else(|| crate::corpus_recorder::default_corpus_paths(&base_url).0);
    if !corpus_path.exists() {
        eprintln!(
            "error: corpus {} does not exist.\n\
             Run a campaign first, e.g.:\n  \
             wafrift hunt --target cumulusfire --max-duration-secs 3600\n\
             then re-run harvest.",
            corpus_path.display()
        );
        return 1;
    }
    // Parse the corpus EXPLICITLY so a corrupt/truncated file is a hard
    // error, not a silent empty. `RuleBypassCorpus::load_or_default`
    // swallows parse failures into a fresh corpus — correct for the WRITE
    // side (bench/hunt are about to fill it) but dangerous here: a broken
    // corpus would read as "no bypasses to harvest" and the operator could
    // silently miss submittable findings (= lost bounty money).
    let raw = match crate::safe_body::read_bounded_text_file(&corpus_path, 128 * 1024 * 1024) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read corpus {}: {e}", corpus_path.display());
            return 1;
        }
    };
    let corpus: RuleBypassCorpus = match serde_json::from_str(&raw) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: corpus {} is not valid JSON: {e}\n\
                 It may be truncated or corrupt. harvest will NOT silently treat a broken \
                 corpus as empty (you could miss submittable bypasses) — re-run the hunt or \
                 `bench-waf --corpus-out` to regenerate it.",
                corpus_path.display()
            );
            return 1;
        }
    };

    // Collect unique, not-yet-handled candidate bypasses across all rule
    // buckets. Dedup by (class, payload) so the same winning payload
    // recorded under several rule_ids is re-verified once.
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut candidates: Vec<(String, RecordedBypass)> = Vec::new();
    for bucket in corpus.buckets.values() {
        for bp in &bucket.bypassed {
            if !is_unhandled(&bp.submission) {
                continue;
            }
            let key = (bp.payload_class.as_str().to_string(), bp.payload.clone());
            if seen.insert(key) {
                candidates.push((bucket.rule_id.0.clone(), bp.clone()));
            }
        }
    }
    // Root-cause collapse (opt-in): keep ONE canonical (shortest payload)
    // per (class × technique) so a corpus of hundreds of near-duplicate
    // variants harvests as a handful of submittable reports rather than a
    // ban-risk flood. Applied BEFORE the limit so `--limit` counts root
    // causes, not raw variants.
    if args.root_cause {
        let before = candidates.len();
        candidates = collapse_to_root_causes(candidates);
        eprintln!(
            "[wafrift harvest] root-cause dedup: {before} variants → {} unique (class × technique)",
            candidates.len()
        );
    }
    if args.limit > 0 && candidates.len() > args.limit {
        candidates.truncate(args.limit);
    }

    let host = host_of(&base_url);
    let out_dir = args.out.clone().unwrap_or_else(|| {
        let slug = crate::corpus_recorder::target_slug(&base_url);
        crate::corpus_recorder::default_corpus_paths(&base_url)
            .0
            .parent()
            .map(|p| p.join(format!("harvest-{slug}")))
            .unwrap_or_else(|| PathBuf::from(format!("harvest-{slug}")))
    });
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("error: cannot create report dir {}: {e}", out_dir.display());
        return 1;
    }

    eprintln!(
        "[wafrift harvest] {} unique candidate bypasses from {} ({})",
        candidates.len(),
        corpus_path.display(),
        if args.no_reverify {
            "no re-verify — reports marked UNVERIFIED"
        } else {
            "re-verifying against the live target"
        }
    );

    if candidates.is_empty() {
        eprintln!(
            "[wafrift harvest] nothing to do — corpus has no un-handled bypasses. \
             (Already-submitted/accepted/rejected entries are skipped.)"
        );
        return 0;
    }

    // Async only needed for the live re-verify probes.
    let proofs: Vec<Option<ReverifyProof>> = if args.no_reverify {
        candidates.iter().map(|_| None).collect()
    } else {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("error: tokio runtime: {e}");
                return 1;
            }
        };
        let prove = args.prove_execution;
        if prove && !crate::exec_proof::available() {
            eprintln!(
                "[wafrift harvest] WARNING — --prove-execution set but the `detonate` \
                 tool was not found (PATH or $WAFRIFT_DETONATE_BIN). Proceeding WITHOUT \
                 execution proof; install `detonate` to elevate reflected bypasses to \
                 confirmed exploits."
            );
        }
        rt.block_on(reverify_all(
            &base_url,
            &candidates,
            args.timeout_secs,
            args.delay_ms,
            prove,
        ))
    };

    let mut written = 0usize;
    let mut still_working = 0usize;
    // Honest bypass-vs-exploit split: of the re-verified bypasses, how many were
    // proven to actually EXECUTE (alert(1) fired) by detonation, vs merely
    // bypass the WAF and reflect inert. This is the gap behind "real payloads
    // struggle vs what we classify as a bypass" — surfaced as a headline, never
    // hidden inside per-report JSON.
    let mut executed = 0usize;
    for ((rule_id, bp), proof) in candidates.iter().zip(proofs.iter()) {
        // When re-verifying, only write reports for bypasses that STILL
        // work — a candidate the WAF now blocks is not submittable.
        if !args.no_reverify && proof.is_none() {
            continue;
        }
        if proof.is_some() {
            still_working += 1;
        }
        if proof
            .as_ref()
            .and_then(|p| p.execution.as_ref())
            .is_some_and(|e| e.executed)
        {
            executed += 1;
        }
        let (filename, content) =
            render_report(&base_url, &host, rule_id, bp, proof.as_ref(), &team);
        let path = out_dir.join(&filename);
        match std::fs::write(&path, content) {
            Ok(()) => written += 1,
            Err(e) => eprintln!("warn: write {}: {e}", path.display()),
        }
    }

    eprintln!(
        "[wafrift harvest] wrote {written} report(s) to {}",
        out_dir.display()
    );
    if !args.no_reverify {
        eprintln!(
            "[wafrift harvest] {still_working}/{} candidates still bypass the live WAF.",
            candidates.len()
        );
    }
    if args.prove_execution {
        let bypass_only = still_working.saturating_sub(executed);
        eprintln!(
            "[wafrift harvest] bypass-vs-exploit: {executed}/{still_working} re-verified \
             bypasses EXECUTE (confirmed exploits, alert(1) fired); {bypass_only} bypass the \
             WAF but reflect inert. Only the {executed} executing finding(s) are submittable \
             exploits — the rest are WAF bypasses, not proven XSS."
        );
    }
    eprintln!(
        "[wafrift harvest] REVIEW each report, then file the good ones ONE at a time:\n  \
         wafrift submit --report {}/<file>.md --confirm\n\
         wafrift never auto-submits — batch-filing is a bounty-program ban risk.",
        out_dir.display()
    );
    0
}

/// A bypass is a harvest candidate only if it has NOT already been
/// submitted / accepted / marked duplicate / rejected. `Queued` and
/// `DryRunHold` mean "discovered, never filed" → eligible.
fn is_unhandled(status: &SubmissionStatus) -> bool {
    matches!(
        status,
        SubmissionStatus::Queued | SubmissionStatus::DryRunHold { .. }
    )
}

/// The technique that defines a bypass's root cause: the first non-identity
/// step of its encoding chain (the transform that actually evades the WAF),
/// or `"identity"` when the payload bypassed unmodified. Paired with the
/// attack class this keys a `(class × technique)` root cause — the unit a
/// bounty triager treats as one distinct bypass.
fn root_cause_technique(bp: &RecordedBypass) -> &str {
    bp.encoding_chain
        .iter()
        .map(String::as_str)
        .find(|t| *t != "identity")
        .unwrap_or("identity")
}

/// Collapse candidates to one canonical per `(class × technique)` root cause,
/// keeping the SHORTEST payload (the minimal, cleanest reproduction). Fully
/// deterministic — ties broken by payload bytes — so the same corpus always
/// yields the same canonical set. Each kept bypass retains its `rule_id`.
fn collapse_to_root_causes(
    candidates: Vec<(String, RecordedBypass)>,
) -> Vec<(String, RecordedBypass)> {
    use std::collections::BTreeMap;
    let mut best: BTreeMap<(String, String), (String, RecordedBypass)> = BTreeMap::new();
    for (rule_id, bp) in candidates {
        let key = (
            bp.payload_class.as_str().to_string(),
            root_cause_technique(&bp).to_string(),
        );
        match best.get(&key) {
            // Keep the incumbent only when it is the shorter (or equal) payload.
            Some((_, cur)) if keeps_incumbent(cur, &bp) => {}
            _ => {
                best.insert(key, (rule_id, bp));
            }
        }
    }
    best.into_values().collect()
}

/// True when the incumbent `cur` should be KEPT over candidate `cand` — i.e.
/// `cur` is the shorter payload, ties broken by lexicographic bytes so the
/// canonical choice is deterministic across runs.
fn keeps_incumbent(cur: &RecordedBypass, cand: &RecordedBypass) -> bool {
    (cur.payload.len(), cur.payload.as_str()) <= (cand.payload.len(), cand.payload.as_str())
}

/// Fresh proof captured by re-firing a candidate at the live target.
struct ReverifyProof {
    /// Human description of the delivery that reproduced the bypass
    /// (for the report's "Delivery:" line).
    delivery_desc: String,
    /// Ready-to-paste curl that reproduces EXACTLY this delivery —
    /// rendered from the request actually fired, so it matches whatever
    /// shape (faithful recorded shape or standard fallback) reproduced.
    repro_curl: String,
    status: u16,
    latency_ms: f64,
    /// True iff the winning payload bytes were reflected in the response
    /// body — strong evidence it reached origin un-sanitized.
    reflected: bool,
    /// Bounded, control-stripped excerpt of the response body.
    body_excerpt: String,
    /// Execution proof from the external `detonate` tool (`--prove-execution`).
    /// `Some(p)` when detonation ran; `p.executed` ⇒ a confirmed exploit (the
    /// reflected payload's JS actually fired a dialog sink). `None` when proof
    /// was not requested or the tool was unavailable.
    execution: Option<crate::exec_proof::ExecutionProof>,
}

/// Build a [`ReverifyProof`] from a confirming probe response. Shared by
/// the faithful-shape path and the standard-shape fallback so the
/// body/reflection/excerpt extraction lives in ONE place (§7).
fn proof_from_env(
    env: &ProbeEnvelope,
    payload: &str,
    delivery_desc: String,
    repro_curl: String,
    prove: bool,
    url: &str,
) -> ReverifyProof {
    let body = String::from_utf8_lossy(&env.body);
    let reflected = body.contains(payload);
    // Only spend a detonation when the payload actually reflected — an
    // unreflected bypass has no JS in the response to execute.
    let execution = if prove && reflected {
        crate::exec_proof::prove_execution(&body, url)
    } else {
        None
    };
    ReverifyProof {
        delivery_desc,
        repro_curl,
        status: env.status,
        latency_ms: env.latency_ms,
        reflected,
        body_excerpt: excerpt(&body, 400),
        execution,
    }
}

async fn reverify_all(
    base_url: &str,
    candidates: &[(String, RecordedBypass)],
    timeout_secs: u64,
    delay_ms: u64,
    prove: bool,
) -> Vec<Option<ReverifyProof>> {
    let client = match crate::smuggle_transport::build_client(timeout_secs) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: build HTTP client: {e}");
            return candidates.iter().map(|_| None).collect();
        }
    };
    let mut out = Vec::with_capacity(candidates.len());
    for (i, (_rule, bp)) in candidates.iter().enumerate() {
        if i > 0 && delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        out.push(reverify_one(&client, base_url, bp, timeout_secs, delay_ms, prove).await);
    }
    out
}

/// Re-fire one candidate and return proof if it STILL bypasses
/// (oracle-verified, not just unblocked).
///
/// Faithful-first: if the corpus recorded the exact delivery shape that
/// beat the WAF, re-fire THAT shape first — it reproduces the original
/// request byte-for-byte, which is the only re-fire that reliably works
/// for equiv-cegis bypasses (they depend on a specific delivery channel,
/// not just the payload bytes). Only if there's no recorded shape, or it
/// no longer reproduces, do we fall back to the standard shapes.
async fn reverify_one(
    client: &reqwest::Client,
    base_url: &str,
    bp: &RecordedBypass,
    timeout_secs: u64,
    delay_ms: u64,
    prove: bool,
) -> Option<ReverifyProof> {
    let class = bp.payload_class.as_str();

    // 1) Faithful re-fire of the recorded delivery shape (if any).
    if !bp.delivery.is_empty() {
        match serde_json::from_str::<DeliveryShape>(&bp.delivery) {
            Ok(shape) => {
                let req = build_request_for_delivery(base_url, &shape, &bp.payload);
                if let Ok(env) = send_with_envelope(client, &req, timeout_secs).await
                    && verified_bypass(class, &bp.payload, &bp.payload, env.blocked, env.status)
                    && differential_credits(client, class, timeout_secs, |p| {
                        build_request_for_delivery(base_url, &shape, p)
                    })
                    .await
                {
                    return Some(proof_from_env(
                        &env,
                        &bp.payload,
                        format!("recorded shape `{}` — faithful re-fire", shape.label()),
                        request_to_curl(&req),
                        prove,
                        base_url,
                    ));
                }
                // Recorded shape no longer reproduces — be polite before
                // trying the fallback shapes.
                if delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
            }
            // A corrupt/unknown shape string is not fatal: fall through to
            // the standard shapes rather than dropping the candidate.
            Err(e) => eprintln!(
                "warn: corpus delivery for payload {:?} did not parse ({e}); \
                 falling back to standard shapes",
                truncate_for_log(&bp.payload, 60)
            ),
        }
    }

    // 2) Fallback: standard delivery shapes (pre-capture corpora,
    //    payload-mutation strategies, or a no-longer-reproducing shape).
    for (i, (mode, mode_desc)) in REVERIFY_MODES.iter().enumerate() {
        // Delay between delivery-shape probes too (not only between
        // candidates): re-verify fires several requests per candidate and
        // a live bounty surface may rate-limit rapid bursts.
        if i > 0 && delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        let req = build_request_for_payload(base_url, mode, &bp.payload);
        let Ok(env) = send_with_envelope(client, &req, timeout_secs).await else {
            continue;
        };
        // Same independent oracle the bench/hunt use: not blocked AND
        // reached the app AND still a working attack of its class — plus, under
        // --differential-baseline, the class's un-evaded probe must be BLOCKED
        // in this same mode (else the sink was never policed: false positive).
        if verified_bypass(class, &bp.payload, &bp.payload, env.blocked, env.status)
            && differential_credits(client, class, timeout_secs, |p| {
                build_request_for_payload(base_url, mode, p)
            })
            .await
        {
            return Some(proof_from_env(
                &env,
                &bp.payload,
                (*mode_desc).to_string(),
                curl_repro(base_url, mode, &bp.payload),
                prove,
                base_url,
            ));
        }
    }
    None
}

/// Render a fired [`wafrift_types::Request`] as a copy-pasteable curl
/// reproduction. Generic over any delivery shape (method + URL + headers
/// + body), so the faithful-re-fire path produces an exact reproduction
/// for shapes the canned [`curl_repro`] modes don't cover (HPP, header,
/// cookie, multipart, XML, GraphQL, …). Control/non-printable bytes in
/// the body switch to byte-exact bash ANSI-C `$'…'` quoting.
fn request_to_curl(req: &wafrift_types::Request) -> String {
    let mut parts = vec![format!(
        "curl -sk -X {} '{}'",
        req.method.as_str(),
        sq_escape(&req.url)
    )];
    for (k, v) in &req.headers {
        parts.push(format!("-H '{}: {}'", sq_escape(k), sq_escape(v)));
    }
    if let Some(body) = &req.body {
        let s = String::from_utf8_lossy(body);
        if needs_ansi_c_quoting(&s) {
            parts.push(format!("--data-binary $'{}'", ansi_c_escape(&s)));
        } else {
            parts.push(format!("--data-binary '{}'", sq_escape(&s)));
        }
    }
    parts.join(" \\\n  ")
}

/// Truncate a payload for a one-line warning so a multi-KB payload can't
/// flood stderr. Char-boundary safe.
fn truncate_for_log(s: &str, max_chars: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { '.' } else { c })
        .take(max_chars)
        .collect();
    if s.chars().count() > max_chars {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

/// Render a single review-ready HackerOne report. Returns
/// `(filename, content)`. The first line is a machine-readable
/// `<!-- wafrift-submit: {..} -->` comment consumed by `wafrift submit`;
/// everything after it is the human-readable + H1-ready Markdown body.
fn render_report(
    base_url: &str,
    host: &str,
    rule_id: &str,
    bp: &RecordedBypass,
    proof: Option<&ReverifyProof>,
    team: &str,
) -> (String, String) {
    let class = bp.payload_class.as_str();
    let weakness_id = weakness_id_for_class(class);
    let technique = if bp.encoding_chain.is_empty() {
        rule_id.to_string()
    } else {
        bp.encoding_chain.join("+")
    };
    // Execution proof (when `--prove-execution` ran detonate): a fired dialog
    // sink elevates a reflected bypass to a confirmed exploit, raising both the
    // headline and the severity.
    let execution = proof.and_then(|p| p.execution.as_ref());
    let exploit_confirmed = execution.is_some_and(|e| e.executed);
    let severity = if exploit_confirmed {
        "critical"
    } else {
        "high"
    };
    let title = if exploit_confirmed {
        let arg = execution.and_then(|e| e.message.as_deref()).unwrap_or("1");
        format!(
            "Confirmed {class} exploit (alert({arg}) executes) via WAF bypass `{technique}` on {host}"
        )
    } else {
        format!("WAF bypass: {class} payload reaches origin via {technique} on {host}")
    };

    let meta = serde_json::json!({
        "team": team,
        "title": title,
        "class": class,
        "severity": severity,
        "weakness_id": weakness_id,
        "verified": proof.is_some(),
        "exploit_confirmed": exploit_confirmed,
    });
    let header = format!(
        "<!-- wafrift-submit: {} -->\n",
        serde_json::to_string(&meta).unwrap_or_default()
    );

    let mut b = String::new();
    b.push_str(&format!("# {title}\n\n"));
    b.push_str("## Summary\n\n");
    b.push_str(&format!(
        "A `{class}`-class attack payload bypasses the WAF on `{host}` and \
         reaches the origin application unfiltered. Discovered and "
    ));
    b.push_str(if proof.is_some() {
        "re-verified live by `wafrift`.\n\n"
    } else {
        "recorded by `wafrift` (NOT re-verified — confirm before submitting).\n\n"
    });

    b.push_str(&format!(
        "- **Target**: `{base_url}`\n- **Attack class**: `{class}` (CWE-{weakness_id})\n\
         - **Bypass technique**: `{technique}`\n- **WAF rule observed**: `{rule_id}`\n\n"
    ));

    b.push_str("## Payload\n\nThe exact bytes that bypassed the WAF (on the wire):\n\n```\n");
    b.push_str(&bp.payload);
    b.push_str("\n```\n");
    if needs_ansi_c_quoting(&bp.payload) {
        b.push_str(
            "\nThis payload contains non-printable bytes (rendered raw above — they may be \
             invisible). Byte-exact (bash ANSI-C) form:\n\n```\n$'",
        );
        b.push_str(&ansi_c_escape(&bp.payload));
        b.push_str("'\n```\n");
    }
    b.push('\n');

    b.push_str("## Reproduction\n\n");
    // When re-verified, use the curl for the exact request that
    // reproduced (faithful recorded shape or the standard shape that
    // worked). Unverified reports fall back to the canonical form shape.
    let repro = match proof {
        Some(p) => {
            b.push_str(&format!("Delivery: {}\n\n", p.delivery_desc));
            p.repro_curl.clone()
        }
        None => curl_repro(base_url, "body_form_q", &bp.payload),
    };
    b.push_str("```sh\n");
    b.push_str(&repro);
    b.push_str("\n```\n\n");

    b.push_str("## Proof\n\n");
    match proof {
        Some(p) => {
            b.push_str(&format!(
                "Re-fired live: the WAF returned **HTTP {}** (not a block) in {:.0} ms, \
                 and the oracle confirms the payload is still a working `{class}` attack.\n\n",
                p.status, p.latency_ms
            ));
            b.push_str(&format!(
                "- Payload reflected in response body: **{}**\n\n",
                if p.reflected {
                    "yes (reached origin)"
                } else {
                    "not reflected"
                }
            ));
            if let Some(e) = &p.execution {
                if e.executed {
                    b.push_str(&format!(
                        "- **Execution proven**: the reflected payload's JavaScript ran in a \
                         sandboxed browser (jsdet) and fired `{}({})` — this is a confirmed \
                         exploit, not merely a WAF bypass.\n\n",
                        e.sink.as_deref().unwrap_or("alert"),
                        e.message.as_deref().unwrap_or("1"),
                    ));
                } else {
                    b.push_str(
                        "- Execution proof: the reflection did NOT execute in the sandbox \
                         (lands in a non-executable / escaped context) — a WAF bypass, but \
                         not a proven exploit on this endpoint.\n\n",
                    );
                }
            }
            b.push_str("Response body excerpt:\n\n```\n");
            b.push_str(&p.body_excerpt);
            b.push_str("\n```\n\n");
        }
        None => {
            b.push_str(
                "UNVERIFIED — this report was emitted with `--no-reverify`. \
                 Re-run harvest without that flag (or fire the reproduction above) \
                 to capture a live HTTP response before submitting.\n\n",
            );
        }
    }

    b.push_str("## Impact\n\n");
    b.push_str(
        "The WAF is intended to block this attack class but passes this payload through \
         to the origin. Any origin endpoint relying on the WAF as a control is exposed \
         to the underlying vulnerability.\n",
    );

    let filename = report_filename(class, &technique, &bp.payload);
    (filename, format!("{header}{b}"))
}

/// Deterministic, filesystem-safe report filename derived from the
/// class, technique, and a short payload hash (so two payloads under the
/// same technique don't collide).
fn report_filename(class: &str, technique: &str, payload: &str) -> String {
    let hash = wafrift_types::hash::fnv1a_64(payload.as_bytes());
    let tech_slug: String = technique
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(40)
        .collect();
    format!("{class}-{tech_slug}-{hash:016x}.md")
}

/// Build a copy-pasteable curl reproduction for the given delivery mode.
fn curl_repro(base_url: &str, mode: &str, payload: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let ansi = needs_ansi_c_quoting(payload);
    match mode {
        // URL-encoding already makes control bytes safe (`%0c`, etc).
        "url_query_q" => format!("curl -sk '{base}/get?q={}'", urlencoding::encode(payload)),
        "raw_body" if ansi => format!(
            "curl -sk -X POST '{base}/post' -H 'Content-Type: text/plain' \\\n  --data-binary $'{}'",
            ansi_c_escape(payload)
        ),
        "raw_body" => format!(
            "curl -sk -X POST '{base}/post' -H 'Content-Type: text/plain' \\\n  --data-binary '{}'",
            sq_escape(payload)
        ),
        // body_form_q (default): let curl URL-encode the form value.
        // `q=$'...'` — the shell expands the ANSI-C string and prepends
        // `q=`, so curl sees one `q=<bytes>` arg and URL-encodes the value.
        _ if ansi => format!(
            "curl -sk -X POST '{base}/post' \\\n  --data-urlencode q=$'{}'",
            ansi_c_escape(payload)
        ),
        _ => format!(
            "curl -sk -X POST '{base}/post' \\\n  --data-urlencode 'q={}'",
            sq_escape(payload)
        ),
    }
}

/// Escape a string for safe embedding inside a single-quoted shell arg.
fn sq_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// True if the payload has any byte outside printable ASCII (control
/// bytes, UTF-8 multibyte). Those can't survive a plain single-quoted
/// shell arg intact — and for WAF bypasses the non-printable byte is
/// often the bypass itself (`\f`, `\t`, NUL, fullwidth unicode) — so the
/// curl repro must switch to byte-exact bash ANSI-C `$'...'` quoting.
fn needs_ansi_c_quoting(s: &str) -> bool {
    s.bytes().any(|b| !(0x20..=0x7e).contains(&b))
}

/// Escape a payload for bash ANSI-C `$'...'` quoting, BYTE-exact: every
/// byte outside printable ASCII becomes `\xHH` (named escapes for the
/// common control bytes), and `'`/`\` are escaped. Pasted into bash/zsh
/// this reconstructs the exact wire bytes — including the control bytes
/// that carry the bypass.
fn ansi_c_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for &b in s.as_bytes() {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// Bounded, control-stripped excerpt of a response body for the report.
fn excerpt(body: &str, max_chars: usize) -> String {
    let cleaned: String = body
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '.'
            } else {
                c
            }
        })
        .take(max_chars)
        .collect();
    if body.chars().count() > max_chars {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

/// Host portion of a URL for titles/filenames; falls back to the raw
/// string if it doesn't parse.
fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

// ─── submit (guarded, one report at a time) ──────────────────────────────────

#[derive(Args, Debug)]
pub(crate) struct SubmitArgs {
    /// Path to a SINGLE review-ready report produced by `wafrift harvest`.
    #[arg(long)]
    pub report: PathBuf,

    /// Actually file the report to HackerOne. WITHOUT this flag, submit
    /// is a dry run that prints exactly what would be sent. wafrift never
    /// auto-submits and never batch-submits — you file one reviewed
    /// report at a time, deliberately.
    #[arg(long)]
    pub confirm: bool,

    /// Override the HackerOne team handle embedded in the report.
    #[arg(long)]
    pub team: Option<String>,
}

pub(crate) fn run_submit(args: SubmitArgs) -> ExitCode {
    ExitCode::from(run_submit_inner(args))
}

fn run_submit_inner(args: SubmitArgs) -> u8 {
    // §15 OOM / hostile-symlink guard + §10 coherence with the safe_body
    // rule ("NEVER raw fs::read_to_string for operator files"): a harvest
    // report is markdown (KBs), so the 1 MiB cap is generous and stops a
    // `/dev/zero` typo, a multi-GB file, or a symlinked --report from being
    // slurped whole into memory. This site was missed by the original
    // read_bounded_text_file sweep.
    let raw = match crate::safe_body::read_bounded_text_file(
        &args.report,
        crate::safe_body::MAX_OPERATOR_INPUT_BYTES,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read report {}: {e}", args.report.display());
            return 1;
        }
    };
    let Some(meta) = parse_report_meta(&raw) else {
        eprintln!(
            "error: {} is not a wafrift harvest report (missing the \
             `<!-- wafrift-submit: {{..}} -->` header on line 1).",
            args.report.display()
        );
        return 2;
    };
    let team = args.team.clone().unwrap_or(meta.team);
    if team.is_empty() {
        eprintln!("error: no HackerOne team handle — pass --team <handle>.");
        return 2;
    }
    // The H1 body is the Markdown with the machine header stripped.
    let body: String = raw.lines().skip(1).collect::<Vec<_>>().join("\n");

    if !args.confirm {
        println!("DRY RUN — nothing was submitted.\n");
        println!("  Team       : {team}");
        println!("  Title      : {}", meta.title);
        println!(
            "  Severity   : {}  (CWE-{})",
            meta.severity, meta.weakness_id
        );
        println!("  Verified   : {}", meta.verified);
        println!("  Report     : {}", args.report.display());
        println!(
            "\nReview the report above. To file THIS one report to HackerOne, re-run with \
             --confirm:\n  wafrift submit --report {} --confirm",
            args.report.display()
        );
        if !meta.verified {
            println!(
                "\nWARNING: this report is UNVERIFIED (harvested with --no-reverify). \
                 Re-verify before filing."
            );
        }
        return 0;
    }

    if !meta.verified {
        eprintln!(
            "error: refusing to submit an UNVERIFIED report. Re-harvest without \
             --no-reverify so the bypass is confirmed live first."
        );
        return 2;
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: tokio runtime: {e}");
            return 1;
        }
    };
    match rt.block_on(submit_report_to_h1(
        &team,
        &meta.title,
        &body,
        meta.severity.as_str(),
        meta.weakness_id,
    )) {
        Ok(report_id) => {
            println!("filed to HackerOne team `{team}` — report id: {report_id}");
            0
        }
        Err(e) => {
            eprintln!("error: submit failed: {e}");
            1
        }
    }
}

/// Metadata parsed from a harvest report's machine header.
struct ReportMeta {
    team: String,
    title: String,
    severity: String,
    weakness_id: u32,
    verified: bool,
}

/// Parse the `<!-- wafrift-submit: {json} -->` header from line 1.
fn parse_report_meta(raw: &str) -> Option<ReportMeta> {
    let first = raw.lines().next()?;
    let inner = first
        .trim()
        .strip_prefix("<!-- wafrift-submit:")?
        .strip_suffix("-->")?
        .trim();
    let v: serde_json::Value = serde_json::from_str(inner).ok()?;
    Some(ReportMeta {
        team: v.get("team")?.as_str()?.to_string(),
        title: v.get("title")?.as_str()?.to_string(),
        severity: v
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("high")
            .to_string(),
        weakness_id: v
            .get("weakness_id")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(20) as u32,
        verified: v
            .get("verified")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

/// File ONE prepared report to HackerOne via their Reports API v1.
///
/// Requires `H1_API_KEY` (token) and `H1_USERNAME` (handle) in the
/// environment. Only ever reached from `wafrift submit --confirm`, one
/// report per invocation — wafrift has no automatic or batch submit path.
async fn submit_report_to_h1(
    team: &str,
    title: &str,
    body: &str,
    severity: &str,
    weakness_id: u32,
) -> Result<String, String> {
    let api_key = std::env::var("H1_API_KEY")
        .map_err(|_| "H1_API_KEY not set — cannot submit to HackerOne".to_string())?;
    let username = std::env::var("H1_USERNAME").map_err(|_| "H1_USERNAME not set".to_string())?;

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.hackerone.com/v1/hackers/reports")
        .basic_auth(&username, Some(&api_key))
        .json(&serde_json::json!({
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": team,
                    "title": title,
                    "vulnerability_information": body,
                    "severity_rating": severity,
                    "impact": "WAF bypass allows unfiltered attack payloads to reach the origin.",
                    "weakness_id": weakness_id,
                }
            }
        }))
        .send()
        .await
        .map_err(|e| format!("H1 API request failed: {e}"))?;

    let status = resp.status();
    if status.is_success() {
        // Best-effort extraction of the created report id.
        let body = crate::safe_body::read_bounded_text(resp, 256 * 1024)
            .await
            .unwrap_or_default();
        let id = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("data")
                    .and_then(|d| d.get("id"))
                    .and_then(|i| i.as_str().map(str::to_string))
            })
            .unwrap_or_else(|| "(id not returned)".to_string());
        Ok(id)
    } else {
        let body = crate::safe_body::read_bounded_text(resp, 64 * 1024)
            .await
            .unwrap_or_default();
        Err(format!("H1 API returned {status}: {body}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_evolution::coverage_feedback::PayloadClass;

    // ── policing-probe table (differential-baseline re-verify) ───────────────

    #[test]
    fn embedded_policing_probes_load_and_are_nonempty() {
        let m = load_policing_probes(POLICING_PROBES_TOML).expect("shipped probe table is valid");
        assert!(
            m.len() >= 8,
            "ship a real per-class probe table, got {}",
            m.len()
        );
        assert!(m.values().all(|p| !p.trim().is_empty()));
    }

    #[test]
    fn policing_probes_cover_every_recorded_corpus_class() {
        // The cumulusfire corpus carries exactly these classes; the differential
        // gate must have a probe for each or it would silently drop candidates.
        for class in [
            "cmdi", "sql", "ssrf", "ssti", "ldap", "nosql", "path", "xxe", "xss", "cve_pocs",
        ] {
            assert!(
                class_policing_probe(class).is_some(),
                "no policing probe for corpus class `{class}` — differential would drop it"
            );
        }
    }

    #[test]
    fn policing_probe_loader_fails_closed_on_empty() {
        assert!(load_policing_probes("# nothing\n").is_err());
        assert!(load_policing_probes("").is_err());
    }

    #[test]
    fn policing_probe_loader_rejects_an_empty_payload() {
        let bad = "[[probe]]\nclass=\"sql\"\npayload=\"\"\n";
        assert!(load_policing_probes(bad).is_err());
    }

    #[test]
    fn an_unknown_class_has_no_policing_probe() {
        assert!(class_policing_probe("totally-unknown-class").is_none());
    }

    fn bypass(class: &str, payload: &str, chain: &[&str]) -> RecordedBypass {
        RecordedBypass {
            payload: payload.to_string(),
            payload_class: PayloadClass::new(class),
            encoding_chain: chain.iter().map(|s| (*s).to_string()).collect(),
            response_hash: 0,
            observed_at_secs: 0,
            submission: SubmissionStatus::Queued,
            delivery: String::new(),
        }
    }

    #[test]
    fn weakness_id_maps_known_classes_and_defaults() {
        assert_eq!(weakness_id_for_class("sql"), 89);
        assert_eq!(weakness_id_for_class("ssrf"), 918);
        assert_eq!(weakness_id_for_class("xxe"), 611);
        // Unknown class falls back to CWE-20, never panics.
        assert_eq!(weakness_id_for_class("brand-new-class"), 20);
    }

    #[test]
    fn root_cause_technique_is_first_non_identity_step() {
        assert_eq!(
            root_cause_technique(&bypass("ssrf", "x", &["identity", "inet_aton_form"])),
            "inet_aton_form"
        );
        assert_eq!(
            root_cause_technique(&bypass("sql", "x", &["ws_equiv", "case"])),
            "ws_equiv"
        );
        // All-identity (or empty) chain → "identity".
        assert_eq!(
            root_cause_technique(&bypass("xss", "x", &["identity"])),
            "identity"
        );
        assert_eq!(root_cause_technique(&bypass("xss", "x", &[])), "identity");
    }

    #[test]
    fn collapse_keeps_one_shortest_canonical_per_class_technique() {
        // 4 SSRF inet_aton variants + 1 SSRF rfc3986 + 1 cmdi → 3 root causes,
        // and the SSRF inet_aton canonical is the SHORTEST of its group.
        let cands = vec![
            (
                "r".into(),
                bypass("ssrf", "http://0xC0.0xA8.0.1/longest", &["inet_aton_form"]),
            ),
            ("r".into(), bypass("ssrf", "//0/", &["inet_aton_form"])), // shortest
            (
                "r".into(),
                bypass("ssrf", "http://2130706433/", &["inet_aton_form"]),
            ),
            (
                "r".into(),
                bypass("ssrf", "http://allowed@0.0.0.0/", &["rfc3986_userinfo"]),
            ),
            ("r".into(), bypass("cmdi", "; id ", &["separator_swap"])),
            (
                "r".into(),
                bypass("cmdi", "; cat /etc/passwd", &["separator_swap"]),
            ),
        ];
        let out = collapse_to_root_causes(cands);
        assert_eq!(out.len(), 3, "3 unique (class × technique) root causes");
        let ssrf_inet = out
            .iter()
            .find(|(_, b)| {
                b.payload_class.as_str() == "ssrf" && root_cause_technique(b) == "inet_aton_form"
            })
            .expect("ssrf inet_aton root cause present");
        assert_eq!(
            ssrf_inet.1.payload, "//0/",
            "canonical must be the shortest variant"
        );
        let cmdi = out
            .iter()
            .find(|(_, b)| b.payload_class.as_str() == "cmdi")
            .expect("cmdi root cause present");
        assert_eq!(cmdi.1.payload, "; id ", "shortest cmdi variant kept");
    }

    #[test]
    fn collapse_is_deterministic_across_runs() {
        let mk = || {
            vec![
                ("r".into(), bypass("sql", "1 OR 1=1", &["ws_equiv"])),
                ("r".into(), bypass("sql", "1 OR 1=1", &["ws_equiv"])),
                ("r".into(), bypass("sql", "1 OR 2=2", &["ws_equiv"])),
            ]
        };
        let a = collapse_to_root_causes(mk());
        let b = collapse_to_root_causes(mk());
        assert_eq!(a.len(), 1);
        assert_eq!(
            a[0].1.payload, b[0].1.payload,
            "same corpus → same canonical"
        );
    }

    #[test]
    fn is_unhandled_only_true_for_queued_and_dryrun() {
        assert!(is_unhandled(&SubmissionStatus::Queued));
        assert!(is_unhandled(&SubmissionStatus::DryRunHold {
            release_at_secs: 1
        }));
        assert!(!is_unhandled(&SubmissionStatus::Submitted {
            report_id: "1".into()
        }));
        assert!(!is_unhandled(&SubmissionStatus::Accepted {
            report_id: "1".into()
        }));
        assert!(!is_unhandled(&SubmissionStatus::Duplicate {
            duplicate_of: "1".into()
        }));
        assert!(!is_unhandled(&SubmissionStatus::Rejected {
            reason: "na".into()
        }));
    }

    #[test]
    fn report_carries_payload_and_parses_back() {
        let bp = bypass("sql", "' OR 1=1-- x", &["ws_equiv", "keyword_morph"]);
        let (fname, content) = render_report(
            "https://waf.cumulusfire.net",
            "waf.cumulusfire.net",
            "cf:?:?",
            &bp,
            None,
            "cumulusfire",
        );
        assert!(fname.starts_with("sql-"));
        assert!(fname.ends_with(".md"));
        // The exact wire payload must appear verbatim in the report.
        assert!(content.contains("' OR 1=1-- x"));
        // The machine header must round-trip through the submit parser.
        let meta = parse_report_meta(&content).expect("header must parse");
        assert_eq!(meta.team, "cumulusfire");
        assert_eq!(meta.weakness_id, 89);
        assert_eq!(meta.severity, "high");
        // No proof was supplied → marked unverified.
        assert!(!meta.verified);
        assert!(content.contains("UNVERIFIED"));
    }

    #[test]
    fn report_filename_is_stable_and_distinct_per_payload() {
        let a = report_filename("sql", "ws_equiv", "payload-A");
        let b = report_filename("sql", "ws_equiv", "payload-B");
        let a2 = report_filename("sql", "ws_equiv", "payload-A");
        assert_eq!(a, a2, "same inputs → same filename");
        assert_ne!(a, b, "different payloads → different filenames");
    }

    #[test]
    fn curl_repro_escapes_single_quotes() {
        let c = curl_repro("https://x.test", "body_form_q", "a' OR '1'='1");
        // The single quotes in the payload must be shell-escaped so the
        // generated curl line is copy-pasteable without breaking quoting.
        assert!(c.contains("'\\''"));
        assert!(!c.contains("q=a' OR"));
    }

    #[test]
    fn parse_report_meta_rejects_non_report() {
        assert!(parse_report_meta("# just a markdown file\n\nbody").is_none());
        assert!(parse_report_meta("").is_none());
    }

    #[test]
    fn excerpt_bounds_and_strips_control_bytes() {
        let long = "A".repeat(1000);
        let e = excerpt(&long, 400);
        assert!(e.chars().count() <= 401, "bounded to max+ellipsis");
        assert!(e.ends_with('…'));
        let ctrl = excerpt("ok\u{0007}\u{0000}bell", 100);
        assert!(!ctrl.contains('\u{0007}'));
        assert!(ctrl.contains("ok"));
    }

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wafrift_harvest_test_{}_{}_{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn ansi_c_escape_renders_control_bytes_byte_exact() {
        // formfeed (0x0c), tab, single-quote, backslash — the bytes that
        // a WAF bypass payload commonly carries.
        let s = "a\u{0c}b\tc'd\\e";
        assert_eq!(ansi_c_escape(s), "a\\x0cb\\tc\\'d\\\\e");
    }

    #[test]
    fn needs_ansi_c_quoting_detects_nonprintable_only() {
        assert!(needs_ansi_c_quoting("has\u{0c}formfeed"));
        assert!(needs_ansi_c_quoting("\t"));
        assert!(needs_ansi_c_quoting("fullwidth\u{ff1f}")); // non-ASCII unicode
        // Single quotes are printable ASCII — handled by the single-quote
        // form, so they do NOT force ANSI-C quoting.
        assert!(!needs_ansi_c_quoting("plain ' OR 1=1 -- printable"));
    }

    #[test]
    fn curl_repro_uses_ansi_c_for_control_byte_payload() {
        let c = curl_repro("https://x.test", "body_form_q", "a\u{0c}b");
        assert!(
            c.contains("q=$'"),
            "control-byte payload must use ANSI-C $'...' quoting: {c}"
        );
        assert!(c.contains("\\x0c"), "formfeed must render as \\x0c: {c}");
        // A printable payload stays in the readable single-quote form.
        let c2 = curl_repro("https://x.test", "body_form_q", "plain");
        assert!(
            !c2.contains("$'"),
            "printable payload must not use ANSI-C: {c2}"
        );
        assert!(c2.contains("--data-urlencode 'q=plain'"));
    }

    fn verified_proof() -> ReverifyProof {
        ReverifyProof {
            delivery_desc: "POST /post form".into(),
            repro_curl: "curl -sk -X POST 'https://x/post' \\\n  --data-urlencode 'q=...'".into(),
            status: 200,
            latency_ms: 3.0,
            reflected: true,
            body_excerpt: "{\"ok\":true}".into(),
            execution: None,
        }
    }

    #[test]
    fn render_report_elevates_to_exploit_when_execution_proven() {
        let bp = bypass("xss", "<script>alert(1)</script>", &["identity"]);
        let mut proof = verified_proof();
        proof.execution = Some(crate::exec_proof::ExecutionProof {
            executed: true,
            sink: Some("alert".into()),
            message: Some("1".into()),
        });
        let (_f, content) = render_report(
            "https://t/x",
            "t",
            "cf:xss",
            &bp,
            Some(&proof),
            "cumulusfire",
        );
        assert!(
            content.contains("Confirmed xss exploit"),
            "title elevated: {content}"
        );
        assert!(
            content.contains("\"exploit_confirmed\":true"),
            "meta flags exploit"
        );
        assert!(
            content.contains("\"severity\":\"critical\""),
            "severity raised to critical"
        );
        assert!(
            content.contains("Execution proven"),
            "proof section states execution"
        );
        assert!(content.contains("alert(1)"), "names the fired sink + arg");
    }

    #[test]
    fn render_report_stays_bypass_when_no_execution_proof() {
        let bp = bypass("xss", "<script>alert(1)</script>", &["identity"]);
        let proof = verified_proof(); // execution: None
        let (_f, content) = render_report(
            "https://t/x",
            "t",
            "cf:xss",
            &bp,
            Some(&proof),
            "cumulusfire",
        );
        assert!(content.contains("WAF bypass:"), "stays a bypass headline");
        assert!(content.contains("\"exploit_confirmed\":false"));
        assert!(content.contains("\"severity\":\"high\""));
    }

    #[test]
    fn submit_dry_run_returns_zero_without_network() {
        let bp = bypass("sql", "' OR 1=1-- z", &["keyword_morph"]);
        let proof = verified_proof();
        let (fname, content) = render_report(
            "https://waf.cumulusfire.net",
            "waf.cumulusfire.net",
            "cf:?:?",
            &bp,
            Some(&proof),
            "cumulusfire",
        );
        let path = tmp(&fname);
        std::fs::write(&path, content).unwrap();
        // confirm:false → dry-run, never touches the network, exit 0.
        let rc = run_submit_inner(SubmitArgs {
            report: path.clone(),
            confirm: false,
            team: None,
        });
        let _ = std::fs::remove_file(&path);
        assert_eq!(rc, 0, "dry-run submit must succeed without submitting");
    }

    #[test]
    fn submit_confirm_refuses_unverified_report_before_network() {
        let bp = bypass("sql", "' OR 1=1-- z", &["keyword_morph"]);
        // None proof → report marked UNVERIFIED.
        let (fname, content) = render_report(
            "https://waf.cumulusfire.net",
            "waf.cumulusfire.net",
            "cf:?:?",
            &bp,
            None,
            "cumulusfire",
        );
        let path = tmp(&fname);
        std::fs::write(&path, content).unwrap();
        // confirm:true but UNVERIFIED → refuse (exit 2) before any H1 call.
        let rc = run_submit_inner(SubmitArgs {
            report: path.clone(),
            confirm: true,
            team: None,
        });
        let _ = std::fs::remove_file(&path);
        assert_eq!(rc, 2, "must refuse to submit an unverified report");
    }

    #[test]
    fn submit_missing_report_file_errors() {
        let rc = run_submit_inner(SubmitArgs {
            report: tmp("does-not-exist.md"),
            confirm: false,
            team: None,
        });
        assert_eq!(rc, 1);
    }

    #[test]
    fn request_to_curl_get_has_url_no_body() {
        let req = build_request_for_delivery(
            "http://h",
            &DeliveryShape::Query { param: "q".into() },
            "abc",
        );
        let c = request_to_curl(&req);
        assert!(
            c.starts_with("curl -sk -X GET 'http://h/get?q=abc'"),
            "got: {c}"
        );
        assert!(!c.contains("--data-binary"), "GET must have no body: {c}");
    }

    #[test]
    fn request_to_curl_form_body_has_data_binary() {
        let req = build_request_for_delivery(
            "http://h",
            &DeliveryShape::FormBody { param: "q".into() },
            "1 OR 1=1",
        );
        let c = request_to_curl(&req);
        assert!(c.contains("-X POST 'http://h/post'"), "got: {c}");
        assert!(
            c.contains("-H 'content-type: application/x-www-form-urlencoded'"),
            "got: {c}"
        );
        // urlencoded body, single-quoted (printable).
        assert!(c.contains("--data-binary 'q=1%20OR%201%3D1'"), "got: {c}");
    }

    #[test]
    fn request_to_curl_control_bytes_use_ansi_c() {
        // A multipart field carries the payload RAW between boundaries, so
        // a formfeed reaches the body as byte 0x0c — request_to_curl must
        // switch to byte-exact ANSI-C `$'…\x0c…'` quoting so the repro
        // reconstructs the exact bytes that carried the bypass.
        let req = build_request_for_delivery(
            "http://h",
            &DeliveryShape::MultipartField { name: "f".into() },
            "a\u{0c}b",
        );
        let c = request_to_curl(&req);
        assert!(
            c.contains("--data-binary $'"),
            "control byte must use ANSI-C: {c}"
        );
        assert!(
            c.contains("\\x0c"),
            "formfeed must render byte-exact as \\x0c: {c}"
        );
    }

    #[test]
    fn report_uses_proofs_repro_curl_verbatim() {
        // The report's reproduction block must be the EXACT curl captured
        // at re-verify time (faithful shape), not a re-derived guess.
        let bp = bypass("sql", "1 OR 1=1 --", &["hpp_split"]);
        let proof = ReverifyProof {
            delivery_desc: "recorded shape `hpp_split` — faithful re-fire".into(),
            repro_curl: "curl -sk -X GET 'http://t/get?q=v0&q=1%20OR%201%3D1%20--'".into(),
            status: 200,
            latency_ms: 5.0,
            reflected: true,
            body_excerpt: "ok".into(),
            execution: None,
        };
        let (_f, content) =
            render_report("http://t", "t", "cf:?:?", &bp, Some(&proof), "cumulusfire");
        assert!(
            content.contains("Delivery: recorded shape `hpp_split`"),
            "{content}"
        );
        assert!(
            content.contains("curl -sk -X GET 'http://t/get?q=v0&q=1%20OR%201%3D1%20--'"),
            "report must embed the faithful repro curl: {content}"
        );
    }

    #[test]
    fn truncate_for_log_caps_and_strips_control() {
        // Control byte early (index 1) so it's within the kept window and
        // must be stripped; long enough that the ellipsis is appended.
        let s = format!("a\u{0007}{}", "z".repeat(50));
        let t = truncate_for_log(&s, 10);
        assert_eq!(t.chars().count(), 11, "10 chars + ellipsis");
        assert!(t.ends_with('…'));
        assert!(
            !t.contains('\u{0007}'),
            "control byte must be stripped: {t:?}"
        );
        assert!(t.starts_with("a.z"), "BEL → '.', then content: {t:?}");
    }
}
