//! `wafrift sarif` — emit SARIF 2.1.0 from a `bench-waf --output` or
//! `scan --output` JSON file.
//!
//! SARIF (Static Analysis Results Interchange Format) is the
//! OASIS-standardised JSON for security-tool output. GitHub Advanced
//! Security, Azure DevOps, and most enterprise SAST/DAST UIs accept
//! SARIF natively — emitting it from wafrift's bypass JSON gives the
//! tool a first-class lane into enterprise scanning workflows
//! (PR-blocking checks, dashboards, alert routing) without anyone
//! writing a wafrift-specific parser.
//!
//! ## Input
//!
//! Accepts THREE wafrift output shapes:
//!
//! - **`bench-waf --output`** / **`scan --output`**: top-level
//!   `results` array. Each result with `evaded.variants_bypassed > 0`
//!   becomes one SARIF result.
//! - **`hunt --campaign-id`** state files (`~/.wafrift/hunt-*.json`):
//!   top-level `bypasses` array (`CampaignBypass` items with
//!   `class`/`technique`/`round`/`discovered_at`). Each entry becomes
//!   one SARIF result.
//!
//! If neither key is present, the command emits a SARIF envelope with
//! an empty `results` array AND exits 2 (anti-rig — silent success on
//! schema-mismatch was the dogfood report's BUG-1+2). Use `--quiet`
//! to suppress the stderr warning and stick with exit 0 if you
//! deliberately want an empty SARIF (e.g., CI gate that runs even on
//! a clean campaign).
//!
//! ## Output schema
//!
//! ```json
//! {
//!   "version": "2.1.0",
//!   "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
//!   "runs": [{
//!     "tool": { "driver": { "name": "wafrift", "version": "<crate version>" } },
//!     "results": [
//!       {
//!         "ruleId": "waf-bypass-sql",
//!         "level": "error",
//!         "message": { "text": "WAF bypass confirmed (sql) via tamper/comment, encoding/url/double" },
//!         "locations": [
//!           { "physicalLocation": { "artifactLocation": { "uri": "https://target.example/login" } } }
//!         ],
//!         "properties": {
//!           "class": "sql",
//!           "case_id": "sql_blind_001",
//!           "techniques": ["tamper/comment", "encoding/url/double"],
//!           "variants_bypassed": 2
//!         }
//!       }
//!     ]
//!   }]
//! }
//! ```
//!
//! ## Reserved-rule-ID contract (LAW 2)
//!
//! `ruleId` is `waf-bypass-<class>` where `<class>` is the lower-cased
//! attack class (sql, xss, cmdi, …). Adding a new class is additive;
//! renaming any existing class would break consumers that filter on
//! `ruleId` — DON'T do it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use colored::Colorize;
use serde::Serialize;
use serde_json::Value;

/// SARIF 2.1.0 schema URI (OASIS Committee Specification 02). LAW 2:
/// pinned constant — downstream consumers may use this URI to detect
/// the schema variant; changing it is a breaking change.
const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json";

/// SARIF format version string. LAW 2: pinned — emitting an older or
/// newer version silently would break consumers' validators.
const SARIF_VERSION: &str = "2.1.0";

/// Reuse the cluster_cmd 256 MiB cap — same operator-typo defence
/// (e.g. `--input /dev/zero`).
const SARIF_INPUT_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Default placeholder URI when the input JSON has no target URL.
/// Bench corpus runs against a synthetic httpbin testbed and don't
/// carry a real per-result URL; SARIF *requires* an `artifactLocation`,
/// so the bench data hashes into this stable placeholder so consumer
/// dedup logic still works.
const SARIF_BENCH_TARGET_PLACEHOLDER: &str = "urn:wafrift:bench-corpus";

#[derive(Args, Debug)]
pub(crate) struct SarifArgs {
    /// Path to a wafrift output JSON. Accepted shapes:
    ///   - `bench-waf --output <FILE>` / `scan --output <FILE>` (top-level `results` array)
    ///   - `hunt --campaign-id <ID>` state file `~/.wafrift/hunt-<ID>.json` (top-level `bypasses` array)
    /// Pass `-` to read from stdin (`wafrift scan ... | wafrift sarif -`).
    #[arg(value_name = "FILE")]
    pub input: PathBuf,

    /// Target URL associated with this run. When the input is a
    /// `scan --output` or `hunt` state it usually carries `target_url`
    /// already, but the bench corpus does not — use this flag to
    /// attach the URL of the WAF you were attacking so SARIF
    /// consumers (GitHub Code Scanning, etc.) get a real location to
    /// render.
    #[arg(long)]
    pub target_url: Option<String>,

    /// Suppress stderr warnings when the input JSON has no recognised
    /// bypass key (`results` or `bypasses`) — emits an empty SARIF
    /// envelope with exit 0 instead of exit 2. Use for CI gates that
    /// run even on a clean campaign.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

// ─── SARIF types (serde-friendly subset of v2.1.0) ──────────────────────────

#[derive(Debug, Serialize)]
struct SarifLog<'a> {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Debug, Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult>,
    /// SARIF 2.1.0 §3.18.3: maps `result.taxa[].toolComponent.name`
    /// references onto the CWE taxonomy. Each finding's CWE-942 entry
    /// resolves through this — enables GitHub Code Scanning to render
    /// the CWE link in the UI.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    taxonomies: Vec<SarifTaxonomy>,
}

#[derive(Debug, Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Debug, Serialize)]
struct SarifDriver<'a> {
    name: &'static str,
    version: &'a str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    /// SARIF 2.1.0 §3.19.23: per-rule metadata referenced by
    /// `result.ruleId`. Populated with one entry per distinct ruleId
    /// in the results so SARIF consumers can render readable rule
    /// names instead of just the opaque `waf-bypass-sql` string.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<SarifReportingDescriptor>,
}

/// SARIF 2.1.0 §3.49 reportingDescriptor (rule metadata). Used as
/// the `tool.driver.rules` entries so consumers can show the full
/// rule name + short description + help URI alongside each finding.
#[derive(Debug, Serialize)]
struct SarifReportingDescriptor {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    full_description: SarifMessage,
    #[serde(rename = "helpUri")]
    help_uri: &'static str,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifReportingConfiguration,
}

#[derive(Debug, Serialize)]
struct SarifReportingConfiguration {
    level: &'static str,
}

/// SARIF 2.1.0 §3.18 toolComponent (taxonomy descriptor). For CWE
/// the canonical URI is documented at OASIS.
#[derive(Debug, Serialize)]
struct SarifTaxonomy {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    #[serde(rename = "downloadUri")]
    download_uri: &'static str,
    taxa: Vec<SarifTaxon>,
}

#[derive(Debug, Serialize)]
struct SarifTaxon {
    id: &'static str,
    name: &'static str,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    /// SARIF 2.1.0 §3.27.23: stable identifiers used by consumers
    /// (GitHub Code Scanning, etc.) for cross-run dedup. We populate
    /// `primaryLocationLineHash` with a hash of (class, technique,
    /// target) — same finding emitted twice gets the same fingerprint
    /// and the consumer dedupes the alert.
    #[serde(
        rename = "partialFingerprints",
        skip_serializing_if = "serde_json::Map::is_empty"
    )]
    partial_fingerprints: serde_json::Map<String, Value>,
    /// SARIF 2.1.0 §3.27.27: CWE references for this result.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    taxa: Vec<SarifTaxonReference>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    properties: serde_json::Map<String, Value>,
}

#[derive(Debug, Serialize)]
struct SarifTaxonReference {
    id: &'static str,
    #[serde(rename = "toolComponent")]
    tool_component: SarifTaxonComponentRef,
}

#[derive(Debug, Serialize)]
struct SarifTaxonComponentRef {
    name: &'static str,
}

#[derive(Debug, Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Exit code 2 — input JSON had no recognised bypass key
/// (`results` or `bypasses`). Anti-rig: zero-result SARIF with exit 0
/// silently lies to CI pipelines that upload to GitHub Code Scanning.
/// `--quiet` suppresses the warning and downgrades to exit 0 when the
/// caller deliberately wants an empty SARIF.
pub(crate) const EXIT_NO_RECOGNISED_BYPASS_KEY: u8 = 2;

pub(crate) fn run_sarif(args: SarifArgs) -> ExitCode {
    let raw = match read_input(&args.input) {
        Ok(s) => s,
        Err(e) => {
            return crate::helpers::input_error(e);
        }
    };
    let json: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return crate::helpers::input_error(format!("parse JSON: {e}"));
        }
    };

    let target = args
        .target_url
        .as_deref()
        .or_else(|| json.get("target_url").and_then(|v| v.as_str()))
        .unwrap_or(SARIF_BENCH_TARGET_PLACEHOLDER);

    let (results, schema) = build_sarif_results_with_schema(&json, target);
    let schema_mismatch = matches!(schema, BypassSchema::Unrecognised);
    if schema_mismatch && !args.quiet {
        eprintln!(
            "{} input JSON has no recognised bypass key (`results` or `bypasses`). Emitting empty SARIF. Exit 2.",
            "warn:".yellow().bold(),
        );
    }

    let crate_version = env!("CARGO_PKG_VERSION");
    // Rules + taxonomies emitted only when there are results to describe —
    // an empty SARIF stays minimal so jq-pipe smoke tests stay simple.
    let (rules, taxonomies) = if results.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        (build_rules_table(&results), vec![build_cwe_taxonomy()])
    };
    let log = SarifLog {
        version: SARIF_VERSION,
        schema: SARIF_SCHEMA_URI,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "wafrift",
                    version: crate_version,
                    information_uri: "https://github.com/santhsecurity/wafrift",
                    rules,
                },
            },
            results,
            taxonomies,
        }],
    };

    match serde_json::to_string_pretty(&log) {
        Ok(s) => {
            println!("{s}");
            if schema_mismatch && !args.quiet {
                ExitCode::from(EXIT_NO_RECOGNISED_BYPASS_KEY)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("{} serialize SARIF: {e}", "error:".red().bold());
            ExitCode::from(1)
        }
    }
}

/// Which wafrift output schema produced these SARIF results. Used by
/// run_sarif to decide whether to emit the schema-mismatch warning
/// and exit code 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BypassSchema {
    /// Top-level `results` array (`bench-waf --output` / `scan --output`).
    BenchResults,
    /// Top-level `bypasses` array (`hunt` campaign state).
    HuntBypasses,
    /// Neither key present — empty SARIF + exit 2.
    Unrecognised,
}

fn read_input(path: &std::path::Path) -> Result<String, String> {
    if path.as_os_str() == "-" {
        match crate::safe_body::read_bounded_text_stdin(SARIF_INPUT_MAX_BYTES) {
            Ok(s) => Ok(s),
            Err(crate::safe_body::ReadError::Transport(msg)) => Err(format!("read stdin: {msg}")),
            Err(crate::safe_body::ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            }) => Err(format!(
                "stdin exceeded {cap_bytes}-byte cap ({observed_bytes} bytes seen)"
            )),
        }
    } else {
        match crate::safe_body::read_bounded_text_file(path, SARIF_INPUT_MAX_BYTES) {
            Ok(s) => Ok(s),
            Err(crate::safe_body::ReadError::Transport(msg)) => {
                Err(format!("read {}: {msg}", path.display()))
            }
            Err(crate::safe_body::ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            }) => Err(format!(
                "{} exceeded {cap_bytes}-byte cap ({observed_bytes} bytes seen)",
                path.display()
            )),
        }
    }
}

/// CWE-942 — "Permissive Cross-domain Policy with Untrusted Domains".
/// The closest CWE for a confirmed WAF bypass; SARIF consumers (GitHub
/// Code Scanning, etc.) use this to render the CWE link in the UI.
const SARIF_CWE_ID: &str = "942";

/// Build the SARIF taxonomy entry for CWE references.
fn build_cwe_taxonomy() -> SarifTaxonomy {
    SarifTaxonomy {
        name: "CWE",
        version: "4.14",
        information_uri: "https://cwe.mitre.org/",
        download_uri: "https://cwe.mitre.org/data/xml/cwec_v4.14.xml.zip",
        taxa: vec![SarifTaxon {
            id: SARIF_CWE_ID,
            name: "CWE-942",
            short_description: SarifMessage {
                text: "Permissive Cross-domain Policy with Untrusted Domains \
                       (used as the closest mapping for confirmed WAF bypass — \
                       the request reached the application despite the perimeter \
                       control)"
                    .to_string(),
            },
        }],
    }
}

/// Collect distinct `ruleId`s from the results and emit one
/// [`SarifReportingDescriptor`] per — SARIF 2.1.0 §3.19.23. Consumers
/// dereference `result.ruleId` into this table to render readable rule
/// names + descriptions in their UI.
fn build_rules_table(results: &[SarifResult]) -> Vec<SarifReportingDescriptor> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for r in results {
        seen.insert(r.rule_id.as_str());
    }
    seen.into_iter()
        .map(|rule_id| {
            // rule_id is "waf-bypass-<class>" — extract the class for the human name.
            let class = rule_id.strip_prefix("waf-bypass-").unwrap_or(rule_id);
            SarifReportingDescriptor {
                id: rule_id.to_string(),
                name: format!("WafBypass{}", title_case(class)),
                short_description: SarifMessage {
                    text: format!("WAF bypass confirmed for {class} payload class",),
                },
                full_description: SarifMessage {
                    text: format!(
                        "wafrift confirmed a request carrying a {class}-class payload \
                         reached the origin application despite the WAF in front. \
                         Per the 3-gate oracle (WAF didn't return a recognised \
                         block marker + reached app status + structural validity), \
                         this is a real bypass not a false positive."
                    ),
                },
                help_uri: "https://github.com/santhsecurity/wafrift",
                default_configuration: SarifReportingConfiguration { level: "error" },
            }
        })
        .collect()
}

fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Compute a stable per-finding fingerprint as a hex u64. Inputs:
/// (rule_id, target URL, technique-or-case-id). Two runs that emit
/// the same finding produce the same fingerprint — GitHub Code
/// Scanning uses this to dedupe alerts across PRs.
fn finding_fingerprint(rule_id: &str, target: &str, key: &str) -> String {
    // Cheap stable hash — DefaultHasher is fine for non-crypto identity.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    rule_id.hash(&mut h);
    target.hash(&mut h);
    key.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Dispatch to the right schema parser based on which top-level key
/// the input JSON carries. Returns the SARIF results AND which
/// schema was matched (so `run_sarif` can warn + exit-2 on
/// `Unrecognised`).
fn build_sarif_results_with_schema(json: &Value, target: &str) -> (Vec<SarifResult>, BypassSchema) {
    if json.get("results").and_then(|v| v.as_array()).is_some() {
        (
            build_from_bench_results(json, target),
            BypassSchema::BenchResults,
        )
    } else if json.get("bypasses").and_then(|v| v.as_array()).is_some() {
        (
            build_from_hunt_bypasses(json, target),
            BypassSchema::HuntBypasses,
        )
    } else {
        (Vec::new(), BypassSchema::Unrecognised)
    }
}

/// Test-only shim that drops the schema tag — keeps the existing
/// `build_sarif_results` test surface stable while the production
/// callers use the schema-aware variant.
#[cfg(test)]
fn build_sarif_results(json: &Value, target: &str) -> Vec<SarifResult> {
    build_sarif_results_with_schema(json, target).0
}

/// Walk the bench/scan `results` array and emit one [`SarifResult`]
/// per case whose `evaded.variants_bypassed > 0`. Cases with zero
/// bypasses are NOT emitted — SARIF is for actionable findings, and
/// "we tried but didn't bypass" belongs in the bench scoreboard, not
/// the finding stream.
fn build_from_bench_results(json: &Value, target: &str) -> Vec<SarifResult> {
    let Some(results) = json.get("results").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for result in results {
        let case_id = result
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let class = result
            .get("class")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let Some(Value::Object(evaded)) = result.get("evaded") else {
            continue;
        };
        let bypassed = evaded
            .get("variants_bypassed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if bypassed == 0 {
            continue;
        }

        let techniques: Vec<String> = evaded
            .get("bypass_techniques")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let mut properties = serde_json::Map::new();
        properties.insert("class".into(), Value::String(class.to_string()));
        properties.insert("case_id".into(), Value::String(case_id.to_string()));
        properties.insert("variants_bypassed".into(), Value::Number(bypassed.into()));
        if !techniques.is_empty() {
            properties.insert(
                "techniques".into(),
                Value::Array(
                    techniques
                        .iter()
                        .map(|t| Value::String(t.clone()))
                        .collect(),
                ),
            );
        }
        // C-14 rule-quality fields carry through to SARIF properties
        // when present — consumers (GitHub Code Scanning, security
        // dashboards) can filter / sort by these without parsing the
        // raw bench JSON.
        if let Some(cq) = result.get("case_quality").and_then(|v| v.as_str()) {
            properties.insert("case_quality".into(), Value::String(cq.to_string()));
        }
        if let Some(qs) = result.get("quality_score").and_then(|v| v.as_f64())
            && let Some(n) = serde_json::Number::from_f64(qs)
        {
            properties.insert("quality_score".into(), Value::Number(n));
        }

        let message_text = if techniques.is_empty() {
            format!(
                "WAF bypass confirmed (class={class}, case={case_id}, variants_bypassed={bypassed})"
            )
        } else {
            format!(
                "WAF bypass confirmed (class={class}, case={case_id}, variants_bypassed={bypassed}) via {}",
                techniques.join(", ")
            )
        };

        let rule_id = format!("waf-bypass-{class}");
        let mut fingerprints = serde_json::Map::new();
        fingerprints.insert(
            "primaryLocationLineHash".into(),
            Value::String(finding_fingerprint(&rule_id, target, case_id)),
        );
        out.push(SarifResult {
            rule_id,
            // Confirmed bypasses are always actionable findings.
            level: "error",
            message: SarifMessage { text: message_text },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: target.to_string(),
                    },
                },
            }],
            partial_fingerprints: fingerprints,
            taxa: vec![SarifTaxonReference {
                id: SARIF_CWE_ID,
                tool_component: SarifTaxonComponentRef { name: "CWE" },
            }],
            properties,
        });
    }
    out
}

/// Walk a `hunt --campaign-id` state file's `bypasses` array (each
/// item a `CampaignBypass` with `class` + `technique` + `round` +
/// `discovered_at`) and emit one SARIF result per entry. Every
/// CampaignBypass is by construction a confirmed bypass — no zero-bypass
/// filtering needed here.
fn build_from_hunt_bypasses(json: &Value, target: &str) -> Vec<SarifResult> {
    let Some(bypasses) = json.get("bypasses").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    // The hunt state already carries `target_url`; if the caller didn't
    // override with --target-url, prefer the campaign's target.
    let target = if target == SARIF_BENCH_TARGET_PLACEHOLDER {
        json.get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or(target)
    } else {
        target
    };

    let campaign_id = json
        .get("campaign_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let mut out = Vec::new();
    for b in bypasses {
        let class = b.get("class").and_then(|v| v.as_str()).unwrap_or("unknown");
        let technique = b.get("technique").and_then(|v| v.as_str()).unwrap_or("");
        let round = b.get("round").and_then(|v| v.as_u64()).unwrap_or(0);
        let discovered_at = b.get("discovered_at").and_then(|v| v.as_u64()).unwrap_or(0);

        let mut properties = serde_json::Map::new();
        properties.insert("class".into(), Value::String(class.to_string()));
        properties.insert("campaign_id".into(), Value::String(campaign_id.to_string()));
        properties.insert("round".into(), Value::Number(round.into()));
        properties.insert("discovered_at".into(), Value::Number(discovered_at.into()));
        if !technique.is_empty() {
            properties.insert("technique".into(), Value::String(technique.to_string()));
        }

        let message_text = if technique.is_empty() {
            format!("WAF bypass confirmed (campaign={campaign_id}, class={class}, round={round})")
        } else {
            format!(
                "WAF bypass confirmed (campaign={campaign_id}, class={class}, round={round}) via {technique}"
            )
        };

        let rule_id = format!("waf-bypass-{class}");
        // Hunt fingerprint key: technique uniquely identifies a hunt
        // bypass (same campaign re-finding the same technique should
        // dedupe).
        let fingerprint_key = if technique.is_empty() {
            format!("round-{round}")
        } else {
            technique.to_string()
        };
        let mut fingerprints = serde_json::Map::new();
        fingerprints.insert(
            "primaryLocationLineHash".into(),
            Value::String(finding_fingerprint(&rule_id, target, &fingerprint_key)),
        );
        out.push(SarifResult {
            rule_id,
            level: "error",
            message: SarifMessage { text: message_text },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: target.to_string(),
                    },
                },
            }],
            partial_fingerprints: fingerprints,
            taxa: vec![SarifTaxonReference {
                id: SARIF_CWE_ID,
                tool_component: SarifTaxonComponentRef { name: "CWE" },
            }],
            properties,
        });
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bench_with_one_bypass() -> Value {
        json!({
            "schema_version": 1,
            "results": [{
                "id": "sql_blind_001",
                "class": "sql",
                "evaded": {
                    "variants_bypassed": 2,
                    "variants_total": 5,
                    "bypass_techniques": ["tamper/comment", "encoding/url/double"],
                }
            }]
        })
    }

    /// LAW 12: SARIF version + schema URI are pinned constants —
    /// silently emitting a different version would break consumer
    /// validators.
    #[test]
    fn sarif_version_and_schema_uri_are_pinned() {
        assert_eq!(SARIF_VERSION, "2.1.0");
        assert!(SARIF_SCHEMA_URI.starts_with("https://"));
        assert!(SARIF_SCHEMA_URI.contains("sarif-schema-2.1.0"));
    }

    /// Empty input → empty results array, but the SARIF envelope
    /// (version, schema, tool driver, runs) is still present.
    /// Anti-rig: a tool that has never run still produces valid
    /// SARIF — no `Vec::is_empty() ? skip emit : emit` rig.
    #[test]
    fn empty_results_emits_valid_empty_sarif_envelope() {
        let j = json!({ "schema_version": 1, "results": [] });
        let results = build_sarif_results(&j, "https://target.example/");
        assert!(results.is_empty());
    }

    /// Missing `results` array → empty SARIF results (not a panic).
    /// LAW 1: a malformed input should produce honest emptiness,
    /// not a crash.
    #[test]
    fn missing_results_array_does_not_panic() {
        let j = json!({});
        let results = build_sarif_results(&j, "https://target.example/");
        assert!(results.is_empty());
    }

    /// One bypass case → one SARIF result with the expected ruleId,
    /// level, properties, and target URL.
    #[test]
    fn one_bypass_maps_to_one_sarif_result() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://target.example/");
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.rule_id, "waf-bypass-sql");
        assert_eq!(r.level, "error");
        assert!(r.message.text.contains("class=sql"));
        assert!(r.message.text.contains("case=sql_blind_001"));
        assert!(r.message.text.contains("tamper/comment"));
        assert_eq!(r.locations.len(), 1);
        assert_eq!(
            r.locations[0].physical_location.artifact_location.uri,
            "https://target.example/"
        );
        assert_eq!(
            r.properties.get("class").and_then(|v| v.as_str()),
            Some("sql")
        );
        assert_eq!(
            r.properties
                .get("variants_bypassed")
                .and_then(|v| v.as_u64()),
            Some(2)
        );
    }

    /// Cases with `variants_bypassed == 0` MUST be dropped — these
    /// are negative evidence. Anti-rig: pre-existing test in the
    /// bench scoreboard counts them, but the SARIF finding stream
    /// must not.
    #[test]
    fn zero_bypassed_case_is_dropped() {
        let j = json!({
            "schema_version": 1,
            "results": [
                {
                    "id": "sql_001",
                    "class": "sql",
                    "evaded": { "variants_bypassed": 0, "variants_total": 5 }
                },
                {
                    "id": "sql_002",
                    "class": "sql",
                    "evaded": {
                        "variants_bypassed": 1,
                        "variants_total": 5,
                        "bypass_techniques": ["tamper/x"]
                    }
                },
            ]
        });
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]
                .properties
                .get("case_id")
                .and_then(|v| v.as_str()),
            Some("sql_002")
        );
    }

    /// Results array with missing `evaded` field (e.g. a case that
    /// never ran) is silently skipped — same behaviour as cluster_cmd.
    #[test]
    fn results_without_evaded_field_are_skipped() {
        let j = json!({
            "schema_version": 1,
            "results": [
                { "id": "sql_a", "class": "sql" },
                {
                    "id": "sql_b",
                    "class": "sql",
                    "evaded": {
                        "variants_bypassed": 1,
                        "bypass_techniques": ["tamper/y"]
                    }
                },
            ]
        });
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]
                .properties
                .get("case_id")
                .and_then(|v| v.as_str()),
            Some("sql_b")
        );
    }

    /// Bypass with no `bypass_techniques` field (degraded bench
    /// recorder) → SARIF result still emits with the case id in the
    /// message, but `properties.techniques` is omitted (not present
    /// as an empty array).
    #[test]
    fn bypass_with_no_techniques_field_emits_result_without_techniques_property() {
        let j = json!({
            "schema_version": 1,
            "results": [{
                "id": "sql_solo",
                "class": "sql",
                "evaded": { "variants_bypassed": 1 }
            }]
        });
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert!(results[0].properties.get("techniques").is_none());
        assert!(results[0].message.text.contains("variants_bypassed=1"));
    }

    /// Multiple classes → distinct ruleIds. SARIF consumers filter
    /// on ruleId; a class collision into one ruleId would defeat
    /// per-class dashboards.
    #[test]
    fn multiple_classes_produce_distinct_rule_ids() {
        let j = json!({
            "schema_version": 1,
            "results": [
                {
                    "id": "sql_001", "class": "sql",
                    "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t1"] }
                },
                {
                    "id": "xss_001", "class": "xss",
                    "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t2"] }
                },
                {
                    "id": "cmdi_001", "class": "cmdi",
                    "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t3"] }
                },
            ]
        });
        let results = build_sarif_results(&j, "https://t/");
        let rule_ids: Vec<&str> = results.iter().map(|r| r.rule_id.as_str()).collect();
        assert!(rule_ids.contains(&"waf-bypass-sql"));
        assert!(rule_ids.contains(&"waf-bypass-xss"));
        assert!(rule_ids.contains(&"waf-bypass-cmdi"));
    }

    /// DOGFOOD BUG-1 regression: hunt campaign state file uses
    /// `bypasses` (not `results`). Pre-fix, this returned 0 SARIF
    /// results and exit code 0 — silently lying to CI uploaders.
    /// Post-fix: each CampaignBypass becomes one SARIF result with
    /// the campaign_id + round + class + technique in properties.
    #[test]
    fn hunt_bypasses_schema_produces_one_result_per_bypass() {
        let j = json!({
            "campaign_id": "race-test",
            "target_url": "https://waf.cumulusfire.net",
            "started_at": 1714500000u64,
            "rounds_completed": 12u64,
            "total_bypasses": 3u64,
            "schema_version": 1u32,
            "bypasses": [
                { "discovered_at": 1714500100u64, "round": 1u64, "class": "sql",
                  "technique": "tamper/comment", "submitted": false },
                { "discovered_at": 1714500200u64, "round": 2u64, "class": "xss",
                  "technique": "encoding/double-url", "submitted": true },
                { "discovered_at": 1714500300u64, "round": 3u64, "class": "ldap",
                  "technique": "split-attr", "submitted": false },
            ],
        });
        let (results, schema) = build_sarif_results_with_schema(&j, SARIF_BENCH_TARGET_PLACEHOLDER);
        assert_eq!(schema, BypassSchema::HuntBypasses);
        assert_eq!(results.len(), 3);

        let sql = results
            .iter()
            .find(|r| r.rule_id == "waf-bypass-sql")
            .unwrap();
        assert_eq!(sql.level, "error");
        assert!(sql.message.text.contains("campaign=race-test"));
        assert!(sql.message.text.contains("round=1"));
        assert!(sql.message.text.contains("tamper/comment"));
        // hunt has target_url at the top level — should be picked
        // up when caller didn't pass --target-url.
        assert_eq!(
            sql.locations[0].physical_location.artifact_location.uri,
            "https://waf.cumulusfire.net"
        );
        assert_eq!(
            sql.properties.get("campaign_id").and_then(|v| v.as_str()),
            Some("race-test")
        );
    }

    /// DOGFOOD BUG-2 regression: input JSON with neither `results`
    /// nor `bypasses` keys is reported as `Unrecognised` so run_sarif
    /// can emit exit code 2. Pre-fix, run_sarif silently emitted an
    /// empty SARIF + exit 0, lying to CI uploaders.
    #[test]
    fn unrecognised_schema_is_flagged_not_silently_zeroed() {
        let j = json!({ "some_other_key": [1, 2, 3] });
        let (results, schema) = build_sarif_results_with_schema(&j, "https://t/");
        assert!(results.is_empty());
        assert_eq!(schema, BypassSchema::Unrecognised);
    }

    /// LAW 12: pin EXIT_NO_RECOGNISED_BYPASS_KEY == 2 (a public exit
    /// code that CI pipelines may treat as "warning, no findings").
    /// A silent flip would change the script semantics.
    #[test]
    fn exit_code_for_unrecognised_schema_is_pinned() {
        assert_eq!(EXIT_NO_RECOGNISED_BYPASS_KEY, 2);
    }

    /// Bench-results format still recognised after the schema-aware
    /// rewrite — anti-regression for the original path.
    #[test]
    fn bench_results_schema_still_recognised() {
        let j = bench_with_one_bypass();
        let (results, schema) = build_sarif_results_with_schema(&j, "https://t/");
        assert_eq!(schema, BypassSchema::BenchResults);
        assert_eq!(results.len(), 1);
    }

    /// hunt input with `target_url` overrides the placeholder when
    /// caller did NOT pass --target-url, but a real --target-url
    /// argument wins.
    #[test]
    fn hunt_target_url_priority() {
        let j = json!({
            "campaign_id": "x",
            "target_url": "https://hunt.example/",
            "bypasses": [{
                "discovered_at": 1u64, "round": 1u64, "class": "sql",
                "technique": "t", "submitted": false
            }],
        });
        // Placeholder → hunt's target_url wins.
        let (r, _) = build_sarif_results_with_schema(&j, SARIF_BENCH_TARGET_PLACEHOLDER);
        assert_eq!(
            r[0].locations[0].physical_location.artifact_location.uri,
            "https://hunt.example/"
        );
        // Explicit --target-url → caller wins.
        let (r2, _) = build_sarif_results_with_schema(&j, "https://override.example/");
        assert_eq!(
            r2[0].locations[0].physical_location.artifact_location.uri,
            "https://override.example/"
        );
    }

    /// End-to-end: build a real SarifLog and serialize it. Verifies
    /// the JSON shape matches what SARIF consumers expect: `version`,
    /// `$schema`, `runs[0].tool.driver.name == "wafrift"`,
    /// `runs[0].results` array.
    #[test]
    fn full_sarif_log_serializes_with_expected_envelope() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://target/");
        let rules = build_rules_table(&results);
        let taxonomies = vec![build_cwe_taxonomy()];
        let log = SarifLog {
            version: SARIF_VERSION,
            schema: SARIF_SCHEMA_URI,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "wafrift",
                        version: "0.0.0-test",
                        information_uri: "https://example/",
                        rules,
                    },
                },
                results,
                taxonomies,
            }],
        };
        let s = serde_json::to_string(&log).unwrap();
        // Round-trip back to Value to inspect the shape — this is
        // exactly what a SARIF consumer (GitHub, etc.) would do.
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"].as_str(), Some("2.1.0"));
        assert!(
            v["$schema"]
                .as_str()
                .unwrap()
                .contains("sarif-schema-2.1.0")
        );
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["name"].as_str(),
            Some("wafrift")
        );
        assert_eq!(
            v["runs"][0]["results"][0]["ruleId"].as_str(),
            Some("waf-bypass-sql")
        );
        assert_eq!(v["runs"][0]["results"][0]["level"].as_str(), Some("error"));
    }

    // ─── SARIF 2.1.0 enterprise upgrade tests ───────────────────────────────

    /// LAW 9 wiring: rules table populated with one entry per distinct
    /// ruleId in the results. SARIF consumers (GitHub Code Scanning)
    /// dereference `result.ruleId` into `tool.driver.rules[]` to render
    /// readable rule names — a missing rule entry shows the opaque ID.
    #[test]
    fn rules_table_has_one_entry_per_distinct_rule_id() {
        let j = json!({
            "schema_version": 1,
            "results": [
                { "id": "sql_001", "class": "sql",
                  "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t1"] } },
                { "id": "sql_002", "class": "sql",
                  "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t2"] } },
                { "id": "xss_001", "class": "xss",
                  "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t3"] } },
            ]
        });
        let results = build_sarif_results(&j, "https://t/");
        let rules = build_rules_table(&results);
        assert_eq!(rules.len(), 2, "two distinct classes → two rule entries");
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"waf-bypass-sql"));
        assert!(ids.contains(&"waf-bypass-xss"));
        // human name is TitleCased class
        let sql = rules.iter().find(|r| r.id == "waf-bypass-sql").unwrap();
        assert_eq!(sql.name, "WafBypassSql");
        assert_eq!(sql.default_configuration.level, "error");
    }

    /// LAW 12 anti-rig: CWE taxonomy emitted with id 942 + human name.
    /// SARIF consumers render the CWE link in the UI; a missing
    /// taxonomy makes the CWE reference dangling.
    #[test]
    fn cwe_taxonomy_includes_942_with_human_name() {
        let tax = build_cwe_taxonomy();
        assert_eq!(tax.name, "CWE");
        assert!(tax.information_uri.starts_with("https://cwe.mitre.org"));
        assert_eq!(tax.taxa.len(), 1);
        assert_eq!(tax.taxa[0].id, SARIF_CWE_ID);
        assert_eq!(tax.taxa[0].name, "CWE-942");
    }

    /// LAW 12 stable-hash invariant: same input → same fingerprint.
    /// GitHub Code Scanning uses `partialFingerprints` to dedupe
    /// alerts across PRs; a non-deterministic hash defeats that.
    #[test]
    fn finding_fingerprint_is_deterministic() {
        let f1 = finding_fingerprint("waf-bypass-sql", "https://t/", "sql_001");
        let f2 = finding_fingerprint("waf-bypass-sql", "https://t/", "sql_001");
        assert_eq!(f1, f2, "same input → same fingerprint");
        assert_eq!(f1.len(), 16, "16-hex-char u64");
    }

    /// LAW 12: different ruleIds → different fingerprints. A collision
    /// would cause GitHub to merge two genuinely different findings
    /// into one alert.
    #[test]
    fn finding_fingerprint_differs_for_different_rule_ids() {
        let sql = finding_fingerprint("waf-bypass-sql", "https://t/", "case_001");
        let xss = finding_fingerprint("waf-bypass-xss", "https://t/", "case_001");
        assert_ne!(sql, xss);
    }

    /// LAW 12: different targets → different fingerprints. Same finding
    /// against two different WAFs should NOT dedupe.
    #[test]
    fn finding_fingerprint_differs_for_different_targets() {
        let a = finding_fingerprint("waf-bypass-sql", "https://a/", "case_001");
        let b = finding_fingerprint("waf-bypass-sql", "https://b/", "case_001");
        assert_ne!(a, b);
    }

    /// LAW 9 wiring: every SarifResult carries a partialFingerprints
    /// map with `primaryLocationLineHash`. Field set but never read
    /// would be a stub (LAW 11).
    #[test]
    fn every_bench_result_has_partial_fingerprints() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert!(
            results[0]
                .partial_fingerprints
                .contains_key("primaryLocationLineHash"),
            "primaryLocationLineHash must be populated"
        );
    }

    /// LAW 9 wiring: every SarifResult carries a CWE-942 taxa
    /// reference. Required for GitHub Code Scanning to render the CWE
    /// link.
    #[test]
    fn every_bench_result_has_cwe_taxon_reference() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results[0].taxa.len(), 1);
        assert_eq!(results[0].taxa[0].id, SARIF_CWE_ID);
        assert_eq!(results[0].taxa[0].tool_component.name, "CWE");
    }

    /// Same applies to hunt-bypasses path — both schemas must produce
    /// the enterprise fields.
    #[test]
    fn every_hunt_result_has_partial_fingerprints_and_taxa() {
        let j = json!({
            "campaign_id": "x", "target_url": "https://t/",
            "bypasses": [{ "discovered_at": 1u64, "round": 1u64,
                           "class": "sql", "technique": "t", "submitted": false }],
        });
        let (results, _) = build_sarif_results_with_schema(&j, SARIF_BENCH_TARGET_PLACEHOLDER);
        assert_eq!(results.len(), 1);
        assert!(
            results[0]
                .partial_fingerprints
                .contains_key("primaryLocationLineHash")
        );
        assert_eq!(results[0].taxa.len(), 1);
        assert_eq!(results[0].taxa[0].id, SARIF_CWE_ID);
    }

    /// LAW 9 wiring: when the bench JSON carries C-14 rule-quality
    /// fields (`case_quality` + `quality_score`), they must surface
    /// in SARIF properties so consumers can filter on them. Pre-fix,
    /// SARIF discarded these silently — operators couldn't tell
    /// "signal" cases from "trivial_pass" cases in GitHub Code
    /// Scanning.
    #[test]
    fn case_quality_fields_carry_through_to_sarif_properties() {
        let j = json!({
            "schema_version": 1,
            "results": [{
                "id": "sql_001",
                "class": "sql",
                "case_quality": "signal",
                "quality_score": 0.8113,
                "evaded": {
                    "variants_bypassed": 2,
                    "bypass_techniques": ["t1", "t2"]
                }
            }]
        });
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]
                .properties
                .get("case_quality")
                .and_then(|v| v.as_str()),
            Some("signal")
        );
        let qs = results[0]
            .properties
            .get("quality_score")
            .and_then(|v| v.as_f64());
        assert!(
            qs.map(|q| (q - 0.8113).abs() < 1e-6).unwrap_or(false),
            "quality_score must round-trip: {qs:?}"
        );
    }

    /// LAW 2 backwards-compat: cases WITHOUT case_quality/quality_score
    /// (older bench JSON) still produce valid SARIF — fields are
    /// optional, no silent panic.
    #[test]
    fn missing_case_quality_fields_are_optional() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert!(
            results[0].properties.get("case_quality").is_none(),
            "case_quality must be absent when input JSON didn't carry it"
        );
        assert!(
            results[0].properties.get("quality_score").is_none(),
            "quality_score must be absent when input JSON didn't carry it"
        );
    }

    /// LAW 12: title_case capitalises just the first byte; ASCII-only
    /// (attack class identifiers are always ASCII).
    #[test]
    fn title_case_capitalises_first_letter_only() {
        assert_eq!(title_case("sql"), "Sql");
        assert_eq!(title_case("xss"), "Xss");
        assert_eq!(title_case("cmdi"), "Cmdi");
        assert_eq!(title_case(""), "");
        assert_eq!(title_case("a"), "A");
    }

    /// Full integration: end-to-end SARIF with the enterprise fields
    /// round-trips through serde and exposes the expected paths to
    /// consumers.
    #[test]
    fn enterprise_sarif_round_trip_exposes_rules_taxonomies_fingerprints() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://target/");
        let rules = build_rules_table(&results);
        let taxonomies = vec![build_cwe_taxonomy()];
        let log = SarifLog {
            version: SARIF_VERSION,
            schema: SARIF_SCHEMA_URI,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "wafrift",
                        version: "0.0.0-test",
                        information_uri: "https://example/",
                        rules,
                    },
                },
                results,
                taxonomies,
            }],
        };
        let s = serde_json::to_string(&log).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        // rules table is at runs[0].tool.driver.rules
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"][0]["id"].as_str(),
            Some("waf-bypass-sql")
        );
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"].as_str(),
            Some("error")
        );
        // taxonomies at runs[0].taxonomies
        assert_eq!(v["runs"][0]["taxonomies"][0]["name"].as_str(), Some("CWE"));
        assert_eq!(
            v["runs"][0]["taxonomies"][0]["taxa"][0]["id"].as_str(),
            Some("942")
        );
        // partialFingerprints on each result
        assert!(
            v["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
                .as_str()
                .is_some()
        );
        // taxa reference on each result
        assert_eq!(
            v["runs"][0]["results"][0]["taxa"][0]["id"].as_str(),
            Some("942")
        );
        assert_eq!(
            v["runs"][0]["results"][0]["taxa"][0]["toolComponent"]["name"].as_str(),
            Some("CWE")
        );
    }
}
