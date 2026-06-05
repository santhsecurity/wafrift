//! Shared HTTP transport primitives for the `wafrift smuggle-*`
//! fire subcommands.
//!
//! Centralises the "build request → fire → bound response → classify"
//! pipeline so `smuggle-fire`, `smuggle-cross-product --fire-target`,
//! and `smuggle-chain --fire-target` all share one execution path.
//!
//! ## Bypass-signal contract (stable across all fire subcommands)
//!
//! Every fire reports against a baseline:
//!
//! - `canary-reflected` : a probe canary token appeared verbatim in the
//!   probe response headers or body — STRONGEST signal. The smuggled marker
//!   reached a surface that echoed it back (Location, Set-Cookie, a debug
//!   echo header, or the body), confirming the request was processed past
//!   the WAF. Takes precedence over the divergence signals below. Only
//!   possible when `--canary-header` placed the token on the wire.
//! - `none`            : probe response matches baseline status + body length
//! - `status-diverged` : probe status differs from baseline status
//! - `body-diverged`   : probe body length differs >threshold fraction
//! - `both-diverged`   : both status AND body length diverged
//! - `error`           : probe HTTP fire failed (timeout, refused, etc.)
//!
//! Canary reflection is false-positive-free: tokens are 16-char random
//! base62 ([`wafrift_types::canary::Canary`]) so a baseline that never
//! carried the token cannot contain it by chance.
//!
//! ## Resource safety
//!
//! Response body reads are HARD-CAPPED at [`MAX_RESPONSE_BYTES`].
//! A WAF-protected origin returning a multi-GB decompression bomb
//! cannot OOM the operator's host — the stream is aborted once the
//! cap is exceeded and the error surfaces in the per-probe report.

use std::io::Write;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use reqwest::redirect::Policy;

use wafrift_types::probe::ComposedArtifact;

/// Hard cap on response body bytes read per probe. Set to 4 MiB —
/// well above any realistic WAF response page (Cloudflare's
/// challenge page is ~32 KiB; ModSecurity blocks ~200 B). Anything
/// beyond this size is almost certainly a decompression bomb or a
/// log dump leak; cap-and-error is safer than streaming to oblivion.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Build a default reqwest client tuned for smuggle-fire-class
/// probing: no auto-redirect (we want to OBSERVE redirects, not
/// follow them), the operator-supplied timeout.
pub fn build_client(timeout_secs: u64) -> Result<reqwest::Client, String> {
    build_client_with_resolve(timeout_secs, None)
}

/// Like [`build_client`] but, when `resolve` is `Some((host, addr))`,
/// pins DNS for `host` to `addr` at the connector (reqwest `.resolve`).
/// Every request whose URL host is `host` then connects to `addr` while
/// the request still carries the original `Host` header and TLS SNI.
///
/// This is the WAF go-around primitive (`--origin-ip`): aim the fire at
/// a discovered origin IP and the edge proxy / WAF is bypassed at the
/// connection layer, yet the backend sees the genuine `Host` (and any
/// `--family auth` edge-trust headers), so an origin that *trusts the
/// edge* is probed directly. `None` reproduces the plain
/// [`build_client`] behaviour exactly, so the existing fire callers are
/// unaffected (LAW 2).
pub fn build_client_with_resolve(
    timeout_secs: u64,
    resolve: Option<(&str, SocketAddr)>,
) -> Result<reqwest::Client, String> {
    let scan_identity = crate::config::shared_scan_browser_headers(None)
        .map_err(|e| format!("failed to resolve shared browser headers: {e}"))?;
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        // WIRING (§9) / record-vs-reverify coherence: scan, raw_runner, and
        // session_init resolve their wire identity through
        // `config::shared_scan_browser_headers`. Smuggle-fire uses the same
        // header set so re-verification is not UA-only while the recorded scan
        // carried browser Accept / Accept-Language / Sec-Fetch metadata.
        .default_headers(scan_identity.headers)
        .redirect(Policy::none());
    if let Some((host, addr)) = resolve {
        builder = builder.resolve(host, addr);
    }
    builder
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))
}

/// Read a response body up to [`MAX_RESPONSE_BYTES`]. Returns
/// `Err` if the body exceeds the cap. This is the bounded-read
/// primitive every fire subcommand uses — a single function so
/// raising or lowering the cap touches one place.
pub async fn bounded_body_bytes(resp: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(format!(
                "response exceeded {MAX_RESPONSE_BYTES} byte cap — aborting (possible decompression bomb)"
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Outcome of firing a single request: the response status, the
/// response body length, and any probe canary tokens that appeared
/// verbatim in the response body (in-band reflection).
///
/// Bundled into a struct rather than a tuple so adding a future
/// observation (response headers, timing breakdown, …) doesn't ripple
/// through every caller's destructuring — LAW 4.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FireOutcome {
    /// HTTP status code of the response.
    pub status: u16,
    /// Length in bytes of the (bounded) response body.
    pub body_len: usize,
    /// Subset of the supplied canary tokens that appeared as a
    /// contiguous byte substring of the response body. Empty when no
    /// reflection occurred (or no canaries were on the wire).
    pub reflected_canaries: Vec<String>,
}

/// Scan `body` for each token in `needles`, returning the subset that
/// appear as a contiguous byte substring. This is the in-band
/// canary-reflection oracle: a 16-char random token echoed back by
/// the origin confirms the smuggled marker was processed past the WAF.
///
/// Empty needles are ignored (an empty string is a substring of
/// everything — counting it would be a guaranteed false positive).
#[must_use]
pub fn reflected_tokens(body: &[u8], needles: &[String]) -> Vec<String> {
    needles
        .iter()
        .filter(|n| !n.is_empty() && contains_subslice(body, n.as_bytes()))
        .cloned()
        .collect()
}

/// True when `needle` occurs as a contiguous run of bytes inside
/// `haystack`. Linear-scan substring match — adequate for the
/// network-bound fire path (body is capped at [`MAX_RESPONSE_BYTES`]
/// and needles are 16 bytes).
#[must_use]
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Fire ONE baseline request — `method` against `target` carrying
/// the supplied headers and (optional) body. Returns a
/// [`FireOutcome`] whose `reflected_canaries` is always empty (the
/// baseline carries no smuggle canaries). Body reads are bounded via
/// [`bounded_body_bytes`].
#[tracing::instrument(skip(client, body, headers), fields(target = %target, method = %method))]
pub async fn fire_baseline(
    client: &reqwest::Client,
    target: &str,
    method: &str,
    body: &[u8],
    headers: &[(String, String)],
) -> Result<FireOutcome, String> {
    let m = method
        .parse::<reqwest::Method>()
        .map_err(|e| e.to_string())?;
    let mut rb = client.request(m, target);
    for (n, v) in headers {
        rb = rb.header(n, v);
    }
    if !body.is_empty() {
        rb = rb.body(body.to_vec());
    }
    let resp = rb.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = bounded_body_bytes(resp).await?;
    Ok(FireOutcome {
        status,
        body_len: body.len(),
        reflected_canaries: Vec::new(),
    })
}

/// Fire a smuggle probe described by `(headers, body)` against
/// `target`. Headers carrying the special `:path` pseudo-header
/// splice into the URL path component. Optional `canary_header`
/// pairs are appended to the outgoing headers (one per token in
/// `canaries`).
///
/// Returns a [`FireOutcome`] on success. When `canary_header_name`
/// placed the canary tokens on the wire, the response headers AND
/// body are scanned for verbatim reflection of those tokens —
/// populating `reflected_canaries`. Body reads are bounded.
#[tracing::instrument(skip(client, headers, body, canaries), fields(target = %target, header_count = headers.len(), has_body = body.is_some()))]
pub async fn fire_smuggle_request(
    client: &reqwest::Client,
    target: &str,
    headers: &[(String, String)],
    body: Option<(&str, &[u8])>,
    canary_header_name: Option<&str>,
    canaries: &[String],
) -> Result<FireOutcome, String> {
    // First pass: extract a `:path` value if present so we know
    // which URL to fire against.
    let mut effective_url = target.to_string();
    let mut path_consumed = false;
    for (name, value) in headers {
        if name == ":path" {
            effective_url = crate::helpers::splice_path(target, value);
            path_consumed = true;
            break;
        }
    }

    // Method: POST if a body is supplied, GET otherwise.
    let method = if body.is_some() {
        reqwest::Method::POST
    } else {
        reqwest::Method::GET
    };

    let mut rb = client.request(method, &effective_url);
    for (name, value) in headers {
        if path_consumed && name == ":path" {
            continue;
        }
        rb = rb.header(name, value);
    }
    if let Some((ct, b)) = body {
        rb = rb.header("Content-Type", ct).body(b.to_vec());
    }
    if let Some(hname) = canary_header_name {
        for token in canaries {
            rb = rb.header(hname, token);
        }
    }

    let resp = rb.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    // Capture the response headers for reflection scanning BEFORE the
    // body stream consumes `resp` — only when tokens were on the wire
    // (otherwise nothing can reflect, so skip the work).
    let scan_reflection = canary_header_name.is_some();
    let header_blob = if scan_reflection {
        response_header_blob(&resp)
    } else {
        Vec::new()
    };
    let body = bounded_body_bytes(resp).await?;
    // Reflection scan only when the tokens were actually sent — if
    // `--canary-header` was unset the canaries never hit the wire and
    // can't reflect. The scan covers BOTH response headers (Location,
    // Set-Cookie, debug echoes) and the body.
    let reflected_canaries = if scan_reflection {
        reflected_in_response(&header_blob, &body, canaries)
    } else {
        Vec::new()
    };
    Ok(FireOutcome {
        status,
        body_len: body.len(),
        reflected_canaries,
    })
}

/// Flatten a response's headers into a `name:value\n` byte blob for
/// reflection scanning. Header values are opaque bytes (may be
/// non-UTF-8), so they're scanned as raw bytes rather than decoded.
#[must_use]
fn response_header_blob(resp: &reqwest::Response) -> Vec<u8> {
    let mut blob = Vec::new();
    for (name, value) in resp.headers() {
        blob.extend_from_slice(name.as_str().as_bytes());
        blob.push(b':');
        blob.extend_from_slice(value.as_bytes());
        blob.push(b'\n');
    }
    blob
}

/// Scan both the response header blob and the response body for
/// canary reflection, returning the deduplicated union — header hits
/// first, then any tokens found only in the body, preserving
/// discovery order. A token echoed in both places appears once.
#[must_use]
pub fn reflected_in_response(header_blob: &[u8], body: &[u8], needles: &[String]) -> Vec<String> {
    let mut hits = reflected_tokens(header_blob, needles);
    for token in reflected_tokens(body, needles) {
        if !hits.contains(&token) {
            hits.push(token);
        }
    }
    hits
}

/// Classify a probe response relative to baseline. The single
/// source of truth for the `bypass_signal` field across every fire
/// subcommand — if this function changes, the signal semantics
/// change everywhere.
#[must_use]
pub fn classify(
    probe_status: u16,
    probe_body: usize,
    baseline_status: u16,
    baseline_body: usize,
    body_threshold: f64,
) -> &'static str {
    let status_diverged = probe_status != baseline_status;
    let body_diverged = {
        let max = probe_body.max(baseline_body) as f64;
        if max == 0.0 {
            false
        } else {
            let delta = (probe_body as i64 - baseline_body as i64).unsigned_abs() as f64;
            delta / max > body_threshold
        }
    };
    match (status_diverged, body_diverged) {
        (true, true) => "both-diverged",
        (true, false) => "status-diverged",
        (false, true) => "body-diverged",
        (false, false) => "none",
    }
}

/// Classify a probe response, treating in-band canary reflection as
/// the strongest signal. When `canary_reflected` is true the verdict
/// is `"canary-reflected"` regardless of status/body divergence — a
/// reflected marker is a confirmed smuggle, not a heuristic. Otherwise
/// this delegates to [`classify`], so the divergence semantics stay
/// in exactly one place.
#[must_use]
pub fn classify_with_reflection(
    probe_status: u16,
    probe_body: usize,
    baseline_status: u16,
    baseline_body: usize,
    body_threshold: f64,
    canary_reflected: bool,
) -> &'static str {
    if canary_reflected {
        return "canary-reflected";
    }
    classify(
        probe_status,
        probe_body,
        baseline_status,
        baseline_body,
        body_threshold,
    )
}

/// Per-composed-artifact fire report. The `wafrift smuggle-cross-
/// product` and `wafrift smuggle-chain` fire pipelines emit this
/// shape (one JSON object per fired composed artifact). The shape
/// is intentionally distinct from `smuggle-fire`'s `FireReport`
/// (`techniques`/`canaries` are arrays instead of scalars) so
/// operators can disambiguate via JSON keys.
#[derive(serde::Serialize)]
pub struct ComposedFireReport {
    pub techniques: Vec<String>,
    pub canaries: Vec<String>,
    pub status: u16,
    pub body_len: usize,
    pub latency_ms: u128,
    pub baseline_status: u16,
    pub baseline_body_len: usize,
    pub bypass_signal: String,
    /// Canary tokens that reflected verbatim in the response body.
    /// Omitted from JSON when empty so existing consumers keep
    /// working — additive, backwards-compatible (LAW 2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reflected_canaries: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproducer_curl: Option<String>,
}

/// Configuration for [`fire_composed_pipeline`]. Bundled into a
/// struct so adding a knob doesn't ripple through every caller.
pub struct ComposedFireConfig<'a> {
    pub target: &'a str,
    pub timeout_secs: u64,
    pub baseline_method: &'a str,
    pub baseline_body: &'a [u8],
    pub baseline_headers: &'a [(String, String)],
    pub canary_header: &'a str,
    pub cap: usize,
    pub delay_ms: u64,
    pub parallel: usize,
    pub body_divergence_threshold: f64,
    pub include_reproducer: bool,
    pub no_summary: bool,
}

/// Fire a sequence of composed artifacts against a live target.
/// Emits one [`ComposedFireReport`] JSON line per fired artifact to
/// stdout. Writes an end-of-run summary to stderr unless
/// `no_summary` is set.
///
/// Used by both `smuggle-cross-product --fire-target` and
/// `smuggle-chain --fire-target` — single source of truth for the
/// composed-fire pipeline.
pub async fn fire_composed_pipeline(
    composed: &[ComposedArtifact],
    cfg: &ComposedFireConfig<'_>,
) -> ExitCode {
    let client = match build_client(cfg.timeout_secs) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{e}");
            return ExitCode::from(1);
        }
    };

    let baseline = match fire_baseline(
        &client,
        cfg.target,
        cfg.baseline_method,
        cfg.baseline_body,
        cfg.baseline_headers,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "wafrift smuggle-fire: baseline request failed: {e}"
            );
            return ExitCode::from(1);
        }
    };
    // The composed fire path only needs the baseline's (status,
    // body_len) for divergence classification — a Copy tuple that
    // can be shared across every concurrent fire without cloning.
    let baseline_ref = (baseline.status, baseline.body_len);

    let to_fire: Vec<&ComposedArtifact> = if cfg.cap > 0 {
        composed.iter().take(cfg.cap).collect()
    } else {
        composed.iter().collect()
    };
    if to_fire.is_empty() {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-fire: zero composed artifacts to fire"
        );
        return ExitCode::from(2);
    }

    let reports: Vec<ComposedFireReport> = if cfg.parallel <= 1 {
        let mut acc = Vec::with_capacity(to_fire.len());
        for c in &to_fire {
            acc.push(fire_one_composed(&client, cfg, baseline_ref, c).await);
            if cfg.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(cfg.delay_ms)).await;
            }
        }
        acc
    } else {
        let parallel = cfg.parallel;
        let client_ref = &client;
        let cfg_ref = cfg;
        let baseline_copy = baseline_ref;
        futures_util::stream::iter(to_fire)
            .map(|c| async move { fire_one_composed(client_ref, cfg_ref, baseline_copy, c).await })
            .buffer_unordered(parallel)
            .collect()
            .await
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut signal_counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    let mut fired = 0usize;
    for report in &reports {
        let signal_key: &'static str = match report.bypass_signal.as_str() {
            "canary-reflected" => "canary-reflected",
            "none" => "none",
            "status-diverged" => "status-diverged",
            "body-diverged" => "body-diverged",
            "both-diverged" => "both-diverged",
            "error" => "error",
            _ => "other",
        };
        *signal_counts.entry(signal_key).or_insert(0) += 1;
        match serde_json::to_string(report) {
            Ok(s) => {
                let _ = writeln!(out, "{s}");
                fired += 1;
            }
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "serialize error: {e}");
                return ExitCode::from(1);
            }
        }
    }

    if !cfg.no_summary {
        let canary_reflected = reports
            .iter()
            .filter(|r| !r.reflected_canaries.is_empty())
            .count();
        let summary = serde_json::json!({
            "kind": "summary",
            "target": cfg.target,
            "fired": fired,
            "baseline_status": baseline.status,
            "baseline_body_len": baseline.body_len,
            "canary_reflected": canary_reflected,
            "per_signal": signal_counts,
        });
        let _ = writeln!(
            std::io::stderr(),
            "{}",
            serde_json::to_string(&summary).unwrap_or_default()
        );
    }
    ExitCode::SUCCESS
}

/// Fire ONE composed artifact and build a [`ComposedFireReport`].
/// Used by both the sequential and concurrent paths in
/// [`fire_composed_pipeline`].
async fn fire_one_composed(
    client: &reqwest::Client,
    cfg: &ComposedFireConfig<'_>,
    baseline: (u16, usize),
    c: &ComposedArtifact,
) -> ComposedFireReport {
    let canary_header_name = if cfg.canary_header.is_empty() {
        None
    } else {
        Some(cfg.canary_header)
    };

    let body_tuple = c.body.as_ref().map(|(ct, b)| (ct.as_str(), b.as_slice()));

    let reproducer_curl = if cfg.include_reproducer {
        // Build a curl reproducer for the composed artifact. Splice
        // canary headers (if any) into the composed.headers copy
        // before rendering so the reproducer is fire-equivalent.
        let mut effective_headers: Vec<(String, String)> = c.headers.to_vec();
        if let Some(hname) = canary_header_name {
            for token in &c.canaries {
                effective_headers.insert(0, (hname.to_string(), token.clone()));
            }
        }
        // Build a SmuggleArtifact wrapper so we can reuse the curl
        // renderer. Headers-only OR body — frames are dropped (the
        // composed artifact shouldn't contain frames in fire mode).
        let artifact = if let Some((ct, body)) = &c.body {
            wafrift_types::probe::SmuggleArtifact::BodyWithContentType {
                content_type: ct.clone(),
                body: body.clone(),
            }
        } else {
            wafrift_types::probe::SmuggleArtifact::Headers(effective_headers.clone())
        };
        // For body-shaped composed, the composed headers still need
        // to go into the curl. We use the SmuggleArtifact wrapper for
        // path-splice handling; the body case carries extras
        // (composed headers + canary) via the third argument.
        let extras: Vec<(String, String)> = if c.body.is_some() {
            effective_headers
        } else {
            Vec::new()
        };
        crate::helpers::render_artifact_as_curl(&artifact, cfg.target, &extras)
    } else {
        None
    };

    let t0 = Instant::now();
    let result = fire_smuggle_request(
        client,
        cfg.target,
        &c.headers,
        body_tuple,
        canary_header_name,
        &c.canaries,
    )
    .await;
    let latency_ms = t0.elapsed().as_millis();

    match result {
        Ok(outcome) => {
            let reflected = !outcome.reflected_canaries.is_empty();
            let signal = classify_with_reflection(
                outcome.status,
                outcome.body_len,
                baseline.0,
                baseline.1,
                cfg.body_divergence_threshold,
                reflected,
            );
            ComposedFireReport {
                techniques: c.techniques.clone(),
                canaries: c.canaries.clone(),
                status: outcome.status,
                body_len: outcome.body_len,
                latency_ms,
                baseline_status: baseline.0,
                baseline_body_len: baseline.1,
                bypass_signal: signal.to_string(),
                reflected_canaries: outcome.reflected_canaries,
                error: None,
                reproducer_curl,
            }
        }
        Err(e) => ComposedFireReport {
            techniques: c.techniques.clone(),
            canaries: c.canaries.clone(),
            status: 0,
            body_len: 0,
            latency_ms,
            baseline_status: baseline.0,
            baseline_body_len: baseline.1,
            bypass_signal: "error".into(),
            reflected_canaries: Vec::new(),
            error: Some(e),
            reproducer_curl,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_without_resolve_succeeds() {
        // None must reproduce the plain build_client path (LAW 2).
        assert!(build_client_with_resolve(5, None).is_ok());
        assert!(build_client(5).is_ok());
    }

    #[test]
    fn build_client_with_resolve_override_succeeds() {
        let addr: SocketAddr = "203.0.113.7:443".parse().unwrap();
        assert!(
            build_client_with_resolve(5, Some(("protected.example.com", addr))).is_ok(),
            "pinning a host to an origin IP must build a usable client"
        );
    }

    #[tokio::test]
    async fn build_client_sends_configured_user_agent_on_the_wire() {
        // Test truth, not shape (LAW 6): assert the BYTES on the wire carry a
        // non-empty User-Agent from the shared browser identity. Regression
        // guard for the harvest 0/N false-negative — a no-UA client is 403'd
        // outright by CumulusFire/Cloudflare, so record-vs-reverify MUST share
        // the same wire signature every other fire path already uses (§9).
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ua"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = build_client(5).expect("build client");
        let url = format!("{}/ua", server.uri());
        client.get(&url).send().await.expect("send");

        let reqs = server
            .received_requests()
            .await
            .expect("mock recorded requests");
        assert_eq!(reqs.len(), 1, "exactly one request reached the server");
        let request_headers = &reqs[0].headers;
        let expected_identity =
            crate::config::shared_scan_browser_headers(None).expect("shared browser identity");
        let ua = request_headers
            .get("user-agent")
            .expect("live-fire client MUST send a User-Agent header")
            .to_str()
            .expect("UA is valid ascii");
        assert!(!ua.is_empty(), "User-Agent must be non-empty");
        assert_eq!(
            ua, expected_identity.user_agent,
            "build_client must send the shared scan UA, not a bare/empty one"
        );
        if !expected_identity.explicit_user_agent {
            let facts = guise::fingerprint::profile_facts(
                expected_identity
                    .profile
                    .expect("default identity should include profile"),
            );
            assert_eq!(
                request_headers
                    .get("accept")
                    .and_then(|value| value.to_str().ok()),
                Some(facts.accept),
                "build_client must send shared browser Accept"
            );
            assert_eq!(
                request_headers
                    .get("accept-language")
                    .and_then(|value| value.to_str().ok()),
                Some(facts.accept_language),
                "build_client must send shared browser Accept-Language"
            );
        }
    }

    #[test]
    fn classify_none_when_status_and_body_match() {
        assert_eq!(classify(403, 100, 403, 100, 0.05), "none");
    }

    #[test]
    fn classify_status_diverged() {
        assert_eq!(classify(200, 100, 403, 100, 0.05), "status-diverged");
    }

    #[test]
    fn classify_body_diverged() {
        // 1000 vs 100 -> 900/1000 = 90% > 5% threshold.
        assert_eq!(classify(403, 100, 403, 1000, 0.05), "body-diverged");
    }

    #[test]
    fn classify_both_diverged() {
        assert_eq!(classify(200, 100, 403, 1000, 0.05), "both-diverged");
    }

    #[test]
    fn classify_small_delta_below_threshold_is_none() {
        // 1000 vs 1020 -> 20/1020 = ~2% < 5%.
        assert_eq!(classify(200, 1020, 200, 1000, 0.05), "none");
    }

    #[test]
    fn classify_zero_body_both_sides_is_none() {
        assert_eq!(classify(403, 0, 403, 0, 0.05), "none");
    }

    #[test]
    fn max_response_bytes_is_four_megabytes() {
        // Anti-rig: pin the documented limit so a regression that
        // silently raises the cap to 1 GiB surfaces here.
        assert_eq!(MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
    }

    #[test]
    fn reflected_tokens_finds_present_token() {
        let body = b"prefix-AbC123XyZ0000token-suffix";
        let needles = vec!["AbC123XyZ0000token".to_string()];
        assert_eq!(reflected_tokens(body, &needles), vec!["AbC123XyZ0000token"]);
    }

    #[test]
    fn reflected_tokens_returns_only_present_subset() {
        let body = b"the canary ABCDEFGHIJKLMNOP is here";
        let needles = vec![
            "ABCDEFGHIJKLMNOP".to_string(),
            "ZZZZZZZZZZZZZZZZ".to_string(),
        ];
        // Only the first token reflects; the second must not appear.
        assert_eq!(reflected_tokens(body, &needles), vec!["ABCDEFGHIJKLMNOP"]);
    }

    #[test]
    fn reflected_tokens_empty_when_none_present() {
        let body = b"blocked-by-mock-waf";
        let needles = vec!["AbC123XyZ0000token".to_string()];
        assert!(reflected_tokens(body, &needles).is_empty());
    }

    #[test]
    fn reflected_tokens_ignores_empty_needle() {
        // Anti-rig: an empty needle is a substring of everything;
        // counting it would be a guaranteed false-positive reflection.
        let body = b"any body";
        let needles = vec![String::new()];
        assert!(reflected_tokens(body, &needles).is_empty());
    }

    #[test]
    fn reflected_tokens_needle_longer_than_body_is_not_found() {
        let body = b"hi";
        let needles = vec!["this-needle-is-far-longer-than-the-body".to_string()];
        assert!(reflected_tokens(body, &needles).is_empty());
    }

    #[test]
    fn reflected_tokens_empty_body_finds_nothing() {
        let needles = vec!["AbC123XyZ0000token".to_string()];
        assert!(reflected_tokens(b"", &needles).is_empty());
    }

    #[test]
    fn classify_with_reflection_overrides_every_divergence_verdict() {
        // Reflection is the strongest signal: even when status AND
        // body both match the baseline (would be "none"), a reflected
        // canary forces "canary-reflected".
        assert_eq!(
            classify_with_reflection(403, 100, 403, 100, 0.05, true),
            "canary-reflected"
        );
        // And it wins over both-diverged too.
        assert_eq!(
            classify_with_reflection(200, 100, 403, 1000, 0.05, true),
            "canary-reflected"
        );
    }

    #[test]
    fn classify_with_reflection_delegates_when_not_reflected() {
        // Without reflection, the verdict must match plain classify()
        // exactly — the divergence semantics live in one place.
        for (ps, pb, bs, bb) in [
            (403u16, 100usize, 403u16, 100usize),
            (200, 100, 403, 100),
            (403, 1000, 403, 100),
            (200, 1000, 403, 100),
        ] {
            assert_eq!(
                classify_with_reflection(ps, pb, bs, bb, 0.05, false),
                classify(ps, pb, bs, bb, 0.05),
            );
        }
    }

    #[test]
    fn fire_outcome_default_has_empty_reflection() {
        let o = FireOutcome::default();
        assert_eq!(o.status, 0);
        assert_eq!(o.body_len, 0);
        assert!(o.reflected_canaries.is_empty());
    }

    #[test]
    fn reflected_in_response_finds_header_only_reflection() {
        // Token echoed into a response header (e.g. Location) but NOT
        // the body — the header-reflection surface body-only scanning
        // would miss.
        let header_blob = b"location:/next?id=ABCDEFGHIJKLMNOP\ncontent-type:text/html\n";
        let body = b"<html>nothing here</html>";
        let needles = vec!["ABCDEFGHIJKLMNOP".to_string()];
        assert_eq!(
            reflected_in_response(header_blob, body, &needles),
            vec!["ABCDEFGHIJKLMNOP"]
        );
    }

    #[test]
    fn reflected_in_response_finds_body_only_reflection() {
        let header_blob = b"content-type:text/plain\n";
        let body = b"reflected:ABCDEFGHIJKLMNOP";
        let needles = vec!["ABCDEFGHIJKLMNOP".to_string()];
        assert_eq!(
            reflected_in_response(header_blob, body, &needles),
            vec!["ABCDEFGHIJKLMNOP"]
        );
    }

    #[test]
    fn reflected_in_response_dedups_token_in_both_header_and_body() {
        // A token present in BOTH header and body must appear exactly
        // once — header-first ordering, no duplicate.
        let header_blob = b"x-echo:ABCDEFGHIJKLMNOP\n";
        let body = b"body also has ABCDEFGHIJKLMNOP in it";
        let needles = vec!["ABCDEFGHIJKLMNOP".to_string()];
        assert_eq!(
            reflected_in_response(header_blob, body, &needles),
            vec!["ABCDEFGHIJKLMNOP"]
        );
    }

    #[test]
    fn reflected_in_response_empty_when_neither_contains_token() {
        let header_blob = b"content-type:text/plain\n";
        let body = b"blocked-by-waf";
        let needles = vec!["ABCDEFGHIJKLMNOP".to_string()];
        assert!(reflected_in_response(header_blob, body, &needles).is_empty());
    }

    #[test]
    fn reflected_in_response_header_first_ordering_with_distinct_tokens() {
        // Distinct tokens: one only in header, one only in body. The
        // header hit comes first, preserving discovery order.
        let header_blob = b"x-echo:HEADERTOKEN0001x\n";
        let body = b"body has BODYTOKEN00002xy here";
        let needles = vec![
            "HEADERTOKEN0001x".to_string(),
            "BODYTOKEN00002xy".to_string(),
        ];
        assert_eq!(
            reflected_in_response(header_blob, body, &needles),
            vec!["HEADERTOKEN0001x", "BODYTOKEN00002xy"]
        );
    }
}
