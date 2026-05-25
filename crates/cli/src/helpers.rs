//! Pure helper functions shared across CLI commands.

use colored::Colorize;
use std::collections::HashSet;

use wafrift_encoding::encoding::{self, Strategy};
use wafrift_evolution::differential::ProbeTarget;
use wafrift_grammar::grammar::{self, PayloadType};

use crate::Level;
use crate::explain::{ExplainTrace, Outcome};
use crate::target_context::{TargetContext, context_applicability};

pub(crate) const LIGHT_VARIANTS: usize = 4;
pub(crate) const MEDIUM_VARIANTS: usize = 12;
pub(crate) const HEAVY_VARIANTS: usize = 50;

/// Evasion variant produced by the variant builder.
#[derive(Debug)]
pub struct Variant {
    pub payload: String,
    pub techniques: Vec<String>,
    pub confidence: f64,
}

/// Split a single `Name: Value` header line on the first colon and
/// trim surrounding whitespace. Accepts empty values per RFC 9110
/// §5.5 — the WAF / origin server decides whether an empty value is
/// meaningful, not this parser. Rejects missing colon and empty name.
///
/// Returns a short error fragment ("missing ':' separator", "empty
/// name") so callers can compose their own context — `"invalid
/// header \`{raw}\`; {frag}"` for [`parse_headers`], `"-H/--header
/// {raw:?} {frag}"` for [`crate::scan::pentest_client::parse_header`].
pub fn parse_header_pair(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| "missing ':' separator".to_string())?;
    let name = name.trim();
    if name.is_empty() {
        return Err("empty name".to_string());
    }
    Ok((name.to_string(), value.trim().to_string()))
}

pub(crate) fn parse_headers(raw_headers: &[String]) -> Result<Vec<(String, String)>, String> {
    raw_headers
        .iter()
        .map(|header| {
            if !header.contains(':') {
                return Err(format!("invalid header `{header}`; expected `key: value`"));
            }
            parse_header_pair(header).map_err(|frag| format!("invalid header `{header}`; {frag}"))
        })
        .collect()
}

/// Walk a `reqwest::Error`'s cause chain and return a string that includes
/// every level, joined by " — caused by: ".
///
/// reqwest's own `Display` is famously short — "error sending request" —
/// without the underlying DNS / TCP / TLS cause.  This helper, first
/// extracted during dogfood pass 5 (2026-05), surfaces the full chain
/// (e.g. "dns error — caused by: No such host is known. (os error 11001)")
/// so operators never have to guess whether the failure is NXDOMAIN,
/// connection refused, TLS handshake failure, or something else.
///
/// `detect_cmd::fetch_for_detect` was the first site to walk the chain;
/// `bypass_probe::run_async` and `bank_registry::http_get_blocking` /
/// `http_post_blocking` were fixed in the same pass.
pub(crate) fn walk_reqwest_error(e: &reqwest::Error) -> String {
    let mut detail = format!("{e}");
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(s) = src {
        detail.push_str(" — caused by: ");
        detail.push_str(&s.to_string());
        src = std::error::Error::source(s);
    }
    detail
}

/// Single-quote a string for safe interpolation into a Bourne-shell
/// command. Returns the FULLY wrapped form `'…'` so callers do not
/// add their own quotes. A literal `'` inside the input becomes
/// `'\''` (close-quote, escape, open-quote); every other byte rides
/// verbatim.
///
/// This is the canonical shell escape used by the curl reproducer in
/// [`crate::raw_request::RawRequest::to_curl`] and the `wafrift replay`
/// reproducer in `report::render_*`. Centralised so a single
/// round-trip-through-bash test exercises every caller.
pub fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        match ch {
            // `'` is the standard close-and-reopen escape.
            '\'' => out.push_str("'\\''"),
            // NUL inside a single-quoted shell token would
            // terminate the C string in libc and silently
            // truncate the argument. CR resets the terminal
            // cursor and can hide preceding output (operator
            // copies a curl from logs that looks shorter than
            // it is). Bash's `$'\\x00'` / `$'\\r'` ANSI-C
            // quoting is the safe form — fall out of the
            // single-quote run, splice the ANSI-C literal,
            // reopen the run.
            '\0' => out.push_str("'$'\\x00''"),
            '\r' => out.push_str("'$'\\r''"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

/// Build the canonical `curl -G --data-urlencode` reproducer for a
/// URL-query bypass. The non-raw scan loop emits `bypass_variants`
/// with `payload` but historically NOT a `repro_curl` field — making
/// the JSON twin of the raw-runner output incomplete. Operators
/// pasting bypass_variants into a pentest report had to re-construct
/// the curl by hand, which both wastes time and risks under-escaping
/// shell metacharacters in the payload.
///
/// Uses `shell_single_quote` for both the param=value pair and the
/// target URL — the same primitive every other curl emitter in this
/// crate uses, so a single round-trip-through-bash test exercises
/// every caller.
#[must_use]
pub fn url_query_repro_curl(target: &str, param: &str, payload: &str) -> String {
    // `--data-urlencode <param>=<value>` is the wire-correct way to
    // express "this exact byte sequence in this exact param" without
    // letting the shell or curl re-encode anything. -G promotes
    // the data to the query string, matching `wafrift scan`'s actual
    // probe shape. The whole `param=payload` literal becomes one
    // single-quoted shell token so an embedded `&` or `=` in the
    // payload doesn't terminate the argument early.
    format!(
        "curl -G --data-urlencode {arg} {target}",
        arg = shell_single_quote(&format!("{param}={payload}")),
        target = shell_single_quote(target),
    )
}

/// Normalise a user-supplied URL or hostname into a fully-qualified URL.
///
/// Rules (applied in order):
/// 1. Strip leading/trailing whitespace.
/// 2. If the result contains `://`, return it as-is (already has a scheme).
/// 3. If the result starts with `//` (protocol-relative), promote to `https://`.
/// 4. Otherwise, prepend `https://`.
///
/// This fixes the "relative URL without a base" error that occurs when a user
/// passes `example.com` instead of `https://example.com` to any subcommand.
#[must_use]
pub fn normalize_target_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.contains("://") {
        trimmed.to_string()
    } else if let Some(rest) = trimmed.strip_prefix("//") {
        format!("https://{rest}")
    } else {
        format!("https://{trimmed}")
    }
}

pub fn strategies_for_level(level: Level) -> Vec<Strategy> {
    let all = encoding::all_strategies();
    match level {
        Level::Light => all.iter().copied().take(3).collect(),
        Level::Medium => all.iter().copied().take(6).collect(),
        Level::Heavy => all.to_vec(),
    }
}

/// Strategy pool for a `--level`, widened to the full set when the user
/// has named techniques explicitly via `--only`. Rationale: a user who
/// types `--only encoding/base64/standard --level light` expects base64
/// to run, not be silently dropped because base64 sits above the
/// light-level aggressiveness cut. `--level` still bounds the variant
/// count via `max_mutations_for_level`.
pub fn strategy_pool(level: Level, explicit_selection: bool) -> Vec<Strategy> {
    if explicit_selection {
        encoding::all_strategies().to_vec()
    } else {
        strategies_for_level(level)
    }
}

pub fn max_mutations_for_level(level: Level) -> usize {
    match level {
        Level::Light => LIGHT_VARIANTS,
        Level::Medium => MEDIUM_VARIANTS,
        Level::Heavy => HEAVY_VARIANTS,
    }
}

pub(crate) fn payload_type_label(payload_type: PayloadType) -> &'static str {
    match payload_type {
        PayloadType::Sql => "SQL Injection",
        PayloadType::Xss => "XSS",
        PayloadType::CommandInjection => "Command Injection",
        PayloadType::Ldap => "LDAP Injection",
        PayloadType::Ssrf => "SSRF",
        PayloadType::PathTraversal => "Path Traversal",
        PayloadType::TemplateInjection => "Template Injection",
        _ => "Unknown",
    }
}

pub(crate) fn variant_confidence(
    payload_type: PayloadType,
    grammar_rule_count: usize,
    encoding_only: bool,
    strategy: Strategy,
) -> f64 {
    let type_score = match payload_type {
        PayloadType::Unknown => 0.45,
        PayloadType::Ldap
        | PayloadType::Ssrf
        | PayloadType::PathTraversal
        | PayloadType::TemplateInjection => 0.72,
        PayloadType::Sql | PayloadType::Xss | PayloadType::CommandInjection => 0.82,
        _ => 0.45,
    };

    let grammar_bonus = if encoding_only {
        0.0
    } else {
        (grammar_rule_count as f64 * 0.04).min(0.12)
    };

    let strategy_score = match strategy {
        Strategy::CaseAlternation => 0.03,
        Strategy::WhitespaceInsertion => 0.05,
        Strategy::SqlCommentInsertion => 0.07,
        Strategy::UrlEncode => 0.05,
        Strategy::DoubleUrlEncode => 0.07,
        Strategy::UnicodeEncode => 0.06,
        Strategy::HtmlEntityEncode => 0.06,
        Strategy::NullByte => 0.08,
        Strategy::TripleUrlEncode => 0.09,
        Strategy::ChunkedSplit => 0.1,
        Strategy::ParameterPollution => 0.08,
        Strategy::OverlongUtf8 => 0.11,
        Strategy::Base64Encode => 0.05,
        Strategy::HexEncode => 0.05,
        Strategy::Utf7Encode => 0.07,
        _ => 0.05,
    };

    (type_score + grammar_bonus + strategy_score).min(0.99)
}

pub(crate) fn confidence_badge(confidence: f64) -> colored::ColoredString {
    let label = format!("confidence {:.0}%", (confidence * 100.0).round());
    if confidence >= 0.9 {
        label.bright_green().bold()
    } else if confidence >= 0.75 {
        label.yellow().bold()
    } else {
        label.red().bold()
    }
}

pub(crate) fn probe_target_label(target: &ProbeTarget) -> String {
    match target {
        ProbeTarget::SqlKeyword(value) => format!("sql_keyword:{value}"),
        ProbeTarget::SqlOperator(value) => format!("sql_operator:{value}"),
        ProbeTarget::SqlComment(value) => format!("sql_comment:{value}"),
        ProbeTarget::SqlQuote => "sql_quote".to_string(),
        ProbeTarget::SqlTautology(value) => format!("sql_tautology:{value}"),
        ProbeTarget::XssTag(value) => format!("xss_tag:{value}"),
        ProbeTarget::XssEvent(value) => format!("xss_event:{value}"),
        ProbeTarget::XssExecFunction(value) => format!("xss_exec_function:{value}"),
        ProbeTarget::CmdSeparator(value) => format!("cmd_separator:{value}"),
        ProbeTarget::CmdCommand(value) => format!("cmd_command:{value}"),
        ProbeTarget::CmdPath(value) => format!("cmd_path:{value}"),
        ProbeTarget::Baseline => "baseline".to_string(),
    }
}

/// Build encoding × grammar variants for a given payload.
///
/// Backwards-compatible wrapper around `build_variants_explained` for
/// callers (bench_waf, scan) that don't need context filtering or a
/// trace. Behavior is identical to the pre-explain implementation:
/// no applicability filtering, no per-strategy logging.
pub fn build_variants(
    payload: &str,
    payload_type: PayloadType,
    encoding_only: bool,
    strategies: &[Strategy],
    max_mutations: usize,
) -> Vec<Variant> {
    build_variants_explained(
        payload,
        payload_type,
        encoding_only,
        strategies,
        max_mutations,
        None,
        None,
    )
}

/// Like `build_variants` but optionally filters strategies by target
/// context and records per-strategy outcomes into an `ExplainTrace`.
///
/// Pass `target_context = None` to skip applicability filtering. Pass
/// `trace = None` to disable trace collection (then the result is
/// equivalent to `build_variants`, modulo context filtering).
pub fn build_variants_explained(
    payload: &str,
    payload_type: PayloadType,
    encoding_only: bool,
    strategies: &[Strategy],
    max_mutations: usize,
    target_context: Option<TargetContext>,
    mut trace: Option<&mut ExplainTrace>,
) -> Vec<Variant> {
    let applicable: Vec<Strategy> = strategies
        .iter()
        .copied()
        .filter(|s| match target_context {
            None => true,
            Some(ctx) => match context_applicability(*s, ctx) {
                Ok(()) => true,
                Err(reason) => {
                    if let Some(t) = trace.as_deref_mut() {
                        t.record(*s, Outcome::NotApplicableToContext(reason));
                    }
                    false
                }
            },
        })
        .collect();

    let mut seen = HashSet::new();
    let mut variants = Vec::new();

    let grammar_mutations = if encoding_only {
        Vec::new()
    } else {
        grammar::mutate_as(payload, payload_type, max_mutations)
    };

    for mutation in &grammar_mutations {
        if seen.insert(mutation.payload.clone()) {
            let techniques: Vec<String> = mutation
                .rules_applied
                .iter()
                .map(|rule| (*rule).to_string())
                .collect();
            variants.push(Variant {
                payload: mutation.payload.clone(),
                techniques,
                confidence: variant_confidence(
                    payload_type,
                    mutation.rules_applied.len(),
                    false,
                    Strategy::CaseAlternation,
                ),
            });
        }
    }

    for mutation in &grammar_mutations {
        for strategy in &applicable {
            match encoding::encode(&mutation.payload, *strategy) {
                Ok(encoded) => {
                    if seen.insert(encoded.clone()) {
                        let mut techniques: Vec<String> = mutation
                            .rules_applied
                            .iter()
                            .map(|rule| (*rule).to_string())
                            .collect();
                        techniques.push(format!("encoding::{strategy:?}"));
                        variants.push(Variant {
                            payload: encoded,
                            techniques,
                            confidence: variant_confidence(
                                payload_type,
                                mutation.rules_applied.len(),
                                false,
                                *strategy,
                            ),
                        });
                        if let Some(t) = trace.as_deref_mut() {
                            t.record(*strategy, Outcome::Applied { variant_count: 1 });
                        }
                    } else if let Some(t) = trace.as_deref_mut() {
                        t.record(*strategy, Outcome::AllDuplicates);
                    }
                }
                Err(e) => {
                    if let Some(t) = trace.as_deref_mut() {
                        t.record(*strategy, Outcome::EncodingError(format!("{e:?}")));
                    }
                }
            }
        }
    }

    for strategy in &applicable {
        match encoding::encode(payload, *strategy) {
            Ok(encoded) => {
                if seen.insert(encoded.clone()) {
                    variants.push(Variant {
                        payload: encoded,
                        techniques: vec![format!("encoding::{strategy:?}")],
                        confidence: variant_confidence(payload_type, 0, encoding_only, *strategy),
                    });
                    if let Some(t) = trace.as_deref_mut() {
                        t.record(*strategy, Outcome::Applied { variant_count: 1 });
                    }
                } else if let Some(t) = trace.as_deref_mut() {
                    t.record(*strategy, Outcome::AllDuplicates);
                }
            }
            Err(e) => {
                if let Some(t) = trace.as_deref_mut() {
                    t.record(*strategy, Outcome::EncodingError(format!("{e:?}")));
                }
            }
        }
    }

    if !encoding_only && seen.insert(payload.to_string()) {
        variants.insert(
            0,
            Variant {
                payload: payload.to_string(),
                techniques: vec!["original".to_string()],
                confidence: variant_confidence(payload_type, 0, false, Strategy::CaseAlternation),
            },
        );
    }

    if let Some(t) = trace {
        t.finalize();
    }

    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_headers_trims_whitespace() {
        let headers = parse_headers(&[
            "Server: cloudflare".to_string(),
            " Content-Type : text/html ".to_string(),
        ])
        .expect("valid headers");

        assert_eq!(
            headers,
            vec![
                ("Server".to_string(), "cloudflare".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ]
        );
    }

    #[test]
    fn parse_headers_rejects_missing_separator() {
        let err = parse_headers(&["missing separator".to_string()]).expect_err("invalid header");
        assert!(err.contains("expected `key: value`"));
    }

    #[test]
    fn strategies_for_level_scales_with_aggressiveness() {
        let light = strategies_for_level(Level::Light);
        let medium = strategies_for_level(Level::Medium);
        let heavy = strategies_for_level(Level::Heavy);

        assert_eq!(light.len(), 3);
        assert_eq!(medium.len(), 6);
        assert!(heavy.len() >= medium.len());
        assert!(heavy.contains(&Strategy::OverlongUtf8));
    }

    #[test]
    fn mutation_budget_matches_level() {
        assert_eq!(max_mutations_for_level(Level::Light), LIGHT_VARIANTS);
        assert_eq!(max_mutations_for_level(Level::Medium), MEDIUM_VARIANTS);
        assert_eq!(max_mutations_for_level(Level::Heavy), HEAVY_VARIANTS);
    }

    #[test]
    fn variant_confidence_rewards_stronger_strategies() {
        let light = variant_confidence(PayloadType::Sql, 1, false, Strategy::CaseAlternation);
        let heavy = variant_confidence(PayloadType::Sql, 3, false, Strategy::OverlongUtf8);

        assert!(heavy > light);
        assert!(heavy <= 0.99);
    }

    #[test]
    fn probe_target_label_formats_variants() {
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlKeyword("union".into())),
            "sql_keyword:union"
        );
        assert_eq!(probe_target_label(&ProbeTarget::Baseline), "baseline");
    }

    #[test]
    fn strategy_pool_widens_only_on_explicit_selection() {
        let default_light = strategy_pool(Level::Light, false);
        assert_eq!(default_light.len(), 3);

        let explicit_light = strategy_pool(Level::Light, true);
        let all = encoding::all_strategies();
        assert_eq!(explicit_light.len(), all.len());
        assert!(explicit_light.contains(&Strategy::Base64Encode));
        assert!(explicit_light.contains(&Strategy::OverlongUtf8));
    }

    #[test]
    fn build_variants_explained_filters_by_context() {
        let mut trace = ExplainTrace::default();
        let variants = build_variants_explained(
            "SELECT 1",
            PayloadType::Sql,
            true,
            &[Strategy::GzipEncode, Strategy::Base64Encode],
            4,
            Some(TargetContext::Header),
            Some(&mut trace),
        );
        let payloads: Vec<&str> = variants.iter().map(|v| v.payload.as_str()).collect();
        assert!(
            payloads.iter().any(|p| p.contains("U0VMRUNUIDE=")),
            "base64 variant should appear: {payloads:?}"
        );
        let recorded_paths: Vec<&str> = trace
            .entries
            .iter()
            .map(|e| crate::technique_filter::strategy_path(e.strategy))
            .collect();
        assert!(
            recorded_paths.contains(&"encoding/compression/gzip"),
            "gzip should be in the trace as not_applicable: {recorded_paths:?}"
        );
    }

    #[test]
    fn build_variants_unchanged_signature_still_works() {
        let variants = build_variants(
            "hello",
            PayloadType::Unknown,
            true,
            &[Strategy::Base64Encode],
            4,
        );
        assert!(
            variants.iter().any(|v| v.payload == "aGVsbG8="),
            "base64 of 'hello' should appear"
        );
    }

    // ── payload_type_label ────────────────────────────────────

    #[test]
    fn payload_type_label_covers_every_known_class() {
        // A new PayloadType variant added without updating
        // payload_type_label silently falls into "Unknown" — locks
        // every named variant in.
        assert_eq!(payload_type_label(PayloadType::Sql), "SQL Injection");
        assert_eq!(payload_type_label(PayloadType::Xss), "XSS");
        assert_eq!(
            payload_type_label(PayloadType::CommandInjection),
            "Command Injection"
        );
        assert_eq!(payload_type_label(PayloadType::Ldap), "LDAP Injection");
        assert_eq!(payload_type_label(PayloadType::Ssrf), "SSRF");
        assert_eq!(
            payload_type_label(PayloadType::PathTraversal),
            "Path Traversal"
        );
        assert_eq!(
            payload_type_label(PayloadType::TemplateInjection),
            "Template Injection"
        );
    }

    #[test]
    fn payload_type_label_unknown_falls_through_to_unknown_string() {
        assert_eq!(payload_type_label(PayloadType::Unknown), "Unknown");
    }

    // ── variant_confidence math ───────────────────────────────

    #[test]
    fn variant_confidence_is_never_above_ninety_nine_percent() {
        // The closed-form sum bumps against the .min(0.99) clamp
        // for the strongest combination. Anti-rig against a refactor
        // that bumped the ceiling.
        let max = variant_confidence(PayloadType::Sql, 100, false, Strategy::OverlongUtf8);
        assert!(max <= 0.99);
        assert!(max >= 0.9);
    }

    #[test]
    fn variant_confidence_encoding_only_drops_grammar_bonus() {
        let with_grammar = variant_confidence(PayloadType::Sql, 3, false, Strategy::Base64Encode);
        let encoding_only = variant_confidence(PayloadType::Sql, 3, true, Strategy::Base64Encode);
        assert!(
            with_grammar > encoding_only,
            "grammar bonus must add: {with_grammar} > {encoding_only}"
        );
    }

    #[test]
    fn variant_confidence_unknown_payload_type_gets_lower_base() {
        let unknown = variant_confidence(PayloadType::Unknown, 0, false, Strategy::Base64Encode);
        let sql = variant_confidence(PayloadType::Sql, 0, false, Strategy::Base64Encode);
        assert!(sql > unknown, "Sql base > Unknown base: {sql} vs {unknown}");
    }

    #[test]
    fn variant_confidence_grammar_bonus_caps_at_twelve_pct() {
        // 4 * 0.04 = 0.16 should cap at 0.12.
        let a = variant_confidence(PayloadType::Sql, 100, false, Strategy::CaseAlternation);
        let b = variant_confidence(PayloadType::Sql, 3, false, Strategy::CaseAlternation);
        // Both saturate at the grammar bonus cap, so they're equal
        // up to floating-point precision.
        assert!((a - b).abs() < 1e-9, "grammar cap must hold: {a} vs {b}");
    }

    // ── strategies_for_level invariants ───────────────────────

    #[test]
    fn strategies_for_level_each_returns_non_empty() {
        for level in [Level::Light, Level::Medium, Level::Heavy] {
            assert!(
                !strategies_for_level(level).is_empty(),
                "{level:?} must yield ≥1 strategy"
            );
        }
    }

    #[test]
    fn strategies_for_level_is_monotone_in_aggressiveness() {
        // light ⊆ medium ⊆ heavy in terms of set size.
        let l = strategies_for_level(Level::Light).len();
        let m = strategies_for_level(Level::Medium).len();
        let h = strategies_for_level(Level::Heavy).len();
        assert!(l <= m, "light <= medium: {l} <= {m}");
        assert!(m <= h, "medium <= heavy: {m} <= {h}");
    }

    #[test]
    fn max_mutations_for_level_is_monotone() {
        let l = max_mutations_for_level(Level::Light);
        let m = max_mutations_for_level(Level::Medium);
        let h = max_mutations_for_level(Level::Heavy);
        assert!(l < m, "light < medium: {l} < {m}");
        assert!(m < h, "medium < heavy: {m} < {h}");
    }

    // ── probe_target_label total coverage ─────────────────────

    #[test]
    fn probe_target_label_covers_every_variant() {
        // If a new ProbeTarget is added without a probe_target_label
        // arm, this fails to compile (exhaustive match in the impl).
        // Run a representative case from every family to ensure no
        // arm got silently changed.
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlOperator("AND".into())),
            "sql_operator:AND"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlComment("--".into())),
            "sql_comment:--"
        );
        assert_eq!(probe_target_label(&ProbeTarget::SqlQuote), "sql_quote");
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlTautology("1=1".into())),
            "sql_tautology:1=1"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::XssEvent("onerror".into())),
            "xss_event:onerror"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::XssExecFunction("eval".into())),
            "xss_exec_function:eval"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::CmdSeparator(";".into())),
            "cmd_separator:;"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::CmdCommand("whoami".into())),
            "cmd_command:whoami"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::CmdPath("/etc/passwd".into())),
            "cmd_path:/etc/passwd"
        );
    }

    // ── parse_headers more edges ──────────────────────────────

    #[test]
    fn parse_headers_handles_empty_input() {
        let r = parse_headers(&[]).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn parse_headers_preserves_value_internal_colons() {
        // A `Date: Wed, 21 Oct 2015 07:28:00 GMT` style header
        // contains colons inside the value — splitting on the FIRST
        // `:` must preserve the rest.
        let r = parse_headers(&["Date: Wed, 21 Oct 2015 07:28:00 GMT".into()]).unwrap();
        assert_eq!(r[0].0, "Date");
        assert_eq!(r[0].1, "Wed, 21 Oct 2015 07:28:00 GMT");
    }

    #[test]
    fn parse_headers_rejects_empty_key() {
        // A `: value` line is malformed — key half is empty.
        let r = parse_headers(&[": value".into()]);
        assert!(r.is_err(), "empty key must be rejected");
    }

    // ── parse_header_pair (shared primitive) ──────────────────

    #[test]
    fn parse_header_pair_splits_on_first_colon() {
        let (n, v) = parse_header_pair("X-Custom: hello").unwrap();
        assert_eq!(n, "X-Custom");
        assert_eq!(v, "hello");
    }

    #[test]
    fn parse_header_pair_trims_both_halves() {
        let (n, v) = parse_header_pair("  X  :   Bearer abc   ").unwrap();
        assert_eq!(n, "X");
        assert_eq!(v, "Bearer abc");
    }

    #[test]
    fn parse_header_pair_preserves_value_internal_colons() {
        // Bearer tokens / dates / URLs may contain `:` — the FIRST
        // colon is the separator, everything after stays in the value.
        let (_, v) = parse_header_pair("X-Time: 12:34:56").unwrap();
        assert_eq!(v, "12:34:56");
    }

    #[test]
    fn parse_header_pair_accepts_empty_value_per_rfc_9110() {
        // RFC 9110 §5.5 permits empty header values; curl accepts
        // them. We follow suit.
        let (n, v) = parse_header_pair("X-Empty:").unwrap();
        assert_eq!(n, "X-Empty");
        assert_eq!(v, "");
    }

    #[test]
    fn parse_header_pair_rejects_missing_colon() {
        let err = parse_header_pair("nocolon").unwrap_err();
        assert!(err.contains("missing"), "got: {err}");
    }

    #[test]
    fn parse_header_pair_rejects_empty_name() {
        let err = parse_header_pair(": value").unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    // ── shell_single_quote ────────────────────────────────────

    #[test]
    fn shell_single_quote_wraps_safe_string_in_quotes() {
        assert_eq!(shell_single_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_single_quote_escapes_internal_apostrophes() {
        // Bourne escape: 'don'\''t'
        assert_eq!(shell_single_quote("don't"), "'don'\\''t'");
    }

    #[test]
    fn shell_single_quote_handles_empty_string() {
        assert_eq!(shell_single_quote(""), "''");
    }

    #[test]
    fn shell_single_quote_passes_dangerous_metacharacters_verbatim() {
        // Single-quoting means metacharacters lose meaning — `$`, `;`,
        // backticks, parens all ride through as bytes.
        assert_eq!(
            shell_single_quote("$(rm -rf /); `whoami`"),
            "'$(rm -rf /); `whoami`'"
        );
    }

    #[test]
    fn shell_single_quote_escapes_nul_byte() {
        // Regression for F72: NUL inside a single-quoted shell
        // token silently truncates the argument at the libc layer.
        // Use bash ANSI-C quoting to splice the NUL safely.
        let out = shell_single_quote("a\0b");
        // Output must not contain a raw NUL — every byte must be
        // representable in a shell here-doc / copy-paste.
        assert!(
            !out.contains('\0'),
            "raw NUL must be escaped, got: {out:?}"
        );
        // Bash form: `'a'$'\x00''b'` (close + ANSI-C + reopen).
        assert!(out.contains("$'\\x00'"), "got: {out:?}");
    }

    #[test]
    fn shell_single_quote_escapes_carriage_return() {
        // Regression for F72: CR resets the terminal cursor and
        // can hide preceding output when the operator copies a
        // curl from logs. Escape via ANSI-C `\r`.
        let out = shell_single_quote("a\rb");
        assert!(!out.contains('\r'), "raw CR must be escaped: {out:?}");
        assert!(out.contains("$'\\r'"), "got: {out:?}");
    }

    #[cfg(unix)]
    #[test]
    fn shell_single_quote_round_trips_through_bash() {
        // Single canonical shell escape — round-tripped through bash
        // to confirm both halves (wrap + apostrophe escape) are wire-
        // compatible. Replaces the bash round-trip previously in
        // report.rs (one source of truth for the escape).
        let inputs = [
            "hello world",
            "it's working",
            "'\''",
            "foo;bar|baz",
            "$(danger)",
            "`backtick`",
            "emoji: 🚀",
        ];
        for raw in &inputs {
            let escaped = shell_single_quote(raw);
            let script = format!("echo {escaped}");
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("bash must be available");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                stdout.trim_end(),
                *raw,
                "shell_single_quote round-trip failed for {raw:?}: script={script:?}"
            );
        }
    }

    // ── Bug 8 regression: bypass_probe shell_single_quote with apostrophe ─
    //
    // PRE-FIX BUG: the curl reproducer lines in bypass_probe were built with
    // raw string interpolation using bare single-quote delimiters:
    //   `curl -s -H '{}' '{}'`  (no escaping of ' inside the value)
    // A probe value containing `'` (e.g. X-Original-URL: /admin';DROP) or a
    // URL path with `'` produced a curl_cmd that was syntactically broken
    // shell — the practitioner couldn't copy-paste it to reproduce the finding.
    //
    // POST-FIX: every argument in the curl reproducer passes through
    // `shell_single_quote()`, which converts internal `'` → `'\''` (close,
    // escape, open). The resulting command is always valid Bourne shell.
    //
    // We test `shell_single_quote` directly because that's the deduped
    // primitive — all three probe kinds (header, path, method) now route
    // through it.

    #[test]
    fn shell_single_quote_with_apostrophe_in_url_path_is_valid_shell() {
        // A URL path containing a single quote: `/admin'path`
        // Pre-fix: this would appear as `'/admin'path'` which is syntactically
        // broken (the third `'` is an unclosed string). Post-fix: `'/admin'\''path'`.
        let url = "http://target.example.com/admin'path?id=1";
        let quoted = shell_single_quote(url);

        // The output must start and end with a single quote.
        assert!(quoted.starts_with('\''), "must be single-quoted: {quoted}");
        assert!(quoted.ends_with('\''), "must be single-quoted: {quoted}");

        // The interior must not contain a bare `'` (only the escaped form `'\''`).
        // Strip the outer quotes and check:
        let inner = &quoted[1..quoted.len() - 1];
        // Bare `'` in the interior means the quoting is broken.
        // The only allowed `'` sequences in a correctly Bourne-escaped
        // string interior are `'\''` (or empty). We check that
        // there's no isolated `'` that doesn't form `'\''`.
        let mut i = 0;
        let chars: Vec<char> = inner.chars().collect();
        while i < chars.len() {
            if chars[i] == '\'' {
                // A `'` in the interior must be followed by `\''` — that's
                // the close-escape-reopen sequence.
                assert!(
                    i + 3 < chars.len()
                        && chars[i + 1] == '\\'
                        && chars[i + 2] == '\''
                        && chars[i + 3] == '\'',
                    "bare apostrophe in shell_single_quote output interior \
                     — should be '\\''  (the standard Bourne escape).\n\
                     input={url:?}\noutput={quoted:?}\nposition={i}"
                );
                i += 4;
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn shell_single_quote_header_value_with_apostrophe_is_valid() {
        // X-Original-URL probe value: `/path?q=it's`
        // Pre-fix: curl reproducer `'X-Original-URL: /path?q=it's'` is broken.
        // Post-fix: `'X-Original-URL: /path?q=it'\''s'`.
        let header_val = "X-Original-URL: /path?q=it's";
        let quoted = shell_single_quote(header_val);

        // Round-trip: splitting on `'\''` and reassembling gives back the original.
        // Simplified check: the quoted form, when unescaped by the Bourne rules,
        // yields the original string. We implement that manually.
        let reconstructed = quoted.trim_matches('\'').replace("'\\''", "'");
        assert_eq!(
            reconstructed, header_val,
            "shell_single_quote must round-trip: input={header_val:?}, \
             quoted={quoted:?}, reconstructed={reconstructed:?}"
        );
    }

    // ── Bug 13 regression: walk_reqwest_error chain depth ────────────────
    //
    // PRE-FIX BUG: detect_cmd, bank_registry, and bypass_probe called
    // `format!("{e}")` on reqwest::Error, which only shows the top-level
    // description ("error sending request for url ...") — not the underlying
    // DNS / TCP / TLS cause. Operators saw uninformative one-liners.
    //
    // POST-FIX: `walk_reqwest_error` was extracted and now walks
    // `std::error::Error::source` until it returns None, joining each level
    // with " — caused by: ".
    //
    // We test the walker with a mock error chain using a std::error::Error
    // implementation — this is a pure unit test that doesn't need reqwest.

    #[derive(Debug)]
    struct ChainedError {
        msg: &'static str,
        cause: Option<Box<dyn std::error::Error + Send + Sync>>,
    }
    impl std::fmt::Display for ChainedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.msg)
        }
    }
    impl std::error::Error for ChainedError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.cause.as_ref().map(|b| b.as_ref() as &_)
        }
    }

    /// A shallow clone of `walk_reqwest_error`'s algorithm applied to any
    /// `std::error::Error` chain, so we can test the chain-walk logic without
    /// needing a real `reqwest::Error` (which is hard to construct in tests).
    fn walk_std_error(e: &dyn std::error::Error) -> String {
        let mut detail = e.to_string();
        let mut src = e.source();
        while let Some(s) = src {
            detail.push_str(" — caused by: ");
            detail.push_str(&s.to_string());
            src = s.source();
        }
        detail
    }

    #[test]
    fn walk_error_surfaces_single_level() {
        // PRE-FIX: `format!("{e}")` returns only the top-level message.
        // POST-FIX: the walker also surfaces it (no regression for 1-level chain).
        let e = ChainedError {
            msg: "outer error",
            cause: None,
        };
        let walked = walk_std_error(&e);
        assert_eq!(walked, "outer error");
    }

    #[test]
    fn walk_error_surfaces_deep_cause_chain() {
        // PRE-FIX: `format!("{e}")` → "outer error" only.
        // POST-FIX: walk_reqwest_error joins every level.
        let root = ChainedError {
            msg: "connection refused",
            cause: None,
        };
        let mid = ChainedError {
            msg: "tcp connect failed",
            cause: Some(Box::new(root)),
        };
        let top = ChainedError {
            msg: "error sending request",
            cause: Some(Box::new(mid)),
        };
        let walked = walk_std_error(&top);
        assert_eq!(
            walked,
            "error sending request — caused by: tcp connect failed — caused by: connection refused",
            "walk_std_error must join every level of the cause chain"
        );
        // Anti-regression: the result must NOT be just the top-level string.
        assert_ne!(
            walked, "error sending request",
            "bare top-level message means the cause chain was not walked"
        );
    }

    // ── url_query_repro_curl ──────────────────────────────────────

    #[test]
    fn url_query_repro_curl_wraps_param_value_pair_in_single_quotes() {
        let curl = url_query_repro_curl("https://x/y", "q", "abc");
        assert!(curl.starts_with("curl -G --data-urlencode "));
        assert!(curl.contains("'q=abc'"));
        assert!(curl.contains("'https://x/y'"));
    }

    #[test]
    fn url_query_repro_curl_protects_metacharacters_in_payload() {
        // `$(rm -rf /)` is the classic shell-injection canary. After
        // single-quoting it must appear verbatim, no expansion.
        let curl = url_query_repro_curl("https://target", "q", "$(rm -rf /); `whoami`");
        assert!(curl.contains("'q=$(rm -rf /); `whoami`'"));
    }

    #[test]
    fn url_query_repro_curl_handles_apostrophe_in_payload() {
        // The canonical SQLi `' OR 1=1--` contains the same quote
        // character we use to wrap the arg. shell_single_quote
        // escapes it via '\'' — the curl must still be parseable
        // by bash.
        let curl = url_query_repro_curl("https://x", "q", "' OR 1=1--");
        // Resulting form: 'q='\'' OR 1=1--' — the '\'' is the close-
        // escape-open sequence.
        assert!(curl.contains("'\\''"), "apostrophe not escaped: {curl}");
        // The literal payload bytes must appear unmangled across
        // the escape boundary.
        assert!(curl.contains("OR 1=1--"));
    }

    #[test]
    fn url_query_repro_curl_handles_empty_payload() {
        let curl = url_query_repro_curl("https://x", "q", "");
        // 'q=' is the right wire form for an empty value.
        assert!(curl.contains("'q='"));
    }

    #[test]
    fn url_query_repro_curl_handles_ampersand_in_payload_without_breaking_arg() {
        // & inside the payload must NOT split into a second curl
        // argument — single-quoting protects it.
        let curl = url_query_repro_curl("https://x", "q", "a&b=c");
        assert!(
            curl.contains("'q=a&b=c'"),
            "ampersand split arg or was re-encoded: {curl}"
        );
    }

    // ── normalize_target_url ──────────────────────────────────────────

    #[test]
    fn normalize_bare_hostname_prepends_https() {
        assert_eq!(normalize_target_url("example.com"), "https://example.com");
    }

    #[test]
    fn normalize_http_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("http://example.com"),
            "http://example.com"
        );
    }

    #[test]
    fn normalize_https_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("https://example.com"),
            "https://example.com"
        );
    }

    #[test]
    fn normalize_ws_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("ws://example.com"),
            "ws://example.com"
        );
    }

    #[test]
    fn normalize_wss_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("wss://example.com"),
            "wss://example.com"
        );
    }

    #[test]
    fn normalize_whitespace_stripped() {
        assert_eq!(
            normalize_target_url("  example.com  "),
            "https://example.com"
        );
    }

    #[test]
    fn normalize_host_with_port_prepends_https() {
        assert_eq!(
            normalize_target_url("example.com:8080"),
            "https://example.com:8080"
        );
    }

    #[test]
    fn normalize_host_with_path_prepends_https() {
        assert_eq!(
            normalize_target_url("example.com/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn normalize_ipv4_literal_prepends_https() {
        assert_eq!(
            normalize_target_url("192.168.1.1"),
            "https://192.168.1.1"
        );
    }

    #[test]
    fn normalize_ipv4_with_port_and_path() {
        assert_eq!(
            normalize_target_url("127.0.0.1:8080/admin"),
            "https://127.0.0.1:8080/admin"
        );
    }

    #[test]
    fn normalize_localhost_prepends_https() {
        assert_eq!(
            normalize_target_url("localhost"),
            "https://localhost"
        );
    }

    #[test]
    fn normalize_localhost_with_port() {
        assert_eq!(
            normalize_target_url("localhost:3000"),
            "https://localhost:3000"
        );
    }

    #[test]
    fn normalize_protocol_relative_promotes_to_https() {
        assert_eq!(
            normalize_target_url("//example.com"),
            "https://example.com"
        );
    }

    #[test]
    fn normalize_scheme_typo_passes_through_for_caller_error() {
        // A misspelled scheme like "htps://example.com" still contains "://"
        // so it passes through unchanged — reqwest will surface the parse error.
        let out = normalize_target_url("htps://example.com");
        assert_eq!(out, "htps://example.com");
    }

    #[test]
    fn normalize_empty_input_prepends_https() {
        // Empty string → "https://" — reqwest will error, which is correct.
        assert_eq!(normalize_target_url(""), "https://");
    }

    #[test]
    fn normalize_whitespace_only_becomes_https_empty() {
        assert_eq!(normalize_target_url("   "), "https://");
    }

    #[test]
    fn normalize_host_with_query_string() {
        assert_eq!(
            normalize_target_url("example.com/search?q=test"),
            "https://example.com/search?q=test"
        );
    }

    #[test]
    fn normalize_ftp_scheme_passes_through() {
        // Any declared scheme passes through — caller decides if it's valid.
        assert_eq!(
            normalize_target_url("ftp://files.example.com"),
            "ftp://files.example.com"
        );
    }
}
