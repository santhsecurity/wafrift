//! Header-obfuscation phase — Step 6/7 of `wafrift scan`.
//!
//! Re-emit each top-confidence payload with the Content-Type /
//! X-Forwarded-For header NAME mutated through the
//! wafrift-encoding header-obfuscation primitives (case mixing,
//! underscore substitution, null-byte injection, whitespace
//! padding, trailing space, line folding). WAFs that key their
//! body-processor selection on a strict header-name match miss
//! the variant entirely; backends that fold header names
//! case-insensitively (HTTP/1.1 RFC 9110 §5.1) still see the
//! same Content-Type and parse the body normally.
//!
//! Mirrors `scan::multi_vector` structurally — a separate module
//! so the dispatch + per-technique wire shape doesn't live in
//! scan/mod.rs.
//!
//! Same rescue treatment as multi_vector: tries both
//! already-bypassed payloads AND top blocked payloads, tagging
//! rescue wins with `header::<technique>::rescue`.

use std::time::Duration;

use colored::Colorize;
use reqwest::Client;
use tokio_util::sync::CancellationToken;
use wafrift_encoding::header as header_obfuscation;
use wafrift_oracle::response_oracle::{ResponseContext, ResponseOracle};

/// One header-obfuscation technique. The `target_header` is the
/// canonical header name being mutated; the `value` is what the
/// header carries on the wire.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeaderTechnique {
    pub name: &'static str,
    pub target_header: &'static str,
}

/// Catalogue. Adding a new technique = one row + one match arm in
/// `obfuscate`. The catalogue stays narrow on purpose — every
/// technique here corresponds to a documented WAF parser bug
/// that's worth re-emitting against fresh targets.
pub(crate) const TECHNIQUES: &[HeaderTechnique] = &[
    HeaderTechnique {
        name: "case_mixing",
        target_header: "Content-Type",
    },
    HeaderTechnique {
        name: "underscore_sub",
        target_header: "Content-Type",
    },
    HeaderTechnique {
        name: "null_byte",
        target_header: "X-Forwarded-For",
    },
    HeaderTechnique {
        name: "whitespace_pad",
        target_header: "Content-Type",
    },
    HeaderTechnique {
        name: "trailing_space",
        target_header: "Content-Type",
    },
    HeaderTechnique {
        name: "line_fold",
        target_header: "Content-Type",
    },
];

const HEADER_VALUE: &str = "application/x-www-form-urlencoded";

/// Apply `technique` to `target_header` and return the obfuscated
/// header-name string the request should carry. Pure function —
/// no I/O.
#[must_use]
pub(crate) fn obfuscate(technique: &HeaderTechnique) -> String {
    match technique.name {
        "case_mixing" => header_obfuscation::case_mix(technique.target_header),
        "underscore_sub" => header_obfuscation::underscore_substitute(technique.target_header),
        "null_byte" => header_obfuscation::null_byte_inject(technique.target_header),
        "whitespace_pad" => {
            header_obfuscation::whitespace_pad(technique.target_header, HEADER_VALUE)
        }
        "trailing_space" => {
            header_obfuscation::trailing_space(technique.target_header, HEADER_VALUE)
        }
        "line_fold" => header_obfuscation::line_fold(technique.target_header, HEADER_VALUE),
        _ => technique.target_header.to_string(),
    }
}

/// The phase's I/O surface.
pub(crate) struct PhaseInput<'a> {
    pub http: &'a Client,
    pub target: &'a str,
    pub param: &'a str,
    /// Already-bypassed payloads — broaden the bypass set.
    pub top_payloads: &'a [String],
    /// Top blocked payloads — rescue attempts.
    pub rescue_payloads: &'a [String],
    pub oracle: &'a ResponseOracle,
    pub cancel: &'a CancellationToken,
    pub scan_text: bool,
    pub delay: Duration,
    /// Starting fire counter for monotone telemetry IDs.
    pub variant_id_base: usize,
    /// Global fires already counted by the orchestrator before this phase.
    pub fires_so_far: usize,
    /// Global fire-budget cap (--max-fires). 0 = unlimited.
    pub max_fires: usize,
}

#[derive(Debug, Default)]
pub(crate) struct PhaseOutcome {
    pub total_fired_delta: usize,
    pub bypassed_delta: u32,
    pub blocked_delta: u32,
    pub errors_delta: u32,
    pub new_bypass_variants: Vec<(usize, String, Vec<String>, f64)>,
    pub new_variant_outcomes: Vec<(Vec<String>, bool)>,
}

/// Build the (param=urlencoded(payload)) URL. INTENTIONALLY a
/// raw string-concat — NOT a delegation to
/// `super::scan_url_with_param`. The two paths produce different
/// outputs by design:
///
/// * `scan_url_with_param` routes through `reqwest::Url::query_pairs_mut`
///   which RE-ENCODES any `%` in the input, double-encoding pre-
///   encoded payloads (`%E2%9C%93` → `%25E2%259C%2593`). All scan-
///   path callers already call `urlencoding::encode(...)` before
///   passing to it, so the actual wire is double-encoded.
/// * The header-obfuscation path needs the payload BYTES to land
///   on the wire singly-encoded (the whole point of encoding-based
///   bypass), so this local helper concatenates the already-encoded
///   value without a second pass.
///
/// Unifying the two requires fixing `scan_url_with_param` to NOT
/// re-encode (changes 10+ call sites + tests). Tracked separately;
/// leaving the duplication explicit here is the safer interim.
fn scan_url(target: &str, param: &str, value_encoded: &str) -> String {
    if target.contains('?') {
        format!("{target}&{param}={value_encoded}")
    } else {
        format!("{target}?{param}={value_encoded}")
    }
}

pub(crate) async fn run_phase(input: PhaseInput<'_>) -> PhaseOutcome {
    let mut outcome = PhaseOutcome::default();

    let combined: Vec<(&String, bool)> = input
        .top_payloads
        .iter()
        .map(|p| (p, false))
        .chain(input.rescue_payloads.iter().map(|p| (p, true)))
        .collect();

    if input.scan_text {
        eprintln!(
            "\n{}",
            format!(
                "[6/7] Header obfuscation — {} payloads ({} bypass + {} rescue) × {} techniques...",
                combined.len(),
                input.top_payloads.len(),
                input.rescue_payloads.len(),
                TECHNIQUES.len()
            )
            .bold()
            .cyan()
        );
    }

    for (payload, is_rescue) in &combined {
        if input.cancel.is_cancelled() {
            break;
        }
        // Respect the global --max-fires budget. 0 = unlimited.
        if input.max_fires != 0 && input.fires_so_far + outcome.total_fired_delta >= input.max_fires
        {
            break;
        }
        for technique in TECHNIQUES {
            if input.cancel.is_cancelled() {
                break;
            }
            // Also gate the inner loop per-fire.
            if input.max_fires != 0
                && input.fires_so_far + outcome.total_fired_delta >= input.max_fires
            {
                break;
            }
            let obfuscated_header = obfuscate(technique);
            let url = scan_url(input.target, input.param, &urlencoding::encode(payload));

            let result = input
                .http
                .get(&url)
                .header(&obfuscated_header, HEADER_VALUE)
                .send()
                .await;

            let verdict = match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = crate::safe_body::read_bounded(
                        resp,
                        crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                    )
                    .await
                    .unwrap_or_default();
                    input.oracle.classify(&ResponseContext {
                        status,
                        body: body.to_vec(),
                        ..Default::default()
                    })
                }
                Err(_) => {
                    outcome.errors_delta += 1;
                    continue;
                }
            };

            outcome.total_fired_delta += 1;
            let tag = if *is_rescue {
                format!("header::{}::rescue", technique.name)
            } else {
                format!("header::{}", technique.name)
            };
            let techs = vec![tag];
            outcome
                .new_variant_outcomes
                .push((techs.clone(), verdict.is_blocked()));

            if !verdict.is_blocked() && !verdict.is_challenge() {
                outcome.bypassed_delta += 1;
                outcome.new_bypass_variants.push((
                    input.variant_id_base + outcome.total_fired_delta,
                    (*payload).clone(),
                    techs,
                    if *is_rescue { 0.75 } else { 0.85 },
                ));
                if input.scan_text {
                    let marker = if *is_rescue { "R" } else { "!" };
                    print!("{}", marker.bright_green().bold());
                }
            } else {
                outcome.blocked_delta += 1;
                if input.scan_text {
                    print!("{}", ".".bright_black());
                }
            }

            if !input.delay.is_zero() {
                tokio::time::sleep(input.delay).await;
            }
        }
    }

    if input.scan_text && outcome.total_fired_delta > 0 {
        let rate = f64::from(outcome.bypassed_delta) / outcome.total_fired_delta as f64 * 100.0;
        eprintln!(
            "\n  {} {}",
            "Header results:".bold().cyan(),
            format!(
                "{}/{} bypassed ({rate:.0}%)",
                outcome.bypassed_delta, outcome.total_fired_delta
            )
            .yellow()
        );
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn techniques_catalogue_is_unique_by_name() {
        let mut seen = std::collections::HashSet::new();
        for t in TECHNIQUES {
            assert!(seen.insert(t.name), "duplicate technique: {}", t.name);
        }
    }

    #[test]
    fn techniques_catalogue_covers_documented_classes() {
        // Anti-rig: a refactor that dropped case_mixing or
        // line_fold would silently weaken the engine. Lock the
        // headline techniques in.
        let names: std::collections::HashSet<&str> = TECHNIQUES.iter().map(|t| t.name).collect();
        for required in ["case_mixing", "underscore_sub", "null_byte", "line_fold"] {
            assert!(names.contains(required), "missing {required}");
        }
    }

    #[test]
    fn obfuscate_case_mixing_changes_header_name_casing() {
        let t = TECHNIQUES.iter().find(|t| t.name == "case_mixing").unwrap();
        let out = obfuscate(t);
        // Output must differ in casing from the canonical
        // Content-Type. case_mix is the wafrift-encoding helper;
        // it always returns SOMETHING different than the input.
        assert!(out.eq_ignore_ascii_case("content-type"));
        assert_ne!(out, "Content-Type", "case_mix must actually mix casing");
    }

    #[test]
    fn obfuscate_underscore_substitute_replaces_dashes() {
        let t = TECHNIQUES
            .iter()
            .find(|t| t.name == "underscore_sub")
            .unwrap();
        let out = obfuscate(t);
        assert!(out.contains('_'), "underscore_sub must produce '_'");
    }

    #[test]
    fn obfuscate_null_byte_injects_null_into_header_name() {
        let t = TECHNIQUES.iter().find(|t| t.name == "null_byte").unwrap();
        let out = obfuscate(t);
        // Null-byte inject puts \0 in the header name. Verify the
        // raw bytes contain it.
        assert!(out.as_bytes().contains(&0), "null_byte must inject \\0");
    }

    #[test]
    fn obfuscate_unknown_technique_returns_canonical_header() {
        // Defence in depth — a misspelled technique key returns
        // the un-mutated header name instead of panicking.
        let bogus = HeaderTechnique {
            name: "not_a_real_technique",
            target_header: "Content-Type",
        };
        assert_eq!(obfuscate(&bogus), "Content-Type");
    }

    #[test]
    fn scan_url_appends_query_when_no_existing_query() {
        let u = scan_url("http://x/", "q", "abc");
        assert_eq!(u, "http://x/?q=abc");
    }

    #[test]
    fn scan_url_appends_with_ampersand_when_query_exists() {
        let u = scan_url("http://x/?a=1", "q", "abc");
        assert_eq!(u, "http://x/?a=1&q=abc");
    }

    #[tokio::test]
    async fn run_phase_with_empty_payloads_returns_zero_deltas() {
        use wafrift_oracle::response_oracle::ResponseOracle;
        let h = reqwest::Client::builder().build().unwrap();
        let cancel = CancellationToken::new();
        let oracle = ResponseOracle::new();
        let outcome = run_phase(PhaseInput {
            http: &h,
            target: "http://127.0.0.1:1/",
            param: "q",
            top_payloads: &[],
            rescue_payloads: &[],
            oracle: &oracle,
            cancel: &cancel,
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 0,
            fires_so_far: 0,
            max_fires: 0, // 0 = unlimited
        })
        .await;
        assert_eq!(outcome.total_fired_delta, 0);
        assert!(outcome.new_bypass_variants.is_empty());
    }

    #[tokio::test]
    async fn run_phase_exits_immediately_when_cancelled() {
        use wafrift_oracle::response_oracle::ResponseOracle;
        let h = reqwest::Client::builder().build().unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let oracle = ResponseOracle::new();
        let outcome = run_phase(PhaseInput {
            http: &h,
            target: "http://127.0.0.1:1/",
            param: "q",
            top_payloads: &["x".into()],
            rescue_payloads: &[],
            oracle: &oracle,
            cancel: &cancel,
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 0,
            fires_so_far: 0,
            max_fires: 0, // 0 = unlimited
        })
        .await;
        assert_eq!(outcome.total_fired_delta, 0);
        assert_eq!(outcome.bypassed_delta, 0);
        assert_eq!(outcome.blocked_delta, 0);
        assert_eq!(outcome.errors_delta, 0);
        assert!(outcome.new_bypass_variants.is_empty());
        assert!(outcome.new_variant_outcomes.is_empty());
    }

    #[test]
    fn techniques_catalogue_size_matches_expected_count() {
        // Anti-rig: the spec describes 6 techniques. A refactor
        // that silently dropped one (or added a duplicate masking
        // an old one) would break the bypass surface. Lock the
        // expected count in.
        assert_eq!(
            TECHNIQUES.len(),
            6,
            "documented technique count: case_mixing, underscore_sub, null_byte, \
             whitespace_pad, trailing_space, line_fold"
        );
    }

    #[test]
    fn techniques_all_target_either_content_type_or_x_forwarded_for() {
        // Each technique mutates ONE specific header — the
        // catalogue's invariant is that mutation targets are
        // either Content-Type (body-processor-routing) or
        // X-Forwarded-For (IP-classification). A new technique
        // targeting something exotic should be added thoughtfully.
        let targets: std::collections::HashSet<&str> =
            TECHNIQUES.iter().map(|t| t.target_header).collect();
        for tgt in &targets {
            assert!(
                ["Content-Type", "X-Forwarded-For"].contains(tgt),
                "unexpected target header in catalogue: {tgt}"
            );
        }
    }

    #[test]
    fn techniques_canonical_target_headers_use_title_case() {
        // RFC 9110 §5.1: header names are case-insensitive on the
        // wire, but our catalogue uses Title-Case (Content-Type
        // not content-type) for human readability and grep'ability
        // of the source. Lock the convention.
        for t in TECHNIQUES {
            let first = t.target_header.chars().next().unwrap();
            assert!(
                first.is_ascii_uppercase(),
                "target header {} should start with an uppercase letter",
                t.target_header
            );
        }
    }

    #[test]
    fn obfuscate_case_mixing_preserves_canonical_header_when_lowercased() {
        // case_mix may permute casing arbitrarily, but the
        // lowercased output MUST equal the canonical lowercased
        // header name — otherwise the WAF / origin see a
        // different header than we intended.
        let t = TECHNIQUES.iter().find(|t| t.name == "case_mixing").unwrap();
        for _ in 0..10 {
            let out = obfuscate(t);
            assert_eq!(out.to_ascii_lowercase(), "content-type");
        }
    }

    #[test]
    fn obfuscate_underscore_sub_lowercased_replaces_hyphens_with_underscores() {
        // underscore_substitute outputs `content_type` (or some
        // casing). Lowercase form MUST equal `content_type`
        // — apps that map header names through `_` aliasing
        // (PHP / nginx) will see the same effective key but
        // a strict WAF table-driven match won't.
        let t = TECHNIQUES
            .iter()
            .find(|t| t.name == "underscore_sub")
            .unwrap();
        let out = obfuscate(t);
        assert_eq!(out.to_ascii_lowercase(), "content_type");
    }

    #[test]
    fn obfuscate_null_byte_contains_only_one_null() {
        // Defensive: exactly one NULL injected (per the spec —
        // multiple nulls would be a different attack class with
        // its own coverage).
        let t = TECHNIQUES.iter().find(|t| t.name == "null_byte").unwrap();
        let out = obfuscate(t);
        let null_count = out.as_bytes().iter().filter(|&&b| b == 0).count();
        assert_eq!(null_count, 1, "must inject exactly ONE null");
    }

    #[test]
    fn obfuscate_null_byte_keeps_target_header_recognisable() {
        // The post-null bytes should still spell out
        // X-Forwarded-For (or a case variant). Strip the null and
        // compare lowercase.
        let t = TECHNIQUES.iter().find(|t| t.name == "null_byte").unwrap();
        let out = obfuscate(t);
        let cleaned: String = out.chars().filter(|c| *c != '\0').collect();
        // The mutator may swap a single char to null but most
        // bytes survive — confirm enough remain that the header
        // is still identifiable.
        let lower = cleaned.to_ascii_lowercase();
        assert!(
            lower.contains("forwarded") || lower.contains("orwarded"),
            "null-byte injection should leave the rest of the header name intact"
        );
    }

    #[test]
    fn obfuscate_whitespace_pad_includes_header_name_and_value() {
        // whitespace_pad emits the WHOLE header line (`Name: value`)
        // with random whitespace padding around both sides of the
        // value. Confirm the canonical header name and the
        // application/x-www-form-urlencoded value both appear
        // somewhere in the output.
        let t = TECHNIQUES
            .iter()
            .find(|t| t.name == "whitespace_pad")
            .unwrap();
        let out = obfuscate(t);
        let lower = out.to_ascii_lowercase();
        assert!(lower.contains("content-type"), "{out:?}");
        assert!(
            lower.contains("application/x-www-form-urlencoded"),
            "{out:?}"
        );
    }

    #[test]
    fn obfuscate_trailing_space_returns_some_string() {
        // trailing_space may produce just the canonical name with
        // a trailing space or tab. The test asserts the function
        // returns a non-empty string — exact byte shape is the
        // underlying library's concern.
        let t = TECHNIQUES
            .iter()
            .find(|t| t.name == "trailing_space")
            .unwrap();
        let out = obfuscate(t);
        assert!(!out.is_empty());
    }

    #[test]
    fn obfuscate_line_fold_returns_some_string() {
        let t = TECHNIQUES.iter().find(|t| t.name == "line_fold").unwrap();
        let out = obfuscate(t);
        assert!(!out.is_empty());
    }

    #[test]
    fn obfuscate_for_each_documented_technique_returns_non_empty() {
        // Catalogue-wide invariant — no technique returns empty.
        // Anti-rig: a refactor that broke one of the underlying
        // wafrift-encoding helpers would surface as empty output
        // (silent regression on a less-tested helper).
        for t in TECHNIQUES {
            let out = obfuscate(t);
            assert!(
                !out.is_empty(),
                "{} returned empty obfuscated header",
                t.name
            );
        }
    }

    #[test]
    fn obfuscate_returns_string_different_from_target_for_mutating_techniques() {
        // Every technique EXCEPT trailing_space + line_fold is
        // expected to materially change the header name. (The
        // latter two operate on the header VALUE.) Track them
        // separately so a regression that flattens case_mixing
        // back to canonical surfaces here.
        for t in TECHNIQUES {
            let out = obfuscate(t);
            match t.name {
                "case_mixing" | "underscore_sub" | "null_byte" | "whitespace_pad" => {
                    assert_ne!(
                        out, t.target_header,
                        "{} must mutate the canonical header name",
                        t.name
                    );
                }
                _ => {
                    // trailing_space / line_fold may pass the name
                    // through unchanged — they live in the VALUE.
                }
            }
        }
    }

    #[test]
    fn header_value_constant_is_a_real_mime_type() {
        // The constant the catalogue uses must be a real
        // form-urlencoded MIME — typos would silently break
        // every header-obfuscation probe. Lock the literal in.
        assert_eq!(HEADER_VALUE, "application/x-www-form-urlencoded");
    }

    #[test]
    fn scan_url_handles_target_with_existing_path_no_query() {
        let u = scan_url("http://x/a/b/c", "q", "x");
        assert_eq!(u, "http://x/a/b/c?q=x");
    }

    #[test]
    fn scan_url_handles_target_with_trailing_question_mark() {
        let u = scan_url("http://x/a?", "q", "x");
        assert_eq!(u, "http://x/a?&q=x");
    }

    #[test]
    fn scan_url_handles_target_with_existing_multi_param_query() {
        let u = scan_url("http://x/?a=1&b=2", "q", "v");
        assert_eq!(u, "http://x/?a=1&b=2&q=v");
    }

    #[test]
    fn scan_url_handles_unicode_in_value() {
        // The fn doesn't urlencode (caller does); confirm pass-
        // through for non-ASCII so a future refactor doesn't
        // accidentally double-encode.
        let u = scan_url("http://x/", "q", "%E2%9C%93");
        assert_eq!(u, "http://x/?q=%E2%9C%93");
    }

    #[test]
    fn scan_url_empty_param_value_works() {
        let u = scan_url("http://x/", "q", "");
        assert_eq!(u, "http://x/?q=");
    }

    #[test]
    fn phase_outcome_default_is_all_zero() {
        let o = PhaseOutcome::default();
        assert_eq!(o.total_fired_delta, 0);
        assert_eq!(o.bypassed_delta, 0);
        assert_eq!(o.blocked_delta, 0);
        assert_eq!(o.errors_delta, 0);
        assert!(o.new_bypass_variants.is_empty());
        assert!(o.new_variant_outcomes.is_empty());
    }

    #[tokio::test]
    async fn run_phase_with_only_rescue_payloads_still_runs_techniques() {
        // When top_payloads is empty but rescue_payloads has
        // entries, the phase MUST still fire — rescue alone is a
        // valid mode (e.g. the first scan iteration where the
        // explore phase found no bypasses but blocked variants
        // are worth rescuing).
        use wafrift_oracle::response_oracle::ResponseOracle;
        let h = reqwest::Client::builder().build().unwrap();
        let cancel = CancellationToken::new();
        let oracle = ResponseOracle::new();
        let _outcome = run_phase(PhaseInput {
            http: &h,
            target: "http://127.0.0.1:1/", // unreachable on purpose
            param: "q",
            top_payloads: &[],
            rescue_payloads: &["payload-to-rescue".into()],
            oracle: &oracle,
            cancel: &cancel,
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 0,
            fires_so_far: 0,
            max_fires: 0, // 0 = unlimited
        })
        .await;
        // The unreachable target produces only errors_delta, but
        // the IMPORTANT property is the function returns without
        // panic — the rescue-only path is a valid mode.
    }

    #[tokio::test]
    async fn run_phase_combines_top_and_rescue_in_one_pass() {
        // Both pools at once — no duplication of techniques, no
        // panic. (Errors-only path because target is unreachable.)
        use wafrift_oracle::response_oracle::ResponseOracle;
        let h = reqwest::Client::builder().build().unwrap();
        let cancel = CancellationToken::new();
        let oracle = ResponseOracle::new();
        let outcome = run_phase(PhaseInput {
            http: &h,
            target: "http://127.0.0.1:1/",
            param: "q",
            top_payloads: &["top-1".into(), "top-2".into()],
            rescue_payloads: &["rescue-1".into()],
            oracle: &oracle,
            cancel: &cancel,
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 0,
            fires_so_far: 0,
            max_fires: 0, // 0 = unlimited
        })
        .await;
        // 3 payloads × 6 techniques = 18 attempted fires; each
        // fails at the network layer so each becomes an error.
        let attempted = outcome.errors_delta as usize + outcome.total_fired_delta;
        assert_eq!(
            attempted, 18,
            "every (payload, technique) combination must be attempted"
        );
    }

    #[test]
    fn header_technique_struct_can_be_copied_in_const_context() {
        // Anti-rig: HeaderTechnique was derive(Copy) so the const
        // slice composition works. A future refactor that
        // accidentally removed Copy would surface here.
        const _CHECK: HeaderTechnique = TECHNIQUES[0];
    }

    #[test]
    fn techniques_with_underscore_target_only_one_specific_header() {
        // Cross-axis anti-rig: underscore_sub should ONLY be
        // associated with Content-Type (X-Forwarded-For has no
        // dash to substitute and would noop).
        let underscore = TECHNIQUES
            .iter()
            .find(|t| t.name == "underscore_sub")
            .unwrap();
        assert_eq!(underscore.target_header, "Content-Type");
    }

    #[test]
    fn techniques_null_byte_targets_xff_not_content_type() {
        // Cross-axis anti-rig: null-byte injection is documented
        // against X-Forwarded-For (IP-classification confusion);
        // the catalogue should reflect that.
        let nb = TECHNIQUES.iter().find(|t| t.name == "null_byte").unwrap();
        assert_eq!(nb.target_header, "X-Forwarded-For");
    }

    #[test]
    fn obfuscate_deterministic_techniques_round_trip_equally() {
        // The DETERMINISTIC techniques (underscore_sub, null_byte,
        // trailing_space, line_fold) must return the same value on
        // every call. case_mixing and whitespace_pad use random
        // seeding internally (the former mixes casing per-call;
        // the latter randomises the whitespace amount) and are
        // documented exceptions.
        let deterministic = ["underscore_sub", "null_byte", "trailing_space", "line_fold"];
        for t in TECHNIQUES {
            if !deterministic.contains(&t.name) {
                continue;
            }
            let a = obfuscate(t);
            let b = obfuscate(t);
            assert_eq!(a, b, "{} must be deterministic", t.name);
        }
    }
}
