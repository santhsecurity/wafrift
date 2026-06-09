//! Passive **finding classification** for traffic another tool drives through
//! wafrift-proxy.
//!
//! wafrift is commonly chained as a proxy (sqlmap / Burp / Caido / ffuf /
//! manual → wafrift-proxy → target). Those tools provide the payloads; wafrift,
//! sitting in the path, classifies each transaction it forwards: did a request
//! input **reflect** in the response, and does that reflection actually
//! **execute**? This turns wafrift-as-a-proxy into a live exploit-classifier —
//! separating "the input came back" (noise every scanner floods you with) from
//! "the input runs" (a confirmed client-side exploit), for whatever tool is
//! driving the traffic.
//!
//! Reflection detection is cheap and always on. Execution proof is opt-in (it
//! shells out to the external `detonate` tool) and only attempted when a
//! reflection landed in an HTML response — see [`classify`].

/// How a single proxied transaction classifies as a (potential) finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingClass {
    /// No request input reflected in the response — nothing to flag.
    None,
    /// One or more inputs reflected, but execution was not proven (response
    /// wasn't HTML, the detonate tool was unavailable, or the reflection lands
    /// in a non-executable context). Worth a human look — the noisy default.
    Reflected { params: Vec<String> },
    /// A reflected input EXECUTED in the jsdet sandbox — a confirmed
    /// client-side exploit (e.g. `alert(1)` fired), not merely a reflection.
    ExploitConfirmed {
        params: Vec<String>,
        sink: String,
        message: String,
    },
}

impl FindingClass {
    /// A short, operator-facing one-liner for the proxy log / findings report.
    #[must_use]
    pub fn summary(&self) -> Option<String> {
        match self {
            FindingClass::None => None,
            FindingClass::Reflected { params } => Some(format!(
                "REFLECTED — input(s) {} echoed in the response (review for XSS)",
                params.join(", ")
            )),
            FindingClass::ExploitConfirmed {
                params,
                sink,
                message,
            } => Some(format!(
                "EXPLOIT CONFIRMED — input(s) {} reflect and EXECUTE `{sink}({message})` in a sandbox (client-side exploit)",
                params.join(", ")
            )),
        }
    }

    /// True for the strongest verdict — a proven, executing exploit.
    #[must_use]
    pub fn is_exploit(&self) -> bool {
        matches!(self, FindingClass::ExploitConfirmed { .. })
    }
}

/// Minimum length of an input value we will treat as a reflection candidate.
/// Short values (`1`, `q`, `on`) reflect coincidentally all over a page and
/// would drown the signal in false positives; an attacker's payload is longer.
const MIN_REFLECT_LEN: usize = 6;

/// Which of `inputs` (the param/body values the driving tool sent) appear
/// verbatim in `body`. Skips values shorter than [`MIN_REFLECT_LEN`] and
/// de-duplicates. The match is a raw byte-substring check — exactly the
/// "did my input come back unmodified" question reflection-XSS turns on.
#[must_use]
pub fn reflected_inputs(inputs: &[String], body: &[u8]) -> Vec<String> {
    let mut hits = Vec::new();
    for v in inputs {
        if v.len() < MIN_REFLECT_LEN {
            continue;
        }
        if contains(body, v.as_bytes()) && !hits.contains(v) {
            hits.push(v.clone());
        }
    }
    hits
}

/// True iff `needle` occurs as a contiguous byte run in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// True when a response Content-Type can carry executable HTML/JS — the only
/// case where detonation can meaningfully prove execution.
#[must_use]
pub fn is_html_like(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("text/html") || ct.contains("application/xhtml") || ct.contains("image/svg")
}

/// Classify a forwarded transaction.
///
/// - `inputs`: the request param / body values the driving tool sent.
/// - `body` / `content_type` / `url`: the upstream response.
/// - `prove`: when `true` and a reflection landed in an HTML-like response,
///   detonate the body (out-of-process) to confirm execution.
///
/// `detonate` is the injected execution-proof hook — `None` from it (tool
/// absent / no sink fired) degrades the verdict to [`FindingClass::Reflected`].
/// Taking it as a parameter keeps this module pure and unit-testable without a
/// subprocess.
#[must_use]
pub fn classify(
    inputs: &[String],
    body: &[u8],
    content_type: &str,
    prove: bool,
    detonate: impl FnOnce(&[u8]) -> Option<DetonationVerdict>,
) -> FindingClass {
    let params = reflected_inputs(inputs, body);
    if params.is_empty() {
        return FindingClass::None;
    }
    if prove
        && is_html_like(content_type)
        && let Some(v) = detonate(body)
        && v.executed
    {
        return FindingClass::ExploitConfirmed {
            params,
            sink: v.sink,
            message: v.message,
        };
    }
    FindingClass::Reflected { params }
}

/// Minimal execution verdict the detonate hook returns (a sink fired + which).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetonationVerdict {
    pub executed: bool,
    pub sink: String,
    pub message: String,
}

/// Extract the candidate input VALUES the driving tool sent — query-string
/// params plus `application/x-www-form-urlencoded` body params — percent-decoded
/// so they match the (decoded) bytes that would reflect in the response. These
/// are the injection points reflection-XSS turns on; passing them to
/// [`reflected_inputs`] answers "did the tool's payload come back unmodified".
#[must_use]
pub fn extract_request_inputs(
    uri: &str,
    body: Option<&[u8]>,
    req_content_type: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((_, q)) = uri.split_once('?') {
        collect_pairs(q.as_bytes(), &mut out);
    }
    if req_content_type
        .to_ascii_lowercase()
        .contains("x-www-form-urlencoded")
        && let Some(b) = body
    {
        collect_pairs(b, &mut out);
    }
    out
}

/// Split `raw` on `&`, percent-decode each `name=VALUE`'s value, and push the
/// distinct non-empty results onto `out`.
fn collect_pairs(raw: &[u8], out: &mut Vec<String>) {
    for pair in raw.split(|&c| c == b'&') {
        let Some(eq) = pair.iter().position(|&c| c == b'=') else {
            continue;
        };
        let decoded = percent_decode(&pair[eq + 1..]);
        if !decoded.is_empty() && !out.contains(&decoded) {
            out.push(decoded);
        }
    }
}

/// Percent + `+`-decode a form/query value to the bytes that would appear in
/// the response if reflected. Lossy-UTF8 — the reflection check is byte-based.
fn percent_decode(v: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        match v[i] {
            b'+' => {
                bytes.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < v.len() => match (hexval(v[i + 1]), hexval(v[i + 2])) {
                (Some(h), Some(l)) => {
                    bytes.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    bytes.push(b'%');
                    i += 1;
                }
            },
            c => {
                bytes.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflected_inputs_finds_long_values_only() {
        let body = b"<html>q=hello and payload <script>alert(1)</script> here</html>";
        let inputs = vec![
            "q".to_string(),                         // too short
            "hello".to_string(),                     // 5 < MIN
            "<script>alert(1)</script>".to_string(), // reflected
            "notpresent-longvalue".to_string(),      // not in body
        ];
        let hits = reflected_inputs(&inputs, body);
        assert_eq!(hits, vec!["<script>alert(1)</script>".to_string()]);
    }

    #[test]
    fn classify_none_when_no_reflection() {
        let c = classify(
            &["notpresent-longvalue".into()],
            b"<html>clean</html>",
            "text/html",
            true,
            |_| panic!("must not detonate when nothing reflected"),
        );
        assert_eq!(c, FindingClass::None);
    }

    #[test]
    fn classify_reflected_when_not_html() {
        // Reflected into a JSON response — no executable context, so no
        // detonation is attempted and the verdict stays Reflected.
        let c = classify(
            &["<script>alert(1)</script>".into()],
            br#"{"q":"<script>alert(1)</script>"}"#,
            "application/json",
            true,
            |_| panic!("must not detonate a non-HTML response"),
        );
        assert!(matches!(c, FindingClass::Reflected { .. }));
    }

    #[test]
    fn classify_reflected_when_detonate_unavailable() {
        let c = classify(
            &["<script>alert(1)</script>".into()],
            b"<html><script>alert(1)</script></html>",
            "text/html",
            true,
            |_| None, // tool absent / nothing executed
        );
        assert!(matches!(c, FindingClass::Reflected { .. }));
    }

    #[test]
    fn classify_exploit_confirmed_when_execution_proven() {
        let c = classify(
            &["<script>alert(1)</script>".into()],
            b"<html><script>alert(1)</script></html>",
            "text/html; charset=utf-8",
            true,
            |_| {
                Some(DetonationVerdict {
                    executed: true,
                    sink: "alert".into(),
                    message: "1".into(),
                })
            },
        );
        assert!(c.is_exploit(), "{c:?}");
        assert!(c.summary().unwrap().contains("EXPLOIT CONFIRMED"));
        assert!(c.summary().unwrap().contains("alert(1)"));
    }

    #[test]
    fn classify_skips_detonation_when_prove_off() {
        let c = classify(
            &["<script>alert(1)</script>".into()],
            b"<html><script>alert(1)</script></html>",
            "text/html",
            false, // prove off
            |_| panic!("must not detonate when prove=false"),
        );
        assert!(matches!(c, FindingClass::Reflected { .. }));
    }

    #[test]
    fn extract_inputs_decodes_query_and_form() {
        // Query: percent-encoded XSS payload must decode to the bytes that
        // would reflect in the response.
        let q = extract_request_inputs(
            "http://t/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&page=2",
            None,
            "",
        );
        assert!(
            q.contains(&"<script>alert(1)</script>".to_string()),
            "{q:?}"
        );

        // Form body decoded only for form-urlencoded content type.
        let f = extract_request_inputs(
            "http://t/post",
            Some(b"name=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"),
            "application/x-www-form-urlencoded",
        );
        assert!(f.iter().any(|v| v.contains("onerror=alert(1)")), "{f:?}");

        // Non-form body is ignored (no false inputs from a JSON body).
        let j = extract_request_inputs("http://t/post", Some(b"{\"a\":\"b\"}"), "application/json");
        assert!(j.is_empty(), "{j:?}");
    }

    #[test]
    fn extract_then_reflect_end_to_end() {
        // The decoded query value reflects verbatim in an HTML response.
        let inputs =
            extract_request_inputs("http://t/r?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", None, "");
        let body = b"<html>you searched: <script>alert(1)</script></html>";
        assert_eq!(
            reflected_inputs(&inputs, body),
            vec!["<script>alert(1)</script>".to_string()]
        );
    }

    #[test]
    fn is_html_like_recognizes_executable_types() {
        assert!(is_html_like("text/html; charset=utf-8"));
        assert!(is_html_like("image/svg+xml"));
        assert!(is_html_like("application/xhtml+xml"));
        assert!(!is_html_like("application/json"));
        assert!(!is_html_like("text/plain"));
    }

    // ---- helpers -----------------------------------------------------------

    /// A detonate hook that must never be invoked — proves a code path skips
    /// detonation entirely (panics loudly if the contract is violated).
    fn no_detonate(_: &[u8]) -> Option<DetonationVerdict> {
        panic!("detonate hook must not be called on this path");
    }

    /// A detonate hook that always reports an executing sink.
    fn fired(_: &[u8]) -> Option<DetonationVerdict> {
        Some(DetonationVerdict {
            executed: true,
            sink: "alert".into(),
            message: "1".into(),
        })
    }

    /// Convenience for building owned input vectors from &str slices.
    fn inv(vs: &[&str]) -> Vec<String> {
        vs.iter().map(|s| (*s).to_string()).collect()
    }

    // ---- MIN_REFLECT_LEN boundary (false-positive resistance) --------------

    #[test]
    fn reflect_value_exactly_one_below_min_never_reflects() {
        // 5 bytes — below MIN_REFLECT_LEN(6) — present verbatim, must NOT flag.
        let body = b"prefix ABCDE suffix";
        assert!(reflected_inputs(&inv(&["ABCDE"]), body).is_empty());
    }

    #[test]
    fn reflect_value_exactly_at_min_reflects() {
        // 6 bytes — exactly MIN_REFLECT_LEN — present verbatim, must flag.
        let body = b"prefix ABCDEF suffix";
        assert_eq!(reflected_inputs(&inv(&["ABCDEF"]), body), inv(&["ABCDEF"]));
    }

    #[test]
    fn reflect_short_value_present_in_body_is_ignored() {
        // The classic false-positive source: a 2-char value that coincidentally
        // appears all over a page. Must never be treated as a reflection.
        let body = b"<input type=on checked onmouseover=on>";
        assert!(reflected_inputs(&inv(&["on"]), body).is_empty());
    }

    #[test]
    fn reflect_value_not_in_body_is_not_reflected() {
        let body = b"<html>totally unrelated content here</html>";
        assert!(reflected_inputs(&inv(&["payload-not-present"]), body).is_empty());
    }

    #[test]
    fn reflect_empty_inputs_yields_nothing() {
        assert!(reflected_inputs(&[], b"<html>body</html>").is_empty());
    }

    #[test]
    fn reflect_empty_body_yields_nothing() {
        assert!(reflected_inputs(&inv(&["longenoughvalue"]), b"").is_empty());
    }

    #[test]
    fn reflect_value_longer_than_body_not_reflected() {
        // needle longer than haystack — contains() must short-circuit false.
        assert!(
            reflected_inputs(&inv(&["this-needle-is-way-longer-than-body"]), b"short").is_empty()
        );
    }

    // ---- dedup / multiplicity ----------------------------------------------

    #[test]
    fn reflect_dedups_duplicate_inputs() {
        let body = b"<p>repeated-payload appears repeated-payload twice</p>";
        let hits = reflected_inputs(&inv(&["repeated-payload", "repeated-payload"]), body);
        assert_eq!(
            hits,
            inv(&["repeated-payload"]),
            "duplicates must collapse to one"
        );
    }

    #[test]
    fn reflect_preserves_first_seen_order() {
        let body = b"alpha-input then beta-input then gamma-input";
        let hits = reflected_inputs(&inv(&["beta-input", "alpha-input", "gamma-input"]), body);
        // Order follows the inputs slice, not body position.
        assert_eq!(hits, inv(&["beta-input", "alpha-input", "gamma-input"]));
    }

    #[test]
    fn reflect_multiple_distinct_hits_all_returned() {
        let body = b"first-payload and second-payload both reflect";
        let hits = reflected_inputs(&inv(&["first-payload", "second-payload"]), body);
        assert_eq!(hits, inv(&["first-payload", "second-payload"]));
    }

    #[test]
    fn reflect_overlapping_substrings_each_matched_independently() {
        // "longpayload" and a substring "ngpayload" (>=6) both byte-occur.
        let body = b"xxlongpayloadxx";
        let hits = reflected_inputs(&inv(&["longpayload", "ngpayload"]), body);
        assert_eq!(hits, inv(&["longpayload", "ngpayload"]));
    }

    // ---- unicode / multibyte (byte-based match) ----------------------------

    #[test]
    fn reflect_multibyte_unicode_value_matches_on_bytes() {
        // "café☕!" reflected verbatim. Byte length comfortably >= 6.
        let value = "café☕menu";
        let mut body = b"<div>".to_vec();
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"</div>");
        assert_eq!(reflected_inputs(&inv(&[value]), &body), inv(&[value]));
    }

    #[test]
    fn reflect_uses_byte_length_not_char_count() {
        // Two chars but their UTF-8 byte length is >= 6 → passes the gate and,
        // present in body, reflects. Proves the gate is byte- not char-based.
        let value = "☕☕"; // 6 bytes, 2 chars
        assert_eq!(value.len(), 6);
        let mut body = b"prefix".to_vec();
        body.extend_from_slice(value.as_bytes());
        assert_eq!(reflected_inputs(&inv(&[value]), &body), inv(&[value]));
    }

    #[test]
    fn reflect_multibyte_partial_byte_match_does_not_false_positive() {
        // A value sharing only a leading byte run with body must not match.
        let body = "naïveword".as_bytes();
        assert!(reflected_inputs(&inv(&["naïveOTHER"]), body).is_empty());
    }

    // ---- percent / plus decode edge cases ----------------------------------

    #[test]
    fn decode_percent_41_becomes_a() {
        let out = extract_request_inputs("h://t?x=%41%41%41%41%41%41", None, "");
        assert_eq!(out, inv(&["AAAAAA"]));
    }

    #[test]
    fn decode_plus_becomes_space() {
        let out = extract_request_inputs("h://t?x=a+b+c+d+e", None, "");
        assert_eq!(out, inv(&["a b c d e"]));
    }

    #[test]
    fn decode_mixed_percent_and_plus() {
        let out = extract_request_inputs("h://t?x=hi+%41%42+there", None, "");
        assert_eq!(out, inv(&["hi AB there"]));
    }

    #[test]
    fn decode_lowercase_hex() {
        // %2f -> '/', lowercase hex digits accepted.
        let out = extract_request_inputs("h://t?path=a%2fb%2fcccc", None, "");
        assert_eq!(out, inv(&["a/b/cccc"]));
    }

    #[test]
    fn decode_invalid_hex_capital_z_kept_literal() {
        // %ZZ is not valid hex — the '%' is emitted literally and parsing
        // resumes at the next byte.
        let out = extract_request_inputs("h://t?x=ab%ZZcd", None, "");
        assert_eq!(out, inv(&["ab%ZZcd"]));
    }

    #[test]
    fn decode_invalid_hex_single_bad_nibble_kept_literal() {
        // %4Z: second nibble invalid -> literal '%', then "4Z" follow.
        let out = extract_request_inputs("h://t?x=start%4Zend", None, "");
        assert_eq!(out, inv(&["start%4Zend"]));
    }

    #[test]
    fn decode_trailing_lone_percent_kept_literal() {
        // A '%' with no following hex bytes at end stays literal.
        let out = extract_request_inputs("h://t?x=value1%", None, "");
        assert_eq!(out, inv(&["value1%"]));
    }

    #[test]
    fn decode_trailing_percent_one_hex_kept_literal() {
        // "%4" at the very end — only one trailing byte after '%'. The decoder's
        // bounds guard (i+2 < len) means this is NOT decoded; '%' stays literal.
        let out = extract_request_inputs("h://t?x=value1%4", None, "");
        assert_eq!(out, inv(&["value1%4"]));
    }

    #[test]
    fn decode_percent_pair_at_exact_end_decodes() {
        // "%42" where the pair fully fits before end-of-input. There must be a
        // byte boundary check; here the value continues conceptually but this
        // asserts the documented behavior for a fully-formed escape mid-string.
        let out = extract_request_inputs("h://t?x=AAAAA%42Z", None, "");
        assert_eq!(out, inv(&["AAAAABZ"]));
    }

    #[test]
    fn decode_empty_value_after_eq_is_dropped() {
        // name= with empty value -> nothing collected (empty decoded dropped).
        let out = extract_request_inputs("h://t?empty=&real=longvalue", None, "");
        assert_eq!(out, inv(&["longvalue"]));
    }

    #[test]
    fn decode_pair_without_eq_is_skipped() {
        // A bare "name" with no '=' is not a value pair and is skipped.
        let out = extract_request_inputs("h://t?bareflag&k=realvalue", None, "");
        assert_eq!(out, inv(&["realvalue"]));
    }

    #[test]
    fn decode_multiple_eq_splits_on_first() {
        // "k=a=b=c": split on the FIRST '=', value is the remainder "a=b=c".
        let out = extract_request_inputs("h://t?k=a=b=c=d", None, "");
        assert_eq!(out, inv(&["a=b=c=d"]));
    }

    #[test]
    fn decode_empty_pairs_from_double_amp_ignored() {
        // "&&" produces empty pairs (no '='), which are skipped.
        let out = extract_request_inputs("h://t?a=firstval&&&b=secondval", None, "");
        assert_eq!(out, inv(&["firstval", "secondval"]));
    }

    #[test]
    fn decode_leading_and_trailing_amp_ignored() {
        let out = extract_request_inputs("h://t?&k=onlyvalue&", None, "");
        assert_eq!(out, inv(&["onlyvalue"]));
    }

    #[test]
    fn decode_dedups_repeated_values_across_pairs() {
        // Same decoded value from two params -> collected once.
        let out = extract_request_inputs("h://t?a=samevalue&b=samevalue", None, "");
        assert_eq!(out, inv(&["samevalue"]));
    }

    #[test]
    fn decode_percent_byte_then_invalid_continues_parsing() {
        // %3Cscript -> "<script" : valid escape followed by literal text.
        let out = extract_request_inputs("h://t?x=%3Cscript%3E", None, "");
        assert_eq!(out, inv(&["<script>"]));
    }

    // ---- extract: query-only / form-only / both ----------------------------

    #[test]
    fn extract_query_only_no_body() {
        let out = extract_request_inputs("h://t?q=querypayload", None, "");
        assert_eq!(out, inv(&["querypayload"]));
    }

    #[test]
    fn extract_form_only_no_query() {
        let out = extract_request_inputs(
            "h://t/post",
            Some(b"field=formpayload"),
            "application/x-www-form-urlencoded",
        );
        assert_eq!(out, inv(&["formpayload"]));
    }

    #[test]
    fn extract_both_query_and_form_combined() {
        let out = extract_request_inputs(
            "h://t/post?q=querypayload",
            Some(b"field=formpayload"),
            "application/x-www-form-urlencoded",
        );
        assert_eq!(out, inv(&["querypayload", "formpayload"]));
    }

    #[test]
    fn extract_no_query_no_body_is_empty() {
        assert!(extract_request_inputs("h://t/plain", None, "").is_empty());
    }

    #[test]
    fn extract_uri_without_question_mark_yields_no_query_inputs() {
        let out = extract_request_inputs(
            "h://t/path-only",
            Some(b"f=bodyvalue"),
            "application/x-www-form-urlencoded",
        );
        assert_eq!(out, inv(&["bodyvalue"]));
    }

    // ---- form decode gated on content type ---------------------------------

    #[test]
    fn extract_json_body_ignored_even_with_form_shaped_bytes() {
        // Body looks form-encoded but content type is JSON -> body NOT parsed.
        let out = extract_request_inputs(
            "h://t/post?q=querypayload",
            Some(b"injected=shouldnotappear"),
            "application/json",
        );
        assert_eq!(out, inv(&["querypayload"]));
        assert!(!out.iter().any(|v| v.contains("shouldnotappear")));
    }

    #[test]
    fn extract_form_content_type_case_insensitive() {
        let out = extract_request_inputs(
            "h://t/post",
            Some(b"f=mixedcasevalue"),
            "Application/X-WWW-Form-UrlEncoded",
        );
        assert_eq!(out, inv(&["mixedcasevalue"]));
    }

    #[test]
    fn extract_form_content_type_with_charset_param() {
        let out = extract_request_inputs(
            "h://t/post",
            Some(b"f=charsetvalue"),
            "application/x-www-form-urlencoded; charset=utf-8",
        );
        assert_eq!(out, inv(&["charsetvalue"]));
    }

    #[test]
    fn extract_form_body_present_but_empty_slice() {
        let out = extract_request_inputs(
            "h://t/post?q=onlyquery",
            Some(b""),
            "application/x-www-form-urlencoded",
        );
        assert_eq!(out, inv(&["onlyquery"]));
    }

    // ---- is_html_like extra coverage ---------------------------------------

    #[test]
    fn is_html_like_case_insensitive() {
        assert!(is_html_like("TEXT/HTML"));
        assert!(is_html_like("Image/SVG+XML"));
        assert!(is_html_like("Application/XHTML+XML"));
    }

    #[test]
    fn is_html_like_rejects_other_types() {
        assert!(!is_html_like("application/json; charset=utf-8"));
        assert!(!is_html_like("text/plain; charset=utf-8"));
        assert!(!is_html_like("application/octet-stream"));
        assert!(!is_html_like("image/png"));
        assert!(!is_html_like(""));
    }

    // ---- classify: false-positive resistance & verdict matrix --------------

    #[test]
    fn classify_short_input_in_html_never_detonates() {
        // Value below MIN_REFLECT_LEN -> no reflection -> None, hook untouched.
        let c = classify(
            &inv(&["abc"]),
            b"<html>abc</html>",
            "text/html",
            true,
            no_detonate,
        );
        assert_eq!(c, FindingClass::None);
    }

    #[test]
    fn classify_value_absent_from_body_is_none() {
        let c = classify(
            &inv(&["payload-not-here"]),
            b"<html>clean page</html>",
            "text/html",
            true,
            no_detonate,
        );
        assert_eq!(c, FindingClass::None);
    }

    #[test]
    fn classify_plain_text_response_never_detonates() {
        let c = classify(
            &inv(&["<script>alert(1)</script>"]),
            b"reflected <script>alert(1)</script> as plain text",
            "text/plain",
            true,
            no_detonate,
        );
        assert!(matches!(c, FindingClass::Reflected { .. }));
    }

    #[test]
    fn classify_json_response_never_detonates() {
        let c = classify(
            &inv(&["<script>alert(1)</script>"]),
            br#"{"echo":"<script>alert(1)</script>"}"#,
            "application/json",
            true,
            no_detonate,
        );
        assert!(matches!(c, FindingClass::Reflected { .. }));
    }

    #[test]
    fn classify_reflected_carries_param_list() {
        let c = classify(
            &inv(&["first-payload", "second-payload"]),
            b"first-payload and second-payload",
            "application/json",
            false,
            no_detonate,
        );
        match c {
            FindingClass::Reflected { params } => {
                assert_eq!(params, inv(&["first-payload", "second-payload"]));
            }
            other => panic!("expected Reflected, got {other:?}"),
        }
    }

    #[test]
    fn classify_exploit_only_when_executed_true() {
        // Hook returns executed=false -> must degrade to Reflected, NOT exploit.
        let c = classify(
            &inv(&["<script>alert(1)</script>"]),
            b"<html><script>alert(1)</script></html>",
            "text/html",
            true,
            |_| {
                Some(DetonationVerdict {
                    executed: false,
                    sink: "alert".into(),
                    message: "1".into(),
                })
            },
        );
        assert!(!c.is_exploit());
        assert!(matches!(c, FindingClass::Reflected { .. }));
    }

    #[test]
    fn classify_exploit_confirmed_on_svg_response() {
        // image/svg+xml is html-like; an executing sink confirms the exploit.
        let c = classify(
            &inv(&["<svg onload=alert(1)>"]),
            b"<svg onload=alert(1)></svg>",
            "image/svg+xml",
            true,
            fired,
        );
        assert!(c.is_exploit(), "{c:?}");
    }

    #[test]
    fn classify_exploit_confirmed_carries_sink_and_params() {
        let c = classify(
            &inv(&["<script>document.cookie</script>"]),
            b"<html><script>document.cookie</script></html>",
            "text/html",
            true,
            |_| {
                Some(DetonationVerdict {
                    executed: true,
                    sink: "eval".into(),
                    message: "document.cookie".into(),
                })
            },
        );
        match &c {
            FindingClass::ExploitConfirmed {
                params,
                sink,
                message,
            } => {
                assert_eq!(params, &inv(&["<script>document.cookie</script>"]));
                assert_eq!(sink, "eval");
                assert_eq!(message, "document.cookie");
            }
            other => panic!("expected ExploitConfirmed, got {other:?}"),
        }
    }

    #[test]
    fn classify_detonate_returns_none_degrades_to_reflected() {
        let c = classify(
            &inv(&["<script>alert(1)</script>"]),
            b"<html><script>alert(1)</script></html>",
            "text/html",
            true,
            |_| None,
        );
        assert!(matches!(c, FindingClass::Reflected { .. }));
        assert!(!c.is_exploit());
    }

    // ---- summary() / is_exploit() text contracts ---------------------------

    #[test]
    fn summary_none_is_none() {
        assert!(FindingClass::None.summary().is_none());
        assert!(!FindingClass::None.is_exploit());
    }

    #[test]
    fn summary_reflected_lists_all_params() {
        let fc = FindingClass::Reflected {
            params: inv(&["alpha-param", "beta-param"]),
        };
        let s = fc.summary().expect("reflected has a summary");
        assert!(s.contains("REFLECTED"), "{s}");
        assert!(s.contains("alpha-param"), "{s}");
        assert!(s.contains("beta-param"), "{s}");
        assert!(!fc.is_exploit());
    }

    #[test]
    fn summary_exploit_contains_sink_and_args() {
        let fc = FindingClass::ExploitConfirmed {
            params: inv(&["xss-param"]),
            sink: "alert".into(),
            message: "1337".into(),
        };
        let s = fc.summary().expect("exploit has a summary");
        assert!(s.contains("EXPLOIT CONFIRMED"), "{s}");
        assert!(s.contains("xss-param"), "{s}");
        assert!(s.contains("alert(1337)"), "{s}");
        assert!(fc.is_exploit());
    }

    // ---- DetonationVerdict value semantics ---------------------------------

    #[test]
    fn detonation_verdict_equality_and_clone() {
        let v = DetonationVerdict {
            executed: true,
            sink: "alert".into(),
            message: "1".into(),
        };
        assert_eq!(v.clone(), v);
        let differ = DetonationVerdict {
            executed: false,
            ..v.clone()
        };
        assert_ne!(differ, v);
    }

    // ---- property-style: short values never reflect, present long ones do ---

    #[test]
    fn property_value_under_min_never_reflects_any_body() {
        // Exhaustive over short ASCII-ish needles 0..MIN_REFLECT_LEN bytes,
        // each embedded in a body that DOES contain it. None may reflect.
        for len in 0..MIN_REFLECT_LEN {
            let needle: String = std::iter::repeat_n('Z', len).collect();
            let mut body = b"head".to_vec();
            body.extend_from_slice(needle.as_bytes());
            body.extend_from_slice(b"tail");
            assert!(
                reflected_inputs(&inv(&[needle.as_str()]), &body).is_empty(),
                "len {len} reflected but is below MIN_REFLECT_LEN"
            );
        }
    }

    #[test]
    fn property_value_at_or_over_min_present_always_reflects() {
        for len in MIN_REFLECT_LEN..MIN_REFLECT_LEN + 8 {
            let needle: String = std::iter::repeat_n('Q', len).collect();
            let mut body = b"head".to_vec();
            body.extend_from_slice(needle.as_bytes());
            body.extend_from_slice(b"tail");
            assert_eq!(
                reflected_inputs(&inv(&[needle.as_str()]), &body),
                inv(&[needle.as_str()]),
                "len {len} present but did not reflect"
            );
        }
    }

    #[test]
    fn property_roundtrip_decode_then_reflect_matches() {
        // For a set of payloads: percent-encode, extract (decode), and the
        // decoded value must reflect when embedded verbatim in the body.
        let payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(2)>",
            "javascript:void(0)//xss",
            "café-payload-unicode",
        ];
        for p in payloads {
            let encoded = percent_encode_for_test(p);
            let uri = format!("h://t?inj={encoded}");
            let inputs = extract_request_inputs(&uri, None, "");
            assert_eq!(inputs, inv(&[p]), "decode mismatch for {p}");
            let mut body = b"<div>".to_vec();
            body.extend_from_slice(p.as_bytes());
            body.extend_from_slice(b"</div>");
            assert_eq!(reflected_inputs(&inputs, &body), inv(&[p]));
        }
    }

    /// Test-only percent-encoder: encodes every byte except unreserved ASCII so
    /// the result is safe to feed back through the module's decoder.
    fn percent_encode_for_test(s: &str) -> String {
        let mut out = String::new();
        for &b in s.as_bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }
}
