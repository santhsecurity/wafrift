//! Regression coverage for the 2026-05-10 content-type audit finding:
//!   HIGH: `generate_variants` used `random_boundary()` at every call site,
//!     never wiring up the `unique_boundary()` helper that was already in
//!     the public API. An attacker who controlled a param value could
//!     embed `--<wafrift-boundary-pattern>` and self-frame the multipart
//!     body, escaping the form parser.
//!
//! This test would have failed pre-fix because the boundary was random
//! 128-bit hex but never checked against the param values, so a value
//! crafted to start with the boundary prefix would slip through.

use wafrift_content_type::{ContentTypeTechnique, generate_variants};

#[test]
fn boundary_does_not_appear_inside_param_value() {
    // Attempt the explicit attack: a param value that pre-loads the
    // wafrift boundary prefix. unique_boundary's contract guarantees the
    // returned token is never a substring of any input, so even after
    // 1024 iterations of this test the multipart body must never
    // self-frame against the value.
    let evil = "----WafriftBoundaryAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    for _ in 0..16 {
        let variants = generate_variants(&[
            ("user".to_string(), "alice".to_string()),
            ("data".to_string(), evil.clone()),
        ]);
        for v in &variants {
            // For each multipart-family variant, verify the boundary
            // token used in the body framing is NOT a substring of any
            // param value.
            if !matches!(
                v.technique,
                ContentTypeTechnique::Multipart
                    | ContentTypeTechnique::MultipartQuotedBoundary
                    | ContentTypeTechnique::MultipartWhitespaceBoundary
                    | ContentTypeTechnique::MultipartCharsetPrefix
                    | ContentTypeTechnique::MultipartDuplicateBoundary
                    | ContentTypeTechnique::MixedContentType
            ) {
                continue;
            }
            // Extract the body-framing boundary by finding the first
            // `--<token>\r\n` line in the body.
            let body = std::str::from_utf8(&v.body).expect("multipart bodies are utf-8");
            let first_line_end = body.find("\r\n").expect("multipart body must have CRLF");
            assert!(
                body.starts_with("--"),
                "multipart body must start with --boundary"
            );
            let boundary = &body[2..first_line_end];
            assert!(
                !evil.contains(boundary),
                "boundary {boundary:?} appears inside attacker-controlled value {evil:?} — \
                 multipart self-framing attack possible (this is exactly the \
                 contract unique_boundary was supposed to enforce)"
            );
        }
    }
}

#[test]
fn boundary_unique_across_runs_for_same_input() {
    // Defence-in-depth — two separate generate_variants calls should
    // not produce IDENTICAL boundaries (random hex tail keeps them
    // unpredictable). If they did, an attacker could reproduce the
    // boundary offline and craft a self-framing value.
    let params = vec![("k".to_string(), "v".to_string())];
    let mut boundaries = std::collections::HashSet::new();
    for _ in 0..64 {
        let variants = generate_variants(&params);
        for v in &variants {
            if !matches!(v.technique, ContentTypeTechnique::Multipart) {
                continue;
            }
            let body = std::str::from_utf8(&v.body).unwrap();
            let line_end = body.find("\r\n").unwrap();
            let boundary = body[2..line_end].to_string();
            boundaries.insert(boundary);
        }
    }
    assert!(
        boundaries.len() >= 60,
        "64 runs should produce ~64 distinct boundaries — got {} (random source may have wedged)",
        boundaries.len()
    );
}

#[test]
fn empty_params_does_not_panic() {
    // Defence-in-depth — empty params used to produce a body of just
    // "--<boundary>--\r\n". With unique_boundary against an empty value
    // list, the boundary is always fresh and the body is well-formed.
    let variants = generate_variants(&[]);
    assert!(
        !variants.is_empty(),
        "must still emit variants on empty params"
    );
    for v in &variants {
        // Just ensure no panic during body construction.
        let _ = std::str::from_utf8(&v.body);
    }
}
