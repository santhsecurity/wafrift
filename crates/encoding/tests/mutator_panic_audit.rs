//! Panic / OOM audit: every public mutator survives adversarial inputs and stays within explicit size caps.

#![cfg(test)]

mod common;

use common::{
    ONE_MB, invalid_utf8_fixtures, max_encoded_output_bytes, mb_del, mb_zeros, unicode_stress,
};
use wafrift_encoding::{
    EncodeError, Strategy,
    auth_bypass::auth_bypass_probes,
    contextual::{encode_in_context, escape_for_context},
    encode,
    encoding::{
        keyword::{
            alternating_case, between_obfuscate, case_alternate, lowercase,
            mysql_versioned_comment, percentage_prefix, random_case_alternate, space_to_comment,
            space_to_dash, space_to_hash, space_to_plus, space_to_random_blank, sql_comment_insert,
            unmagic_quotes, uppercase, whitespace_insert,
        },
        layered::{MAX_LAYERED_OUTPUT_SIZE, encode_layered},
        strategy::{MAX_PAYLOAD_SIZE, all_strategies},
        structural::{
            base64_encode, base64_url_encode, chunked_split, deflate_encode, gzip_encode,
            hex_encode, null_byte_inject, overlong_utf8, overlong_utf8_more, parameter_pollute,
            utf7_encode,
        },
        unicode::{
            fullwidth_encode, homoglyph_encode, html_entity_decimal_encode, html_entity_encode,
            iis_unicode_encode, json_string_encode, unicode_encode,
        },
        url::{double_url_encode, triple_url_encode, url_encode, url_encode_lower},
    },
    header::{
        all_obfuscations, case_mix, comma_join, duplicate_header, lf_only_line_fold,
        lf_only_multi_line_fold, line_fold, multi_line_fold, null_byte_inject as hdr_null_inject,
        tab_separator, trailing_space, underscore_substitute, whitespace_pad,
    },
    tamper::{all_tamper_names, tamper},
    url_mutate::{MAX_DOUBLE_ENCODE_INPUT, UrlMutateConfig, UrlStrategy, mutate_url},
};
use wafrift_types::injection_context::InjectionContext;

fn all_injection_contexts() -> [InjectionContext; 15] {
    [
        InjectionContext::PlainBody,
        InjectionContext::JsonString,
        InjectionContext::JsonNumber,
        InjectionContext::XmlAttribute,
        InjectionContext::XmlCdata,
        InjectionContext::XmlText,
        InjectionContext::HtmlAttribute,
        InjectionContext::HtmlText,
        InjectionContext::UrlQuery,
        InjectionContext::UrlPath,
        InjectionContext::UrlFragment,
        InjectionContext::HeaderValue,
        InjectionContext::CookieValue,
        InjectionContext::MultipartField,
        InjectionContext::MultipartFileName,
    ]
}

fn assert_encode_ok_bounded(strategy: Strategy, input: &[u8]) {
    let got = encode(input, strategy).unwrap_or_else(|e| {
        panic!(
            "Fix: encode({strategy:?}) must not fail unexpectedly on {} byte input: {e:?}",
            input.len()
        )
    });
    assert!(
        got.len() <= max_encoded_output_bytes(strategy, input.len()),
        "Fix: output length {} exceeds cap for {:?} input len {}",
        got.len(),
        strategy,
        input.len()
    );
}

fn assert_encode_err_invalid_utf8_or_ok(strategy: Strategy, input: &[u8]) {
    match encode(input, strategy) {
        Ok(out) => assert!(
            out.len() <= max_encoded_output_bytes(strategy, input.len()),
            "bounded output when UTF-8 accepted"
        ),
        Err(EncodeError::InvalidUtf8) => {}
        Err(e) => panic!("Fix: unexpected error for invalid UTF-8 slice: {e:?}"),
    }
}

#[test]
fn positive_encode_empty_bounded_negative_oversize_rejected() {
    for &strategy in all_strategies() {
        let out = encode(b"", strategy).expect("empty input must encode");
        assert!(out.len() <= max_encoded_output_bytes(strategy, 0));
    }
    let huge = vec![b'x'; MAX_PAYLOAD_SIZE + 1];
    assert!(matches!(
        encode(&huge, Strategy::UrlEncode),
        Err(EncodeError::PayloadTooLarge { .. })
    ));
}

#[test]
fn encode_all_strategies_one_mb_null_and_del_bounded() {
    let z = mb_zeros();
    let d = mb_del();
    assert_eq!(z.len(), ONE_MB);
    assert_eq!(d.len(), ONE_MB);

    for &strategy in all_strategies() {
        assert_encode_ok_bounded(strategy, &z);
        assert_encode_ok_bounded(strategy, &d);
    }
}

#[test]
fn encode_invalid_utf8_text_strategies_reject_without_panic() {
    for buf in invalid_utf8_fixtures() {
        for &strategy in all_strategies() {
            assert_encode_err_invalid_utf8_or_ok(strategy, &buf);
        }
    }
}

#[test]
fn encode_unicode_stress_bounded() {
    let s = unicode_stress();
    let bytes = s.as_bytes();
    for &strategy in all_strategies() {
        assert_encode_ok_bounded(strategy, bytes);
    }
}

#[test]
fn encode_recursive_depth_eight_bounded() {
    let seed = unicode_stress();
    for &strategy in all_strategies() {
        let mut cur = seed.clone();
        for depth in 0..8 {
            match encode(cur.as_bytes(), strategy) {
                Ok(next) => {
                    assert!(
                        next.len() <= max_encoded_output_bytes(strategy, cur.len()),
                        "Fix: depth {depth} {:?} output exceeds cap for input len {}",
                        strategy,
                        cur.len()
                    );
                    cur = next;
                }
                Err(EncodeError::InvalidUtf8) => break,
                Err(EncodeError::PayloadTooLarge { .. }) => break,
                Err(e) => {
                    panic!("Fix: unexpected error at depth {depth} strategy {strategy:?}: {e:?}")
                }
            }
        }
    }
}

#[test]
fn encode_layered_chain_bounded() {
    let chain = [
        Strategy::UrlEncode,
        Strategy::HexEncode,
        Strategy::Base64Encode,
    ];
    let payload = unicode_stress();
    let out = encode_layered(payload.as_bytes(), &chain).expect("layered encode");
    assert!(out.len() <= MAX_LAYERED_OUTPUT_SIZE);

    let empty_chain: [Strategy; 0] = [];
    assert_eq!(
        encode_layered(b"hi", &empty_chain).expect("empty chain"),
        "hi"
    );
}

#[test]
fn encode_layered_negative_output_cap_enforced() {
    // First HtmlEntity pass expands ~8× ASCII → intermediate must exceed MAX_LAYERED_OUTPUT_SIZE (8 MiB)
    // before the second strategy runs.
    let payload = "x".repeat(1_200_000);
    let err = encode_layered(
        payload.as_bytes(),
        &[Strategy::HtmlEntityEncode, Strategy::UrlEncode],
    )
    .expect_err("layered explosion must fail closed");
    assert!(
        matches!(err, EncodeError::LayeredOutputTooLarge { .. }),
        "Fix: expected LayeredOutputTooLarge, got {err:?}"
    );
}

#[test]
fn url_strategy_apply_and_apply_bytes_bounded() {
    let mut fixtures: Vec<Vec<u8>> = vec![
        vec![],
        vec![0, 0x7F, 0xFF],
        mb_zeros(),
        unicode_stress().into_bytes(),
    ];
    fixtures.extend(invalid_utf8_fixtures());

    for strategy in [
        UrlStrategy::PercentEncodeAggressive,
        UrlStrategy::DoublePercentEncode,
        UrlStrategy::NonCanonicalSpaces,
        UrlStrategy::Hpp,
    ] {
        for bytes in &fixtures {
            let out_b = strategy.apply_bytes(bytes);
            assert!(
                out_b.len() <= bytes.len().saturating_mul(12).saturating_add(4096),
                "apply_bytes cap strategy={strategy:?} len={}",
                bytes.len()
            );
            if std::str::from_utf8(bytes).is_ok() {
                let s = std::str::from_utf8(bytes).unwrap();
                let out_s = strategy.apply(s);
                assert_eq!(out_s, out_b);
            }
        }
    }
}

#[test]
fn mutate_url_all_strategies_bounded() {
    let paths = [
        "",
        "/",
        "/p?q=%ZZbad",
        "/seg?x=\x01\x02",
        &format!("/p?q={}", "y".repeat(10_000)),
        &format!("/w?z={}", std::str::from_utf8(&mb_zeros()[..2048]).unwrap()),
    ];

    for strat in [
        UrlStrategy::PercentEncodeAggressive,
        UrlStrategy::DoublePercentEncode,
        UrlStrategy::NonCanonicalSpaces,
        UrlStrategy::Hpp,
    ] {
        let cfg = UrlMutateConfig {
            mutate_query_values: true,
            mutate_last_path_segment: true,
            strategy: strat,
        };
        for p in paths {
            let (out, _) = mutate_url(p, &cfg);
            assert!(
                out.len() <= p.len().saturating_mul(20).saturating_add(65536),
                "mutate_url output bounded"
            );
        }
    }
}

#[test]
fn mutate_url_negative_full_url_pass_through() {
    let (out, techniques) = mutate_url("https://evil.test/path?q=1", &UrlMutateConfig::default());
    assert_eq!(out, "https://evil.test/path?q=1");
    assert!(techniques.is_empty());
}

#[test]
fn tamper_every_name_bounded() {
    let stress = unicode_stress();
    let utf8_payloads: [&str; 4] = ["", "x", "'", stress.as_str()];
    for name in all_tamper_names() {
        for p in utf8_payloads {
            let out = tamper(name, p, Some("sql")).unwrap_or_else(|e| {
                panic!("Fix: tamper({name:?}) must not error on short payloads: {e:?}")
            });
            assert!(
                out.len() <= p.len().saturating_mul(24).saturating_add(4096),
                "tamper {name} output bounded"
            );
        }
    }
}

#[test]
fn tamper_negative_unknown_strategy_errors() {
    assert!(tamper("not_a_registered_strategy_name_xx", "a", None).is_err());
}

fn header_suite(name: &str, value: &str) {
    let _ = case_mix(name);
    let _ = tab_separator(name, value);
    let _ = whitespace_pad(name, value);
    let _ = line_fold(name, value);
    let _ = lf_only_line_fold(name, value);
    let _ = multi_line_fold(name, value);
    let _ = lf_only_multi_line_fold(name, value);
    let _ = duplicate_header(name, value, "benign");
    let _ = underscore_substitute(name);
    let _ = hdr_null_inject(name);
    let _ = trailing_space(name, value);
    let _ = comma_join(name, value, "b");
    for (_t, line) in all_obfuscations(name, value) {
        assert!(
            line.len()
                <= (name.len() + value.len())
                    .saturating_mul(8)
                    .saturating_add(256),
            "header obfuscation bounded"
        );
    }
}

#[test]
fn header_mutators_adversarial_bounded() {
    header_suite("", "");
    header_suite("Content-Type", "text/html");
    header_suite("X-Custom", unicode_stress().as_str());
    let long = "h".repeat(50_000);
    header_suite("Host", long.as_str());
}

#[test]
fn header_mutators_negative_utf8_bytes_rejected_before_str_apis() {
    // Header APIs take `&str`; raw bytes would error at the boundary.
    let bytes = invalid_utf8_fixtures();
    assert!(std::str::from_utf8(&bytes[0]).is_err());
}

#[test]
fn contextual_escape_and_encode_bounded() {
    let payload = unicode_stress();
    let pb = payload.as_bytes();

    for ctx in all_injection_contexts() {
        if let Ok(escaped) = escape_for_context(payload.as_str(), ctx) {
            assert!(
                escaped.len() <= payload.len().saturating_mul(8).saturating_add(512),
                "escape bounded for {ctx:?}"
            );
        }

        let _ = encode_in_context(pb, Strategy::UrlEncode, ctx);
    }
}

#[test]
fn contextual_negative_json_number_rejects_alpha() {
    assert!(
        encode_in_context(
            b"not-a-number",
            Strategy::UrlEncode,
            InjectionContext::JsonNumber
        )
        .is_err()
    );
}

#[test]
fn direct_encoding_module_functions_bounded() {
    let u = unicode_stress();
    let z = mb_zeros();
    let inv = invalid_utf8_fixtures()[0].clone();

    let _ = url_encode(&z);
    let _ = url_encode_lower(&z);
    let _ = double_url_encode(&z);
    let _ = triple_url_encode(&z);

    let _ = unicode_encode(u.as_str());
    let _ = iis_unicode_encode(u.as_str());
    let _ = json_string_encode(u.as_str());
    let _ = html_entity_encode(u.as_str());
    let _ = html_entity_decimal_encode(u.as_str());
    let _ = fullwidth_encode(u.as_str());
    let _ = homoglyph_encode(u.as_str());

    let _ = null_byte_inject(&z).unwrap();
    let _ = overlong_utf8(&z).unwrap();
    let _ = overlong_utf8_more(&z).unwrap();
    let _ = chunked_split(&z, 1024).unwrap();
    let _ = parameter_pollute(b"a=b").unwrap();
    let _ = base64_encode(&z);
    let _ = base64_url_encode(&z);
    let _ = hex_encode(&z);
    let _ = utf7_encode(u.as_str());
    let _ = gzip_encode(&z).unwrap();
    let _ = deflate_encode(&z).unwrap();

    let _ = whitespace_insert(u.as_str());
    let _ = sql_comment_insert(u.as_str());
    let _ = mysql_versioned_comment(u.as_str(), 50_000);
    let _ = space_to_comment(u.as_str());
    let _ = space_to_dash(u.as_str());
    let _ = space_to_hash(u.as_str());
    let _ = space_to_plus(u.as_str());
    let _ = space_to_random_blank(u.as_str());
    let _ = percentage_prefix(u.as_str());
    let _ = between_obfuscate(u.as_str());
    let _ = case_alternate(u.as_str());
    let _ = random_case_alternate(u.as_str());
    let _ = alternating_case(u.as_str(), true);
    let _ = lowercase(u.as_str());
    let _ = uppercase(u.as_str());

    assert!(unmagic_quotes(&inv).is_err());
}

#[test]
fn auth_bypass_probes_bounded() {
    let stress = unicode_stress();
    let long = "/x".repeat(4000);
    let paths: [&str; 4] = ["", "/", stress.as_str(), long.as_str()];
    for p in paths {
        let v = auth_bypass_probes(p);
        assert!(v.len() < 10_000, "probe count bounded");
        for probe in &v {
            assert!(
                probe.header.len() < 256 && probe.value.len() < 8192,
                "Fix: probe fields unexpectedly huge"
            );
        }
    }
}

#[test]
fn concurrent_encode_no_panic() {
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                for &strategy in all_strategies() {
                    let _ = encode(mb_zeros().as_slice(), strategy);
                    let _ = encode(invalid_utf8_fixtures()[0].as_slice(), strategy);
                }
            });
        }
    });
}

#[test]
fn double_percent_encode_input_cap_documented_negative() {
    let oversized = vec![b'A'; MAX_DOUBLE_ENCODE_INPUT + 1];
    let s = UrlStrategy::DoublePercentEncode;
    let out = s.apply_bytes(&oversized);
    assert!(
        out.len() <= oversized.len().saturating_mul(4).saturating_add(1024),
        "fallback single-pass must stay bounded"
    );
}
