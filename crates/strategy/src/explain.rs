//! Per-finding explanation engine for audit reports.
//!
//! Given an original payload, the bypass payload, the technique chain
//! that produced it, and the detected WAF, build a structured
//! [`Explanation`] practitioners can drop straight into a pentest report.
//!
//! # What "audit-grade" means here
//!
//! - **Triggered rules:** which rule classes the *original* payload
//!   would have lit up (from `wafrift_detect::explain::explain_block`).
//! - **Bypassed rules:** which of those are NO LONGER triggered after
//!   the bypass — the actual *evidence* that the technique worked.
//! - **Diff:** Myers-style line-of-changes between original and bypass,
//!   so a human reviewer can see exactly what was mutated.
//! - **Human summary:** templated narrative naming the bypassed rule
//!   IDs and explaining the technique that removed each match.
//!   Educational mode adds a "Why this works" paragraph per technique.

use wafrift_detect::waf_detect::DetectedWaf;
use wafrift_types::Technique;
use wafrift_types::explanation::{DiffHunk, Explanation, ExplanationMode, RuleAttribution};

/// Build an [`Explanation`] for a single bypass.
///
/// `original` and `bypass` are payload strings; `techniques` is the
/// chain of mutations applied (e.g. `[CaseAlternation, DoubleUrlEncode]`).
/// `mode` controls verbosity of the `human_summary`.
#[must_use]
pub fn explain_bypass(
    original: &str,
    bypass: &str,
    techniques: &[Technique],
    waf: &DetectedWaf,
    mode: ExplanationMode,
) -> Explanation {
    let original_rules = wafrift_detect::explain::explain_block(original, waf);
    let bypass_rules = wafrift_detect::explain::explain_block(bypass, waf);

    let bypassed_rule_ids: Vec<&str> = original_rules
        .iter()
        .filter(|r| !bypass_rules.iter().any(|b| b.rule_id == r.rule_id))
        .map(|r| r.rule_id.as_str())
        .collect();

    let diff = textual_diff(original, bypass);
    let human_summary = build_summary(&original_rules, &bypassed_rule_ids, techniques, waf, mode);

    Explanation {
        original_payload: original.to_string(),
        bypass_payload: bypass.to_string(),
        technique_chain: techniques.to_vec(),
        triggered_rules: original_rules,
        diff,
        human_summary,
        mode,
    }
}

/// Build the human-readable summary string.
///
/// Three tiers, controlled by [`ExplanationMode`]:
///   - `Minimal`: one line — `"Bypassed N rule(s) via M technique(s)."`
///   - `Standard`: rule IDs + technique names + the diff direction.
///   - `Educational`: adds a "Why this works" paragraph per technique
///     and per bypassed rule, suitable for training material.
fn build_summary(
    original_rules: &[RuleAttribution],
    bypassed_ids: &[&str],
    techniques: &[Technique],
    waf: &DetectedWaf,
    mode: ExplanationMode,
) -> String {
    if matches!(mode, ExplanationMode::Minimal) {
        return format!(
            "Bypassed {} of {} rule(s) via {} technique(s).",
            bypassed_ids.len(),
            original_rules.len(),
            techniques.len()
        );
    }

    let mut out = String::new();
    if original_rules.is_empty() {
        out.push_str(&format!(
            "Original payload did not match any tracked rule classes for {}. ",
            waf.name
        ));
        out.push_str(
            "Either the payload is benign or it triggers a vendor-private rule \
                      class wafrift does not yet have a public template for.",
        );
        return out;
    }

    out.push_str(&format!(
        "Original payload matched {} rule class(es) on {}: {}. ",
        original_rules.len(),
        waf.name,
        original_rules
            .iter()
            .map(|r| format!("{} ({})", r.rule_id, r.rule_name))
            .collect::<Vec<_>>()
            .join(", ")
    ));

    if bypassed_ids.is_empty() {
        out.push_str(
            "After applying the technique chain, the bypass payload still triggers all \
             of those rules — this is a SOFT bypass (the request reached upstream but \
             the WAF would have classified it identically). Investigate whether the \
             upstream backend handled the payload differently.",
        );
    } else {
        out.push_str(&format!(
            "Bypass payload no longer matches: {}. ",
            bypassed_ids.join(", ")
        ));
        out.push_str(&format!(
            "Technique chain that removed those matches: {}. ",
            techniques
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" → ")
        ));
    }

    if matches!(mode, ExplanationMode::Educational) && !bypassed_ids.is_empty() {
        out.push_str("\n\n## Why this works\n");
        for tech in techniques {
            out.push_str(&format!("- **{tech}**: "));
            out.push_str(why_technique_works(tech));
            out.push('\n');
        }
    }

    out
}

/// Educational explanation of *why* a technique bypasses pattern matchers.
/// Used by `ExplanationMode::Educational`.
fn why_technique_works(tech: &Technique) -> &'static str {
    match tech {
        Technique::PayloadEncoding(s) if s.contains("DoubleUrl") => {
            "The WAF URL-decodes the request once, then runs regex against the result. \
             Encoding twice means the regex sees `%55nion` (one decode of `%2555nion`) \
             instead of `union`, missing the keyword. The application then decodes a \
             second time and gets the real payload."
        }
        Technique::PayloadEncoding(s) if s.contains("CaseAlternation") => {
            "Older WAF rules use case-sensitive regex. `UnIoN` doesn't match `(?i)\\bunion\\b` \
             when the rule omits the case-insensitive flag. SQL itself is case-insensitive."
        }
        Technique::PayloadEncoding(s) if s.contains("Unicode") || s.contains("Homoglyph") => {
            "WAFs match ASCII keyword bytes; Unicode homoglyphs (e.g. Cyrillic `а` for ASCII `a`) \
             render identically in browsers but have different byte values, so the regex misses."
        }
        Technique::PayloadEncoding(s) if s.contains("OverlongUtf8") => {
            "UTF-8 has multi-byte representations of single characters that strict decoders reject \
             but lenient ones accept. A WAF that doesn't normalize overlong sequences sees \
             different bytes than the application does."
        }
        Technique::PayloadEncoding(s) if s.contains("html_entity_variants") => {
            "HTML entity encoding rotated across `&#xHH;` / `&#XHH;` / `&#DD;` / `&#000DD;` per \
             character. Browsers decode all four forms identically; WAF regexes anchored on the \
             canonical lowercase-x hex form (`&#x[0-9a-f]+;`) miss 3 of every 4 characters."
        }
        Technique::PayloadEncoding(s) if s.contains("math_bold") => {
            "Letters and digits replaced with their U+1D400 (Mathematical Bold) counterparts — \
             `SELECT` becomes `𝐒𝐄𝐋𝐄𝐂𝐓`. Both NFKC-normalise back to ASCII, so backends with \
             Unicode-normalising collations (Postgres ICU, MySQL utf8mb4_0900_ai_ci, Java/.NET/Go) \
             execute the original keyword while WAF byte-regex sees a U+1D4xx codepoint and misses."
        }
        Technique::PayloadEncoding(s) if s.contains("sql_concat_split") => {
            "Every `'string'` literal becomes `CONCAT('s','t','r','i','n','g')`. The literal \
             substring (e.g. `'admin'`, `'/etc/passwd'`) no longer appears contiguously, so \
             CRS-style block-list regexes anchored on these literals don't match. The DB \
             reassembles at runtime."
        }
        Technique::PayloadEncoding(s) if s.contains("sql_char_decompose") => {
            "Every `'string'` literal becomes `CHAR(N1,N2,...)` with one codepoint integer per \
             original char. The payload contains NO single-quoted ASCII tokens at all — defeats \
             literal-substring rules AND CONCAT-shaped rules in one move. MySQL/MariaDB/MSSQL \
             native; Postgres/Oracle use the sibling `pg_chr_decompose` tamper with unary CHR()."
        }
        Technique::PayloadEncoding(s) if s.contains("pg_chr_decompose") => {
            "Postgres/Oracle dialect: every `'string'` literal becomes \
             `(CHR(N)||CHR(N)||...)` — unary CHR() joined by the SQL-standard `||` pipe operator. \
             For ASCII payloads behaves identically to MySQL CHAR() decomposition; the syntactic \
             shape is distinct enough to defeat blocklists trained on one or the other."
        }
        Technique::GrammarMutation(_) => {
            "Grammar mutations replace blocked tokens with semantically-equivalent constructs \
             (e.g. `1=1` → `1 LIKE 1` or `1 BETWEEN 0 AND 2`). The WAF's keyword regex doesn't \
             know SQL semantics; the database does."
        }
        Technique::ContentTypeSwitch(_) => {
            "WAFs inspect content based on declared `Content-Type`. Sending JSON-shaped payload \
             as `text/plain` makes the WAF skip its JSON-specific rules; the application's \
             permissive parser still ingests it."
        }
        Technique::HeaderObfuscation(_) => {
            "Mixed-case or unusual header names (e.g. `X-FoRwArDeD-fOr`) bypass case-sensitive \
             header rule matchers in older or misconfigured WAF deployments."
        }
        Technique::RequestSmuggling(_) => {
            "Conflicting `Content-Length` and `Transfer-Encoding` headers cause the WAF and \
             upstream to disagree on where the request body ends — the WAF sees benign content; \
             the upstream sees the payload."
        }
        Technique::H2Evasion(_) => {
            "HTTP/2 header-name normalization differs between WAF (often built for HTTP/1.1) \
             and modern h2 servers. Mixed-case pseudo-headers, duplicate fields, and frame \
             ordering can split inspection state."
        }
        Technique::UserAgentRotation => {
            "Some WAFs apply less-strict rules to UAs they recognize (Googlebot, Slackbot, etc.). \
             Rotating in a trusted UA can downgrade the rule set in front of the request."
        }
        _ => {
            "This technique alters the request shape in a way that breaks pattern-based \
             inspection while preserving server-side semantics."
        }
    }
}

/// Compute a textual diff between two strings as a sequence of [`DiffHunk`]s.
///
/// Uses Myers' LCS algorithm at character granularity for short payloads
/// (≤ 1024 chars) — sufficient for the sub-kilobyte payloads the engine
/// actually generates. Above that we fall back to a single Delete + Insert
/// pair to keep `Explanation` size bounded.
fn textual_diff(original: &str, modified: &str) -> Vec<DiffHunk> {
    if original == modified {
        return vec![DiffHunk::Equal(original.to_string())];
    }
    if original.len() > 1024 || modified.len() > 1024 {
        return vec![
            DiffHunk::Delete(original.to_string()),
            DiffHunk::Insert(modified.to_string()),
        ];
    }

    let a: Vec<char> = original.chars().collect();
    let b: Vec<char> = modified.chars().collect();
    let lcs = longest_common_subsequence(&a, &b);
    backtrack_diff(&a, &b, &lcs)
}

/// Compute the LCS length matrix.
fn longest_common_subsequence(a: &[char], b: &[char]) -> Vec<Vec<usize>> {
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0; n + 1]; m + 1];
    for i in 0..m {
        for j in 0..n {
            dp[i + 1][j + 1] = if a[i] == b[j] {
                dp[i][j] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    dp
}

/// Walk the LCS matrix to produce hunks.
fn backtrack_diff(a: &[char], b: &[char], dp: &[Vec<usize>]) -> Vec<DiffHunk> {
    let mut hunks: Vec<DiffHunk> = Vec::new();
    let mut i = a.len();
    let mut j = b.len();

    while i > 0 || j > 0 {
        if i > 0 && j > 0 && a[i - 1] == b[j - 1] {
            push_or_extend(&mut hunks, DiffHunk::Equal(a[i - 1].to_string()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            push_or_extend(&mut hunks, DiffHunk::Insert(b[j - 1].to_string()));
            j -= 1;
        } else {
            push_or_extend(&mut hunks, DiffHunk::Delete(a[i - 1].to_string()));
            i -= 1;
        }
    }

    hunks.reverse();
    // Hunks built in reverse order have prepended characters; merge by
    // reversing each hunk's contents.
    hunks
        .into_iter()
        .map(|h| match h {
            DiffHunk::Equal(s) => DiffHunk::Equal(s.chars().rev().collect()),
            DiffHunk::Insert(s) => DiffHunk::Insert(s.chars().rev().collect()),
            DiffHunk::Delete(s) => DiffHunk::Delete(s.chars().rev().collect()),
        })
        .collect()
}

/// Append `next` onto the last hunk if same kind, else push as new hunk.
fn push_or_extend(hunks: &mut Vec<DiffHunk>, next: DiffHunk) {
    match (hunks.last_mut(), &next) {
        (Some(DiffHunk::Equal(prev)), DiffHunk::Equal(s)) => prev.push_str(s),
        (Some(DiffHunk::Insert(prev)), DiffHunk::Insert(s)) => prev.push_str(s),
        (Some(DiffHunk::Delete(prev)), DiffHunk::Delete(s)) => prev.push_str(s),
        _ => hunks.push(next),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cf_waf() -> DetectedWaf {
        DetectedWaf {
            name: "Cloudflare".into(),
            confidence: 0.9,
            indicators: vec![],
        }
    }

    #[test]
    fn explain_real_bypass_attributes_removed_rule() {
        // Original SQLi payload triggers SQLI-001 (UNION) + SQLI-002 (1=1) +
        // SQLI-003 (quote-comment). Double-url-encoded bypass removes the
        // keyword match (SQLI-001) but keeps tautology / quote.
        let exp = explain_bypass(
            "' UNION SELECT 1=1--",
            "%2527 %2555NION %2553ELECT 1=1--",
            &[Technique::PayloadEncoding("DoubleUrlEncode".into())],
            &cf_waf(),
            ExplanationMode::Standard,
        );
        assert!(!exp.triggered_rules.is_empty());
        assert!(exp.human_summary.contains("Cloudflare"));
        assert!(exp.human_summary.contains("DoubleUrlEncode"));
    }

    #[test]
    fn explain_minimal_mode_is_one_line() {
        let exp = explain_bypass(
            "<script>alert(1)</script>",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            &[Technique::PayloadEncoding("HtmlEntityEncode".into())],
            &cf_waf(),
            ExplanationMode::Minimal,
        );
        assert!(exp.human_summary.starts_with("Bypassed"));
        assert!(!exp.human_summary.contains('\n'));
    }

    #[test]
    fn explain_educational_includes_why() {
        // Use a double-url-encoded bypass — the bypass payload's lowercased
        // form is `%2575nion %2553elect`, which doesn't contain `union` or
        // `select`, so SQLI-001 is genuinely no-longer-attributed and the
        // educational summary gets to explain WHY DoubleUrlEncode bypassed
        // the WAF's keyword regex.
        let exp = explain_bypass(
            "' UNION SELECT--",
            "' %2555NION %2553ELECT--",
            &[Technique::PayloadEncoding("DoubleUrlEncode".into())],
            &cf_waf(),
            ExplanationMode::Educational,
        );
        assert!(
            exp.human_summary.contains("Why this works"),
            "educational mode should include the rationale section, got: {}",
            exp.human_summary
        );
        assert!(exp.human_summary.contains("URL-decode"));
    }

    #[test]
    fn benign_payload_explanation_says_so() {
        let exp = explain_bypass("hello", "hello", &[], &cf_waf(), ExplanationMode::Standard);
        assert!(exp.human_summary.contains("did not match any tracked rule"));
    }

    #[test]
    fn diff_identical_strings_one_equal_hunk() {
        let hunks = textual_diff("abc", "abc");
        assert_eq!(hunks.len(), 1);
        assert!(matches!(hunks[0], DiffHunk::Equal(ref s) if s == "abc"));
    }

    #[test]
    fn diff_pure_insert() {
        let hunks = textual_diff("abc", "axbc");
        let inserts: String = hunks
            .iter()
            .filter_map(|h| match h {
                DiffHunk::Insert(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(inserts, "x");
    }

    #[test]
    fn diff_pure_delete() {
        let hunks = textual_diff("abc", "ab");
        let deletes: String = hunks
            .iter()
            .filter_map(|h| match h {
                DiffHunk::Delete(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(deletes, "c");
    }

    #[test]
    fn diff_substitution() {
        let hunks = textual_diff("abc", "axc");
        // Should be Equal("a"), Delete("b"), Insert("x"), Equal("c")
        // Ordering of Delete/Insert when they coexist is up to the algorithm;
        // we just assert that one delete and one insert of the right chars exist.
        assert!(
            hunks
                .iter()
                .any(|h| matches!(h, DiffHunk::Delete(s) if s == "b"))
        );
        assert!(
            hunks
                .iter()
                .any(|h| matches!(h, DiffHunk::Insert(s) if s == "x"))
        );
    }

    #[test]
    fn diff_long_payload_falls_back_to_single_hunk_pair() {
        let a: String = "a".repeat(1500);
        let b: String = "b".repeat(1500);
        let hunks = textual_diff(&a, &b);
        assert_eq!(hunks.len(), 2);
        assert!(matches!(hunks[0], DiffHunk::Delete(_)));
        assert!(matches!(hunks[1], DiffHunk::Insert(_)));
    }

    #[test]
    fn diff_round_trip_preserves_modified_string() {
        // Reconstruct the modified string from the diff: Equal + Insert chars.
        let original = "the quick brown fox";
        let modified = "the slow brown dog";
        let hunks = textual_diff(original, modified);
        let recovered: String = hunks
            .iter()
            .filter_map(|h| match h {
                DiffHunk::Equal(s) | DiffHunk::Insert(s) => Some(s.as_str()),
                DiffHunk::Delete(_) => None,
            })
            .collect();
        assert_eq!(recovered, modified);
    }
}
