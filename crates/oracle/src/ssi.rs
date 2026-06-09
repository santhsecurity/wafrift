//! Server-Side Includes (SSI) payload oracle.
//!
//! SSI directives must preserve their `<!--#<directive>` envelope and
//! the directive name itself. Whitespace, quote style, and case-folded
//! attribute names can vary freely (Apache mod_include tolerates all
//! of these), but if the envelope is broken or the directive token is
//! mangled the payload becomes inert HTML markup.
//!
//! # Validation strategy
//!
//! A valid SSI payload must contain:
//! 1. **The opening prefix** `<!--#` — without this Apache never enters
//!    SSI parsing.
//! 2. **A recognised directive name** — `exec`, `include`, `echo`,
//!    `set`, `config`, `fsize`, `flastmod`, `printenv`. Case-insensitive.
//! 3. **A closing `-->`** — open-ended directives produce HTML
//!    text-node leakage and never execute.
//!
//! Directive semantics are then preserved if the same directive name
//! appears in both original and transformed payloads (Apache resolves
//! by directive identity; an `exec`-to-`include` substitution changes
//! the attack class).

use crate::traits::PayloadOracle;

/// SSI-specific oracle that validates the directive envelope and
/// directive identity.
pub struct SsiOracle;

/// Recognised SSI directive tokens per Apache mod_include
/// documentation. Names are matched case-insensitively.
const SSI_DIRECTIVES: &[&str] = &[
    "exec", "include", "echo", "set", "config", "fsize", "flastmod", "printenv",
];

/// Extracts the directive name from an SSI payload, or `None` if the
/// envelope is broken / the directive is not recognised.
fn directive_name(payload: &str) -> Option<&'static str> {
    let trimmed = payload.trim();
    let inner = trimmed
        .strip_prefix("<!--#")
        .and_then(|s| s.strip_suffix("-->").or_else(|| s.strip_suffix("--  >")))?
        .trim_start();
    // First whitespace-separated token is the directive name.
    let token = inner
        .split(|c: char| c.is_whitespace() || c == '=')
        .next()?;
    let token_lower = token.to_ascii_lowercase();
    SSI_DIRECTIVES
        .iter()
        .copied()
        .find(|&d| d == token_lower.as_str())
}

/// Checks whether a payload retains a valid SSI envelope with a
/// known directive name.
fn has_ssi_structure(payload: &str) -> bool {
    directive_name(payload).is_some()
}

impl PayloadOracle for SsiOracle {
    fn is_semantically_valid(&self, original: &str, transformed: &str) -> bool {
        let original_dir = directive_name(original);
        let transformed_dir = directive_name(transformed);

        // If the original had a recognised directive, the transform
        // must preserve THE SAME directive (substituting `include` for
        // `exec` changes the attack class — caller should re-classify
        // not mark as semantically-equivalent).
        match (original_dir, transformed_dir) {
            (Some(orig), Some(new)) => orig == new,
            (None, _) => has_ssi_structure(transformed),
            (Some(_), None) => false,
        }
    }

    fn name(&self) -> &'static str {
        "SSI"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_directive_valid() {
        let oracle = SsiOracle;
        assert!(
            oracle.is_semantically_valid(r#"<!--#exec cmd="ls" -->"#, r#"<!--#exec cmd="ls" -->"#,)
        );
    }

    #[test]
    fn whitespace_reflow_preserved() {
        let oracle = SsiOracle;
        assert!(
            oracle.is_semantically_valid(
                r#"<!--#exec cmd="ls" -->"#,
                r#"<!--#  exec  cmd="ls"  -->"#,
            )
        );
        assert!(oracle.is_semantically_valid(
            r#"<!--#exec cmd="ls" -->"#,
            "<!--#\texec\tcmd=\"ls\"\t-->",
        ));
    }

    #[test]
    fn case_change_preserved() {
        let oracle = SsiOracle;
        assert!(
            oracle.is_semantically_valid(r#"<!--#exec cmd="ls" -->"#, r#"<!--#EXEC cmd="ls" -->"#,)
        );
        assert!(
            oracle.is_semantically_valid(r#"<!--#exec cmd="ls" -->"#, r#"<!--#Exec cmd="ls" -->"#,)
        );
    }

    #[test]
    fn quote_rotation_preserved() {
        let oracle = SsiOracle;
        assert!(
            oracle.is_semantically_valid(r#"<!--#exec cmd="ls" -->"#, r#"<!--#exec cmd='ls' -->"#,)
        );
    }

    /// LAW 12 anti-rig: directive identity matters. An `exec` that
    /// became an `include` is a different attack class — the oracle
    /// MUST refuse this mutation rather than rubber-stamp it.
    #[test]
    fn directive_substitution_rejected() {
        let oracle = SsiOracle;
        assert!(
            !oracle.is_semantically_valid(
                r#"<!--#exec cmd="ls" -->"#,
                r#"<!--#include file="ls" -->"#,
            )
        );
    }

    /// LAW 1 anti-rig: a transform that destroys the SSI envelope
    /// (e.g. URL-encodes the opener) produces HTML text, not an SSI
    /// directive. The oracle must refuse.
    #[test]
    fn url_encoded_opener_rejected() {
        let oracle = SsiOracle;
        assert!(!oracle.is_semantically_valid(
            r#"<!--#exec cmd="ls" -->"#,
            r"%3C%21--%23exec%20cmd%3D%22ls%22%20--%3E",
        ));
    }

    /// LAW 1 anti-rig: unterminated directives never execute on
    /// Apache (the parser falls through to text-node leakage).
    #[test]
    fn unterminated_directive_rejected() {
        let oracle = SsiOracle;
        assert!(
            !oracle.is_semantically_valid(r#"<!--#exec cmd="ls" -->"#, r#"<!--#exec cmd="ls""#,)
        );
    }

    /// LAW 1 anti-rig: a misspelled directive (`exe` instead of
    /// `exec`) doesn't run on Apache.
    #[test]
    fn unknown_directive_rejected() {
        let oracle = SsiOracle;
        assert!(
            !oracle.is_semantically_valid(r#"<!--#exec cmd="ls" -->"#, r#"<!--#exe cmd="ls" -->"#,)
        );
    }

    #[test]
    fn all_known_directives_round_trip() {
        let oracle = SsiOracle;
        for d in [
            "exec", "include", "echo", "set", "config", "fsize", "flastmod", "printenv",
        ] {
            let p = format!("<!--#{d} -->");
            assert!(oracle.is_semantically_valid(&p, &p), "{d} must round-trip");
        }
    }

    #[test]
    fn empty_payloads_rejected() {
        let oracle = SsiOracle;
        assert!(!oracle.is_semantically_valid("", ""));
        assert!(!oracle.is_semantically_valid(r#"<!--#exec cmd="ls" -->"#, ""));
    }

    /// LAW 12: oracle name is a pinned public string — consumer code
    /// may filter on it.
    #[test]
    fn oracle_name_is_pinned() {
        let oracle = SsiOracle;
        assert_eq!(oracle.name(), "SSI");
    }
}
