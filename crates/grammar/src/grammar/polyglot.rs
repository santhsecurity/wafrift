//! Polyglot payload generator — payloads valid across multiple contexts.
//!
//! Combines delimiter-sets from multiple payload types to create cross-context
//! bypasses (e.g., SQL + XSS, CMD + XSS, SSTI + XSS). These exploit WAFs that
//! only classify a payload as one type and only apply rules for that type —
//! a polyglot triggers in whichever context the application actually uses.
//!
//! The polyglot table is community-contributed via
//! `crates/grammar/rules/polyglot/polyglots.toml` and compiled in by
//! `build.rs`. Adding a polyglot is a one-line PR with no Rust knowledge.

include!(concat!(env!("OUT_DIR"), "/polyglots_data.rs"));

/// A polyglot payload with metadata.
#[derive(Debug, Clone)]
pub struct PolyglotPayload {
    /// The polyglot payload string.
    pub payload: String,
    /// Which contexts this payload is valid in.
    pub contexts: Vec<&'static str>,
    /// Human-readable description.
    pub description: String,
}

/// Generate all polyglot payloads.
#[must_use]
pub fn all_polyglots() -> Vec<PolyglotPayload> {
    POLYGLOTS_RAW
        .iter()
        .map(|(payload, contexts, description)| PolyglotPayload {
            payload: (*payload).to_string(),
            contexts: contexts.to_vec(),
            description: (*description).to_string(),
        })
        .collect()
}

/// Generate polyglot payloads filtered by context.
#[must_use]
pub fn polyglots_for(context: &str) -> Vec<String> {
    all_polyglots()
        .into_iter()
        .filter(|p| p.contexts.contains(&context))
        .map(|p| p.payload)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_xss_polyglots_exist() {
        let polyglots = polyglots_for("sql");
        assert!(
            polyglots.len() >= 7,
            "should have at least 7 SQL polyglots, got {}",
            polyglots.len()
        );
        assert!(
            polyglots
                .iter()
                .any(|p| p.contains("<script>") || p.contains("<svg") || p.contains("<img"))
        );
    }

    #[test]
    fn cmd_xss_polyglots_exist() {
        let polyglots = polyglots_for("cmd");
        assert!(polyglots.len() >= 5, "should have at least 5 CMD polyglots");
        assert!(polyglots.iter().any(|p| p.contains("echo")));
    }

    #[test]
    fn ssti_xss_polyglots_exist() {
        let polyglots = polyglots_for("ssti");
        assert!(
            polyglots.len() >= 5,
            "should have at least 5 SSTI polyglots"
        );
        assert!(
            polyglots
                .iter()
                .any(|p| p.contains("{{") || p.contains("${"))
        );
    }

    #[test]
    fn all_polyglots_have_contexts() {
        for p in all_polyglots() {
            assert!(
                !p.contexts.is_empty(),
                "polyglot must declare at least one context"
            );
        }
    }

    #[test]
    fn universal_polyglots_cover_multiple_contexts() {
        let universals: Vec<_> = all_polyglots()
            .into_iter()
            .filter(|p| p.contexts.len() >= 3)
            .collect();
        assert!(
            !universals.is_empty(),
            "must have at least one polyglot covering 3+ contexts"
        );
        for p in &universals {
            assert!(
                p.contexts.len() >= 2,
                "universal polyglots should cover 2+ contexts: {:?}",
                p.contexts
            );
        }
    }

    #[test]
    fn sql_cmd_polyglots_exist() {
        let polyglots: Vec<_> = all_polyglots()
            .into_iter()
            .filter(|p| p.contexts.contains(&"sql") && p.contexts.contains(&"cmd"))
            .collect();
        assert!(polyglots.len() >= 3, "should have SQL+CMD polyglots");
    }

    #[test]
    fn total_polyglot_count() {
        let all = all_polyglots();
        assert!(
            all.len() >= 25,
            "should have at least 25 total polyglots, got {}",
            all.len()
        );
    }

    #[test]
    fn polyglots_for_unknown_context_empty() {
        let polyglots = polyglots_for("nonexistent");
        assert!(polyglots.is_empty());
    }
}
