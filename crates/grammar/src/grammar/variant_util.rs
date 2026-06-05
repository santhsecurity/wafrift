//! Shared post-processing for per-class grammar mutators.
//!
//! §7 DEDUP / §14 INTROSPECTION: `ldap`, `path_traversal`, `jndi`, `ssi`,
//! `template`, `sql`, and `xss` each already drop no-op (== input) variants
//! and de-duplicate before returning. The NoSQL family
//! (`mongo`/`elastic`/`redis`/`cassandra`) did neither, so their `mutate`
//! could echo the unmutated input back as a "variant" (e.g. the array-bypass
//! `payload.replace("$eq","$nin")` is a no-op when the payload has no `$eq`)
//! and emit duplicates — inflating variant counts and, worse, letting a
//! benign but loosely-detected `{…}` JSON body surface as a fake attack
//! mutation. This is the one canonical place that enforces the "a mutation
//! must mutate" contract for those modules so the rule can't drift apart four
//! ways again.

use std::collections::HashSet;

/// Drop variants identical to `original` and de-duplicate, preserving
/// first-seen order. A mutation engine must return *mutations*: a variant
/// equal to the input is a no-op, and a repeated variant is wasted firing
/// budget that also skews the bypass-rate denominator.
#[must_use]
pub(crate) fn finalize(mut variants: Vec<String>, original: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    variants.retain(|v| v != original && seen.insert(v.clone()));
    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_input_equal_variant() {
        let out = finalize(vec!["a".into(), "x".into(), "a".into()], "a");
        assert_eq!(out, vec!["x".to_string()]);
    }

    #[test]
    fn dedups_preserving_first_seen_order() {
        let out = finalize(
            vec!["b".into(), "c".into(), "b".into(), "d".into()],
            "orig",
        );
        assert_eq!(out, vec!["b".to_string(), "c".into(), "d".into()]);
    }

    #[test]
    fn only_input_yields_empty() {
        assert!(finalize(vec!["same".into(), "same".into()], "same").is_empty());
    }
}
