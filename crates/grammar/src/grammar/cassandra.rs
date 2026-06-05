//! Apache Cassandra / CQL injection grammar-aware mutation.

/// Detect Cassandra CQL injection signals.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    lower.contains("cassandra")
        || lower.contains("consistency ")
        || lower.contains("token(")
        || lower.contains("allow filtering")
        || lower.contains("using ttl")
        || (lower.contains("select") && lower.contains("from") && lower.contains("json"))
}

/// Generate Cassandra mutation variants.
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if !detect_type(payload) {
        return Vec::new();
    }
    let mut results = Vec::new();
    let lower = payload.to_ascii_lowercase();

    // JSON output format bypass
    if lower.contains("select") {
        results.push(format!("{payload} JSON"));
        results.push(payload.replace("SELECT ", "SELECT JSON "));
    }

    // Consistency level manipulation
    results.push(format!("CONSISTENCY ALL; {payload}"));
    results.push(format!("CONSISTENCY ONE; {payload}"));

    // Token-based partition key bypass
    if lower.contains("where") {
        results.push(payload.replace("WHERE ", "WHERE token(") + ") > 0");
    }

    // Time-to-live / timestamp injection
    if lower.contains("insert") || lower.contains("update") {
        results.push(format!("{payload} USING TTL 86400"));
    }

    super::variant_util::finalize(results, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cassandra_signals() {
        assert!(detect_type("SELECT JSON * FROM users"));
        assert!(detect_type("CONSISTENCY ONE"));
        assert!(detect_type("SELECT * FROM users USING TTL 86400"));
    }

    #[test]
    fn generates_json_variants() {
        let mutations = mutate("SELECT JSON * FROM users");
        assert!(mutations.iter().any(|m| m.contains("JSON")));
    }

    #[test]
    fn rejects_non_cassandra() {
        assert!(!detect_type("hello world"));
        assert!(mutate("' OR 1=1--").is_empty());
    }

    #[test]
    fn consistency_variants_generated() {
        let mutations = mutate("SELECT * FROM users USING TTL");
        assert!(mutations.iter().any(|m| m.contains("CONSISTENCY")));
    }

    #[test]
    fn ttl_variant_for_insert() {
        let mutations = mutate("INSERT INTO users (id) VALUES (1) USING TTL");
        assert!(mutations.iter().any(|m| m.contains("USING TTL")));
    }

    #[test]
    fn token_variant_for_where() {
        let mutations = mutate("SELECT JSON * FROM users WHERE id = 1");
        assert!(mutations.iter().any(|m| m.contains("token(")));
    }

    #[test]
    fn empty_payload_returns_empty() {
        assert!(mutate("").is_empty());
    }
}
