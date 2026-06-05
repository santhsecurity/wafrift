//! Redis command injection grammar-aware mutation.

/// Detect Redis command injection signals.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let p = payload.to_ascii_uppercase();
    [
        "EVAL ",
        "SCRIPT ",
        "CONFIG ",
        "FLUSHALL",
        "BGSAVE",
        "SHUTDOWN",
        "GET ",
        "SET ",
        "DEL ",
        "HGET ",
        "HMSET ",
        "LPUSH ",
        "RPUSH ",
        "INFO",
        "CLIENT ",
        "MODULE ",
        "SLAVEOF",
        "REPLICAOF",
    ]
    .iter()
    .any(|sig| p.contains(sig))
}

/// Generate Redis mutation variants.
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if !detect_type(payload) {
        return Vec::new();
    }
    let mut results = Vec::new();
    let upper = payload.to_ascii_uppercase();

    // CRLF injection / protocol smuggling
    results.push(payload.replace(' ', "\r\n"));
    results.push(format!("*{payload}\r\n"));

    // EVAL-based RCE
    if upper.contains("EVAL") {
        results.push("EVAL \"return 1\" 0".into());
        results.push("EVAL \"return redis.call('INFO')\" 0".into());
    }

    // Command concatenation with newlines
    results.push(format!("{payload}\r\nCONFIG GET dir"));
    results.push(format!("{payload}\r\nINFO"));

    // Inline command variants
    results.push(payload.replace(' ', "\t"));

    // URL-encoded variants
    results.push(payload.replace(' ', "%20"));

    super::variant_util::finalize(results, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_redis_signals() {
        assert!(detect_type("GET key"));
        assert!(detect_type("EVAL 'return 1' 0"));
        assert!(detect_type("CONFIG GET dir"));
    }

    #[test]
    fn generates_protocol_variants() {
        let mutations = mutate("GET key");
        assert!(mutations.iter().any(|m| m.contains("\r\n")));
    }

    #[test]
    fn rejects_non_redis() {
        assert!(!detect_type("hello world"));
        assert!(mutate("' OR 1=1--").is_empty());
    }

    #[test]
    fn eval_variants_generated() {
        let mutations = mutate("EVAL 'return 1' 0");
        assert!(mutations.iter().any(|m| m.contains("redis.call")));
    }

    #[test]
    fn config_injection_appended() {
        let mutations = mutate("GET key");
        assert!(mutations.iter().any(|m| m.contains("CONFIG GET dir")));
    }

    #[test]
    fn tab_separator_variant() {
        let mutations = mutate("GET key");
        assert!(mutations.iter().any(|m| m.contains('\t')));
    }

    #[test]
    fn empty_payload_returns_empty() {
        assert!(mutate("").is_empty());
    }
}
