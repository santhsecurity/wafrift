//! Community-configurable WAF detection and evasion rules.

use serde::Deserialize;

/// A complete custom rules file containing multiple WAF definitions.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomRulesFile {
    /// WAF detection rules.
    #[serde(default)]
    pub waf: Vec<CustomWafRule>,
}

/// A single WAF detection and evasion rule.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomWafRule {
    /// Human-readable WAF name.
    pub name: String,
    /// Vendor or product family.
    #[serde(default)]
    pub vendor: String,
    /// HTTP response header signatures.
    #[serde(default)]
    pub header_signatures: Vec<HeaderSignature>,
    /// HTTP response body patterns.
    #[serde(default)]
    pub body_signatures: Vec<BodySignature>,
    /// HTTP status codes that indicate blocking.
    #[serde(default)]
    pub block_status_codes: Vec<u16>,
    /// Recommended evasion strategy names.
    #[serde(default)]
    pub evasion_strategies: Vec<String>,
}

/// A header-based WAF detection signature.
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderSignature {
    /// Header name to check (case-insensitive).
    pub name: String,
    /// If present, the header value must contain this substring.
    #[serde(default)]
    pub value_contains: Option<String>,
    /// Detection confidence when this signature matches (0.0–1.0).
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}

/// A body-based WAF detection signature.
#[derive(Debug, Clone, Deserialize)]
pub struct BodySignature {
    /// Substring to search for in the response body (case-insensitive).
    pub pattern: String,
    /// Detection confidence when this signature matches (0.0–1.0).
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}

fn default_confidence() -> f64 {
    0.5
}

/// Result of matching a custom rule against a response.
#[derive(Debug, Clone)]
pub struct CustomDetection {
    pub rule_name: String,
    pub vendor: String,
    pub confidence: f64,
    pub evasion_strategies: Vec<String>,
}

/// Build the valid evasion strategy set dynamically from the gene pool.
fn valid_evasion_strategies() -> Vec<String> {
    let pool = crate::evolution::GenePool::default_wafrift();
    // Include encoding values and content-type values as valid strategies
    let mut values = Vec::new();
    if let Some(encoding_values) = pool.values_for("encoding") {
        for v in encoding_values {
            if v != "None" {
                values.push(v.clone());
            }
        }
    }
    if let Some(content_values) = pool.values_for("content_type") {
        for v in content_values {
            if v != "None" {
                values.push(v.clone());
            }
        }
    }
    if let Some(header_values) = pool.values_for("header_obfuscation") {
        for v in header_values {
            if v != "None" {
                values.push(v.clone());
            }
        }
    }
    if let Some(grammar_values) = pool.values_for("grammar_rule") {
        for v in grammar_values {
            if v != "None" {
                values.push(v.clone());
            }
        }
    }
    // Also include common aliases used in TOML rules
    values.push("Base64Encode".into());
    values.push("HexEncode".into());
    values.push("Utf7Encode".into());
    values.push("Multipart".into());
    values.push("JsonNested".into());
    values.push("XmlCdata".into());
    values
}

/// Maximum byte length of an accepted custom-rules TOML payload.
/// Prevents OOM / stack overflow on malicious deeply-nested input
/// (`toml::from_str` does not enforce a built-in size or depth limit).
/// 1 MiB is generous for any realistic ruleset.
const MAX_CUSTOM_RULES_BYTES: usize = 1024 * 1024;

/// Load custom rules from a TOML string. Inputs larger than 1 MiB are
/// rejected before parsing to bound memory + parse time.
pub fn load_rules(toml_str: &str) -> std::result::Result<CustomRulesFile, String> {
    if toml_str.len() > MAX_CUSTOM_RULES_BYTES {
        return Err(format!(
            "custom rules TOML rejected: {} bytes exceeds maximum of {} bytes",
            toml_str.len(),
            MAX_CUSTOM_RULES_BYTES
        ));
    }
    let rules: CustomRulesFile =
        toml::from_str(toml_str).map_err(|e| format!("failed to parse custom rules TOML: {e}"))?;
    validate_rules(&rules)?;
    validate_evasion_strategies(&rules)?;
    Ok(rules)
}

fn validate_rules(rules: &CustomRulesFile) -> std::result::Result<(), String> {
    for (idx, waf) in rules.waf.iter().enumerate() {
        if waf.name.trim().is_empty() {
            return Err(format!(
                "validation error: waf[{idx}] missing required field 'name'"
            ));
        }
        for (sig_idx, sig) in waf.header_signatures.iter().enumerate() {
            if sig.name.trim().is_empty() {
                return Err(format!(
                    "validation error: waf[{idx}].header_signatures[{sig_idx}] missing required field 'name'"
                ));
            }
            if !(0.0..=1.0).contains(&sig.confidence) {
                return Err(format!(
                    "validation error: waf[{}].header_signatures[{}] confidence must be between 0.0 and 1.0, got {}",
                    idx, sig_idx, sig.confidence
                ));
            }
        }
        for (sig_idx, sig) in waf.body_signatures.iter().enumerate() {
            if sig.pattern.trim().is_empty() {
                return Err(format!(
                    "validation error: waf[{idx}].body_signatures[{sig_idx}] missing required field 'pattern'"
                ));
            }
            if !(0.0..=1.0).contains(&sig.confidence) {
                return Err(format!(
                    "validation error: waf[{}].body_signatures[{}] confidence must be between 0.0 and 1.0, got {}",
                    idx, sig_idx, sig.confidence
                ));
            }
        }
        for code in &waf.block_status_codes {
            if *code == 0 || *code > 999 {
                return Err(format!(
                    "validation error: waf[{idx}] invalid status code {code} (must be 1-999)"
                ));
            }
        }
    }
    Ok(())
}

fn validate_evasion_strategies(rules: &CustomRulesFile) -> std::result::Result<(), String> {
    let valid = valid_evasion_strategies();
    let mut unknown_strategies: Vec<(usize, String)> = Vec::new();
    for (waf_idx, waf) in rules.waf.iter().enumerate() {
        for strategy in &waf.evasion_strategies {
            if !valid.contains(strategy) {
                unknown_strategies.push((waf_idx, strategy.clone()));
            }
        }
    }
    if !unknown_strategies.is_empty() {
        let errors: Vec<String> = unknown_strategies
            .into_iter()
            .map(|(idx, s)| format!("waf[{idx}]: unknown evasion_strategy '{s}'"))
            .collect();
        return Err(format!(
            "validation error: invalid evasion_strategies found:\n  - {}",
            errors.join("\n  - ")
        ));
    }
    Ok(())
}

/// Load custom rules from a file path.
pub fn load_rules_from_file(
    path: &std::path::Path,
) -> std::result::Result<CustomRulesFile, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read rules file {}: {}", path.display(), e))?;
    load_rules(&content)
}

/// Match custom rules against an HTTP response.
#[must_use]
pub fn detect(
    rules: &CustomRulesFile,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Option<CustomDetection> {
    let body_str = String::from_utf8_lossy(&body[..body.len().min(4096)]).to_ascii_lowercase();
    let mut best: Option<CustomDetection> = None;
    for rule in &rules.waf {
        let mut max_confidence: f64 = 0.0;
        let mut matched = false;
        if rule.block_status_codes.contains(&status) {
            max_confidence = max_confidence.max(0.3);
            matched = true;
        }
        for sig in &rule.header_signatures {
            let header_match = headers.iter().any(|(name, value)| {
                if !name.eq_ignore_ascii_case(&sig.name) {
                    return false;
                }
                match &sig.value_contains {
                    Some(substring) => value
                        .to_ascii_lowercase()
                        .contains(&substring.to_ascii_lowercase()),
                    None => true,
                }
            });
            if header_match {
                max_confidence = max_confidence.max(sig.confidence);
                matched = true;
            }
        }
        for sig in &rule.body_signatures {
            if body_str.contains(&sig.pattern.to_ascii_lowercase()) {
                max_confidence = max_confidence.max(sig.confidence);
                matched = true;
            }
        }
        if matched && max_confidence > best.as_ref().map_or(0.0, |b| b.confidence) {
            best = Some(CustomDetection {
                rule_name: rule.name.clone(),
                vendor: rule.vendor.clone(),
                confidence: max_confidence,
                evasion_strategies: rule.evasion_strategies.clone(),
            });
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
[[waf]]
name = "TestWAF"
vendor = "test-vendor"
block_status_codes = [403, 406]
evasion_strategies = ["DoubleUrlEncode", "SqlCommentInsertion"]

[[waf.header_signatures]]
name = "x-test-waf"
confidence = 0.9

[[waf.header_signatures]]
name = "server"
value_contains = "TestWAF"
confidence = 0.8

[[waf.body_signatures]]
pattern = "Blocked by TestWAF"
confidence = 0.95

[[waf]]
name = "AnotherWAF"
vendor = "another"
block_status_codes = [429]
evasion_strategies = ["CaseAlternation"]

[[waf.header_signatures]]
name = "x-another-waf"
confidence = 0.7
"#;

    #[test]
    fn load_rules_basic() {
        let rules = load_rules(SAMPLE_TOML).expect("should parse");
        assert_eq!(rules.waf.len(), 2);
        assert_eq!(rules.waf[0].name, "TestWAF");
        assert_eq!(rules.waf[0].header_signatures.len(), 2);
        assert_eq!(rules.waf[0].body_signatures.len(), 1);
        assert_eq!(rules.waf[0].block_status_codes, vec![403, 406]);
        assert_eq!(rules.waf[0].evasion_strategies.len(), 2);
    }

    #[test]
    fn load_rules_empty() {
        let rules = load_rules("").expect("empty should parse");
        assert!(rules.waf.is_empty());
    }

    #[test]
    fn load_rules_invalid_toml() {
        let result = load_rules("this is not { valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn detect_by_header() {
        let rules = load_rules(SAMPLE_TOML).expect("should parse");
        let headers = vec![("x-test-waf".into(), "active".into())];
        let result = detect(&rules, 200, &headers, b"OK");
        assert!(result.is_some());
        let det = result.unwrap();
        assert_eq!(det.rule_name, "TestWAF");
        assert!((det.confidence - 0.9).abs() < 0.01);
    }

    #[test]
    fn detect_by_body() {
        let rules = load_rules(SAMPLE_TOML).expect("should parse");
        let headers: Vec<(String, String)> = vec![];
        let body = b"Error: Blocked by TestWAF engine";
        let result = detect(&rules, 200, &headers, body);
        assert!(result.is_some());
        let det = result.unwrap();
        assert_eq!(det.rule_name, "TestWAF");
        assert!((det.confidence - 0.95).abs() < 0.01);
    }

    #[test]
    fn detect_by_status() {
        let rules = load_rules(SAMPLE_TOML).expect("should parse");
        let headers: Vec<(String, String)> = vec![];
        let result = detect(&rules, 403, &headers, b"");
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "TestWAF");
    }

    #[test]
    fn detect_no_match() {
        let rules = load_rules(SAMPLE_TOML).expect("should parse");
        let headers = vec![("server".into(), "nginx".into())];
        let result = detect(&rules, 200, &headers, b"Welcome");
        assert!(result.is_none());
    }

    #[test]
    fn dynamic_strategy_validation_accepts_content_type_genes() {
        let toml = r#"
[[waf]]
name = "Test"
evasion_strategies = ["Multipart", "JsonNested"]
"#;
        let rules = load_rules(toml);
        assert!(
            rules.is_ok(),
            "Multipart and JsonNested should be valid strategies"
        );
    }

    #[test]
    fn dynamic_strategy_validation_accepts_grammar_genes() {
        let toml = r#"
[[waf]]
name = "Test"
evasion_strategies = ["tautology_swap", "comment_swap"]
"#;
        let rules = load_rules(toml);
        assert!(rules.is_ok(), "Grammar genes should be valid strategies");
    }

    #[test]
    fn load_rules_rejects_oversized_payload() {
        let huge = "x".repeat(1024 * 1024 + 1);
        let result = load_rules(&huge);
        assert!(result.is_err(), "should reject >1 MiB input");
        let msg = result.unwrap_err();
        assert!(msg.contains("exceeds maximum"), "error should mention size limit: {msg}");
    }

    #[test]
    fn load_rules_rejects_empty_waf_name() {
        let toml = r#"
[[waf]]
name = "   "
"#;
        let result = load_rules(toml);
        assert!(result.is_err(), "should reject empty/whitespace name");
    }

    #[test]
    fn load_rules_rejects_invalid_confidence_high() {
        let toml = r#"
[[waf]]
name = "Test"
[[waf.header_signatures]]
name = "X-Block"
confidence = 1.5
"#;
        let result = load_rules(toml);
        assert!(result.is_err(), "should reject confidence > 1.0");
    }

    #[test]
    fn load_rules_rejects_invalid_confidence_negative() {
        let toml = r#"
[[waf]]
name = "Test"
[[waf.header_signatures]]
name = "X-Block"
confidence = -0.1
"#;
        let result = load_rules(toml);
        assert!(result.is_err(), "should reject negative confidence");
    }

    #[test]
    fn load_rules_rejects_invalid_status_code_zero() {
        let toml = r#"
[[waf]]
name = "Test"
block_status_codes = [0]
"#;
        let result = load_rules(toml);
        assert!(result.is_err(), "should reject status code 0");
    }

    #[test]
    fn load_rules_rejects_invalid_status_code_too_high() {
        let toml = r#"
[[waf]]
name = "Test"
block_status_codes = [1000]
"#;
        let result = load_rules(toml);
        assert!(result.is_err(), "should reject status code > 999");
    }

    #[test]
    fn load_rules_rejects_unknown_evasion_strategy() {
        let toml = r#"
[[waf]]
name = "Test"
evasion_strategies = ["DefinitelyNotRealStrategy123"]
"#;
        let result = load_rules(toml);
        assert!(result.is_err(), "should reject unknown evasion strategy");
        let msg = result.unwrap_err();
        assert!(msg.contains("unknown evasion_strategy"), "error should name the strategy: {msg}");
    }

    #[test]
    fn load_rules_rejects_empty_body_pattern() {
        let toml = r#"
[[waf]]
name = "Test"
[[waf.body_signatures]]
pattern = "   "
"#;
        let result = load_rules(toml);
        assert!(result.is_err(), "should reject empty/whitespace body pattern");
    }

    #[test]
    fn load_rules_rejects_empty_header_name() {
        let toml = r#"
[[waf]]
name = "Test"
[[waf.header_signatures]]
name = "   "
"#;
        let result = load_rules(toml);
        assert!(result.is_err(), "should reject empty/whitespace header name");
    }
}
