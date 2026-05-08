//! Evasion result — a transformed request with metadata.
//!
//! Carries the mutated request, which techniques were applied, a
//! human-readable description, and a confidence score estimating
//! bypass probability.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Request;
use crate::Technique;

/// A transformed request ready to send.
///
/// Carries the mutated request, which techniques were applied, a
/// human-readable description, and a confidence score estimating
/// how likely this is to bypass the WAF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionResult {
    /// The transformed request with evasion techniques applied.
    pub request: Request,
    /// Which techniques were applied.
    pub techniques: Vec<Technique>,
    /// Human-readable description of what was done.
    pub description: String,
    /// Estimated bypass probability (0.0–1.0).
    ///
    /// Higher values indicate more aggressive or historically successful
    /// techniques. Updated by the evolution engine after feedback.
    pub confidence: f64,
}

impl EvasionResult {
    /// Create a new evasion result with heuristic confidence.
    #[must_use]
    pub fn new(request: Request, techniques: Vec<Technique>, description: String) -> Self {
        let confidence = Self::estimate_confidence(&techniques);
        Self {
            request,
            techniques,
            description,
            confidence,
        }
    }

    /// Create with an explicit confidence score (used by evolution engine).
    #[must_use]
    pub fn with_confidence(
        request: Request,
        techniques: Vec<Technique>,
        description: String,
        confidence: f64,
    ) -> Self {
        Self {
            request,
            techniques,
            description,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }

    /// Heuristic confidence estimation based on technique composition.
    ///
    /// Multi-layered evasions score higher. Grammar mutations score higher
    /// than encoding-only because they defeat semantic analysis, not just
    /// pattern matching.
    fn estimate_confidence(techniques: &[Technique]) -> f64 {
        if techniques.is_empty() {
            return 0.0;
        }

        let mut score: f64 = 0.0;
        for t in techniques {
            score += match t {
                Technique::PayloadEncoding(_) | Technique::BoundaryManipulation => 0.15,
                Technique::ContentTypeSwitch(_) => 0.20,
                Technique::JsonUnicodeEscape
                | Technique::TlsFingerprint(_)
                | Technique::HeaderObfuscation(_) => 0.10,
                Technique::UserAgentRotation | Technique::Http2Settings => 0.05,
                Technique::GrammarMutation(_) => 0.30,
                Technique::RequestSmuggling(_) => 0.35,
                Technique::H2Evasion(_) => 0.25,
                Technique::DifferentialProbe => 0.0,
            };
        }

        // Multi-layer bonus: stacking techniques is more effective
        if techniques.len() >= 3 {
            score += 0.10;
        }

        score.min(1.0)
    }

    /// Number of techniques applied.
    #[must_use]
    pub fn technique_count(&self) -> usize {
        self.techniques.len()
    }

    /// Check if a grammar mutation technique was used.
    #[must_use]
    pub fn uses_grammar(&self) -> bool {
        self.techniques
            .iter()
            .any(|t| matches!(t, Technique::GrammarMutation(_)))
    }

    /// Check if smuggling was used (high-impact but high-risk).
    #[must_use]
    pub fn uses_smuggling(&self) -> bool {
        self.techniques
            .iter()
            .any(|t| matches!(t, Technique::RequestSmuggling(_)))
    }

    /// Check if header obfuscation was used.
    #[must_use]
    pub fn uses_header_obfuscation(&self) -> bool {
        self.techniques
            .iter()
            .any(|t| matches!(t, Technique::HeaderObfuscation(_)))
    }
}

impl fmt::Display for EvasionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:.0}%] {} technique(s): {}",
            self.confidence * 100.0,
            self.techniques.len(),
            self.description
        )
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn evasion_result_confidence() {
        let req = Request::get("https://example.com");
        let result = EvasionResult::new(
            req,
            vec![
                Technique::GrammarMutation("sql_tautology".into()),
                Technique::PayloadEncoding("UrlEncode".into()),
            ],
            "grammar + encoding".into(),
        );
        assert!(
            result.confidence > 0.3,
            "grammar + encoding should have decent confidence"
        );
        assert!(result.uses_grammar());
        assert!(!result.uses_smuggling());
    }

    #[test]
    fn evasion_result_empty_zero_confidence() {
        let result = EvasionResult::new(
            Request::get("https://example.com"),
            vec![],
            "no evasion".into(),
        );
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn evasion_result_display() {
        let result = EvasionResult::new(
            Request::get("https://example.com"),
            vec![Technique::GrammarMutation("xss_polyglot".into())],
            "polyglot XSS".into(),
        );
        let s = result.to_string();
        assert!(s.contains('%'));
        assert!(s.contains("polyglot XSS"));
    }

    #[test]
    fn with_confidence_clamps() {
        let result = EvasionResult::with_confidence(
            Request::get("https://example.com"),
            vec![],
            "test".into(),
            1.5,
        );
        assert_eq!(result.confidence, 1.0);

        let result2 = EvasionResult::with_confidence(
            Request::get("https://example.com"),
            vec![],
            "test".into(),
            -0.5,
        );
        assert_eq!(result2.confidence, 0.0);
    }
}
