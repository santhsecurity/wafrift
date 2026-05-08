#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::strategy::{
        CalibrationResult, EscalationLevel, EvasionConfig, EvasionPlan, HostState,
        analyze_calibration, evade, evade_adaptive,
    };
    use wafrift_types::{Request, Technique};

    // ============================================
    // Basic Evasion Tests (1-10)
    // ============================================

    #[test]
    fn no_evasion_on_clean_state() {
        let req = Request::post("https://example.com", b"q=test".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let state = HostState::default();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        // Fingerprint rotation still happens by default
        assert!(
            result
                .techniques
                .iter()
                .all(|t| matches!(t, Technique::UserAgentRotation)),
            "only fingerprint rotation on clean state"
        );
    }

    #[test]
    fn light_evasion_after_blocks() {
        let req = Request::post("https://example.com", b"q=test".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        state.record_block();
        state.record_block();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::PayloadEncoding(_)))
        );
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::HeaderObfuscation(_)))
        );
    }

    #[test]
    fn medium_evasion_content_type_switch() {
        let req = Request::post("https://example.com", b"q=test&a=value".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        for _ in 0..4 {
            state.record_block();
        }
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::ContentTypeSwitch(_)))
        );
    }

    #[test]
    fn medium_evasion_applies_grammar() {
        let req = Request::post("https://example.com", b"q=' OR 1=1--".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        for _ in 0..4 {
            state.record_block();
        }
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::GrammarMutation(_)))
        );
    }

    #[test]
    fn heavy_evasion_after_many_blocks() {
        let _req = Request::post("https://example.com", b"q=test".to_vec());
        let mut state = HostState::default();
        for _ in 0..10 {
            state.record_block();
        }
        assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
    }

    #[test]
    fn fingerprint_rotation_adds_ua() {
        let req = Request::get("https://example.com");
        let state = HostState::default();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert!(result.request.get_header("User-Agent").is_some());
    }

    #[test]
    fn no_fingerprint_when_disabled() {
        let req = Request::get("https://example.com");
        let state = HostState::default();
        let config = EvasionConfig {
            fingerprint_rotation: false,
            ..EvasionConfig::default()
        };
        let result = evade(&req, &state, &config);
        assert!(
            !result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::UserAgentRotation))
        );
    }

    #[test]
    fn calibration_403_is_waf() {
        assert_eq!(
            analyze_calibration(403, b"Forbidden"),
            CalibrationResult::WafPresent
        );
    }

    #[test]
    fn calibration_redirect_is_uncertain() {
        assert_eq!(
            analyze_calibration(301, b"Moved"),
            CalibrationResult::Uncertain
        );
    }

    #[test]
    fn calibration_200_clean_is_no_waf() {
        assert_eq!(analyze_calibration(200, b"OK"), CalibrationResult::NoWaf);
    }

    // ============================================
    // Configuration Tests (11-20)
    // ============================================

    #[test]
    fn strategy_record_success_same_technique() {
        let mut state = HostState::default();
        state.record_success(Technique::PayloadEncoding("DoubleUrlEncode".into()));
        state.record_success(Technique::PayloadEncoding("DoubleUrlEncode".into()));
        assert_eq!(state.successes, 2);
    }

    #[test]
    fn header_obfuscation_disabled() {
        let req = Request::post("https://example.com", b"q=test".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        state.record_block();
        let config = EvasionConfig {
            header_obfuscation: false,
            ..EvasionConfig::default()
        };
        let result = evade(&req, &state, &config);
        assert!(
            !result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::HeaderObfuscation(_)))
        );
    }

    #[test]
    fn grammar_disabled() {
        let req = Request::post("https://example.com", b"q=' OR 1=1--".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        for _ in 0..4 {
            state.record_block();
        }
        let config = EvasionConfig {
            grammar_mutations: false,
            ..EvasionConfig::default()
        };
        let result = evade(&req, &state, &config);
        assert!(
            !result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::GrammarMutation(_)))
        );
    }

    #[test]
    fn encoding_disabled() {
        let req = Request::post("https://example.com", b"q=test".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        state.record_block();
        let config = EvasionConfig {
            encoding_enabled: false,
            ..EvasionConfig::default()
        };
        let result = evade(&req, &state, &config);
        assert!(
            !result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::PayloadEncoding(_)))
        );
    }

    #[test]
    fn content_type_switching_disabled() {
        let req = Request::post("https://example.com", b"q=test&a=value".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        for _ in 0..4 {
            state.record_block();
        }
        let config = EvasionConfig {
            content_type_switching: false,
            ..EvasionConfig::default()
        };
        let result = evade(&req, &state, &config);
        assert!(
            !result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::ContentTypeSwitch(_)))
        );
    }

    // ============================================
    // Adaptive Evasion Tests (21-30)
    // ============================================

    #[test]
    fn evade_adaptive_basic() {
        let req = Request::post("https://example.com", b"q=test".to_vec());
        let config = EvasionConfig::default();
        let plan = EvasionPlan::default();
        let result = evade_adaptive(&req, &config, &plan, &HostState::default());
        // Should still apply fingerprint rotation
        assert!(result.request.get_header("User-Agent").is_some());
    }

    #[test]
    fn evade_adaptive_no_fingerprint() {
        let req = Request::post("https://example.com", b"q=test".to_vec());
        let config = EvasionConfig {
            fingerprint_rotation: false,
            ..EvasionConfig::default()
        };
        let plan = EvasionPlan::default();
        let result = evade_adaptive(&req, &config, &plan, &HostState::default());
        assert!(
            !result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::UserAgentRotation))
        );
    }

    #[test]
    fn evade_adaptive_with_grammar() {
        let req = Request::post("https://example.com", b"q=' OR 1=1".to_vec());
        let config = EvasionConfig::default();
        let plan = EvasionPlan {
            use_grammar: true,
            ..EvasionPlan::default()
        };
        let result = evade_adaptive(&req, &config, &plan, &HostState::default());
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::GrammarMutation(_)))
        );
    }

    #[test]
    fn evade_adaptive_with_header_obfuscation() {
        let req = Request::post("https://example.com", b"q=test".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let config = EvasionConfig::default();
        let plan = EvasionPlan {
            use_header_obfuscation: true,
            ..EvasionPlan::default()
        };
        let result = evade_adaptive(&req, &config, &plan, &HostState::default());
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::HeaderObfuscation(_)))
        );
    }

    #[test]
    fn evade_adaptive_with_smuggling() {
        let req = Request::post("https://example.com", b"q=test".to_vec());
        let config = EvasionConfig::default();
        let plan = EvasionPlan {
            use_smuggling: true,
            ..EvasionPlan::default()
        };
        let result = evade_adaptive(&req, &config, &plan, &HostState::default());
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::RequestSmuggling(_)))
        );
    }

    #[test]
    fn evade_adaptive_with_h2() {
        let req = Request::post("https://example.com", b"q=test".to_vec());
        let config = EvasionConfig::default();
        let plan = EvasionPlan {
            use_h2: true,
            ..EvasionPlan::default()
        };
        let result = evade_adaptive(&req, &config, &plan, &HostState::default());
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::H2Evasion(_)))
        );
    }

    // ============================================
    // Heavy Escalation Tests (31-40)
    // ============================================

    #[test]
    fn heavy_evasion_applies_smuggling_metadata() {
        let req = Request::post("https://example.com", b"q=test".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        for _ in 0..10 {
            state.record_block();
        }
        assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::RequestSmuggling(_)))
        );
    }

    #[test]
    fn heavy_evasion_applies_h2_metadata() {
        let req = Request::post("https://example.com", b"q=test".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        for _ in 0..10 {
            state.record_block();
        }
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::H2Evasion(_)))
        );
    }

    #[test]
    fn heavy_evasion_applies_grammar() {
        let req = Request::post("https://example.com", b"q=' OR 1=1--".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        for _ in 0..10 {
            state.record_block();
        }
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert!(
            result
                .techniques
                .iter()
                .any(|t| matches!(t, Technique::GrammarMutation(_)))
        );
    }

    #[test]
    fn heavy_evasion_multiple_techniques() {
        let req = Request::post("https://example.com", b"q=test&foo=bar".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let mut state = HostState::default();
        for _ in 0..10 {
            state.record_block();
        }
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        // Heavy evasion should apply multiple techniques
        assert!(
            result.techniques.len() >= 3,
            "Heavy evasion should apply at least 3 techniques, got {:?}",
            result.techniques
        );
    }

    #[test]
    fn evasion_result_has_description() {
        let req = Request::post("https://example.com", b"q=test".to_vec());
        let state = HostState::default();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert!(!result.description.is_empty());
    }

    // ============================================
    // Edge Case Tests (41-50)
    // ============================================

    #[test]
    fn get_request_no_body() {
        let req = Request::get("https://example.com/api");
        let state = HostState::default();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert_eq!(result.request.body, None);
    }

    #[test]
    fn put_request_with_body() {
        let req = Request::put("https://example.com/api", b"data=value".to_vec());
        let mut state = HostState::default();
        state.record_block();
        state.record_block();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert!(result.request.body.is_some());
    }

    #[test]
    fn delete_request_no_body() {
        let req = Request::delete("https://example.com/api/1");
        let mut state = HostState::default();
        state.record_block();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert_eq!(result.request.method.as_str(), "DELETE");
    }

    #[test]
    fn empty_body_request() {
        let req = Request::post("https://example.com", vec![]);
        let mut state = HostState::default();
        state.record_block();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        // Request should be processed correctly even with empty body
        assert_eq!(result.request.body, Some(vec![]));
        // Should have applied some light evasion
        assert!(!result.techniques.is_empty());
    }

    #[test]
    fn evasion_plan_default() {
        let plan = EvasionPlan::default();
        assert!(!plan.use_grammar);
        assert!(!plan.use_header_obfuscation);
        assert!(!plan.use_content_type_switch);
        assert!(!plan.use_smuggling);
        assert!(!plan.use_h2);
        assert!(plan.encoding_strategies.is_empty());
    }

    #[test]
    fn evasion_plan_with_strategies() {
        use wafrift_encoding::encoding::Strategy;
        let plan = EvasionPlan {
            encoding_strategies: vec![Strategy::DoubleUrlEncode, Strategy::UnicodeEncode],
            use_grammar: true,
            use_header_obfuscation: true,
            use_content_type_switch: true,
            use_smuggling: true,
            use_h2: true,
            rationale: vec!["test plan".into()],
        };
        assert_eq!(plan.encoding_strategies.len(), 2);
        assert!(plan.use_grammar);
        assert!(plan.use_header_obfuscation);
    }

    #[test]
    fn calibration_503_service_unavailable() {
        assert_eq!(
            analyze_calibration(503, b"Service Unavailable"),
            CalibrationResult::WafPresent
        );
    }

    #[test]
    fn calibration_429_rate_limit() {
        assert_eq!(
            analyze_calibration(429, b"Too Many Requests"),
            CalibrationResult::WafPresent
        );
    }

    #[test]
    fn evasion_preserves_url() {
        let url = "https://example.com/path?query=value";
        let req = Request::get(url);
        let state = HostState::default();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert_eq!(result.request.url, url);
    }

    #[test]
    fn evasion_preserves_method() {
        let req = Request::put("https://example.com/api", b"data".to_vec());
        let state = HostState::default();
        let config = EvasionConfig::default();
        let result = evade(&req, &state, &config);
        assert_eq!(result.request.method.as_str(), "PUT");
    }
}
