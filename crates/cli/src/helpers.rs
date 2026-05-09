//! Pure helper functions shared across CLI commands.

use colored::Colorize;
use std::collections::HashSet;

use wafrift_encoding::encoding::{self, Strategy};
use wafrift_evolution::differential::ProbeTarget;
use wafrift_grammar::grammar::{self, PayloadType};

use crate::Level;

pub(crate) const LIGHT_VARIANTS: usize = 4;
pub(crate) const MEDIUM_VARIANTS: usize = 12;
pub(crate) const HEAVY_VARIANTS: usize = 50;

/// Evasion variant produced by the variant builder.
#[derive(Debug)]
pub struct Variant {
    pub payload: String,
    pub techniques: Vec<String>,
    pub confidence: f64,
}

pub(crate) fn parse_headers(raw_headers: &[String]) -> Result<Vec<(String, String)>, String> {
    raw_headers
        .iter()
        .map(|header| {
            let Some((key, value)) = header.split_once(':') else {
                return Err(format!("invalid header `{header}`; expected `key: value`"));
            };
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                return Err(format!("invalid header `{header}`; empty key"));
            }
            if value.is_empty() {
                return Err(format!("invalid header `{header}`; empty value"));
            }
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

pub fn strategies_for_level(level: Level) -> Vec<Strategy> {
    let all = encoding::all_strategies();
    match level {
        Level::Light => all.into_iter().take(3).collect(),
        Level::Medium => all.into_iter().take(6).collect(),
        Level::Heavy => all,
    }
}

pub fn max_mutations_for_level(level: Level) -> usize {
    match level {
        Level::Light => LIGHT_VARIANTS,
        Level::Medium => MEDIUM_VARIANTS,
        Level::Heavy => HEAVY_VARIANTS,
    }
}

pub(crate) fn payload_type_label(payload_type: PayloadType) -> &'static str {
    match payload_type {
        PayloadType::Sql => "SQL Injection",
        PayloadType::Xss => "XSS",
        PayloadType::CommandInjection => "Command Injection",
        PayloadType::Ldap => "LDAP Injection",
        PayloadType::Ssrf => "SSRF",
        PayloadType::PathTraversal => "Path Traversal",
        PayloadType::TemplateInjection => "Template Injection",
        _ => "Unknown",
    }
}

pub(crate) fn variant_confidence(
    payload_type: PayloadType,
    grammar_rule_count: usize,
    encoding_only: bool,
    strategy: Strategy,
) -> f64 {
    let type_score = match payload_type {
        PayloadType::Unknown => 0.45,
        PayloadType::Ldap
        | PayloadType::Ssrf
        | PayloadType::PathTraversal
        | PayloadType::TemplateInjection => 0.72,
        PayloadType::Sql | PayloadType::Xss | PayloadType::CommandInjection => 0.82,
        _ => 0.45,
    };

    let grammar_bonus = if encoding_only {
        0.0
    } else {
        (grammar_rule_count as f64 * 0.04).min(0.12)
    };

    let strategy_score = match strategy {
        Strategy::CaseAlternation => 0.03,
        Strategy::WhitespaceInsertion => 0.05,
        Strategy::SqlCommentInsertion => 0.07,
        Strategy::UrlEncode => 0.05,
        Strategy::DoubleUrlEncode => 0.07,
        Strategy::UnicodeEncode => 0.06,
        Strategy::HtmlEntityEncode => 0.06,
        Strategy::NullByte => 0.08,
        Strategy::TripleUrlEncode => 0.09,
        Strategy::ChunkedSplit => 0.1,
        Strategy::ParameterPollution => 0.08,
        Strategy::OverlongUtf8 => 0.11,
        Strategy::Base64Encode => 0.05,
        Strategy::HexEncode => 0.05,
        Strategy::Utf7Encode => 0.07,
        _ => 0.05,
    };

    (type_score + grammar_bonus + strategy_score).min(0.99)
}

pub(crate) fn confidence_badge(confidence: f64) -> colored::ColoredString {
    let label = format!("confidence {:.0}%", (confidence * 100.0).round());
    if confidence >= 0.9 {
        label.bright_green().bold()
    } else if confidence >= 0.75 {
        label.yellow().bold()
    } else {
        label.red().bold()
    }
}

pub(crate) fn probe_target_label(target: &ProbeTarget) -> String {
    match target {
        ProbeTarget::SqlKeyword(value) => format!("sql_keyword:{value}"),
        ProbeTarget::SqlOperator(value) => format!("sql_operator:{value}"),
        ProbeTarget::SqlComment(value) => format!("sql_comment:{value}"),
        ProbeTarget::SqlQuote => "sql_quote".to_string(),
        ProbeTarget::SqlTautology(value) => format!("sql_tautology:{value}"),
        ProbeTarget::XssTag(value) => format!("xss_tag:{value}"),
        ProbeTarget::XssEvent(value) => format!("xss_event:{value}"),
        ProbeTarget::XssExecFunction(value) => format!("xss_exec_function:{value}"),
        ProbeTarget::CmdSeparator(value) => format!("cmd_separator:{value}"),
        ProbeTarget::CmdCommand(value) => format!("cmd_command:{value}"),
        ProbeTarget::CmdPath(value) => format!("cmd_path:{value}"),
        ProbeTarget::Baseline => "baseline".to_string(),
    }
}

/// Build encoding × grammar variants for a given payload.
pub fn build_variants(
    payload: &str,
    payload_type: PayloadType,
    encoding_only: bool,
    strategies: &[Strategy],
    max_mutations: usize,
) -> Vec<Variant> {
    let mut seen = HashSet::new();
    let mut variants = Vec::new();

    let grammar_mutations = if encoding_only {
        Vec::new()
    } else {
        grammar::mutate_as(payload, payload_type, max_mutations)
    };

    for mutation in &grammar_mutations {
        // First: add the RAW grammar mutation without any encoding.
        // Keyword-free payloads (like '1-0', '+0+') are designed to bypass
        // WAFs without encoding — extra encoding can hurt by triggering
        // anomaly rules on the encoded characters.
        if seen.insert(mutation.payload.clone()) {
            let techniques: Vec<String> = mutation
                .rules_applied
                .iter()
                .map(|rule| (*rule).to_string())
                .collect();
            variants.push(Variant {
                payload: mutation.payload.clone(),
                techniques,
                confidence: variant_confidence(
                    payload_type,
                    mutation.rules_applied.len(),
                    false,
                    Strategy::CaseAlternation, // baseline confidence
                ),
            });
        }
    }

    for mutation in &grammar_mutations {
        // Then: apply encoding strategies on top.
        for strategy in strategies {
            let encoded = match encoding::encode(&mutation.payload, *strategy) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if seen.insert(encoded.clone()) {
                let mut techniques: Vec<String> = mutation
                    .rules_applied
                    .iter()
                    .map(|rule| (*rule).to_string())
                    .collect();
                techniques.push(format!("encoding::{strategy:?}"));
                variants.push(Variant {
                    payload: encoded,
                    techniques,
                    confidence: variant_confidence(
                        payload_type,
                        mutation.rules_applied.len(),
                        false,
                        *strategy,
                    ),
                });
            }
        }
    }

    for strategy in strategies {
        let encoded = match encoding::encode(payload, *strategy) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if seen.insert(encoded.clone()) {
            variants.push(Variant {
                payload: encoded,
                techniques: vec![format!("encoding::{strategy:?}")],
                confidence: variant_confidence(payload_type, 0, encoding_only, *strategy),
            });
        }
    }

    if !encoding_only && seen.insert(payload.to_string()) {
        variants.insert(
            0,
            Variant {
                payload: payload.to_string(),
                techniques: vec!["original".to_string()],
                confidence: variant_confidence(payload_type, 0, false, Strategy::CaseAlternation),
            },
        );
    }

    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_headers_trims_whitespace() {
        let headers = parse_headers(&[
            "Server: cloudflare".to_string(),
            " Content-Type : text/html ".to_string(),
        ])
        .expect("valid headers");

        assert_eq!(
            headers,
            vec![
                ("Server".to_string(), "cloudflare".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ]
        );
    }

    #[test]
    fn parse_headers_rejects_missing_separator() {
        let err = parse_headers(&["missing separator".to_string()]).expect_err("invalid header");
        assert!(err.contains("expected `key: value`"));
    }

    #[test]
    fn strategies_for_level_scales_with_aggressiveness() {
        let light = strategies_for_level(Level::Light);
        let medium = strategies_for_level(Level::Medium);
        let heavy = strategies_for_level(Level::Heavy);

        assert_eq!(light.len(), 3);
        assert_eq!(medium.len(), 6);
        assert!(heavy.len() >= medium.len());
        assert!(heavy.contains(&Strategy::OverlongUtf8));
    }

    #[test]
    fn mutation_budget_matches_level() {
        assert_eq!(max_mutations_for_level(Level::Light), LIGHT_VARIANTS);
        assert_eq!(max_mutations_for_level(Level::Medium), MEDIUM_VARIANTS);
        assert_eq!(max_mutations_for_level(Level::Heavy), HEAVY_VARIANTS);
    }

    #[test]
    fn variant_confidence_rewards_stronger_strategies() {
        let light = variant_confidence(PayloadType::Sql, 1, false, Strategy::CaseAlternation);
        let heavy = variant_confidence(PayloadType::Sql, 3, false, Strategy::OverlongUtf8);

        assert!(heavy > light);
        assert!(heavy <= 0.99);
    }

    #[test]
    fn probe_target_label_formats_variants() {
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlKeyword("union".into())),
            "sql_keyword:union"
        );
        assert_eq!(probe_target_label(&ProbeTarget::Baseline), "baseline");
    }
}
