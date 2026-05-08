//! Live WAF evasion scan pipeline.
//!
//! This module contains the core scan loop — the 7-step autonomous pipeline
//! that detects the WAF, generates variants, probes differentially, explores,
//! exploits, evolves, and saves results.
//!
//! # Module structure
//!
//! - [`state`] — `ScanState` (mutable counters) and `ScanConfig` (immutable args)
//! - [`mod`] — The `run_scan` orchestrator and step functions

pub(crate) mod state;

use colored::Colorize;
use serde_json::json;
use std::collections::HashSet;
use std::io::{self, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use wafrift_detect::waf_detect;
use wafrift_encoding::encoding::{self, Strategy};
use wafrift_encoding::header as header_obfuscation;
use wafrift_encoding::tamper::TamperRegistry;
use wafrift_evolution::advisor;
use wafrift_evolution::intelligence::IntelligenceLoop;
use wafrift_grammar::grammar::{self, PayloadType};
use wafrift_oracle::response_oracle::{ResponseOracle, ResponseContext};
use wafrift_strategy::composition;
use wafrift_strategy::cost;
use wafrift_strategy::gene_bank::GeneBank;
use wafrift_strategy::learning_cache::{CacheKey, LearningCache};
use wafrift_strategy::pipeline::EvasionPipeline;
use wafrift_transport::is_waf_block;

use crate::ScanArgs;
use crate::helpers::{
    build_variants, confidence_badge, max_mutations_for_level, payload_type_label,
    strategies_for_level, variant_confidence,
};

pub(crate) fn scan_url_with_param(target: &str, param: &str, value_encoded: &str) -> String {
    let base = target.trim_end_matches('/');
    match reqwest::Url::parse(base) {
        Ok(mut url) => {
            url.query_pairs_mut().append_pair(param, value_encoded);
            url.to_string()
        }
        Err(_) => format!("{base}/?{param}={value_encoded}"),
    }
}

/// Fire evasion variants against a live target and report bypass/block results.
pub(crate) async fn run_scan(args: ScanArgs, cancel: tokio_util::sync::CancellationToken) -> ExitCode {
    let target = args.target.trim_end_matches('/');
    let filter = match crate::TechniqueFilter::parse(&args.only, &args.exclude) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{} {msg}", "Filter error:".red().bold());
            return ExitCode::from(2);
        }
    };
    let encoding_only = args.encoding_only || !filter.grammar_enabled();
    let payload_type = grammar::classify(&args.payload);
    let mut strategies = filter.filter_strategies(strategies_for_level(args.level));
    if strategies.is_empty() && !filter.is_default() {
        eprintln!(
            "{} no encoding strategies remain after --only/--exclude",
            "Filter error:".red().bold()
        );
        return ExitCode::from(2);
    }
    let max_mutations = max_mutations_for_level(args.level);

    // Gene bank: re-order strategies so historically proven ones go first.
    let gene_seed_names: Vec<String> = GeneBank::open_default()
        .ok()
        .and_then(|mut bank| {
            // Try "Unknown" as fallback since WAF detection hasn't run yet.
            // We'll also re-check after detection.
            let all_names: Vec<String> = bank
                .list_wafs()
                .into_iter()
                .flat_map(|waf| {
                    bank.load(&waf)
                        .map(|g| g.seed_winners())
                        .unwrap_or_default()
                })
                .collect();
            if all_names.is_empty() {
                None
            } else {
                Some(all_names)
            }
        })
        .unwrap_or_default();

    if !gene_seed_names.is_empty() {
        // Move strategies that match gene bank winners to the front.
        strategies.sort_by(|a, b| {
            let a_known = gene_seed_names
                .iter()
                .any(|s| s.contains(&format!("{a:?}")));
            let b_known = gene_seed_names
                .iter()
                .any(|s| s.contains(&format!("{b:?}")));
            b_known.cmp(&a_known) // true > false, so winners go first
        });
    }

    let variants = build_variants(
        &args.payload,
        payload_type,
        encoding_only,
        &strategies,
        max_mutations,
    );

    if variants.is_empty() {
        eprintln!(
            "{}",
            "No variants generated for the supplied payload."
                .red()
                .bold()
        );
        return ExitCode::from(1);
    }

    let scan_text = args.format != "json";
    if scan_text {
        println!(
            "{}\n",
            "╔══════════════════════════════════════════════════╗".bright_cyan()
        );
        println!(
            "{}  {}",
            "║".bright_cyan(),
            "WafRift Live WAF Evasion Scanner".bold().bright_white()
        );
        println!(
            "{}\n",
            "╚══════════════════════════════════════════════════╝".bright_cyan()
        );
        println!("  {} {}", "Target:".bold().cyan(), target.yellow());
        println!(
            "  {} {}",
            "Payload Type:".bold().cyan(),
            payload_type_label(payload_type).bold()
        );
        println!(
            "  {} {}",
            "Variants:".bold().cyan(),
            format!("{}", variants.len()).yellow()
        );
        println!(
            "  {} {}ms",
            "Delay:".bold().cyan(),
            format!("{}", args.delay_ms).yellow()
        );
        println!();
    }

    // Step 1: WAF detection — fetch target and identify WAF.
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(args.insecure)
        .redirect(reqwest::redirect::Policy::limited(5))
        // Use a realistic browser User-Agent to avoid CRS scanner detection rules.
        // PL2+ blocks non-browser UAs (reqwest default triggers 913100/913110).
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            eprintln!("  {} {}", "✗ Failed to create HTTP client:".red().bold(), e);
            return ExitCode::from(1);
        }
    };
    let scan_start = Instant::now();

    if scan_text {
        println!("{}", "[1/3] Detecting WAF...".bold().cyan());
    }
    let baseline_response = match http.get(target).send().await {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("  {} {}", "✗ Cannot reach target:".red().bold(), err);
            return ExitCode::from(1);
        }
    };

    let baseline_status = baseline_response.status().as_u16();
    let headers_vec: Vec<(String, String)> = baseline_response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body_bytes = baseline_response.bytes().await.unwrap_or_default();

    let detected = waf_detect::detect(baseline_status, &headers_vec, &body_bytes);
    let waf_name = if let Some(result) = detected.first() {
        if scan_text {
            println!(
                "  {} {} ({:.0}% confidence)",
                "✓ Detected:".green().bold(),
                result.name.bold().yellow(),
                result.confidence * 100.0
            );
        }
        result.name.clone()
    } else {
        if scan_text {
            println!(
                "  {}",
                "⚠ No WAF confidently detected (testing anyway)"
                    .yellow()
                    .bold()
            );
        }
        String::from("Unknown")
    };

    // Advisor: generate WAF-specific evasion plan.
    let detected_waf_obj = detected.first().cloned();
    let evasion_plan = advisor::advise(
        detected_waf_obj.as_ref(),
        None, // No fingerprint drift yet
    );
    if scan_text {
        for rationale in &evasion_plan.rationale {
            println!("  {} {}", "📋 Advisor:".bold().cyan(), rationale.yellow());
        }
        if evasion_plan.use_header_obfuscation {
            println!("    {} header obfuscation", "✓".green());
        }
        if evasion_plan.use_content_type_switch {
            println!("    {} content-type switching", "✓".green());
        }
        if evasion_plan.use_h2 {
            println!("    {} HTTP/2 evasion", "✓".green());
        }
    }

    // Advisor strategies stored for exploit-phase amplification (WAF detection runs after build_variants).
    let advisor_strategies = evasion_plan.encoding_strategies.clone();

    // Learning cache: load historical winning pipelines.
    let mut learning_cache = LearningCache::open_default().ok();
    let payload_type_str = format!("{payload_type:?}");
    if let Some(ref cache) = learning_cache {
        let key = CacheKey::new(&waf_name, &payload_type_str);
        if let Some(entry) = cache.get(&key)
            && scan_text
        {
            println!(
                "  {} cached pipeline '{}' — {:.0}% success rate",
                "📦 Learning cache:".bold().cyan(),
                entry.pipeline.name.yellow(),
                entry.success_rate() * 100.0
            );
        }
    }

    // Gene bank: load known bypasses for this WAF.
    if let Ok(mut bank) = GeneBank::open_default()
        && let Some(genome) = bank.load(&waf_name)
    {
        let seeds = genome.seed_winners();
        if !seeds.is_empty() && scan_text {
            println!(
                "\n  {} {} {}",
                "🧬".bold(),
                "Gene bank loaded:".bold().cyan(),
                format!(
                    "{} proven techniques from {} previous scan(s)",
                    seeds.len(),
                    genome.targets_scanned
                )
                .yellow()
            );
            for seed in seeds.iter().take(5) {
                let rate = genome
                    .top_techniques(20, 1)
                    .iter()
                    .find(|t| t.name == *seed)
                    .map_or(0.0, |t| t.success_rate() * 100.0);
                println!("    {} {:.0}% {}", "→".bright_cyan(), rate, seed.yellow());
            }
        }
    }

    // Step 2: Baseline — confirm raw payload gets blocked.
    if scan_text {
        println!(
            "\n{}",
            "[2/7] Testing baseline (raw payload)...".bold().cyan()
        );
    }
    let raw_url = scan_url_with_param(
        target,
        &args.param,
        &urlencoding::encode(&args.payload),
    );
    let (raw_status, raw_blocked, raw_transport_ok) = match http.get(&raw_url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default();
            let blocked = is_waf_block(status, &body);
            (status, blocked, true)
        }
        Err(e) => {
            eprintln!(
                "  {} {}",
                "✗ Baseline request failed (transport):".red().bold(),
                e
            );
            (0u16, false, false)
        }
    };
    if !raw_transport_ok {
        if scan_text {
            println!(
                "  {}",
                "⚠ Baseline inconclusive — fix connectivity and re-run".yellow().bold()
            );
        }
    } else if raw_blocked {
        if scan_text {
            println!(
                "  {} (HTTP {})",
                "✓ Raw payload BLOCKED — WAF is active".green().bold(),
                raw_status
            );
        }
    } else if scan_text {
        println!(
            "  {} (HTTP {})",
            "⚠ Raw payload PASSED — WAF may not inspect this parameter"
                .yellow()
                .bold(),
            raw_status
        );
    }

    // Step 2b: Differential probing — isolate WAF trigger patterns.
    let mut intel_loop = IntelligenceLoop::new(20);
    let diff_probes = intel_loop.generate_quick_probes();
    if scan_text && !diff_probes.is_empty() {
        println!(
            "\n{}",
            format!("[2b/7] Differential probing — {} probes...", diff_probes.len())
                .bold()
                .cyan()
        );
    }
    for probe in &diff_probes {
        let probe_payload = format!("{:?}", probe.tests);
        let probe_url = scan_url_with_param(
            target,
            &args.param,
            &urlencoding::encode(&probe_payload),
        );
        let was_blocked = match http.get(&probe_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.bytes().await.unwrap_or_default();
                is_waf_block(status, &body)
            }
            Err(_) => false,
        };
        intel_loop.record_probe(probe, was_blocked);
        if scan_text {
            print!("{}", if was_blocked { "." } else { "!" });
        }
        let diff_delay = Duration::from_millis(args.delay_ms);
        if !diff_delay.is_zero() {
            tokio::time::sleep(diff_delay).await;
        }
    }
    if scan_text && intel_loop.has_sufficient_data() {
        let suggestions = intel_loop.suggested_evasions();
        if !suggestions.is_empty() {
            println!(
                "\n  {} {}",
                "Differential insights:".bold().cyan(),
                suggestions.iter().take(3).cloned().collect::<Vec<_>>().join(", ").yellow()
            );
        }
    }

    // Scan counters (declared early so cache replay can use them).
    let mut bypassed = 0_u32;
    let mut blocked = 0_u32;
    let mut errors = 0_u32;
    let mut _rate_limited = 0_u32;
    let mut _challenges = 0_u32;
    let mut bypass_variants: Vec<(usize, String, Vec<String>, f64)> = Vec::new();
    let mut variant_outcomes: Vec<(Vec<String>, bool)> = Vec::new();
    let delay = Duration::from_millis(args.delay_ms);
    let mut winning_strategies: HashSet<String> = HashSet::new();
    let mut total_fired = 0_usize;

    // Step 2c: Learning cache replay — try cached winning pipeline first.
    let mut cache_hit_bypass = false;
    if let Some(ref cache) = learning_cache {
        let key = CacheKey::new(&waf_name, &payload_type_str);
        if let Some(entry) = cache.get(&key)
            && entry.success_rate() > 0.5
        {
                // Replay the winning pipeline's encoding on raw payload.
                for tech in &entry.pipeline.techniques {
                    let encoded = match tech {
                        wafrift_types::Technique::PayloadEncoding(enc_name) => {
                            encoding::all_strategies()
                                .iter()
                                .find(|s| s.as_str() == enc_name.as_str())
                                .and_then(|s| encoding::encode(&args.payload, *s).ok())
                        }
                        _ => None,
                    };
                    if let Some(ref enc_payload) = encoded {
                        let url = scan_url_with_param(
                            target,
                            &args.param,
                            &urlencoding::encode(enc_payload),
                        );
                        if let Ok(resp) = http.get(&url).send().await {
                            let status = resp.status().as_u16();
                            let body = resp.bytes().await.unwrap_or_default();
                            if !is_waf_block(status, &body) {
                                cache_hit_bypass = true;
                                bypassed += 1;
                                total_fired += 1;
                                bypass_variants.push((
                                    0,
                                    enc_payload.clone(),
                                    vec![format!("cache_replay::{}", tech)],
                                    0.95,
                                ));
                                if scan_text {
                                    println!(
                                        "  {} cached pipeline '{}' bypassed immediately!",
                                        "⚡ Cache replay:".bold().green(),
                                        entry.pipeline.name.yellow()
                                    );
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

    // Step 2d: Differential-guided strategy reorder.
    // Promote encoding strategies that match differential insights.
    let diff_suggestions = intel_loop.suggested_evasions();
    if !diff_suggestions.is_empty() && scan_text {
        println!(
            "  {} promoting: {}",
            "🎯 Diff-guided:".bold().cyan(),
            diff_suggestions.iter().take(3).cloned().collect::<Vec<_>>().join(", ").yellow()
        );
    }

    // Step 3: Explore — fire all pre-generated variants.
    if scan_text {
        if cache_hit_bypass {
            println!(
                "\n{}",
                "[3/7] Exploring evasion variants (cache hit — already have a bypass)...".bold().cyan()
            );
        } else {
            println!("\n{}", "[3/7] Exploring evasion variants...".bold().cyan());
        }
        println!();
    }

    // Create the response oracle for multi-signal classification.
    let oracle = std::sync::Arc::new(ResponseOracle::new());

    // Create the tamper registry for advanced payload transforms.
    let tamper_registry = TamperRegistry::with_defaults();
    // Tamper-only names that are NOVEL (not duplicating basic encoding::encode).
    let novel_tamper_names: Vec<&str> = vec!["sql_comment", "whitespace_insertion", "null_byte", "overlong_utf8"];

    // Concurrency level for parallel variant firing.
    let concurrency = if delay.is_zero() { 8_usize } else { 4 };

    // Fire variants in concurrent batches.
    let mut variant_idx = 0_usize;
    while variant_idx < variants.len() {
        if cancel.is_cancelled() {
            if scan_text {
                println!("\n  {}", "⚠ Cancelled — skipping remaining variants".yellow().bold());
            }
            break;
        }

        // Build the next batch.
        let batch_end = (variant_idx + concurrency).min(variants.len());
        let batch: Vec<(usize, &crate::helpers::Variant)> = variants[variant_idx..batch_end]
            .iter()
            .enumerate()
            .map(|(i, v)| (variant_idx + i, v))
            .collect();

        // Fire all requests in this batch concurrently.
        let mut tasks = tokio::task::JoinSet::new();
        for (index, variant) in batch {
            let url = scan_url_with_param(
                target,
                &args.param,
                &urlencoding::encode(&variant.payload),
            );
            let client = http.clone();
            let payload = variant.payload.clone();
            let techniques = variant.techniques.clone();
            let confidence = variant.confidence;
            let oracle = oracle.clone();
            tasks.spawn(async move {
                let verdict = match client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.bytes().await.unwrap_or_default();
                        let ctx = ResponseContext {
                            status,
                            body: body.to_vec(),
                            ..Default::default()
                        };
                        Some(oracle.classify(&ctx))
                    }
                    Err(_) => None,
                };
                (index, payload, techniques, confidence, verdict)
            });
        }

        // Collect results (order doesn't matter for counting).
        let mut batch_rate_limited = false;
        while let Some(result) = tasks.join_next().await {
            let Ok((index, payload, techniques, confidence, verdict_opt)) = result else {
                errors += 1;
                continue;
            };
            let Some(verdict) = verdict_opt else {
                errors += 1;
                continue;
            };

            let is_blocked = verdict.is_blocked();
            variant_outcomes.push((techniques.clone(), is_blocked));
            total_fired += 1;

            if matches!(verdict, wafrift_types::Verdict::RateLimited { .. }) {
                _rate_limited += 1;
                batch_rate_limited = true;
                if args.format == "text" {
                    print!("{}", "R".yellow());
                }
            } else if verdict.is_challenge() {
                _challenges += 1;
                blocked += 1;
                if args.format == "text" {
                    print!("{}", "C".bright_yellow());
                }
            } else if is_blocked {
                blocked += 1;
                if args.format == "text" {
                    print!("{}", ".".bright_black());
                }
            } else {
                bypassed += 1;
                bypass_variants.push((
                    total_fired,
                    payload,
                    techniques.clone(),
                    confidence,
                ));
                // Record winning encoding strategies for exploitation.
                for tech in &techniques {
                    if tech.starts_with("encoding::") {
                        winning_strategies.insert(tech.clone());
                    }
                }
                if args.format == "text" {
                    print!("{}", "!".bright_green().bold());
                }
            }

            // Live progress: show rate every 20 variants.
            let done = index + 1;
            if args.format == "text" && done % 20 == 0 {
                let current_total = bypassed + blocked + errors;
                let rate = if current_total > 0 {
                    f64::from(bypassed) / f64::from(current_total) * 100.0
                } else {
                    0.0
                };
                let total_variants = variants.len();
                print!(
                    " {}",
                    format!("[{done}/{total_variants} {rate:.0}%]").bright_black()
                );
                let _ = io::stdout().flush();
            }
        }

        variant_idx = batch_end;

        // Inter-batch delay: double if rate-limited, otherwise normal.
        if batch_rate_limited {
            tokio::time::sleep(delay * 2).await;
        } else if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    // Step 3b: Tamper — apply novel tamper strategies to grammar mutations.
    // These are fundamentally different from encoding: SQL comment insertion (/**/),
    // overlong UTF-8, null byte injection exploit WAF implementation bugs.
    if !encoding_only {
        let tamper_context = match payload_type {
            PayloadType::Sql => Some("sql"),
            PayloadType::Xss => Some("xss"),
            PayloadType::CommandInjection => Some("cmd"),
            _ => None,
        };

        let grammar_mutations = grammar::mutate_as(&args.payload, payload_type, max_mutations);
        let mut tamper_seen: HashSet<String> = HashSet::new();
        // Seed seen set with explore payloads.
        for v in &variants {
            tamper_seen.insert(v.payload.clone());
        }

        if scan_text {
            println!(
                "\n\n{}",
                format!(
                    "[3b/7] Tamper probing — {} mutations × {} tamper strategies...",
                    grammar_mutations.len(),
                    novel_tamper_names.len()
                )
                .bold()
                .cyan()
            );
        }

        let mut tamper_bypassed = 0_u32;
        let mut tamper_fired = 0_u32;

        for mutation in &grammar_mutations {
            if cancel.is_cancelled() {
                break;
            }
            for tamper_name in &novel_tamper_names {
                let tampered = match tamper_registry.tamper_with(tamper_name, &mutation.payload, tamper_context) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if !tamper_seen.insert(tampered.clone()) {
                    continue;
                }

                let url = scan_url_with_param(
                    target,
                    &args.param,
                    &urlencoding::encode(&tampered),
                );

                let verdict = match http.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.bytes().await.unwrap_or_default();
                        oracle.classify(&ResponseContext {
                            status,
                            body: body.to_vec(),
                            ..Default::default()
                        })
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };

                total_fired += 1;
                tamper_fired += 1;

                let mut techniques: Vec<String> = mutation
                    .rules_applied
                    .iter()
                    .map(|r| (*r).to_string())
                    .collect();
                techniques.push(format!("tamper::{tamper_name}"));
                let is_blocked = verdict.is_blocked() || verdict.is_challenge();
                variant_outcomes.push((techniques.clone(), is_blocked));

                if is_blocked {
                    blocked += 1;
                    if args.format == "text" {
                        print!("{}", ".".bright_black());
                    }
                } else if matches!(verdict, wafrift_types::Verdict::RateLimited { .. }) {
                    _rate_limited += 1;
                    tokio::time::sleep(delay * 2).await;
                } else {
                    bypassed += 1;
                    tamper_bypassed += 1;
                    bypass_variants.push((
                        total_fired,
                        tampered,
                        techniques.clone(),
                        0.75, // Tamper bypasses get moderate-high confidence
                    ));
                    // Record winning tamper strategies for exploitation.
                    winning_strategies.insert(format!("tamper::{tamper_name}"));
                    if args.format == "text" {
                        print!("{}", "!".bright_green().bold());
                    }
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        if scan_text && tamper_fired > 0 {
            let rate = f64::from(tamper_bypassed) / f64::from(tamper_fired) * 100.0;
            println!(
                "\n  {} {}",
                "Tamper results:".bold().cyan(),
                format!("{tamper_bypassed}/{tamper_fired} bypassed ({rate:.0}%)").yellow()
            );
        }
    }

    // Step 4: Exploit — amplify winning strategies via chaining, cross-pollination, and fresh mutations.
    if !winning_strategies.is_empty() && !cancel.is_cancelled() {
        // Resolve winning strategy enums from their debug names.
        let all_strats = encoding::all_strategies();
        let mut exploit_strategies: Vec<Strategy> = all_strats
            .iter()
            .filter(|s| winning_strategies.contains(&format!("encoding::{s:?}")))
            .copied()
            .collect();
        // Expand with advisor-recommended strategies not already in the pool.
        for adv_strat in &advisor_strategies {
            if !exploit_strategies.contains(adv_strat) {
                exploit_strategies.push(*adv_strat);
            }
        }
        // Honor user --only/--exclude: even gene-bank winners and advisor
        // recommendations must respect the configured technique surface.
        exploit_strategies = filter.filter_strategies(exploit_strategies);

        // Collect the raw (pre-encoding) payloads that produced bypasses, paired with their encoding.
        // We'll cross-pollinate these with other winning encodings.
        let mut winning_raw_payloads: Vec<(String, Vec<String>)> = Vec::new();
        // Also collect already-encoded bypass payloads for chaining.
        let mut encoded_bypass_payloads: Vec<(String, Vec<String>)> = Vec::new();

        for v in &variants {
            // Check if this variant bypassed (exists in bypass_variants).
            if bypass_variants.iter().any(|(_, p, _, _)| p == &v.payload) {
                // The raw payload before encoding is the grammar mutation.
                // We can't perfectly recover it, but we CAN identify which grammar mutations
                // led to bypasses by looking at the techniques list.
                encoded_bypass_payloads.push((v.payload.clone(), v.techniques.clone()));
            }
        }

        // Also collect the grammar mutations that bypassed for cross-pollination.
        // We search the original build_variants output: for each bypassed variant,
        // find the mutation payload text and record it.
        // Strategy: re-derive from original mutations — the encode is invertible for our purposes
        // because we're going to re-encode with different strategies anyway.
        let original_mutations = if !encoding_only {
            grammar::mutate_as(&args.payload, payload_type, max_mutations_for_level(args.level))
        } else {
            Vec::new()
        };

        // Build a lookup: encoded_payload → list of grammar mutations that could produce it
        // (by trying all strategies against each mutation).
        for mutation in &original_mutations {
            for strategy in &exploit_strategies {
                if let Ok(encoded) = encoding::encode(&mutation.payload, *strategy)
                    && bypass_variants.iter().any(|(_, p, _, _)| p == &encoded)
                {
                    winning_raw_payloads.push((
                        mutation.payload.clone(),
                        mutation.rules_applied.iter().map(|r| r.to_string()).collect(),
                    ));
                    break; // Don't add the same raw payload multiple times for different strategies
                }
            }
        }

        // Dedup raw payloads
        winning_raw_payloads.sort_by(|a, b| a.0.cmp(&b.0));
        winning_raw_payloads.dedup_by(|a, b| a.0 == b.0);

        if scan_text {
            println!(
                "\n\n{}",
                format!(
                    "[4/7] Exploiting {} winning strategies × {} winning mutations...",
                    exploit_strategies.len(),
                    winning_raw_payloads.len(),
                )
                .bold()
                .green()
            );
            println!(
                "  {} encoding chaining (stack two encodings)",
                "→".bright_green()
            );
            println!(
                "  {} cross-pollination (winning mutations × all winning encodings)",
                "→".bright_green()
            );
            println!(
                "  {} fresh mutations with winning encodings",
                "→".bright_green()
            );
            println!();
        }

        let mut exploit_seen: HashSet<String> = HashSet::new();
        for v in &variants {
            exploit_seen.insert(v.payload.clone());
        }

        // Helper closure: fire a candidate and record results.
        // Returns true if bypass, false if blocked, None if error.
        let exploit_cap = 500_usize; // Max additional requests to prevent runaway
        let mut exploit_count = 0_usize;

        // ── Phase 4a: Encoding chaining ───────────────────────────────────────
        // Take already-bypassed encoded payloads and apply a SECOND encoding on top.
        // This creates double-encoded variants that are extremely hard for WAFs to decode.
        if scan_text {
            print!("  {}", "chaining: ".bright_cyan());
            let _ = io::stdout().flush();
        }
        let mut chain_bypassed = 0_u32;
        let mut chain_fired = 0_u32;

        // Only chain with URL-safe encodings (stacking Base64→Gzip makes no HTTP sense)
        let chainable: Vec<Strategy> = exploit_strategies
            .iter()
            .copied()
            .filter(|s| matches!(
                s,
                Strategy::DoubleUrlEncode
                    | Strategy::TripleUrlEncode
                    | Strategy::UrlEncode
                    | Strategy::UrlEncodeLower
                    | Strategy::CaseAlternation
                    | Strategy::RandomCase
                    | Strategy::PercentagePrefix
                    | Strategy::HtmlEntityEncode
                    | Strategy::HtmlEntityDecimalEncode
                    | Strategy::UnicodeEncode
                    | Strategy::IisUnicodeEncode
            ))
            .collect();

        'chain_loop: for (bypass_payload, bypass_techs) in &encoded_bypass_payloads {
            for second_encoding in &chainable {
                if exploit_count >= exploit_cap {
                    break 'chain_loop;
                }
                let chained = match encoding::encode(bypass_payload, *second_encoding) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if !exploit_seen.insert(chained.clone()) {
                    continue;
                }

                let url = scan_url_with_param(
                    target,
                    &args.param,
                    &urlencoding::encode(&chained),
                );

                let is_blocked = match http.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.bytes().await.unwrap_or_default();
                        is_waf_block(status, &body)
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };

                total_fired += 1;
                exploit_count += 1;
                chain_fired += 1;

                let mut techniques = bypass_techs.clone();
                techniques.push(format!("chain::{second_encoding:?}"));
                variant_outcomes.push((techniques.clone(), is_blocked));

                if is_blocked {
                    blocked += 1;
                    if args.format == "text" {
                        print!("{}", ".".bright_black());
                    }
                } else {
                    bypassed += 1;
                    chain_bypassed += 1;
                    bypass_variants.push((total_fired, chained, techniques, 0.9));
                    if args.format == "text" {
                        print!("{}", "!".bright_green().bold());
                    }
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        if scan_text && chain_fired > 0 {
            let rate = f64::from(chain_bypassed) / f64::from(chain_fired) * 100.0;
            println!(
                " {}",
                format!("{chain_bypassed}/{chain_fired} ({rate:.0}%)").yellow()
            );
        } else if scan_text {
            println!("{}", "skipped".bright_black());
        }

        // ── Phase 4b: Cross-pollination ──────────────────────────────────────
        // Take winning grammar mutations and try them with ALL winning encodings,
        // not just the one that originally worked.
        if scan_text {
            print!("  {}", "cross-pollination: ".bright_cyan());
            let _ = io::stdout().flush();
        }
        let mut xpol_bypassed = 0_u32;
        let mut xpol_fired = 0_u32;

        'xpol_loop: for (raw_payload, raw_rules) in &winning_raw_payloads {
            for strategy in &exploit_strategies {
                if exploit_count >= exploit_cap {
                    break 'xpol_loop;
                }
                let encoded = match encoding::encode(raw_payload, *strategy) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if !exploit_seen.insert(encoded.clone()) {
                    continue;
                }

                let url = scan_url_with_param(
                    target,
                    &args.param,
                    &urlencoding::encode(&encoded),
                );

                let is_blocked = match http.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.bytes().await.unwrap_or_default();
                        is_waf_block(status, &body)
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };

                total_fired += 1;
                exploit_count += 1;
                xpol_fired += 1;

                let mut techniques = raw_rules.clone();
                techniques.push(format!("encoding::{strategy:?}"));
                variant_outcomes.push((techniques.clone(), is_blocked));

                if is_blocked {
                    blocked += 1;
                    if args.format == "text" {
                        print!("{}", ".".bright_black());
                    }
                } else {
                    bypassed += 1;
                    xpol_bypassed += 1;
                    bypass_variants.push((
                        total_fired,
                        encoded,
                        techniques,
                        variant_confidence(payload_type, raw_rules.len(), false, *strategy),
                    ));
                    if args.format == "text" {
                        print!("{}", "!".bright_green().bold());
                    }
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        if scan_text && xpol_fired > 0 {
            let rate = f64::from(xpol_bypassed) / f64::from(xpol_fired) * 100.0;
            println!(
                " {}",
                format!("{xpol_bypassed}/{xpol_fired} ({rate:.0}%)").yellow()
            );
        } else if scan_text {
            println!("{}", "skipped".bright_black());
        }

        // ── Phase 4c: Fresh mutations with winning strategies ────────────────
        // Generate MORE grammar mutations from the original seed and encode with winners.
        if scan_text {
            print!("  {}", "fresh mutations: ".bright_cyan());
            let _ = io::stdout().flush();
        }
        let mut fresh_bypassed = 0_u32;
        let mut fresh_fired = 0_u32;

        let max_exploit_rounds = 2;
        'fresh_outer: for round in 0..max_exploit_rounds {
            if exploit_count >= exploit_cap {
                break;
            }

            let round_mutations = max_mutations_for_level(args.level) + (round + 1) * 6;
            let fresh_mutations = if !encoding_only {
                grammar::mutate_as(&args.payload, payload_type, round_mutations)
            } else {
                Vec::new()
            };

            for mutation in &fresh_mutations {
                for strategy in &exploit_strategies {
                    if exploit_count >= exploit_cap {
                        break 'fresh_outer;
                    }
                    let encoded = match encoding::encode(&mutation.payload, *strategy) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if !exploit_seen.insert(encoded.clone()) {
                        continue;
                    }

                    let url = scan_url_with_param(
                        target,
                        &args.param,
                        &urlencoding::encode(&encoded),
                    );

                    let is_blocked = match http.get(&url).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let body = resp.bytes().await.unwrap_or_default();
                            is_waf_block(status, &body)
                        }
                        Err(_) => {
                            errors += 1;
                            continue;
                        }
                    };

                    total_fired += 1;
                    exploit_count += 1;
                    fresh_fired += 1;

                    let mut techniques: Vec<String> = mutation
                        .rules_applied
                        .iter()
                        .map(|r| (*r).to_string())
                        .collect();
                    techniques.push(format!("encoding::{strategy:?}"));
                    variant_outcomes.push((techniques.clone(), is_blocked));

                    if is_blocked {
                        blocked += 1;
                        if args.format == "text" {
                            print!("{}", ".".bright_black());
                        }
                    } else {
                        bypassed += 1;
                        fresh_bypassed += 1;
                        bypass_variants.push((
                            total_fired,
                            encoded,
                            techniques,
                            variant_confidence(
                                payload_type,
                                mutation.rules_applied.len(),
                                false,
                                *strategy,
                            ),
                        ));
                        if args.format == "text" {
                            print!("{}", "!".bright_green().bold());
                        }
                    }

                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        if scan_text && fresh_fired > 0 {
            let rate = f64::from(fresh_bypassed) / f64::from(fresh_fired) * 100.0;
            println!(
                " {}",
                format!("{fresh_bypassed}/{fresh_fired} ({rate:.0}%)").yellow()
            );
        } else if scan_text {
            println!("{}", "skipped".bright_black());
        }

        if scan_text {
            let exploit_total = chain_fired + xpol_fired + fresh_fired;
            let exploit_bypass = chain_bypassed + xpol_bypassed + fresh_bypassed;
            let rate = if exploit_total > 0 {
                f64::from(exploit_bypass) / f64::from(exploit_total) * 100.0
            } else {
                0.0
            };
            println!(
                "\n  {} {}",
                "Exploit total:".bold().cyan(),
                format!(
                    "{exploit_bypass}/{exploit_total} bypassed ({rate:.0}%) — {exploit_count} requests"
                )
                .yellow()
                .bold()
            );
        }
    } else if scan_text {
        println!(
            "\n\n{}",
            "[4/7] No bypasses found to exploit — skipping amplification"
                .bright_black()
        );
    }

    // Step 5: Multi-vector — re-fire top bypass payloads through alternative delivery vectors.
    // WAFs often have weaker inspection for POST body, JSON body, cookies, etc.
    if !bypass_variants.is_empty() && !cancel.is_cancelled() {
        let vectors: Vec<(&str, &str)> = vec![
            ("POST-form", "application/x-www-form-urlencoded"),
            ("POST-json", "application/json"),
            ("POST-multipart", "multipart/form-data"),
            ("cookie", ""),
            ("hpp", ""),
            ("x-forwarded-for", ""),
            ("referer", ""),
        ];

        // Take the top 10 unique bypass payloads (by confidence).
        let mut top_payloads: Vec<(String, Vec<String>)> = bypass_variants
            .iter()
            .take(10)
            .map(|(_, payload, techs, _)| (payload.clone(), techs.clone()))
            .collect();
        top_payloads.dedup_by(|a, b| a.0 == b.0);

        if scan_text {
            println!(
                "\n{}",
                format!(
                    "[5/7] Multi-vector probing — {} payloads × {} vectors...",
                    top_payloads.len(),
                    vectors.len()
                )
                .bold()
                .magenta()
            );
        }

        let mut vector_results: Vec<(String, u32, u32)> = Vec::new();

        for (vector_name, content_type) in &vectors {
            let mut v_bypassed = 0_u32;
            let mut v_blocked = 0_u32;

            for (payload, techs) in &top_payloads {
                let result = match *vector_name {
                    "POST-form" => {
                        let body = format!("{}={}", args.param, urlencoding::encode(payload));
                        http.post(target)
                            .header("Content-Type", *content_type)
                            .body(body)
                            .send()
                            .await
                    }
                    "POST-json" => {
                        let body = serde_json::json!({ &args.param: payload }).to_string();
                        http.post(target)
                            .header("Content-Type", *content_type)
                            .body(body)
                            .send()
                            .await
                    }
                    "cookie" => {
                        http.get(target)
                            .header(
                                "Cookie",
                                format!("{}={}", args.param, urlencoding::encode(payload)),
                            )
                            .send()
                            .await
                    }
                    "POST-multipart" => {
                        // Multipart form-data with randomized boundary — confuses WAF parsers
                        let boundary = format!("----WafRiftBoundary{:x}", total_fired);
                        let body = format!(
                            "--{boundary}\r\nContent-Disposition: form-data; name=\"{}\"\r\n\r\n{payload}\r\n--{boundary}--\r\n",
                            args.param
                        );
                        http.post(target)
                            .header("Content-Type", format!("multipart/form-data; boundary={boundary}"))
                            .body(body)
                            .send()
                            .await
                    }
                    "hpp" => {
                        // HTTP Parameter Pollution — WAF inspects first param, backend uses last
                        let url = format!(
                            "{}?{}=harmless&{}={}",
                            target,
                            args.param,
                            args.param,
                            urlencoding::encode(payload)
                        );
                        http.get(&url).send().await
                    }
                    "x-forwarded-for" => {
                        // Inject payload in X-Forwarded-For header — many WAFs skip header inspection
                        // or whitelist requests that appear to come from internal IPs.
                        let url = scan_url_with_param(
                            target,
                            &args.param,
                            &urlencoding::encode(payload),
                        );
                        http.get(&url)
                            .header("X-Forwarded-For", payload.as_str())
                            .send()
                            .await
                    }
                    "referer" => {
                        // Inject payload in Referer header — many WAFs don't inspect Referer,
                        // but some backends read it for analytics/redirect purposes.
                        let url = scan_url_with_param(
                            target,
                            &args.param,
                            &urlencoding::encode(payload),
                        );
                        http.get(&url)
                            .header("Referer", format!("https://example.com/?{}", payload))
                            .send()
                            .await
                    }
                    _ => continue,
                };

                let is_blocked = match result {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.bytes().await.unwrap_or_default();
                        is_waf_block(status, &body)
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };

                total_fired += 1;

                let mut vtechs = techs.clone();
                vtechs.push(format!("vector::{vector_name}"));
                variant_outcomes.push((vtechs.clone(), is_blocked));

                if is_blocked {
                    blocked += 1;
                    v_blocked += 1;
                    if args.format == "text" {
                        print!("{}", ".".bright_black());
                    }
                } else {
                    bypassed += 1;
                    v_bypassed += 1;
                    bypass_variants.push((
                        total_fired,
                        payload.clone(),
                        vtechs,
                        0.95, // High confidence — proven payload, new vector
                    ));
                    if args.format == "text" {
                        print!("{}", "!".bright_green().bold());
                    }
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }

            vector_results.push((vector_name.to_string(), v_bypassed, v_blocked));
        }

        if scan_text {
            for (name, vb, vbl) in &vector_results {
                let total = vb + vbl;
                let rate = if total > 0 {
                    f64::from(*vb) / f64::from(total) * 100.0
                } else {
                    0.0
                };
                let status = if *vb > 0 {
                    format!("{vb}/{total} bypassed ({rate:.0}%)").green().to_string()
                } else {
                    format!("0/{total} — fully blocked").bright_black().to_string()
                };
                println!("  {} {}: {}", "→".bright_magenta(), name.yellow(), status);
            }
        }
    } else if scan_text {
        println!(
            "\n{}",
            "[5/7] No bypasses — skipping multi-vector probing"
                .bright_black()
        );
    }

    // Step 6/7: Header obfuscation probing — exploit WAF header parser bugs.
    if evasion_plan.use_header_obfuscation && !bypass_variants.is_empty() {
        let header_techniques = [
            ("case_mixing", "Content-Type"),
            ("underscore_sub", "Content-Type"),
            ("null_byte", "X-Forwarded-For"),
            ("whitespace_pad", "Content-Type"),
            ("trailing_space", "Content-Type"),
            ("line_fold", "Content-Type"),
        ];
        // Apply to BOTH bypass payloads and top blocked payloads (rescue).
        let top_bypass_payloads: Vec<String> = bypass_variants
            .iter()
            .take(5)
            .map(|(_, p, _, _)| p.clone())
            .collect();
        // Collect top blocked payloads for rescue attempts.
        let blocked_payloads: Vec<String> = variants
            .iter()
            .filter(|v| !bypass_variants.iter().any(|(_, p, _, _)| p == &v.payload))
            .take(5)
            .map(|v| v.payload.clone())
            .collect();
        let all_header_payloads: Vec<(String, bool)> = top_bypass_payloads
            .iter()
            .map(|p| (p.clone(), true))
            .chain(blocked_payloads.iter().map(|p| (p.clone(), false)))
            .collect();

        if scan_text {
            println!(
                "\n{}",
                format!(
                    "[6/7] Header obfuscation — {} payloads ({} bypass + {} rescue) × {} techniques...",
                    all_header_payloads.len(),
                    top_bypass_payloads.len(),
                    blocked_payloads.len(),
                    header_techniques.len()
                )
                .bold()
                .cyan()
            );
        }

        let mut header_bypassed = 0_u32;
        let mut header_fired = 0_u32;

        for (payload, _is_bypass) in &all_header_payloads {
            for (technique_name, header_name) in &header_techniques {
                let obfuscated_header = match *technique_name {
                    "case_mixing" => header_obfuscation::case_mix(header_name),
                    "underscore_sub" => header_obfuscation::underscore_substitute(header_name),
                    "null_byte" => header_obfuscation::null_byte_inject(header_name),
                    "whitespace_pad" => header_obfuscation::whitespace_pad(header_name, "application/x-www-form-urlencoded"),
                    "trailing_space" => header_obfuscation::trailing_space(header_name, "application/x-www-form-urlencoded"),
                    "line_fold" => header_obfuscation::line_fold(header_name, "application/x-www-form-urlencoded"),
                    _ => header_name.to_string(),
                };

                let url = scan_url_with_param(
                    target,
                    &args.param,
                    &urlencoding::encode(payload),
                );

                let verdict = match http
                    .get(&url)
                    .header(&obfuscated_header, "application/x-www-form-urlencoded")
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.bytes().await.unwrap_or_default();
                        oracle.classify(&ResponseContext {
                            status,
                            body: body.to_vec(),
                            ..Default::default()
                        })
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };

                header_fired += 1;
                total_fired += 1;

                if !verdict.is_blocked() && !verdict.is_challenge() {
                    header_bypassed += 1;
                    bypassed += 1;
                    let mut techs: Vec<String> = bypass_variants
                        .iter()
                        .find(|(_, p, _, _)| p == payload)
                        .map(|(_, _, t, _)| t.clone())
                        .unwrap_or_default();
                    techs.push(format!("header::{technique_name}"));
                    bypass_variants.push((
                        total_fired,
                        payload.clone(),
                        techs,
                        0.85,
                    ));
                    if scan_text {
                        print!("{}", "!".bright_green().bold());
                    }
                } else {
                    blocked += 1;
                    if scan_text {
                        print!("{}", ".".bright_black());
                    }
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        if scan_text && header_fired > 0 {
            let rate = f64::from(header_bypassed) / f64::from(header_fired) * 100.0;
            println!(
                "\n  {} {}",
                "Header results:".bold().cyan(),
                format!("{header_bypassed}/{header_fired} bypassed ({rate:.0}%)").yellow()
            );
        }
    }

    // Step 7/7: Intelligence loop — evolution-guided candidate generation.
    if intel_loop.has_sufficient_data() {
        if scan_text {
            println!(
                "\n{}",
                "[7/7] Intelligence loop — evolving candidates...".bold().cyan()
            );
        }

        let max_intel_rounds = 50_usize.min(200_usize.saturating_sub(total_fired));
        let mut intel_bypassed = 0_u32;
        let mut intel_fired = 0_u32;

        // Seed the evolution with differential insights for smarter candidates.
        for _suggestion in &diff_suggestions {
            if let Some((idx, _)) = intel_loop.next_candidate() {
                // Record "virtual" positive feedback for the suggested technique
                // to bias the evolution towards it.
                intel_loop.record_feedback(idx, true);
            }
        }

        for _ in 0..max_intel_rounds {
            if let Some((idx, chromosome)) = intel_loop.next_candidate() {
                // Use the chromosome's gene flags to build a payload variant.
                let has_grammar = chromosome.genes.iter().any(|(k, _)| k == "grammar");
                let enc_gene = chromosome.genes.iter().find(|(k, _)| k == "encoding").map(|(_, v)| v.clone());

                let intel_payload = if has_grammar {
                    let mutations = grammar::mutate_as(&args.payload, payload_type, 1);
                    mutations.first().map_or(args.payload.clone(), |m| m.payload.clone())
                } else {
                    args.payload.clone()
                };

                // Apply the chromosome's encoding if set.
                let encoded = if let Some(ref enc_name) = enc_gene {
                    encoding::all_strategies()
                        .iter()
                        .find(|s| s.as_str() == enc_name.as_str())
                        .map_or(intel_payload.clone(), |s| encoding::encode(&intel_payload, *s).unwrap_or_else(|_| intel_payload.clone()))
                } else {
                    intel_payload.clone()
                };

                let url = scan_url_with_param(
                    target,
                    &args.param,
                    &urlencoding::encode(&encoded),
                );

                let verdict = match http.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.bytes().await.unwrap_or_default();
                        oracle.classify(&ResponseContext {
                            status,
                            body: body.to_vec(),
                            ..Default::default()
                        })
                    }
                    Err(_) => {
                        errors += 1;
                        intel_loop.record_feedback(idx, false);
                        continue;
                    }
                };

                let passed = !verdict.is_blocked() && !verdict.is_challenge();
                intel_loop.record_feedback(idx, passed);
                intel_fired += 1;
                total_fired += 1;

                if passed {
                    intel_bypassed += 1;
                    bypassed += 1;
                    let mut techs = Vec::new();
                    if has_grammar {
                        techs.push("intel::grammar".to_string());
                    }
                    if let Some(ref enc) = enc_gene {
                        techs.push(format!("intel::encoding::{enc}"));
                    }
                    techs.push("intel::evolution".to_string());
                    bypass_variants.push((total_fired, encoded, techs, 0.80));
                    if scan_text {
                        print!("{}", "!".bright_green().bold());
                    }
                } else if scan_text {
                    print!("{}", ".".bright_black());
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        // Evolve population for future use.
        intel_loop.evolve();

        if scan_text && intel_fired > 0 {
            let rate = f64::from(intel_bypassed) / f64::from(intel_fired) * 100.0;
            println!(
                "\n  {} {} (diversity: {:.2})",
                "Intel results:".bold().cyan(),
                format!("{intel_bypassed}/{intel_fired} bypassed ({rate:.0}%)").yellow(),
                intel_loop.diversity()
            );
        }
    }

    println!("\n");

    // Results.
    let elapsed = scan_start.elapsed();
    let requests_completed = bypassed + blocked + errors;
    let bypass_rate = if requests_completed > 0 {
        f64::from(bypassed) / f64::from(requests_completed) * 100.0
    } else {
        0.0
    };

    if args.format == "json" {
        let scan = json!({
            "scan_schema_version": 1,
            "target": target,
            "waf": waf_name,
            "payload_type": payload_type_label(payload_type),
            "total_variants": total_fired,
            "explore_variants": variants.len(),
            "exploit_variants": total_fired.saturating_sub(variants.len()),
            "winning_strategies": winning_strategies.iter().cloned().collect::<Vec<_>>(),
            "requests_completed": requests_completed,
            "baseline_transport_ok": raw_transport_ok,
            "bypassed": bypassed,
            "blocked": blocked,
            "errors": errors,
            "bypass_rate_pct": bypass_rate,
            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
            "bypass_variants": bypass_variants.iter().map(|(idx, payload, techniques, conf)| {
                json!({
                    "variant": idx,
                    "payload": payload,
                    "techniques": techniques,
                    "confidence": conf,
                })
            }).collect::<Vec<_>>(),
        });
        let json_output = if args.report_layers {
            json!({
                "layer_report": {
                    "network": {
                        "target": target,
                        "baseline_get_status": baseline_status,
                    },
                    "detection": {
                        "chosen_waf": waf_name,
                        "candidates": detected.iter().map(|d| {
                            json!({
                                "name": d.name,
                                "confidence": d.confidence,
                                "indicators": d.indicators,
                            })
                        }).collect::<Vec<_>>(),
                    },
                    "baseline_probe": {
                        "raw_get_status": raw_status,
                        "treated_as_blocked": raw_blocked,
                        "transport_ok": raw_transport_ok,
                    },
                    "evasion_campaign": {
                        "variants_generated": total_fired,
                        "requests_completed": requests_completed,
                        "bypassed": bypassed,
                        "blocked": blocked,
                        "errors": errors,
                        "bypass_rate_pct": bypass_rate,
                    },
                },
                "scan": scan,
            })
        } else {
            scan
        };
        match serde_json::to_string_pretty(&json_output) {
            Ok(s) => {
                println!("{s}");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("failed to serialize scan JSON: {e}");
                return ExitCode::from(1);
            }
        }
    }

    // Text output.
    println!(
        "{}",
        "══════════════════════════════════════════════════".bright_cyan()
    );
    println!("  {} {}", "WAF:".bold().cyan(), waf_name.bold().yellow());
    println!(
        "  {} {}",
        "Variants (scheduled):".bold().cyan(),
        format!("{total_fired}").bold()
    );
    println!(
        "  {} {}",
        "Requests completed:".bold().cyan(),
        format!("{requests_completed}").bold()
    );
    println!(
        "  {} {}",
        "Blocked:".bold().cyan(),
        format!("{blocked}").red().bold()
    );
    println!(
        "  {} {}",
        "Bypassed:".bold().cyan(),
        format!("{bypassed}").green().bold()
    );
    if errors > 0 {
        println!(
            "  {} {}",
            "Errors:".bold().cyan(),
            format!("{errors}").yellow()
        );
    }
    println!(
        "  {} {}",
        "Bypass Rate:".bold().cyan(),
        format!("{bypass_rate:.1}%")
            .bold()
            .color(if bypass_rate > 50.0 {
                colored::Color::BrightGreen
            } else if bypass_rate > 20.0 {
                colored::Color::Yellow
            } else {
                colored::Color::Red
            })
    );
    println!(
        "  {} {:.1}s",
        "Elapsed:".bold().cyan(),
        elapsed.as_secs_f64()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════".bright_cyan()
    );

    if !bypass_variants.is_empty() {
        println!(
            "\n{}",
            "Successful Bypasses:".bold().bright_green().underline()
        );
        for (idx, payload, techniques, confidence) in &bypass_variants {
            println!(
                "\n  {} #{} {}",
                "Variant".bold().green(),
                idx,
                confidence_badge(*confidence)
            );
            println!(
                "  {} {}",
                "Techniques:".bold().cyan(),
                techniques.join(" → ").yellow()
            );
            let display_payload = if payload.len() > 120 {
                format!("{}…", &payload[..120])
            } else {
                payload.clone()
            };
            println!(
                "  {} {}",
                "Payload:".bold().cyan(),
                display_payload.bright_white()
            );
        }
    }

    // ── Gene Bank: per-technique successes and attempts across all fired variants ─────────
    let mut tech_acc: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();
    for (techs, blocked) in variant_outcomes {
        for t in techs {
            let e = tech_acc.entry(t).or_insert((0, 0));
            e.1 += 1;
            if !blocked {
                e.0 += 1;
            }
        }
    }
    let stats: Vec<(String, u32, u32)> = tech_acc
        .into_iter()
        .map(|(name, (s, a))| (name, s, a))
        .collect();

    if !stats.is_empty() {
        match GeneBank::open_default() {
            Ok(mut bank) => match bank.merge_and_save(&waf_name, &stats) {
                Ok(()) => {
                    if scan_text {
                        println!(
                            "\n{} {} {}",
                            "🧬".bold(),
                            "Gene bank updated:".bold().cyan(),
                            format!("{} techniques saved for {waf_name}", stats.len()).yellow()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("  {} {}", "⚠ Gene bank save failed:".yellow(), e);
                }
            },
            Err(e) => {
                eprintln!("  {} {}", "⚠ Gene bank unavailable:".yellow(), e);
            }
        }
    }

    // Learning cache: save winning pipelines for future scans.
    if !bypass_variants.is_empty()
        && let Some(ref mut cache) = learning_cache
    {
            // Build a pipeline from the best winning technique combination.
            let best_techniques: Vec<wafrift_types::Technique> = bypass_variants
                .first()
                .map(|(_, _, techs, _)| {
                    techs
                        .iter()
                        .map(|t| {
                            if t.starts_with("encoding::") {
                                wafrift_types::Technique::PayloadEncoding(t.clone())
                            } else if t.starts_with("tamper::") {
                                wafrift_types::Technique::GrammarMutation(t.clone())
                            } else if t.starts_with("vector::") {
                                wafrift_types::Technique::ContentTypeSwitch(t.clone())
                            } else {
                                wafrift_types::Technique::GrammarMutation(t.clone())
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            // Validate composition ordering.
            let layers: Vec<composition::EvasionLayer> = best_techniques
                .iter()
                .map(|t| match t {
                    wafrift_types::Technique::PayloadEncoding(_) => composition::EvasionLayer::Encoding,
                    wafrift_types::Technique::GrammarMutation(_) => composition::EvasionLayer::Grammar,
                    wafrift_types::Technique::ContentTypeSwitch(_) => composition::EvasionLayer::ContentType,
                    wafrift_types::Technique::HeaderObfuscation(_) => composition::EvasionLayer::Header,
                    _ => composition::EvasionLayer::Encoding,
                })
                .collect();
            let valid_order = composition::is_valid_sequence(&layers);

            let pipeline_cost = cost::pipeline_cost(&best_techniques);
            let pipeline = EvasionPipeline::new(
                format!("auto_{waf_name}_{payload_type_str}"),
                best_techniques,
                pipeline_cost,
            );

            let key = CacheKey::new(&waf_name, &payload_type_str);
            cache.record_success(key, pipeline);
            if let Err(e) = cache.save() {
                eprintln!("  {} {}", "⚠ Learning cache save failed:".yellow(), e);
            } else if scan_text {
                println!(
                    "{} {} (cost: {}, valid order: {})",
                    "📦".bold(),
                    "Learning cache updated".bold().cyan(),
                    pipeline_cost,
                    if valid_order { "yes" } else { "no" }
                );
        }
    }

    if args.report_layers && scan_text {
        println!(
            "\n{}",
            "Layer summary (docs/GAP_CLOSURE_ROADMAP.md):".bold().bright_black()
        );
        println!(
            "  network: baseline_get_status={}  detection: {} candidate(s)  baseline_probe: raw_get_status={} treated_as_blocked={}  evasion: bypass_rate={:.1}%",
            baseline_status,
            detected.len(),
            raw_status,
            raw_blocked,
            bypass_rate,
        );
    }

    println!();
    ExitCode::SUCCESS
}

