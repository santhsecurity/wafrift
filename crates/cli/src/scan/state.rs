//! Shared mutable state for the scan pipeline.
//!
//! Each pipeline step receives `&mut ScanState` to read/update counters and
//! accumulators without needing a 20-argument function signature.

// Infrastructure for incremental pipeline step extraction — not yet consumed.
#![allow(dead_code)]

use std::collections::HashSet;
use std::time::Duration;

use wafrift_encoding::encoding::Strategy;
use wafrift_evolution::intelligence::IntelligenceLoop;
use wafrift_grammar::grammar::PayloadType;
use wafrift_oracle::response_oracle::ResponseOracle;
use wafrift_strategy::learning_cache::LearningCache;

use crate::helpers::Variant;

/// Mutable scan state accumulated across pipeline steps.
pub(crate) struct ScanState {
    // ── Counters ───────────────────────────────────────────────────────
    pub bypassed: u32,
    pub blocked: u32,
    pub errors: u32,
    pub rate_limited: u32,
    pub challenges: u32,
    pub total_fired: usize,

    // ── Winning data ───────────────────────────────────────────────────
    pub bypass_variants: Vec<(usize, String, Vec<String>, f64)>,
    pub variant_outcomes: Vec<(Vec<String>, bool)>,
    pub winning_strategies: HashSet<String>,
    pub cache_hit_bypass: bool,

    // ── Intelligence & learning ────────────────────────────────────────
    pub intel_loop: IntelligenceLoop,
    pub learning_cache: Option<LearningCache>,
    pub oracle: ResponseOracle,

    // ── WAF detection results ──────────────────────────────────────────
    pub waf_name: String,
    pub baseline_status: u16,
    pub raw_status: u16,
    pub raw_blocked: bool,
    pub raw_transport_ok: bool,
    pub detected: Vec<wafrift_detect::waf_detect::DetectedWaf>,
    pub advisor_strategies: Vec<Strategy>,
}

impl ScanState {
    pub fn new() -> Self {
        Self {
            bypassed: 0,
            blocked: 0,
            errors: 0,
            rate_limited: 0,
            challenges: 0,
            total_fired: 0,
            bypass_variants: Vec::new(),
            variant_outcomes: Vec::new(),
            winning_strategies: HashSet::new(),
            cache_hit_bypass: false,
            intel_loop: IntelligenceLoop::new(20),
            learning_cache: LearningCache::open_default().ok(),
            oracle: ResponseOracle::new(),
            waf_name: String::from("Unknown"),
            baseline_status: 0,
            raw_status: 0,
            raw_blocked: false,
            raw_transport_ok: false,
            detected: Vec::new(),
            advisor_strategies: Vec::new(),
        }
    }
}

/// Immutable scan configuration extracted from CLI args.
pub(crate) struct ScanConfig<'a> {
    pub target: &'a str,
    pub param: &'a str,
    pub payload: &'a str,
    pub payload_type: PayloadType,
    pub payload_type_str: String,
    pub scan_text: bool,
    pub format: &'a str,
    pub delay: Duration,
    pub encoding_only: bool,
    pub report_layers: bool,
    pub max_mutations: usize,
    pub http: reqwest::Client,
    pub variants: Vec<Variant>,
}
