//! Core types for the evolution engine.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Rich oracle verdict providing gradient signals for fitness.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct OracleVerdict {
    /// Whether the payload passed the WAF.
    pub passed: bool,
    /// Delta from baseline response status code.
    pub status_delta: i16,
    /// Delta from baseline response body size.
    pub body_delta: i32,
    /// Response latency in milliseconds.
    pub latency_ms: u32,
    /// Oracle confidence (0.0–1.0).
    pub confidence: f64,
    /// Number of WAF rules triggered.
    pub triggered_rules: u32,
}

impl OracleVerdict {
    /// Create a binary pass/fail verdict.
    #[must_use]
    pub fn from_bool(passed: bool) -> Self {
        Self {
            passed,
            status_delta: 0,
            body_delta: 0,
            latency_ms: 0,
            confidence: 1.0,
            triggered_rules: if passed { 0 } else { 1 },
        }
    }

    /// Compute a scalar fitness from the rich verdict.
    ///
    /// Rewards partial progress: fewer triggered rules, lower latency,
    /// smaller body delta, and high oracle confidence.
    #[must_use]
    pub fn to_fitness(&self) -> f64 {
        let base = if self.passed { 1.0 } else { 0.0 };
        let partial = if self.passed {
            0.0
        } else {
            // Partial credit for fewer triggered rules, faster response
            let rule_penalty = (self.triggered_rules as f64 * 0.05).min(0.3);
            let latency_penalty = (self.latency_ms as f64 / 5000.0).min(0.1);
            let body_penalty = (self.body_delta.abs() as f64 / 10000.0).min(0.1);
            0.3 - rule_penalty - latency_penalty - body_penalty
        };
        let confidence_bonus = self.confidence * 0.05;
        (base + partial + confidence_bonus).clamp(0.0, 1.0)
    }
}

impl Default for OracleVerdict {
    fn default() -> Self {
        Self::from_bool(false)
    }
}

/// Feedback from evaluating a candidate.
#[derive(Debug, Clone, PartialEq)]
pub enum Feedback {
    /// Payload passed the WAF.
    Passed,
    /// Payload was blocked.
    Blocked,
    /// Target returned an error (5xx, timeout, etc.).
    TargetError(String),
}

impl Feedback {
    /// Convert feedback to an oracle verdict with default metadata.
    #[must_use]
    pub fn to_verdict(&self) -> OracleVerdict {
        match self {
            Self::Passed => OracleVerdict::from_bool(true),
            Self::Blocked => OracleVerdict::from_bool(false),
            Self::TargetError(_) => OracleVerdict {
                passed: false,
                status_delta: 500,
                body_delta: 0,
                latency_ms: 0,
                confidence: 0.0,
                triggered_rules: 0,
            },
        }
    }
}

/// Hard budget limits for the search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Maximum total oracle evaluations (requests).
    pub max_requests: usize,
    /// Maximum generations.
    pub max_generations: u32,
    /// Maximum time in seconds.
    pub max_time_seconds: u64,
    /// Early-termination stagnation threshold (generations with no improvement).
    pub stagnation_limit: u32,
}

impl Budget {
    /// Default conservative budget.
    #[must_use]
    pub fn default_wafrift() -> Self {
        Self {
            max_requests: 10_000,
            max_generations: 200,
            max_time_seconds: 3_600,
            stagnation_limit: 10,
        }
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::default_wafrift()
    }
}

/// Errors that can occur in the evolution engine.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionError {
    #[error("invalid chromosome index: {0}")]
    InvalidChromosomeIndex(usize),
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),
    #[error("target health critical: {0}")]
    TargetHealthCritical(String),
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("search algorithm error: {0}")]
    AlgorithmError(String),
}

/// Reason for terminating evolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminationReason {
    BudgetExhausted,
    MaxGenerationsReached,
    TimeLimitReached,
    StagnationLimitReached,
    TargetHealthCritical,
    BypassFound,
}

/// Action emitted by the intelligence loop state machine.
#[derive(Debug, Clone, PartialEq)]
pub enum LoopAction {
    /// Evaluate a differential probe.
    SendProbe(crate::differential::Probe),
    /// Evaluate an evolved payload.
    SendPayload(crate::evolution::Chromosome),
    /// Save checkpoint to disk.
    SaveCheckpoint,
    /// Terminate the loop.
    Terminate(TerminationReason),
}

/// Target health monitor with exponential backoff.
#[derive(Debug, Clone)]
pub struct TargetHealthMonitor {
    consecutive_errors: u32,
    last_error: Option<Instant>,
    backoff_seconds: u64,
    max_backoff_seconds: u64,
    error_threshold: u32,
}

impl TargetHealthMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            consecutive_errors: 0,
            last_error: None,
            backoff_seconds: 1,
            max_backoff_seconds: 300,
            error_threshold: 5,
        }
    }

    /// Record a target error.
    pub fn record_error(&mut self) {
        self.consecutive_errors += 1;
        self.last_error = Some(Instant::now());
        self.backoff_seconds = (self.backoff_seconds * 2).min(self.max_backoff_seconds);
    }

    /// Record a successful request.
    pub fn record_success(&mut self) {
        self.consecutive_errors = 0;
        self.backoff_seconds = 1;
    }

    /// Check if the target is considered healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.consecutive_errors < self.error_threshold
    }

    /// Current backoff duration.
    #[must_use]
    pub fn backoff(&self) -> Duration {
        Duration::from_secs(self.backoff_seconds)
    }

    /// Whether we are currently in an active backoff period.
    #[must_use]
    pub fn in_backoff(&self) -> bool {
        self.last_error
            .is_some_and(|t| t.elapsed() < self.backoff())
    }
}

impl Default for TargetHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Search statistics passed to algorithms for termination decisions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SearchStats {
    pub generation: u32,
    pub evaluations: usize,
    pub best_fitness: f64,
    pub stagnation_counter: u32,
    #[serde(skip, default = "Instant::now")]
    pub start_time: Instant,
    pub start_time_system: std::time::SystemTime,
}

impl SearchStats {
    pub fn new() -> Self {
        Self {
            generation: 0,
            evaluations: 0,
            best_fitness: 0.0,
            stagnation_counter: 0,
            start_time: Instant::now(),
            start_time_system: std::time::SystemTime::now(),
        }
    }

    pub fn fixup_start_time(&mut self) {
        if let Ok(elapsed) = self.start_time_system.elapsed() {
            self.start_time = Instant::now()
                .checked_sub(elapsed)
                .unwrap_or_else(Instant::now);
        }
    }
}

impl Default for SearchStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Deduplication helpers.
#[derive(Debug, Clone)]
pub struct Deduper {
    seen: HashSet<u64>,
}

impl Deduper {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    /// Compute a hash for a chromosome based on its genes.
    #[must_use]
    pub fn hash_chromosome(chromosome: &crate::evolution::Chromosome) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        for (name, value) in &chromosome.genes {
            name.hash(&mut hasher);
            value.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Check if this chromosome has been seen before.
    #[must_use]
    pub fn is_duplicate(&self, chromosome: &crate::evolution::Chromosome) -> bool {
        self.seen.contains(&Self::hash_chromosome(chromosome))
    }

    /// Mark a chromosome as seen.
    pub fn insert(&mut self, chromosome: &crate::evolution::Chromosome) {
        self.seen.insert(Self::hash_chromosome(chromosome));
    }

    /// Insert multiple chromosomes.
    pub fn insert_many(&mut self, chromosomes: &[crate::evolution::Chromosome]) {
        for c in chromosomes {
            self.insert(c);
        }
    }
}

impl Default for Deduper {
    fn default() -> Self {
        Self::new()
    }
}

/// Checkpoint persistence helpers.
pub fn save_checkpoint(
    path: &std::path::Path,
    data: &impl Serialize,
) -> Result<(), EvolutionError> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| EvolutionError::SerializationFailed(e.to_string()))?;
    std::fs::write(path, json).map_err(|e| EvolutionError::SerializationFailed(e.to_string()))?;
    Ok(())
}

/// Load a checkpoint from disk.
pub fn load_checkpoint<T: for<'de> Deserialize<'de>>(
    path: &std::path::Path,
) -> Result<T, EvolutionError> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| EvolutionError::DeserializationFailed(e.to_string()))?;
    serde_json::from_str(&json).map_err(|e| EvolutionError::DeserializationFailed(e.to_string()))
}
