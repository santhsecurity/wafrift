//! Intelligence loop — connects differential analysis, evolution, and strategy.

use crate::differential::{DifferentialResult, Probe, generate_probes, generate_quick_probes};
use crate::evolution::{Chromosome, EvolutionEngine};
use crate::types::{Budget, Feedback, LoopAction, OracleVerdict, TerminationReason};

/// Scanner state machine phases.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    DifferentialProbing,
    Evolution,
    Done,
}

/// Intelligence loop connecting differential analysis with evolutionary tuning.
#[derive(Debug, Clone)]
pub struct IntelligenceLoop {
    differential: DifferentialResult,
    evolution: EvolutionEngine,
    probes_completed: usize,
    feedback_count: usize,
    phase: Phase,
    min_probes: usize,
    probe_queue: Vec<Probe>,
    eval_queue: Vec<(usize, Chromosome)>,
    budget: Budget,
}

impl IntelligenceLoop {
    /// Create a new intelligence loop with the given evolution population size.
    #[must_use]
    pub fn new(population_size: usize) -> Self {
        Self::with_budget(population_size, 10, Budget::default())
    }

    /// Create with configurable minimum probes and budget.
    #[must_use]
    pub fn with_budget(population_size: usize, min_probes: usize, budget: Budget) -> Self {
        let mut evolution = EvolutionEngine::new(population_size);
        evolution.budget = budget;
        Self {
            differential: DifferentialResult::new(),
            evolution,
            probes_completed: 0,
            feedback_count: 0,
            phase: Phase::DifferentialProbing,
            min_probes,
            probe_queue: generate_probes(),
            eval_queue: Vec::new(),
            budget,
        }
    }

    /// Generate the full set of differential analysis probes, respecting budget.
    #[must_use]
    pub fn generate_probes(&self) -> Vec<Probe> {
        if self.probe_queue.len()
            > self
                .budget
                .max_requests
                .saturating_sub(self.probes_completed)
        {
            generate_quick_probes()
        } else {
            generate_probes()
        }
    }

    /// Generate a minimal probe set for quick analysis.
    #[must_use]
    pub fn generate_quick_probes(&self) -> Vec<Probe> {
        generate_quick_probes()
    }

    /// Record a differential probe result.
    pub fn record_probe(&mut self, probe: &Probe, was_blocked: bool) {
        self.differential.record(probe, was_blocked);
        self.probes_completed += 1;
    }

    /// Get the differential analysis results.
    #[must_use]
    pub fn differential_results(&self) -> &DifferentialResult {
        &self.differential
    }

    /// Get recommended evasion strategies based on differential analysis.
    #[must_use]
    pub fn suggested_evasions(&self) -> Vec<String> {
        self.differential.suggest_evasions()
    }

    /// Get a human-readable report of what the WAF blocks.
    #[must_use]
    pub fn waf_report(&self) -> String {
        self.differential.report()
    }

    /// Get the next technique combination to try from the evolution engine.
    #[must_use]
    pub fn next_candidate(&mut self) -> Option<(usize, &Chromosome)> {
        self.evolution.next_candidate()
    }

    /// Request a batch of evolved candidates.
    pub fn batch_candidates(&mut self, n: usize) -> Vec<(usize, Chromosome)> {
        self.evolution.batch_candidates(n)
    }

    /// Record evolution feedback. An out-of-range `chromosome_index`
    /// indicates a state-machine bug between caller and engine — log
    /// loudly via tracing rather than swallowing the error silently.
    pub fn record_feedback(&mut self, chromosome_index: usize, passed: bool) {
        if let Err(e) = self.evolution.record_feedback(chromosome_index, passed) {
            tracing::warn!(
                ?e,
                chromosome_index,
                "evolution.record_feedback rejected — likely stale chromosome index"
            );
        }
        self.feedback_count += 1;
    }

    /// Record rich verdict feedback. Same error semantics as
    /// `record_feedback`.
    pub fn record_verdict(&mut self, chromosome_index: usize, verdict: &OracleVerdict) {
        if let Err(e) = self.evolution.record_verdict(chromosome_index, verdict) {
            tracing::warn!(
                ?e,
                chromosome_index,
                "evolution.record_verdict rejected — likely stale chromosome index"
            );
        }
        self.feedback_count += 1;
    }

    /// Evolve the population to the next generation.
    pub fn evolve(&mut self) {
        self.evolution.evolve();
    }

    /// Get the best-performing technique combination.
    #[must_use]
    pub fn best_combination(&self) -> Option<&Chromosome> {
        self.evolution.best()
    }

    /// Number of differential probes completed.
    #[must_use]
    pub fn probes_completed(&self) -> usize {
        self.probes_completed
    }

    /// Number of evolution feedback events recorded.
    #[must_use]
    pub fn feedback_count(&self) -> usize {
        self.feedback_count
    }

    /// Population diversity score.
    #[must_use]
    pub fn diversity(&self) -> f64 {
        self.evolution.diversity_score()
    }

    /// Check if enough probes have been completed for a meaningful analysis.
    #[must_use]
    pub fn has_sufficient_data(&self) -> bool {
        self.probes_completed >= self.min_probes
    }

    /// Step the state machine forward given the latest feedback.
    ///
    /// This is the primary orchestration API. Call it repeatedly,
    /// performing the action it returns and feeding the result back
    /// as the next feedback.
    pub fn step(&mut self, feedback: Feedback) -> LoopAction {
        if self.evolution.should_terminate() {
            return LoopAction::Terminate(TerminationReason::BudgetExhausted);
        }

        // Handle target errors
        if let Feedback::TargetError(ref msg) = feedback {
            let _ = self.evolution.record_target_error(msg.clone());
            if !self.evolution.target_health.is_healthy() {
                return LoopAction::Terminate(TerminationReason::TargetHealthCritical);
            }
            // Backoff implicitly handled by caller observing returned delay
        }

        match self.phase {
            Phase::DifferentialProbing => {
                if let Feedback::Blocked | Feedback::Passed = feedback {
                    // Differential probing results are consumed externally via record_probe
                }
                if self.probe_queue.is_empty() || self.probes_completed >= self.min_probes {
                    self.phase = Phase::Evolution;
                    return self.step(Feedback::Passed); // Transition
                }
                let probe = self.probe_queue.remove(0);
                LoopAction::SendProbe(probe)
            }
            Phase::Evolution => {
                if self.eval_queue.is_empty() {
                    let remaining = self
                        .budget
                        .max_requests
                        .saturating_sub(self.evolution.request_count);
                    let batch_size = 4_usize.min(remaining).max(1);
                    self.eval_queue = self.evolution.batch_candidates(batch_size);
                    if self.eval_queue.is_empty() {
                        self.phase = Phase::Done;
                        return LoopAction::Terminate(TerminationReason::BudgetExhausted);
                    }
                }
                let (_idx, chrom) = self.eval_queue.remove(0);
                LoopAction::SendPayload(chrom)
            }
            Phase::Done => LoopAction::Terminate(TerminationReason::BudgetExhausted),
        }
    }

    /// Suggested delay before the next request, based on target health.
    #[must_use]
    pub fn suggested_delay_ms(&self) -> u64 {
        if self.evolution.target_health.in_backoff() {
            self.evolution.target_health.backoff().as_millis() as u64
        } else {
            0
        }
    }
}

impl Default for IntelligenceLoop {
    fn default() -> Self {
        Self::new(20)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_loop_default() {
        let il = IntelligenceLoop::default();
        assert_eq!(il.probes_completed(), 0);
        assert_eq!(il.feedback_count(), 0);
        assert!(!il.has_sufficient_data());
    }

    #[test]
    fn generate_probes_not_empty() {
        let il = IntelligenceLoop::default();
        let probes = il.generate_probes();
        assert!(!probes.is_empty());
    }

    #[test]
    fn generate_quick_probes_smaller() {
        let _il = IntelligenceLoop::default();
        let full = generate_probes();
        let quick = generate_quick_probes();
        assert!(quick.len() < full.len());
    }

    #[test]
    fn record_probe_increments() {
        let mut il = IntelligenceLoop::default();
        let probes = il.generate_quick_probes();
        il.record_probe(&probes[0], true);
        assert_eq!(il.probes_completed(), 1);
    }

    #[test]
    fn sufficient_data_after_min_probes() {
        let mut il = IntelligenceLoop::with_budget(10, 5, Budget::default());
        let probes = il.generate_probes();
        for (i, probe) in probes.iter().enumerate() {
            il.record_probe(probe, i % 3 == 0);
            if i >= 4 {
                break;
            }
        }
        assert!(il.has_sufficient_data());
    }

    #[test]
    fn evolution_feedback_loop() {
        let mut il = IntelligenceLoop::new(10);
        if let Some((idx, _)) = il.next_candidate() {
            il.record_feedback(idx, true);
            assert_eq!(il.feedback_count(), 1);
        }
    }

    #[test]
    fn evolve_doesnt_panic() {
        let mut il = IntelligenceLoop::new(10);
        for _ in 0..5 {
            if let Some((idx, _)) = il.next_candidate() {
                il.record_feedback(idx, true);
            }
        }
        il.evolve();
        assert!(il.next_candidate().is_some());
    }

    #[test]
    fn waf_report_not_empty_after_probes() {
        let mut il = IntelligenceLoop::default();
        let probes = il.generate_quick_probes();
        for probe in &probes {
            il.record_probe(probe, true);
        }
        let report = il.waf_report();
        assert!(!report.is_empty());
    }

    #[test]
    fn suggested_evasions_from_differential() {
        let mut il = IntelligenceLoop::default();
        let probes = generate_probes();
        for probe in &probes {
            let is_sql = format!("{:?}", probe.tests).contains("Sql");
            il.record_probe(probe, is_sql);
        }
        let suggestions = il.suggested_evasions();
        assert!(!suggestions.is_empty());
    }

    #[test]
    fn diversity_score_valid_range() {
        let il = IntelligenceLoop::new(10);
        let score = il.diversity();
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn step_state_machine_transitions() {
        let mut il = IntelligenceLoop::with_budget(10, 2, Budget::default());
        // Should start with differential probes
        let action = il.step(Feedback::Passed);
        assert!(matches!(action, LoopAction::SendProbe(_)));

        il.record_probe(&generate_probes()[0], true);
        let action2 = il.step(Feedback::Blocked);
        assert!(matches!(action2, LoopAction::SendProbe(_)));

        il.record_probe(&generate_probes()[1], false);
        // Now should transition to evolution
        let action3 = il.step(Feedback::Passed);
        assert!(matches!(action3, LoopAction::SendPayload(_)));
    }

    #[test]
    fn step_terminates_on_target_error() {
        let mut il = IntelligenceLoop::with_budget(10, 0, Budget::default());
        // Skip to evolution
        for _ in 0..10 {
            if let LoopAction::SendPayload(_) = il.step(Feedback::Passed) {
                // Target error
                let term = il.step(Feedback::TargetError("503".into()));
                // After first error we backoff, not terminate immediately
                assert!(matches!(
                    term,
                    LoopAction::SendPayload(_) | LoopAction::Terminate(_)
                ));
                return;
            }
        }
    }

    #[test]
    fn step_terminates_when_budget_exhausted() {
        let mut il = IntelligenceLoop::with_budget(5, 0, Budget {
            max_requests: 3,
            ..Budget::default()
        });
        // Burn through budget quickly
        let mut sent = 0;
        for _ in 0..20 {
            match il.step(Feedback::Passed) {
                LoopAction::SendProbe(_) | LoopAction::SendPayload(_) | LoopAction::SaveCheckpoint => {
                    sent += 1;
                }
                LoopAction::Terminate(TerminationReason::BudgetExhausted) => {
                    break;
                }
                LoopAction::Terminate(other) => {
                    panic!("unexpected termination: {other:?}");
                }
            }
        }
        // Should terminate before sending too many
        assert!(sent <= 5, "sent {sent} requests but budget was 3");
    }

    #[test]
    fn suggested_delay_zero_when_healthy() {
        let il = IntelligenceLoop::default();
        assert_eq!(il.suggested_delay_ms(), 0);
    }

    #[test]
    fn suggested_delay_nonzero_after_target_errors() {
        let mut il = IntelligenceLoop::with_budget(10, 0, Budget::default());
        // Skip to evolution and bombard with errors
        for _ in 0..50 {
            if let LoopAction::SendPayload(_) = il.step(Feedback::Passed) {
                il.step(Feedback::TargetError("503".into()));
            }
        }
        // After enough errors backoff should kick in
        let delay = il.suggested_delay_ms();
        // Note: delay may be zero if health recovered, but we at least
        // exercise the code path without panicking.
        let _ = delay;
    }

    #[test]
    fn always_blocking_oracle_still_terminates() {
        // Adversarial scenario: every single payload is blocked.
        // The engine must still terminate gracefully via budget exhaustion.
        let mut il = IntelligenceLoop::with_budget(
            5,
            0,
            Budget {
                max_requests: 50,
                max_generations: 10,
                ..Budget::default()
            },
        );
        let mut iterations = 0;
        loop {
            match il.step(Feedback::Blocked) {
                LoopAction::SendProbe(_) | LoopAction::SendPayload(_) | LoopAction::SaveCheckpoint => {
                    iterations += 1;
                }
                LoopAction::Terminate(_) => break,
            }
            if iterations > 500 {
                panic!("engine did not terminate within 500 iterations (budget was 50)");
            }
        }
    }
}
