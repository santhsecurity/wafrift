//! Query-economical equivalence oracles — the strategies that make
//! decompiling a *live* WAF affordable.
//!
//! `BoundedExhaustiveEq` (in [`crate::learn`]) is exact but
//! exponential: only viable against a free in-process oracle. Against
//! a real WAF every membership query is an HTTP round-trip, so the
//! equivalence query — which dominates the budget — must be smart:
//!
//! - [`WMethodEq`] — Chow's W-method conformance testing. A *guarantee*,
//!   not sampling: if the true machine has at most
//!   `hyp_states + extra_states` states, a counterexample is found iff
//!   one exists. This is what replaces the exponential exhaustive
//!   oracle while keeping exactness within a stated bound.
//! - [`UcbBanditEq`] — the Phase-C bandit, repurposed. The arms are
//!   hypothesis transitions; UCB1 spends each query where the model is
//!   least exercised (maximum expected information per query), exactly
//!   the "ask the most informative membership query" reframe.
//! - [`SampledEq`] — PAC-bounded random sampling; carries an honest
//!   [`PacBound`] (Angluin's equivalence-query simulation bound) so a
//!   "no counterexample" answer ships with a provable error/confidence,
//!   never a bare claim.
//! - [`ChainedEq`] — run cheap-and-guaranteed first, then the bandit,
//!   then sampling: the practical live strategy.

use crate::error::Result;
use crate::learn::{Alphabet, EquivalenceOracle};
use crate::sfa::{Sfa, StateId};
use std::collections::{HashMap, VecDeque};

/// Angluin's equivalence-query simulation bound: after the `round`-th
/// equivalence query drew `samples` i.i.d. words with no
/// counterexample, the hypothesis has error ≤ `epsilon` with
/// confidence `1 − delta`.
///
/// `ε = (ln(1/δ) + (round+1)·ln 2) / samples` — the textbook bound
/// (Angluin 1988; Kearns & Vazirani §8). Reported, never assumed.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PacBound {
    /// Error bound ε ∈ (0,1].
    pub epsilon: f64,
    /// Confidence parameter δ.
    pub delta: f64,
    /// Samples drawn on the certifying (final) round.
    pub samples: u64,
    /// 0-based index of the certifying equivalence round.
    pub round: u64,
}

impl PacBound {
    /// Compute the bound for `samples` clean draws on round `round`.
    #[must_use]
    pub fn compute(samples: u64, delta: f64, round: u64) -> Self {
        let s = samples.max(1) as f64;
        let eps = ((1.0 / delta).ln() + (round as f64 + 1.0) * std::f64::consts::LN_2) / s;
        PacBound {
            epsilon: eps.min(1.0),
            delta,
            samples,
            round,
        }
    }
}

/// Deterministic SplitMix64 — reproducible draws so a learning run is
/// a pure function of (oracle, seed). No external RNG, no flakiness.
#[derive(Debug, Clone)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    /// Geometric-ish length in `0..=max`, biased short (most WAF
    /// distinguishing inputs are short; long draws waste queries).
    fn geo_len(&mut self, max: usize) -> usize {
        let mut l = 0;
        while l < max && self.next_u64() & 3 != 0 {
            l += 1;
        }
        l
    }
}

/// Treat a learned [`Sfa`] as a DFA over the abstract alphabet (each
/// class → its representative byte). Returns the run's final state.
fn run_abstract(sfa: &Sfa, alpha: &Alphabet, word: &[usize]) -> StateId {
    let mut s = sfa.start_state();
    for &sym in word {
        s = sfa.step_byte(s, alpha.byte_of(sym));
    }
    s
}

/// BFS state-cover: a shortest abstract access word for every
/// reachable hypothesis state.
fn state_cover(sfa: &Sfa, alpha: &Alphabet) -> HashMap<StateId, Vec<usize>> {
    let mut access: HashMap<StateId, Vec<usize>> = HashMap::new();
    access.insert(sfa.start_state(), Vec::new());
    let mut q = VecDeque::from([sfa.start_state()]);
    while let Some(s) = q.pop_front() {
        let base = access[&s].clone();
        for sym in 0..alpha.len() {
            let t = sfa.step_byte(s, alpha.byte_of(sym));
            if let std::collections::hash_map::Entry::Vacant(e) = access.entry(t) {
                let mut w = base.clone();
                w.push(sym);
                e.insert(w);
                q.push_back(t);
            }
        }
    }
    access
}

/// A characterizing set: abstract suffixes that tell every pair of
/// *inequivalent* reachable states apart (BFS over state pairs).
fn characterizing_set(sfa: &Sfa, alpha: &Alphabet) -> Vec<Vec<usize>> {
    let states: Vec<StateId> = state_cover(sfa, alpha).into_keys().collect();
    let mut w: Vec<Vec<usize>> = vec![Vec::new()]; // ε distinguishes by acceptance
    let mut seen: std::collections::HashSet<Vec<usize>> =
        std::collections::HashSet::from([Vec::new()]);
    for i in 0..states.len() {
        for j in (i + 1)..states.len() {
            let (p, qq) = (states[i], states[j]);
            // Shortest abstract suffix on which p and q differ.
            let mut bfs = VecDeque::from([(p, qq, Vec::<usize>::new())]);
            let mut visited = std::collections::HashSet::from([(p, qq)]);
            while let Some((a, b, suf)) = bfs.pop_front() {
                if sfa.is_accepting(a) != sfa.is_accepting(b) {
                    if seen.insert(suf.clone()) {
                        w.push(suf);
                    }
                    break;
                }
                if suf.len() > states.len() + 1 {
                    break; // equivalent within bound ⇒ no separator needed
                }
                for sym in 0..alpha.len() {
                    let na = sfa.step_byte(a, alpha.byte_of(sym));
                    let nb = sfa.step_byte(b, alpha.byte_of(sym));
                    if visited.insert((na, nb)) {
                        let mut ns = suf.clone();
                        ns.push(sym);
                        bfs.push_back((na, nb, ns));
                    }
                }
            }
        }
    }
    w
}

/// Chow's W-method. Tests `state_cover · Σ^{≤extra+1} · W`; the first
/// word the hypothesis classifies differently from the oracle is a
/// counterexample. Guarantees discovery of any fault if the true
/// machine has ≤ `hyp_states + extra_states` states.
#[derive(Debug, Clone, Copy)]
pub struct WMethodEq {
    /// Assumed upper bound on (true states − hypothesis states).
    pub extra_states: usize,
}

impl EquivalenceOracle for WMethodEq {
    fn find_counterexample(
        &mut self,
        hyp: &Sfa,
        alpha: &Alphabet,
        mq: &mut dyn FnMut(&[usize]) -> Result<bool>,
    ) -> Result<Option<Vec<usize>>> {
        let cover = state_cover(hyp, alpha);
        let wset = characterizing_set(hyp, alpha);
        let k = alpha.len();

        // Σ^{≤ extra_states+1} middle sequences.
        let mut middles: Vec<Vec<usize>> = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..=self.extra_states {
            let mut next = Vec::new();
            for m in &frontier {
                for s in 0..k {
                    let mut e = m.clone();
                    e.push(s);
                    next.push(e.clone());
                    middles.push(e);
                }
            }
            frontier = next;
        }

        for access in cover.values() {
            for mid in &middles {
                for suf in &wset {
                    let mut t = access.clone();
                    t.extend_from_slice(mid);
                    t.extend_from_slice(suf);
                    let truth = mq(&t)?;
                    if run_abstract_accepts(hyp, alpha, &t) != truth {
                        return Ok(Some(t));
                    }
                }
            }
        }
        Ok(None)
    }
}

fn run_abstract_accepts(sfa: &Sfa, alpha: &Alphabet, word: &[usize]) -> bool {
    sfa.is_accepting(run_abstract(sfa, alpha, word))
}

/// The Phase-C bandit, repurposed as the equivalence strategy: arms
/// are hypothesis transitions `(state, symbol)`; UCB1 spends the next
/// query where the model is least exercised — maximum expected
/// information per live request.
#[derive(Debug, Clone)]
pub struct UcbBanditEq {
    /// Membership probes per equivalence round.
    pub budget: usize,
    /// Max random suffix length appended after the targeted transition.
    pub max_suffix: usize,
    /// Deterministic seed.
    pub seed: u64,
    counts: HashMap<(StateId, usize), u32>,
    total: u32,
}

impl UcbBanditEq {
    /// New bandit oracle.
    #[must_use]
    pub fn new(budget: usize, max_suffix: usize, seed: u64) -> Self {
        UcbBanditEq {
            budget,
            max_suffix,
            seed,
            counts: HashMap::new(),
            total: 0,
        }
    }

    /// Distinct `(state, symbol)` transition arms the bandit has
    /// probed at least once. UCB1 gives an unvisited arm infinite
    /// priority, so this strictly grows until every transition is
    /// covered — the operational meaning of "spend each query where
    /// the model is least exercised".
    #[must_use]
    pub fn arms_explored(&self) -> usize {
        self.counts.len()
    }
}

impl EquivalenceOracle for UcbBanditEq {
    fn find_counterexample(
        &mut self,
        hyp: &Sfa,
        alpha: &Alphabet,
        mq: &mut dyn FnMut(&[usize]) -> Result<bool>,
    ) -> Result<Option<Vec<usize>>> {
        let cover = state_cover(hyp, alpha);
        let mut rng = SplitMix64(self.seed ^ u64::from(self.total).wrapping_mul(0x100));
        for _ in 0..self.budget {
            self.total += 1;
            // Pick the transition arm with the highest UCB (unvisited
            // arms have +∞ priority ⇒ full coverage first).
            let lnt = (f64::from(self.total) + 1.0).ln();
            let mut best: Option<(StateId, usize)> = None;
            let mut best_score = f64::NEG_INFINITY;
            for &s in cover.keys() {
                for sym in 0..alpha.len() {
                    let n = *self.counts.get(&(s, sym)).unwrap_or(&0);
                    let score = if n == 0 {
                        f64::INFINITY
                    } else {
                        (2.0 * lnt / f64::from(n)).sqrt()
                    };
                    if score > best_score {
                        best_score = score;
                        best = Some((s, sym));
                    }
                }
            }
            let (s, sym) = best.expect("non-empty alphabet and cover");
            *self.counts.entry((s, sym)).or_insert(0) += 1;

            // Word = access(s) · sym · random suffix.
            let mut word = cover[&s].clone();
            word.push(sym);
            let suf_len = rng.geo_len(self.max_suffix);
            for _ in 0..suf_len {
                word.push(rng.below(alpha.len()));
            }
            let truth = mq(&word)?;
            if run_abstract_accepts(hyp, alpha, &word) != truth {
                return Ok(Some(word));
            }
        }
        Ok(None)
    }
}

/// PAC-bounded random sampling. A `None` answer is accompanied by a
/// real [`PacBound`] (read via [`SampledEq::last_bound`]).
#[derive(Debug, Clone)]
pub struct SampledEq {
    /// I.i.d. words drawn per round.
    pub samples: u64,
    /// Max sampled word length.
    pub max_len: usize,
    /// Confidence parameter δ.
    pub delta: f64,
    /// Deterministic seed.
    pub seed: u64,
    round: u64,
    last: Option<PacBound>,
}

impl SampledEq {
    /// New sampling oracle.
    #[must_use]
    pub fn new(samples: u64, max_len: usize, delta: f64, seed: u64) -> Self {
        SampledEq {
            samples,
            max_len,
            delta,
            seed,
            round: 0,
            last: None,
        }
    }

    /// The PAC bound certified by the last clean (no-CE) round, if any.
    #[must_use]
    pub fn last_bound(&self) -> Option<PacBound> {
        self.last
    }
}

impl EquivalenceOracle for SampledEq {
    fn find_counterexample(
        &mut self,
        hyp: &Sfa,
        alpha: &Alphabet,
        mq: &mut dyn FnMut(&[usize]) -> Result<bool>,
    ) -> Result<Option<Vec<usize>>> {
        let mut rng = SplitMix64(self.seed ^ self.round.wrapping_mul(0x9E37_79B9));
        for _ in 0..self.samples {
            let len = rng.geo_len(self.max_len);
            let word: Vec<usize> = (0..len).map(|_| rng.below(alpha.len())).collect();
            let truth = mq(&word)?;
            if run_abstract_accepts(hyp, alpha, &word) != truth {
                self.last = None;
                return Ok(Some(word));
            }
        }
        self.last = Some(PacBound::compute(self.samples, self.delta, self.round));
        self.round += 1;
        Ok(None)
    }
}

/// Run sub-oracles in order; return the first counterexample. `None`
/// only if *every* sub-oracle agrees. Practical strategy:
/// guaranteed-cheap (W-method) → bandit → PAC sampling.
pub struct ChainedEq {
    oracles: Vec<Box<dyn EquivalenceOracle>>,
}

impl ChainedEq {
    /// Build from an ordered list.
    #[must_use]
    pub fn new(oracles: Vec<Box<dyn EquivalenceOracle>>) -> Self {
        ChainedEq { oracles }
    }
}

impl EquivalenceOracle for ChainedEq {
    fn find_counterexample(
        &mut self,
        hyp: &Sfa,
        alpha: &Alphabet,
        mq: &mut dyn FnMut(&[usize]) -> Result<bool>,
    ) -> Result<Option<Vec<usize>>> {
        for o in &mut self.oracles {
            if let Some(ce) = o.find_counterexample(hyp, alpha, mq)? {
                return Ok(Some(ce));
            }
        }
        Ok(None)
    }
}
