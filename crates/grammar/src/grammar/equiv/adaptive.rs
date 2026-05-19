//! Phase C — adaptive feedback search over the provably-sound
//! equivalence space.
//!
//! Phase B gives an infinite space where *every* member is a real
//! attack. Phase C closes the loop: it treats each delivery-shape /
//! rewrite-profile as a bandit arm, plays it against the *live* WAF,
//! and uses the verified-bypass signal as reward. Within a handful of
//! rounds the search concentrates the request budget on exactly the
//! primitives that beat *this* WAF — instead of blindly sampling
//! shapes the WAF blocks. Because the space is sound by construction,
//! no round is ever wasted on a destroyed payload (the failure mode
//! of blind mutation / classic fuzzing).
//!
//! This is the per-target learning that makes the engine *adapt* to
//! an unseen WAF, and the learned arm-statistics are a compounding,
//! unclonable asset.

/// UCB1 multi-armed bandit. Deterministic: no RNG, ties broken by
/// lowest arm index, so a run is fully reproducible from its reward
/// sequence (required for the test battery + auditable runs).
#[derive(Debug, Clone)]
pub struct Bandit {
    counts: Vec<u32>,
    sum_reward: Vec<f64>,
    t: u32,
}

impl Bandit {
    /// `n_arms` independent arms (must be ≥ 1).
    #[must_use]
    pub fn new(n_arms: usize) -> Self {
        let n = n_arms.max(1);
        Self {
            counts: vec![0; n],
            sum_reward: vec![0.0; n],
            t: 0,
        }
    }

    #[must_use]
    pub fn arms(&self) -> usize {
        self.counts.len()
    }

    /// Mean observed reward of `arm` (0.0 if never played).
    #[must_use]
    pub fn mean(&self, arm: usize) -> f64 {
        if self.counts[arm] == 0 {
            0.0
        } else {
            self.sum_reward[arm] / f64::from(self.counts[arm])
        }
    }

    /// Pick the next arm. Every arm is played once first (exploration),
    /// then UCB1: argmax mean + sqrt(2·ln t / nₐ). Ties → lowest index.
    #[must_use]
    pub fn select(&self) -> usize {
        if let Some(unplayed) = self.counts.iter().position(|&c| c == 0) {
            return unplayed;
        }
        let t = f64::from(self.t.max(1));
        let mut best = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        for a in 0..self.counts.len() {
            let n = f64::from(self.counts[a]);
            let ucb = self.mean(a) + (2.0 * t.ln() / n).sqrt();
            if ucb > best_score {
                best_score = ucb;
                best = a;
            }
        }
        best
    }

    /// Record `reward` (clamped to `[0,1]`) for `arm`.
    pub fn update(&mut self, arm: usize, reward: f64) {
        let r = reward.clamp(0.0, 1.0);
        self.counts[arm] += 1;
        self.sum_reward[arm] += r;
        self.t += 1;
    }

    /// The current best arm by observed mean (ties → lowest index).
    #[must_use]
    pub fn best(&self) -> usize {
        let mut best = 0usize;
        let mut bm = f64::NEG_INFINITY;
        for a in 0..self.counts.len() {
            let m = self.mean(a);
            if m > bm {
                bm = m;
                best = a;
            }
        }
        best
    }

    /// Times `arm` has been played.
    #[must_use]
    pub fn plays(&self, arm: usize) -> u32 {
        self.counts[arm]
    }

    /// Total rounds played.
    #[must_use]
    pub fn rounds(&self) -> u32 {
        self.t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plays_every_arm_before_exploiting() {
        let mut b = Bandit::new(4);
        let mut seen = [false; 4];
        for _ in 0..4 {
            let a = b.select();
            assert!(!seen[a], "arm {a} played twice during initial exploration");
            seen[a] = true;
            b.update(a, 0.0);
        }
        assert!(seen.iter().all(|&s| s), "not every arm explored first");
    }

    #[test]
    fn converges_to_the_best_arm() {
        // Arm 2 is the only rewarding arm; the bandit must learn it.
        let mut b = Bandit::new(5);
        for _ in 0..400 {
            let a = b.select();
            let reward = if a == 2 { 1.0 } else { 0.0 };
            b.update(a, reward);
        }
        assert_eq!(b.best(), 2, "bandit failed to identify the best arm");
        // Exploitation: arm 2 should dominate the play count.
        let total: u32 = (0..5).map(|a| b.plays(a)).sum();
        assert!(
            b.plays(2) as f64 / f64::from(total) > 0.7,
            "best arm under-exploited: {}/{}",
            b.plays(2),
            total
        );
    }

    #[test]
    fn converges_with_noisy_stochastic_rewards() {
        // Arm 1 pays 0.8, arm 3 pays 0.3, rest 0.05 — deterministic
        // pseudo-noise so the test is reproducible.
        let mut b = Bandit::new(5);
        let payoff = |a: usize, k: u32| -> f64 {
            let base: f64 = match a {
                1 => 0.8,
                3 => 0.3,
                _ => 0.05,
            };
            // deterministic ±0.15 jitter
            let jit: f64 = if (k.wrapping_mul(2_654_435_761) >> 28) & 1 == 0 {
                0.15
            } else {
                -0.15
            };
            (base + jit).clamp(0.0_f64, 1.0_f64)
        };
        for k in 0..800u32 {
            let a = b.select();
            b.update(a, payoff(a, k));
        }
        assert_eq!(b.best(), 1, "noisy bandit picked the wrong best arm");
        assert!(
            b.mean(1) > b.mean(3) && b.mean(3) > b.mean(0),
            "reward ordering not recovered: {:?}",
            (b.mean(0), b.mean(1), b.mean(3))
        );
    }

    #[test]
    fn reward_is_clamped_and_deterministic() {
        let mut b = Bandit::new(2);
        b.update(0, 5.0); // clamps to 1.0
        b.update(1, -3.0); // clamps to 0.0
        assert!((b.mean(0) - 1.0).abs() < 1e-9);
        assert!(b.mean(1).abs() < 1e-9);
        // Reproducible: same update sequence ⇒ same selections.
        let mut x = Bandit::new(3);
        let mut y = Bandit::new(3);
        for r in 0..50 {
            let ax = x.select();
            let ay = y.select();
            assert_eq!(ax, ay, "bandit non-deterministic at round {r}");
            let rew = f64::from(ax as u32 % 2);
            x.update(ax, rew);
            y.update(ay, rew);
        }
    }

    #[test]
    fn single_arm_is_safe() {
        let mut b = Bandit::new(0); // coerced to 1
        assert_eq!(b.arms(), 1);
        assert_eq!(b.select(), 0);
        b.update(0, 1.0);
        assert_eq!(b.best(), 0);
    }
}
