//! The learned-model artifact: a decompiled WAF, serialized.
//!
//! This is the *product* of P1 — not a log line, an artifact. It is
//! Tier-B TOML (human-inspectable, diffable, checked into a repo) and
//! it is **provenance-stamped**: which WAF it decompiled (ruleset
//! fingerprint), what it cost (membership queries / equivalence
//! rounds), and — when sampling certified equivalence — the honest
//! [`PacBound`] (ε, δ). A `None` PAC field means equivalence was
//! certified by a *guarantee* (W-method), not a probability.
//!
//! Round-trips are lossless and **re-validated**: importing an
//! automaton re-checks the determinism+totality invariant, so a
//! corrupted or hand-tampered artifact is rejected, never trusted.

use crate::equiv_query::PacBound;
use crate::error::{Result, WafModelError};
use crate::learn::Alphabet;
use crate::sfa::{BytePred, Sfa};

/// Bumped on any incompatible artifact-format change.
pub const SCHEMA_VERSION: u32 = 1;

/// One guarded transition, predicate hex-encoded.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Edge {
    to: usize,
    pred: String,
}

/// One automaton state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StateRow {
    accept: bool,
    edge: Vec<Edge>,
}

/// Where a learned model came from and what it cost.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    /// Human label for the oracle (e.g. `"crs-core"`, `"live:example.com"`).
    pub oracle_id: String,
    /// Stable fingerprint of the decompiled ruleset, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruleset_fingerprint: Option<String>,
    /// Distinct membership queries spent.
    pub membership_queries: u64,
    /// Equivalence rounds (counterexamples consumed).
    pub equivalence_rounds: u64,
    /// PAC bound *iff* equivalence was certified by sampling. `None`
    /// ⇒ certified by guarantee (W-method / exhaustive), strictly
    /// stronger than any ε. (Serialized last: it is a sub-table.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pac: Option<PacBound>,
}

/// A decompiled WAF, ready to serialize, mine, diff, or ship.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LearnedModel {
    // Field order is significant for TOML: every scalar / array-of-
    // scalar must precede the first table or array-of-tables, else the
    // serializer emits keys under the wrong table.
    schema_version: u32,
    start: usize,
    /// Raw alphabet (distinguished bytes then catch-all).
    alphabet: Vec<u8>,
    /// Provenance and cost (sub-table).
    pub provenance: Provenance,
    /// States (array of tables) — must serialize last.
    state: Vec<StateRow>,
}

impl LearnedModel {
    /// Capture a learned automaton + its alphabet + provenance.
    #[must_use]
    pub fn capture(alpha: &Alphabet, sfa: &Sfa, provenance: Provenance) -> Self {
        let (start, accept, delta) = sfa.export();
        let state = accept
            .iter()
            .zip(delta.iter())
            .map(|(&acc, edges)| StateRow {
                accept: acc,
                edge: edges
                    .iter()
                    .map(|(p, t)| Edge {
                        to: *t,
                        pred: p.to_hex(),
                    })
                    .collect(),
            })
            .collect();
        LearnedModel {
            schema_version: SCHEMA_VERSION,
            provenance,
            alphabet: alpha.raw_symbols().to_vec(),
            start,
            state,
        }
    }

    /// Serialize to Tier-B TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| WafModelError::Artifact(e.to_string()))
    }

    /// Parse from Tier-B TOML, rejecting an unknown schema version.
    pub fn from_toml(src: &str) -> Result<Self> {
        let m: LearnedModel =
            toml::from_str(src).map_err(|e| WafModelError::Artifact(e.to_string()))?;
        if m.schema_version != SCHEMA_VERSION {
            return Err(WafModelError::Artifact(format!(
                "unsupported schema version {} (this build understands {})",
                m.schema_version, SCHEMA_VERSION
            )));
        }
        Ok(m)
    }

    /// The alphabet, reconstructed and re-validated.
    pub fn alphabet(&self) -> Result<Alphabet> {
        if self.alphabet.is_empty() {
            return Err(WafModelError::Artifact("empty alphabet".into()));
        }
        let mut d = self.alphabet.clone();
        d.sort_unstable();
        let before = d.len();
        d.dedup();
        if d.len() != before {
            return Err(WafModelError::Artifact("duplicate alphabet symbols".into()));
        }
        Ok(Alphabet::from_raw_symbols(self.alphabet.clone()))
    }

    /// The automaton, re-validating the determinism+totality
    /// invariant. A corrupted/tampered artifact is an `Err`, never a
    /// panic and never a silently-accepted broken model.
    pub fn sfa(&self) -> Result<Sfa> {
        let n = self.state.len();
        if self.start >= n {
            return Err(WafModelError::Artifact(format!(
                "start state {} out of range (n={n})",
                self.start
            )));
        }
        let mut accept = Vec::with_capacity(n);
        let mut delta: Vec<Vec<(BytePred, usize)>> = Vec::with_capacity(n);
        for (si, row) in self.state.iter().enumerate() {
            accept.push(row.accept);
            let mut trans = Vec::with_capacity(row.edge.len());
            let mut cover = BytePred::none();
            for e in &row.edge {
                if e.to >= n {
                    return Err(WafModelError::Artifact(format!(
                        "state {si}: edge target {} out of range",
                        e.to
                    )));
                }
                let p = BytePred::from_hex(&e.pred).ok_or_else(|| {
                    WafModelError::Artifact(format!("state {si}: malformed predicate hex"))
                })?;
                if !cover.and(p).is_empty() {
                    return Err(WafModelError::Artifact(format!(
                        "state {si}: overlapping guards (non-deterministic artifact)"
                    )));
                }
                cover = cover.or(p);
                trans.push((p, e.to));
            }
            if cover != BytePred::any() {
                return Err(WafModelError::Artifact(format!(
                    "state {si}: guards are not total (incomplete artifact)"
                )));
            }
            delta.push(trans);
        }
        Ok(Sfa::import(self.start, accept, delta))
    }
}
