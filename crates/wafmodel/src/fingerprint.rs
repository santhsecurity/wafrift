//! Ruleset fingerprinting: identify *which* known WAF configuration
//! (ruleset @ paranoia level) a live target runs, using the shortest
//! discriminating probe sequence — so that against a known config you
//! never search, you *look up* the precomputed minimal bypass.
//!
//! This complements `wafrift-fingerprint` (which fingerprints the WAF
//! *vendor/product*): here we fingerprint the *rule configuration*
//! behind it, the thing that actually determines which payloads pass.
//!
//! The probe sequence is chosen by greedy information gain over a
//! Tier-B probe battery: each selected probe maximally splits the set
//! of still-indistinguishable candidate configs, so identification
//! costs ~log₂(N) live requests instead of one-payload-per-config.

use crate::oracle::{SimRegexWaf, WafOracle};
use crate::outcome::Outcome;
use wafrift_types::Request;

/// JSON-body probe so the whole payload lands in one inspected channel.
fn probe(body: &str) -> Request {
    Request::post("https://h/p", body.as_bytes().to_vec())
        .header("Content-Type", "application/json")
}

/// The default Tier-B probe battery: canonical attacks plus the
/// encoding/case variants that separate paranoia levels and rule
/// families. Extend by appending — it is data, not code.
#[must_use]
pub fn default_battery() -> Vec<Request> {
    [
        "<script>alert(1)</script>",             // raw XSS
        "<ScRiPt>alert(1)</ScRiPt>",             // case-varied XSS
        "%3Cscript%3Ealert(1)%3C/script%3E",     // URL-encoded XSS
        "&lt;script&gt;alert(1)&lt;/script&gt;", // HTML-entity XSS
        "<svg onload=alert(1)>",                 // event-handler XSS
        "1' OR '1'='1",                          // SQLi tautology
        "1 UNION SELECT pw FROM users",          // SQLi union
        "1; SELECT sleep(5)",                    // SQLi blind
        "harmless lookup value",                 // benign control
    ]
    .into_iter()
    .map(probe)
    .collect()
}

/// One labelled candidate configuration.
pub struct Candidate {
    /// Stable id (e.g. `"crs-pl1"`, `"crs-pl2"`, `"sqli-only"`).
    pub id: String,
    /// The modelled ruleset.
    pub waf: SimRegexWaf,
}

/// Result of fingerprinting a live target.
#[derive(Debug, Clone, PartialEq)]
pub struct Identification {
    /// Matched config id, or `None` if no catalog signature matches
    /// (an unknown/abstained config — never a false identification).
    pub matched: Option<String>,
    /// Outcomes observed on the selected probes, in order.
    pub signature: Vec<Outcome>,
    /// Live probes actually sent.
    pub probe_count: usize,
}

/// Precomputed fingerprinter: a minimal discriminating probe subset
/// plus each candidate's signature over it.
pub struct Fingerprinter {
    battery: Vec<Request>,
    selected: Vec<usize>,
    ids: Vec<String>,
    /// `sigs[c]` = candidate c's outcomes over `selected` probes.
    sigs: Vec<Vec<Outcome>>,
}

impl Fingerprinter {
    /// Build from a catalog and a probe battery. Selects probes by
    /// greedy information gain (each new probe resolves the most
    /// still-confusable config pairs).
    #[must_use]
    pub fn build(catalog: Vec<Candidate>, battery: Vec<Request>) -> Self {
        let n = catalog.len();
        // Full battery signatures (offline; no query cost).
        let full: Vec<Vec<Outcome>> = catalog
            .iter()
            .map(|c| {
                battery
                    .iter()
                    .map(|r| {
                        if c.waf.classify_uncounted(r) == Outcome::Block {
                            Outcome::Block
                        } else {
                            Outcome::Pass
                        }
                    })
                    .collect()
            })
            .collect();

        // Unresolved candidate pairs.
        let mut pairs: Vec<(usize, usize)> = Vec::new();
        for i in 0..n {
            for j in (i + 1)..n {
                pairs.push((i, j));
            }
        }
        let mut selected = Vec::new();
        let mut remaining: Vec<usize> = (0..battery.len()).collect();
        while !pairs.is_empty() {
            // Probe that splits the most still-unresolved pairs.
            let best = remaining.iter().copied().max_by_key(|&p| {
                pairs
                    .iter()
                    .filter(|&&(i, j)| full[i][p] != full[j][p])
                    .count()
            });
            let Some(bp) = best else { break };
            let gain = pairs
                .iter()
                .filter(|&&(i, j)| full[i][bp] != full[j][bp])
                .count();
            if gain == 0 {
                break; // no probe can separate the rest (genuine tie)
            }
            selected.push(bp);
            remaining.retain(|&x| x != bp);
            pairs.retain(|&(i, j)| full[i][bp] == full[j][bp]);
        }
        // Positive-confirmation phase: identification must be
        // *confirmable*, not inferred from silence. If a candidate
        // blocks none of the selected probes its signature is all-Pass
        // — indistinguishable from an unprotected or unknown server,
        // so it could never be told apart from an out-of-catalog WAF.
        // Add, per such candidate, the probe it blocks that the most
        // candidates also block (keeps the set small).
        for c in 0..n {
            if selected.iter().all(|&p| full[c][p] == Outcome::Pass) {
                let add = (0..battery.len())
                    .filter(|&p| !selected.contains(&p) && full[c][p] == Outcome::Block)
                    .max_by_key(|&p| (0..n).filter(|&k| full[k][p] == Outcome::Block).count());
                if let Some(p) = add {
                    selected.push(p);
                }
            }
        }
        selected.sort_unstable();

        let sigs = full
            .iter()
            .map(|f| selected.iter().map(|&p| f[p]).collect())
            .collect();
        Fingerprinter {
            battery,
            selected,
            ids: catalog.into_iter().map(|c| c.id).collect(),
            sigs,
        }
    }

    /// The minimal discriminating probe sequence.
    #[must_use]
    pub fn probes(&self) -> Vec<&Request> {
        self.selected.iter().map(|&i| &self.battery[i]).collect()
    }

    /// Identify a live target by running only the selected probes. A
    /// signature shared by ≥2 catalog entries, or matching none, both
    /// yield `matched: None` — identification is unique or abstains.
    pub fn identify(&self, oracle: &mut dyn WafOracle) -> crate::Result<Identification> {
        let mut sig = Vec::with_capacity(self.selected.len());
        for &p in &self.selected {
            sig.push(oracle.classify(&self.battery[p])?);
        }
        let mut hit = None;
        for (idx, cand) in self.sigs.iter().enumerate() {
            if *cand == sig {
                if hit.is_some() {
                    hit = None; // ambiguous ⇒ abstain
                    break;
                }
                hit = Some(idx);
            }
        }
        Ok(Identification {
            matched: hit.map(|i| self.ids[i].clone()),
            signature: sig,
            probe_count: self.selected.len(),
        })
    }
}
