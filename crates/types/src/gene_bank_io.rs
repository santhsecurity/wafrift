//! Canonical schema for the operator's per-host gene-bank persistence
//! file (default path: `~/.wafrift/gene-bank.json`).
//!
//! ## Why this lives in `wafrift-types`
//!
//! Five different crates (cli's `bank`, `seed`, `report`, `replay`,
//! plus the proxy's `gene_bank_io`) each independently defined a
//! private `struct PersistedGeneBank` to deserialize the same on-disk
//! file. The five definitions had silently drifted:
//!
//! - `cli::bank` used `BTreeMap`, the other four used `HashMap`.
//! - `cli::replay`'s `PersistedHostState` had only `proven_winners`
//!   — it was missing `blocklisted` and `waf_name`, so replay was
//!   reading the file through a narrowed window (the bytes for those
//!   fields existed but replay couldn't see them).
//! - `cli::replay`'s `PersistedGeneBank` was missing the `schema`
//!   field entirely — a schema bump would silently deserialize as
//!   `Default` (= 0) only in replay.
//!
//! A schema bump in the proxy would have triggered exactly this
//! class of bug: four consumers update cleanly, one ignores the
//! bump, the file looks correct on save but corrupt on the next
//! load through the lagging consumer.
//!
//! R77 pass-21 §7 DEDUP + §10 COHERENCE — anchor the canonical
//! shape here so adding a field in the future is a single edit and
//! every consumer picks it up at compile-time.
//!
//! ## Why these types are `pub` and `Serialize` + `Deserialize`
//!
//! Both consumers (proxy persistence, cli bank/seed/report/replay)
//! need to read AND write the file. The proxy writes; cli tools
//! both read (to display / merge / replay) and write (to seed /
//! merge). One Serialize + Deserialize derivation, one canonical
//! field set.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Subset of a `wafrift_strategy::HostState` that survives across
/// proxy restarts and cli tool invocations.
///
/// All fields default to empty / `None` via `#[derive(Default)]` so
/// `serde(default)` on the consumer side keeps working for older
/// files that lack newer fields. New fields go at the end with an
/// explicit `#[serde(default)]` and a stable default that means
/// "this field was absent from disk."
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PersistedHostState {
    /// Techniques that have produced confirmed bypasses on this host.
    /// Ordered: most-recently-confirmed first.
    #[serde(default)]
    pub proven_winners: Vec<String>,

    /// Techniques that have produced confirmed BLOCKS on this host
    /// (the WAF reliably catches them). Skip them on the next visit.
    #[serde(default)]
    pub blocklisted: Vec<String>,

    /// WAF vendor identification result from `wafrift detect`.
    /// `None` means detection has not run yet or returned no hit
    /// above the confidence threshold.
    #[serde(default)]
    pub waf_name: Option<String>,
}

/// Top-level shape of `~/.wafrift/gene-bank.json`.
///
/// `schema` is bumped when an incompatible change is made to the
/// on-disk layout — consumers read the field and either auto-migrate
/// or refuse to load. Pre-R77 the `cli::replay` consumer omitted
/// the field, which silently deserialised as `0` regardless of what
/// was actually on disk — defeating the whole point of a schema
/// version.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PersistedGeneBank {
    /// On-disk schema version. Bump only when a breaking change is
    /// made; additive fields don't require a bump because every
    /// consumer reads via `#[serde(default)]`.
    #[serde(default)]
    pub schema: u32,

    /// Per-host persisted state. HashMap (not BTreeMap) because (a)
    /// the file is small (≤10k hosts in practice), (b) lookups in
    /// the proxy hot path want O(1), (c) the JSON output ordering
    /// is not part of any consumer's contract.
    #[serde(default)]
    pub hosts: HashMap<String, PersistedHostState>,
}

impl PersistedGeneBank {
    /// Current canonical schema version. Bump only on breaking
    /// changes; consumers that don't update their `match self.schema`
    /// arm must refuse the load.
    pub const SCHEMA_VERSION: u32 = 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bank_round_trips_through_json() {
        // Anti-rig: an empty bank must round-trip cleanly. If a future
        // refactor accidentally requires a non-empty hosts map (e.g.
        // by dropping `#[serde(default)]`), this test fires.
        let bank = PersistedGeneBank::default();
        let s = serde_json::to_string(&bank).expect("serialize empty");
        let back: PersistedGeneBank = serde_json::from_str(&s).expect("deserialize empty");
        assert_eq!(bank, back);
    }

    #[test]
    fn missing_fields_default_via_serde() {
        // Pre-R77 cli::replay's struct lacked `schema`, `blocklisted`,
        // `waf_name`. A bank file containing those fields would
        // deserialise through replay's narrow struct silently dropping
        // them. The canonical struct + `#[serde(default)]` means a
        // future field-removal accident doesn't propagate as silent
        // data loss — pin that contract here.
        let json = r#"{"hosts": {"a.example": {"proven_winners": ["t1"]}}}"#;
        let bank: PersistedGeneBank = serde_json::from_str(json).expect("parse minimal");
        assert_eq!(bank.schema, 0, "missing schema defaults to 0");
        let host = bank.hosts.get("a.example").expect("host present");
        assert_eq!(host.proven_winners, vec!["t1".to_string()]);
        assert!(host.blocklisted.is_empty(), "missing blocklisted defaults to empty");
        assert!(host.waf_name.is_none(), "missing waf_name defaults to None");
    }

    #[test]
    fn full_field_set_round_trips() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "host.example".into(),
            PersistedHostState {
                proven_winners: vec!["url:percent_encode".into(), "sql:keyword_morph".into()],
                blocklisted: vec!["heavy:naive".into()],
                waf_name: Some("cloudflare".into()),
            },
        );
        let bank = PersistedGeneBank {
            schema: PersistedGeneBank::SCHEMA_VERSION,
            hosts,
        };
        let s = serde_json::to_string(&bank).expect("serialize full");
        let back: PersistedGeneBank = serde_json::from_str(&s).expect("deserialize full");
        assert_eq!(bank, back);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // Forward-compat: a newer wafrift may add fields. Older
        // consumers should ignore unknown fields instead of erroring,
        // so deserialise via serde's default (non-strict) field
        // handling. Pin this so a future #[serde(deny_unknown_fields)]
        // accident fires this test.
        let json = r#"{
            "schema": 1,
            "hosts": {},
            "future_field": "doesn't exist yet",
            "another_future": {"nested": true}
        }"#;
        let bank: PersistedGeneBank = serde_json::from_str(json)
            .expect("unknown top-level fields must be ignored");
        assert_eq!(bank.schema, 1);
    }
}
