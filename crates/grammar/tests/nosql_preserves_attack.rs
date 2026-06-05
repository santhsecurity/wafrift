//! NoSQL / LDAP twin of the SQL/XSS/cmd/path/SSTI preservation contracts.
//!
//! Two invariants the NoSQL family (`mongo`/`elastic`/`redis`/`cassandra`)
//! silently violated until the shared `variant_util::finalize` post-pass:
//!
//!  1. **"a mutation must mutate"** — `mongo`/`redis`/`cassandra`/`elastic`
//!     pushed unconditional `payload.replace(a, b)` variants that are no-ops
//!     when the token is absent (e.g. `payload.replace("$eq","$nin")` on a
//!     `$ne`-only payload), so `mutate` echoed the *unmutated input* back as a
//!     "variant" and emitted duplicates. A bench firing those counts the
//!     baseline payload as a distinct "mutation" — skewing the bypass-rate
//!     denominator with sends that aren't mutations.
//!  2. **intent preservation** — the operator's distinctive target token
//!     (field name, key, command argument) must survive into at least one
//!     variant; the canned auth-bypass / detection probes a mutator *adds*
//!     must never be the *only* thing it emits.
//!
//! Adversarial twin: a benign but loosely-detected `{…}` JSON body (Mongo's
//! detector fires on any `{`-prefixed string) must NOT surface as a fake
//! attack mutation — with no real transform available, `mutate` returns empty.

use wafrift_grammar::grammar::{cassandra, elastic, ldap, mongo, redis};

/// (label, mutate-fn) for the structural invariants every NoSQL/LDAP mutator
/// must satisfy.
fn families() -> Vec<(&'static str, fn(&str) -> Vec<String>)> {
    vec![
        ("mongo", mongo::mutate as fn(&str) -> Vec<String>),
        ("elastic", elastic::mutate),
        ("redis", redis::mutate),
        ("cassandra", cassandra::mutate),
        ("ldap", ldap::mutate),
    ]
}

/// A real, structured attack per family — distinctive operator token that
/// must survive, paired with a benign-looking string the detector rejects.
const ATTACKS: &[(&str, &str, &str)] = &[
    // (family, structured attack, distinctive token that must survive)
    ("mongo", r#"{"role": {"$ne": "guest"}}"#, "role"),
    (
        "elastic",
        r#"{"query": {"match": {"email": "a@b.com"}}}"#,
        "email",
    ),
    ("redis", "CONFIG GET maxmemory", "maxmemory"),
    (
        "cassandra",
        "SELECT * FROM secrets WHERE id=1 ALLOW FILTERING",
        "secrets",
    ),
    ("ldap", "(uid=administrator)", "administrator"),
];

fn mutate_for(family: &str) -> fn(&str) -> Vec<String> {
    families()
        .into_iter()
        .find(|(f, _)| *f == family)
        .unwrap_or_else(|| panic!("unknown family {family}"))
        .1
}

#[test]
fn no_variant_equals_the_input() {
    for (family, attack, _) in ATTACKS {
        let mutate = mutate_for(family);
        let variants = mutate(attack);
        assert!(
            !variants.is_empty(),
            "{family}: no variants for a real attack {attack:?}"
        );
        for v in &variants {
            assert_ne!(
                v, attack,
                "{family}: emitted the unmutated input as a \"variant\""
            );
        }
    }
}

#[test]
fn variants_are_unique() {
    for (family, attack, _) in ATTACKS {
        let mutate = mutate_for(family);
        let variants = mutate(attack);
        let mut sorted = variants.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            variants.len(),
            "{family}: duplicate variants emitted for {attack:?} ({variants:?})"
        );
    }
}

#[test]
fn operator_target_token_survives_into_a_variant() {
    for (family, attack, token) in ATTACKS {
        let mutate = mutate_for(family);
        let variants = mutate(attack);
        assert!(
            variants.iter().any(|v| v.contains(token)),
            "{family}: distinctive operator token {token:?} was erased from \
             every variant of {attack:?} — canned probes replaced the intent: \
             {variants:?}"
        );
    }
}

#[test]
fn benign_json_is_not_minted_into_a_fake_mongo_attack() {
    // Mongo's detector fires on any `{`-prefixed body. A benign document has
    // no operator to mutate and no auth field to graft a canned probe onto,
    // so the only candidates were input-echoes — which finalize() drops.
    for benign in [r#"{"name": "Alice"}"#, r#"{"city": "Paris"}"#] {
        let variants = mongo::mutate(benign);
        assert!(
            variants.is_empty(),
            "benign JSON {benign:?} was minted into fake mongo attack \
             mutations: {variants:?}"
        );
    }
}

#[test]
fn mongo_auth_payload_keeps_its_operator_mutation_not_just_canned_probes() {
    // `{"username":{"$ne":null}}` DOES trigger the canned auth-bypass probes
    // (it contains "username"); ensure the genuine `$ne`-operator rotation is
    // still present, i.e. the canned set does not displace the real mutation.
    let variants = mongo::mutate(r#"{"username": {"$ne": null}}"#);
    assert!(
        variants.iter().any(|v| v.contains("$nin") || v.contains("$not")),
        "mongo dropped the real $ne-operator mutation in favour of canned \
         probes only: {variants:?}"
    );
}

#[test]
fn empty_and_benign_inputs_yield_no_variants() {
    for (family, mutate) in families() {
        assert!(
            mutate("").is_empty(),
            "{family}: empty input produced variants"
        );
        assert!(
            mutate("just some plain prose with no markers").is_empty(),
            "{family}: plain prose produced variants"
        );
    }
}

mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // The two structural invariants must hold for ARBITRARY input, so a
        // future mutator addition can't reintroduce the no-op/duplicate class
        // one entry at a time (§6 GENERALIZATION).
        #[test]
        fn no_op_and_dedup_invariant_for_any_input(s in ".{0,64}") {
            for (family, mutate) in families() {
                let variants = mutate(&s);
                for v in &variants {
                    prop_assert_ne!(
                        v, &s,
                        "{}: returned the unmutated input for {:?}", family, s
                    );
                }
                let mut sorted = variants.clone();
                sorted.sort();
                sorted.dedup();
                prop_assert_eq!(
                    sorted.len(), variants.len(),
                    "{}: duplicate variants for {:?}", family, s
                );
            }
        }
    }
}
