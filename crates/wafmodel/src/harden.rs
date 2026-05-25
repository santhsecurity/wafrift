//! The defensive dual: from a decompiled WAF's holes, synthesize the
//! *minimal* rules that close them, prove zero new false positives
//! against a benign corpus, and **prove the class is closed**
//! (no attack-grammar member survives the hardened config).
//!
//! Offensive WAF tools are commodities. A tool that hands a defender a
//! verified, FP-free patch *and a proof the gap is gone* is a category
//! nobody owns. The proof is constructive and checkable: build the
//! hardened WAF, enumerate the attack class, assert none passes; the
//! negative twin (drop one synthesized rule ⇒ exactly its holes
//! reopen) proves every rule is load-bearing, not decorative.

use crate::learn::Alphabet;
use crate::mine::attack_grammar;
use crate::normalize::{self, Transform};
use crate::oracle::{ChannelSet, Rule, SimRegexWaf};
use crate::outcome::Outcome;
use crate::sfa::Sfa;
use regex::bytes::Regex;
use wafrift_types::Request;

/// What the hardener produced and proved.
#[derive(Debug)]
pub struct ClosureReport {
    /// The synthesized rules a defender deploys.
    pub added_rules: Vec<Rule>,
    /// Attack-class members the WAF passed *before* hardening.
    pub holes_before: usize,
    /// Attack-class members the WAF passes *after* hardening.
    pub holes_after: usize,
    /// Benign-corpus requests the synthesized rules wrongly block.
    pub benign_false_positives: usize,
    /// `true` iff `holes_after == 0` *and* `benign_false_positives == 0`
    /// — closure proven with no precision regression. Never asserted
    /// on faith; computed from the hardened WAF.
    pub proven_closed: bool,
}

fn body(bytes: &[u8]) -> Request {
    Request::post("https://h/p", bytes.to_vec()).header("Content-Type", "application/json")
}

/// Enumeration cap for hole-search. Bounded to keep memory + WAF
/// query count predictable on huge attack grammars. A hit at this
/// boundary means the enumeration was TRUNCATED, not exhaustive —
/// see `holes()` for how that fact propagates into `proven_closed`.
const HOLES_ENUM_CAP: usize = 4096;

/// Enumerate attack-class members (bounded) that `waf` lets through.
/// Returns `(holes, truncated)`. `truncated == true` means the
/// enumerator hit `HOLES_ENUM_CAP` and there may be more attack-class
/// members beyond what we examined — callers MUST NOT claim
/// "proven_closed" when this flag is set.
fn holes(
    waf: &SimRegexWaf,
    attack: &Sfa,
    max_len: usize,
) -> (Vec<Vec<u8>>, bool) {
    // `enumerate_accepted` yields concrete bytes already (the Sfa is
    // byte-level; its witnesses are the alphabet's representative
    // bytes), so these go straight to the WAF.
    let enumerated = attack.enumerate_accepted(HOLES_ENUM_CAP, max_len);
    let truncated = enumerated.len() >= HOLES_ENUM_CAP;
    let filtered = enumerated
        .into_iter()
        .filter(|bytes| waf.classify_uncounted(&body(bytes)) == Outcome::Pass)
        .collect();
    (filtered, truncated)
}

/// Synthesize the minimal rules that close every hole for the attack
/// class defined by `needles`, verify zero false positives on
/// `benign`, and prove the class is closed.
///
/// The closing pattern is *derived from the hole*: the attack token
/// the WAF missed, matched under CRS-grade normalization
/// (urlDecodeUni → htmlEntityDecode → lowercase) so encoded/cased
/// evasions are closed too — not a literal-only band-aid. A
/// synthesized rule that would false-positive on the benign corpus is
/// reported (it does not silently ship).
#[must_use]
pub fn synthesize_closure(
    waf: &SimRegexWaf,
    needles: &[&[u8]],
    channels: ChannelSet,
    benign: &[&[u8]],
    alpha: &Alphabet,
    max_len: usize,
) -> ClosureReport {
    let grammar = attack_grammar(alpha, needles);
    let (before, _before_truncated) = holes(waf, &grammar, max_len);

    // One closing rule per needle: match the (lowercased) token after
    // CRS-grade decoding, scoring at the inbound threshold so a single
    // hit blocks.
    let tf = vec![
        Transform::UrlDecodeUni,
        Transform::HtmlEntityDecode,
        Transform::Lowercase,
    ];
    let mut added = Vec::new();
    for n in needles {
        // Build the pattern on the DECODED form of the needle, not the raw
        // needle bytes. The synthesized rule applies `tf` to the request body
        // before testing the pattern — so the pattern must match what the body
        // looks like AFTER that transform chain, i.e. the decoded/lowercased
        // needle. Without this, a rule for needle `%3cx` would search for the
        // literal string `%3cx` in a body that has already been URL-decoded to
        // `<x` — the pattern can never match and the hole remains open.
        let decoded = normalize::apply_chain(&tf, n);
        let pat = regex::escape(&String::from_utf8_lossy(&decoded));
        if let Ok(re) = Regex::new(&pat) {
            added.push(Rule {
                id: format!("synth-close-{}", String::from_utf8_lossy(&decoded)),
                channels,
                transforms: tf.clone(),
                pattern: re,
                score: waf.threshold(),
            });
        }
    }

    let hardened = waf.with_rules_added(added.clone());

    // Zero-FP proof: the hardened WAF must not block any benign input
    // the *original* WAF allowed (the synthesized rules add no FP).
    let benign_fp = benign
        .iter()
        .filter(|b| {
            waf.classify_uncounted(&body(b)) == Outcome::Pass
                && hardened.classify_uncounted(&body(b)) == Outcome::Block
        })
        .count();

    // Closure proof: re-enumerate the attack class against the
    // hardened WAF — every member must now be blocked.
    let (after, after_truncated) = holes(&hardened, &grammar, max_len);

    ClosureReport {
        added_rules: added,
        holes_before: before.len(),
        holes_after: after.len(),
        benign_false_positives: benign_fp,
        // F102: pre-fix `proven_closed = after.is_empty() && benign_fp
        // == 0`. If the post-hardening enumeration hit the 4096-cap
        // and ALL 4096 examined were blocked, the flag flipped true —
        // but longer attack members beyond the cap might still pass.
        // A defender deploys the synthesized rules trusting a proof
        // that doesn't hold. Require the enumeration to have been
        // exhaustive (`!after_truncated`) before claiming closure.
        proven_closed: after.is_empty()
            && benign_fp == 0
            && !after_truncated,
    }
}
