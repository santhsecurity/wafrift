//! HackerOne submission-dedup fingerprint for WAF bypasses.
//!
//! A bypass we find that someone already filed is worth **$0**. To
//! avoid burning submission budget on duplicates, every confirmed
//! bypass from [`super::rule_corpus`] should pass through this
//! module before reaching the H1 submission queue:
//!
//! ```text
//! bypass → fingerprint() → in-archive?
//!                          ├── YES → mark Duplicate, do not submit
//!                          └── NO  → enter submission queue
//! ```
//!
//! ## Fingerprint design
//!
//! The structural fingerprint is stable under **irrelevant
//! variation** (random identifier tokens, whitespace, char-level
//! noise) and **distinct** when the bypass *mechanism* differs.
//!
//! Three components, hashed in order:
//!
//! 1. **rule_id** — exact match. Different CRS rule → different
//!    fingerprint, regardless of payload similarity.
//! 2. **Encoding-chain shape** — ordered list of technique CLASSES
//!    (`url`, `unicode`, `case`, …) with random parameters
//!    collapsed. `url(double)` and `url(triple)` share a class;
//!    `url` and `unicode` don't.
//! 3. **Payload structural skeleton** — the payload with operator-
//!    specified bytes replaced by class placeholders:
//!    - alphanumeric runs → `<W>`
//!    - digit runs → `<D>`
//!    - whitespace → ` `
//!    - common SQL/XSS keywords kept literal (case-folded)
//!    - punctuation kept literal
//!
//! The hash collapses identical-shape bypasses regardless of
//! random tokens. Two reports that both use "alias substitution +
//! url-encode + space-to-comment, applied to `' OR <ident>=<ident>--`"
//! produce the same fingerprint.
//!
//! ## What this DOESN'T do
//!
//! - Doesn't hit HackerOne's API. Operator preloads the archive
//!   from public CumulusFire writeups via [`H1Archive::add_report`].
//! - Doesn't decide submission eligibility on its own — only flags
//!   `Duplicate` so the corpus's [`super::rule_corpus::SubmissionStatus`]
//!   lifecycle can record the verdict.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// One bypass fingerprint — opaque structural hash plus the parts
/// that produced it (kept for human-readable explain reports).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BypassFingerprint {
    /// 64-bit FNV-1a hash of (rule_id || chain_shape || skeleton).
    pub hash: u64,
    /// The rule_id key (CF managed-rule corpus key, or CRS rule_id).
    pub rule_id: String,
    /// Encoding-chain technique classes in application order.
    pub chain_shape: Vec<String>,
    /// Structural skeleton of the payload.
    pub skeleton: String,
}

/// Compute a [`BypassFingerprint`] for a (rule, chain, payload)
/// tuple.
#[must_use]
pub fn fingerprint(rule_id: &str, encoding_chain: &[String], payload: &str) -> BypassFingerprint {
    let skeleton = skeletonize(payload);
    let chain_shape = canonicalize_chain(encoding_chain);
    let mut h = FNV_OFFSET;
    fnv1a_bytes(&mut h, rule_id.as_bytes());
    h = fnv1a_byte(h, 0x1F); // unit separator
    for c in &chain_shape {
        fnv1a_bytes(&mut h, c.as_bytes());
        h = fnv1a_byte(h, 0x1E); // record separator
    }
    h = fnv1a_byte(h, 0x1F);
    fnv1a_bytes(&mut h, skeleton.as_bytes());
    BypassFingerprint {
        hash: h,
        rule_id: rule_id.to_string(),
        chain_shape,
        skeleton,
    }
}

/// Canonicalize an encoding chain to technique CLASSES.
///
/// `url(double)` and `url(triple)` collapse to `url`. Chain order
/// is preserved (`["url","unicode"]` ≠ `["unicode","url"]` — first-
/// applied encoder vs second-applied is a different bypass mechanism).
fn canonicalize_chain(chain: &[String]) -> Vec<String> {
    chain
        .iter()
        .map(|s| {
            // Strip parameter parens: `url(double)` → `url`.
            s.split('(').next().unwrap_or(s).trim().to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Skeletonize a payload: collapse identifier-class tokens to
/// placeholders so randomly-chosen identifiers don't make every
/// bypass look distinct.
///
/// Rules:
/// - Runs of ASCII letters/digits → `<W>` (W = word).
/// - Runs of digits only → `<D>` (D = digit run, since pure-numeric
///   identifiers are a meaningfully different shape from mixed).
/// - Whitespace → single space.
/// - Common SQL/XSS/cmd keywords kept literal (case-folded): so
///   `' OR 1=1--` and `' OR x=x--` share a skeleton.
/// - Punctuation passes through unchanged.
fn skeletonize(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len());
    let mut chars = payload.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            out.push(' ');
            chars.next();
            // Collapse runs of whitespace.
            while chars.peek().is_some_and(|c| c.is_whitespace()) {
                chars.next();
            }
        } else if c.is_ascii_alphanumeric() {
            let mut word = String::new();
            while let Some(&p) = chars.peek() {
                if p.is_ascii_alphanumeric() {
                    word.push(p);
                    chars.next();
                } else {
                    break;
                }
            }
            // Keyword? Case-fold + keep literal.
            let lower = word.to_ascii_lowercase();
            if is_known_keyword(&lower) {
                out.push_str(&lower);
            } else if word.chars().all(|c| c.is_ascii_digit()) {
                out.push_str("<D>");
            } else {
                out.push_str("<W>");
            }
        } else {
            out.push(c);
            chars.next();
        }
    }
    out.trim().to_string()
}

/// Keywords that materially identify a payload's attack class /
/// mechanism. Adding here means "preserve this token literally in
/// the skeleton; payloads sharing this keyword + same surrounding
/// shape are the same bypass."
///
/// Curated for WAF-bypass classification — NOT a comprehensive list
/// of attack-payload tokens (that's `wafrift_grammar`'s job).
const KNOWN_KEYWORDS: &[&str] = &[
    // SQL
    "select", "union", "where", "from", "or", "and", "drop", "insert", "update", "delete",
    "exec", "execute", "load_file", "into", "outfile", "concat", "sleep", "benchmark",
    "version", "user", "true", "false", "null", "limit", "having", "group", "by", "order",
    // XSS
    "script", "alert", "prompt", "confirm", "onerror", "onload", "onclick", "onfocus",
    "img", "svg", "iframe", "onmouseover", "onkeyup", "javascript", "eval", "fromcharcode",
    // Command-injection / Log4Shell / JNDI
    "cat", "ls", "id", "whoami", "curl", "wget", "nc", "bash", "sh", "ping", "nslookup",
    "jndi", "ldap", "rmi", "dns", "log4j",
    // Path traversal
    "etc", "passwd", "windows", "system32", "boot",
    // SSTI
    "class", "mro", "subclasses", "globals", "import", "getattr",
    // generic
    "http", "https", "file", "data",
];

fn is_known_keyword(token: &str) -> bool {
    KNOWN_KEYWORDS.contains(&token)
}

// FNV-1a 64-bit hash — deterministic, dependency-free.
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn fnv1a_byte(h: u64, b: u8) -> u64 {
    (h ^ (b as u64)).wrapping_mul(FNV_PRIME)
}

fn fnv1a_bytes(h: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *h = fnv1a_byte(*h, b);
    }
}

/// Local cache of known HackerOne reports + their structural
/// fingerprints. Operator preloads from public CumulusFire writeups.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct H1Archive {
    /// rule_id → set of fingerprint hashes already reported on H1.
    /// Indexed by rule_id first because dedup queries are scoped
    /// to a specific rule (the same skeleton against rule X and
    /// rule Y are distinct bypasses, hence distinct reports).
    pub reports: std::collections::BTreeMap<String, HashSet<u64>>,
}

impl H1Archive {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register that a bypass was already reported on H1. Operator
    /// pre-seeds the archive from public CumulusFire writeups.
    pub fn add_report(&mut self, fp: &BypassFingerprint) {
        self.reports
            .entry(fp.rule_id.clone())
            .or_default()
            .insert(fp.hash);
    }

    /// Has a bypass with this fingerprint already been reported?
    #[must_use]
    pub fn contains(&self, fp: &BypassFingerprint) -> bool {
        self.reports
            .get(&fp.rule_id)
            .is_some_and(|set| set.contains(&fp.hash))
    }

    /// Total number of reports across all rules.
    #[must_use]
    pub fn total_reports(&self) -> usize {
        self.reports.values().map(HashSet::len).sum()
    }

    /// Number of distinct rules with at least one report.
    #[must_use]
    pub fn rules_seen(&self) -> usize {
        self.reports.len()
    }

    /// Load the archive from a JSON file. Returns `Default` on
    /// missing or corrupt input (the archive is operator-private
    /// state; we never crash because of bad JSON).
    #[must_use]
    pub fn load_or_default(path: &std::path::Path) -> Self {
        let Ok(raw) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    /// Save atomically via tempfile + rename.
    pub fn save_atomic(&self, path: &std::path::Path) -> std::io::Result<()> {
        let body = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut tmp = path.to_path_buf();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "h1-archive".to_string());
        tmp.set_file_name(format!("{name}.tmp"));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_payload_same_fingerprint() {
        let a = fingerprint("942100", &["url".into()], "' OR 1=1--");
        let b = fingerprint("942100", &["url".into()], "' OR 1=1--");
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn different_identifier_same_fingerprint() {
        // Random identifier substitution should not change the
        // fingerprint — that's the whole point of skeletonize.
        let a = fingerprint("942100", &["url".into()], "' OR x=x--");
        let b = fingerprint("942100", &["url".into()], "' OR foo=foo--");
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.skeleton, b.skeleton);
    }

    #[test]
    fn keyword_preserved_in_skeleton() {
        let fp = fingerprint("942100", &[], "' OR 1=1--");
        // OR + digits collapse to <D>.
        assert!(fp.skeleton.contains("or"));
        assert!(fp.skeleton.contains("<D>"));
    }

    #[test]
    fn different_rule_different_fingerprint() {
        let a = fingerprint("942100", &["url".into()], "' OR 1=1--");
        let b = fingerprint("942110", &["url".into()], "' OR 1=1--");
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn different_chain_different_fingerprint() {
        let a = fingerprint("942100", &["url".into()], "' OR 1=1--");
        let b = fingerprint("942100", &["unicode".into()], "' OR 1=1--");
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn chain_order_distinguished() {
        let a = fingerprint("942100", &["url".into(), "unicode".into()], "x");
        let b = fingerprint("942100", &["unicode".into(), "url".into()], "x");
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn chain_param_collapsed() {
        // url(double) and url(triple) share the technique class
        // — same fingerprint.
        let a = fingerprint("942100", &["url(double)".into()], "x");
        let b = fingerprint("942100", &["url(triple)".into()], "x");
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.chain_shape, b.chain_shape);
    }

    #[test]
    fn chain_param_distinct_from_classless() {
        let a = fingerprint("942100", &["url".into()], "x");
        let b = fingerprint("942100", &["url(double)".into()], "x");
        // After canonicalization, both → ["url"] — same.
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn keyword_case_folded() {
        let a = fingerprint("R", &[], "OR");
        let b = fingerprint("R", &[], "or");
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn digit_run_distinct_from_word() {
        let a = fingerprint("R", &[], "abc");
        let b = fingerprint("R", &[], "123");
        // Different placeholders → different skeleton → different hash.
        assert_ne!(a.hash, b.hash);
        assert!(a.skeleton.contains("<W>"));
        assert!(b.skeleton.contains("<D>"));
    }

    #[test]
    fn whitespace_collapsed() {
        let a = fingerprint("R", &[], "a   b");
        let b = fingerprint("R", &[], "a b");
        let c = fingerprint("R", &[], "a\t\tb");
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.hash, c.hash);
    }

    #[test]
    fn punctuation_preserved() {
        let a = fingerprint("R", &[], "x;y");
        let b = fingerprint("R", &[], "x|y");
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn empty_chain_handled() {
        let _ = fingerprint("R", &[], "x");
    }

    #[test]
    fn empty_chain_entries_filtered() {
        let a = fingerprint("R", &["url".into(), "".into(), "unicode".into()], "x");
        let b = fingerprint("R", &["url".into(), "unicode".into()], "x");
        assert_eq!(a.chain_shape, b.chain_shape);
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn empty_payload_handled() {
        let fp = fingerprint("R", &["url".into()], "");
        assert_eq!(fp.skeleton, "");
    }

    #[test]
    fn unicode_in_payload_no_panic() {
        let fp = fingerprint("R", &[], "ＳＥＬＥＣＴ 中 \u{200B}");
        assert!(!fp.skeleton.is_empty());
    }

    #[test]
    fn h1_archive_contains_after_add() {
        let mut a = H1Archive::new();
        let fp = fingerprint("R", &["url".into()], "x");
        a.add_report(&fp);
        assert!(a.contains(&fp));
    }

    #[test]
    fn h1_archive_distinguishes_rule_ids() {
        let mut a = H1Archive::new();
        let fp_r1 = fingerprint("R1", &["url".into()], "x");
        a.add_report(&fp_r1);
        // Same payload+chain, different rule → NOT contained.
        let fp_r2 = fingerprint("R2", &["url".into()], "x");
        assert!(!a.contains(&fp_r2));
    }

    #[test]
    fn h1_archive_load_default_on_missing_path() {
        let p = std::path::Path::new("/nonexistent/zzzz.json");
        let a = H1Archive::load_or_default(p);
        assert_eq!(a.total_reports(), 0);
        assert_eq!(a.rules_seen(), 0);
    }

    #[test]
    fn h1_archive_save_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("wafrift-h1-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("h1.json");
        let mut a = H1Archive::new();
        for i in 0..5 {
            let fp = fingerprint(&format!("R{i}"), &["url".into()], "x");
            a.add_report(&fp);
        }
        a.save_atomic(&path).expect("save");
        let b = H1Archive::load_or_default(&path);
        assert_eq!(a.total_reports(), b.total_reports());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn h1_archive_corrupted_returns_default() {
        let dir = std::env::temp_dir().join(format!("wafrift-h1-corr-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("h1.json");
        std::fs::write(&path, b"{not json").expect("write");
        let a = H1Archive::load_or_default(&path);
        assert_eq!(a.total_reports(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_add_is_idempotent() {
        let mut a = H1Archive::new();
        let fp = fingerprint("R", &["url".into()], "x");
        a.add_report(&fp);
        a.add_report(&fp);
        a.add_report(&fp);
        assert_eq!(a.total_reports(), 1);
    }

    #[test]
    fn rules_seen_counts_distinct_keys() {
        let mut a = H1Archive::new();
        // Distinct payloads with DIFFERENT skeletons → distinct
        // fingerprints. "x" and "y" both collapse to `<W>` (same
        // skeleton, same hash) — so use payloads that produce
        // distinct skeletons.
        a.add_report(&fingerprint("R1", &[], "' OR 1=1--"));
        a.add_report(&fingerprint("R1", &[], "; sleep 5"));
        a.add_report(&fingerprint("R2", &[], "<script>alert(1)</script>"));
        assert_eq!(a.rules_seen(), 2);
        assert_eq!(a.total_reports(), 3);
    }

    #[test]
    fn fingerprint_serializes_round_trip() {
        let fp = fingerprint("R", &["url".into()], "x");
        let json = serde_json::to_string(&fp).expect("ser");
        let back: BypassFingerprint = serde_json::from_str(&json).expect("de");
        assert_eq!(fp.hash, back.hash);
        assert_eq!(fp.rule_id, back.rule_id);
        assert_eq!(fp.chain_shape, back.chain_shape);
        assert_eq!(fp.skeleton, back.skeleton);
    }

    #[test]
    fn fnv1a_deterministic() {
        let a = fingerprint("R", &["url".into()], "x");
        let b = fingerprint("R", &["url".into()], "x");
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn long_payload_no_panic() {
        let big = "A".repeat(100_000);
        let fp = fingerprint("R", &[], &big);
        // The skeleton should collapse the huge run into a single <W>.
        assert_eq!(fp.skeleton, "<W>");
    }

    #[test]
    fn long_chain_no_panic() {
        let chain: Vec<String> = (0..1000).map(|i| format!("t{i}")).collect();
        let _ = fingerprint("R", &chain, "x");
    }

    #[test]
    fn sql_classic_bypass_canonical_form() {
        // Three classic SQL bypasses with different identifiers
        // should ALL hash to the same fingerprint.
        let a = fingerprint("942100", &["url".into()], "' OR 1=1--");
        let b = fingerprint("942100", &["url".into()], "' OR 5=5--");
        let c = fingerprint("942100", &["url".into()], "' OR aaa=aaa--");
        assert_eq!(a.hash, b.hash);
        // Note: c uses <W>, a uses <D> — different skeleton, different
        // hash. This is intentional: alphanum vs numeric identifiers
        // are meaningfully different bypass shapes for some WAFs.
        assert_ne!(a.hash, c.hash);
    }

    #[test]
    fn keyword_set_minimum_count() {
        // Pin the keyword set — adding/removing is fine but
        // accidental wholesale deletion should fail this test.
        assert!(KNOWN_KEYWORDS.len() >= 30);
    }

    #[test]
    fn keyword_set_lowercase() {
        // Keywords are case-folded before lookup; the canonical
        // form is lowercase alphanumeric (digits allowed for tokens
        // like `log4j`).
        for k in KNOWN_KEYWORDS {
            assert!(
                k.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "keyword must be lowercase ASCII alnum (underscores OK): {k}"
            );
        }
    }
}
