# wafrift robustness audit (2026-05-17)

Triggered by: "it is practically unusable… hundreds of deeper robustness
issues". This is not a deferral doc — every item below is **fixed** and
carries a proving + adversarial regression test in the same change.

Format: `SEVERITY | file:line | defect → fix | test`.

## Attacker-reachable panics (crash the tool on the inputs it exists for)

- **HIGH** | `crates/grammar/src/grammar/sql/strings.rs:11` |
  `split_string_concat` sliced `&value[..i]` for every byte index → panic
  on any multibyte/lossy-decoded SQL payload (`"\u{FFFD}J"`, `'café'`).
  Fixed: iterate `char_indices()` only. |
  `grammar/tests/panic_safety_audit.rs::regression_sql_split_string_concat_multibyte_no_panic`
- **HIGH** | `crates/strategy/src/strategy.rs:808` | obs-fold header
  evasion did `&value[..value.len()/2]` on the User-Agent → panic on any
  multibyte custom UA (set via `import-curl -A`, `--stealth-browser`).
  The existing 10k-case property test never caught it (ASCII-body only).
  Fixed: snap fold point to a char boundary. |
  `strategy/tests/panic_safety_audit.rs::regression_obsfold_multibyte_user_agent_no_panic`
- **HIGH** | `crates/detect/src/waf_detect/rules.rs:433,471` | indicator
  snippet sliced `&body[m.start()..m.start()+40]` on attacker response
  text → panic on multibyte near the match. Fixed: `clamped_snippet`
  (char-boundary safe). | detect waf_detect tests + audit corpus

## Memory-amplification / unbounded work (DoS at proxy scale)

- **HIGH** | `crates/content-type/src/content_type.rs` | `generate_variants`
  re-emits every param per ~12 variants with only an 8 MiB input guard →
  ~100 MB output per call; the proxy calls it per request. Fixed: hard
  `MAX_VARIANT_INPUT_BYTES` (64 KiB) expand cap, char-boundary safe. |
  `content-type/tests/panic_safety_audit.rs::regression_generate_variants_output_is_input_independent`
- **MED** | `crates/grammar/src/grammar/sql/strings.rs` | same function
  allocated `3*(N-1)` formatted strings → 200 KB payload ≈ 600 k allocs.
  Fixed: `MAX_SPLIT_POINTS` cap. |
  `regression_sql_split_string_concat_is_bounded`

## Correctness

- **MED** | `crates/content-type/src/content_type.rs:159` | `xml_safe_name`
  used `char::is_alphanumeric()`, which accepts Unicode `No` (e.g. `²`)
  — not a valid XML `NameChar`; produced malformed XML evasion variants.
  Fixed: real XML 1.0 NameStartChar/NameChar predicates + reserved-`xml`
  shift. | `regression_xml_safe_name_rejects_non_namechar_unicode`
- **HIGH** | `crates/detect/build.rs` + `crates/detect/rules/detect/` |
  build.rs embedded the **in-crate vendored** rules copy, not the
  workspace canonical tree, so an edit to the canonical CloudFront rule
  shipped stale signatures silently (two divergent sources of truth).
  Fixed: prefer workspace tree; sync vendored copy; drift-guard test. |
  `detect/tests/vendored_rules_in_sync.rs`
- **MED** | `crates/cli/src/bench_waf.rs` | an explicit non-existent
  `--corpus X` silently fell back to an exe-relative auto-discovered
  corpus (benchmarked a corpus the operator never chose). Fixed:
  auto-discovery only for the compiled default; explicit missing path
  is a hard error. | `dogfood_fixes_e2e::bench_waf_explicit_missing_corpus_*`

## False-advertised / desynced CLI (the "unusable" surface)

All fixed with end-to-end tests in `crates/cli/tests/dogfood_fixes_e2e.rs`:

- `detect --url` didn't exist → implemented (live probe, redirect-safe).
- `detect --status 999` accepted → `parse_http_status` enforces 100–599.
- CloudFront `via`/`x-cache`/`x-amz-cf-*` not detected → signatures added.
- "No WAF" hid the origin → infra markers now reported honestly.
- `evade --format` advertised, rejected → added (NDJSON, == `--quiet`).
- Binary/NUL `--payload` → actionable error + `--payload-b64` + binary-safe `--stdin`.
- `seed --technique` "optional" but required → `required = true` (clap-enforced + marked).
- `import-curl` couldn't take a curl string and forced `--param/--payload`
  → positional curl arg; no payload ⇒ runs detection on the parsed request.
- `scan` hung 3+ min silently on rate-limited targets → stderr startup
  line + 3 s heartbeat (works in `--format json`), escalating backoff,
  rate-limit early-abort (exit 5, `aborted_rate_limited` in JSON).
- `bypass-probe` flagged every 429 as a LOW bypass → throttle/unavailable
  responses excluded from divergences; degraded-run reported.
- `report` only read the proxy gene bank → `--scan-json` / `--scan-stdin`
  so `scan --format json | report` composes.
- `.wafrift.toml` documented but ignored by `scan` → auto-loaded with
  correct precedence (CLI flag > config > default, via clap ValueSource).
- `scan --from-discovery` documented but **did not exist** → implemented
  (the recon/gossan → wafrift pipe; file or `-` stdin).
- `init` told users to run a `wafrift-proxy` that may not be installed,
  and shipped a stale "scan does not auto-load" note → presence check +
  corrected guidance.

## Follow-on sweep (2026-05-17, continued) — de-rig + remaining crates

These were found by *running* the new audit suites (they are real
tests asserting truth, so they failed against broken code) and by
extending the unicode/lossy-bytes axis to the not-yet-swept crates.

- **HIGH (anti-rig)** | `crates/oracle/src/ldap.rs` (whole module) +
  `crates/oracle/src/lib.rs:230` | the rewritten LDAP oracle rejected
  EVERY canonical filter-break (`*)(|(uid=*`, hex-escaped, OID-aliased)
  and accepted a non-injection — a self-balanced fixed-context model
  forces `assembledΔ == fragmentΔ`, so open-ended breaks never balance;
  no NUL/`%00` truncation modelling; richness gate counted absolute
  leaves (an AND-wrapped host laundered `bob)(uid=bob`); a stale
  `lib.rs` test asserted a *benign* `(uid=admin)` is "valid" (the rig
  itself). → redesigned: host-closer count decoupled from prefix depth,
  `%00`/NUL truncation, escape-tolerant parser, sound richness =
  *fragment* introduced a boolean op or match-all (not leaves); stale
  rig corrected to assert benign-is-rejected. | `oracle::ldap::tests`
  MUST-ACCEPT/MUST-REJECT battery + `lib.rs::ldap_oracle_accepts_injections_and_rejects_standalone_benign_filters`
  (165/165)
- **HIGH** | `crates/recon/src/active/tcp.rs:82` | `classify_line`
  did `t[..4]`/`t[..5]` (byte slice on a `&str`) guarded only by
  `.len()`. The banner is `from_utf8_lossy` of attacker-controlled TCP
  bytes; two leading invalid bytes (`\xff\xff` → `��`) put index 4
  mid-codepoint → panic crashing recon. Fixed: ASCII byte-slice
  compare (`t.as_bytes()`), exactly equivalent for ASCII probe
  prefixes, boundary-safe. | `recon::active::tcp::tests::classify_line_never_panics_on_multibyte_or_lossy_banners` + proving twin
- **MED (correctness/repro)** | `crates/encoding/src/encoding/structural.rs:117`
  | `parameter_pollute` drew the decoy param name from `rand::random()`
  → non-deterministic output: a successful bypass cannot be reproduced
  or regression-pinned (the rest of the evasion pipeline is
  deterministic-seeded). The old unit test never pinned the decoy so
  it slipped through. Fixed: FNV-1a-derived deterministic decoy. |
  `encoding::structural::tests::parameter_pollution_without_equals`
  (strengthened to pin determinism + shape) +
  `exhaustive_encoder_spec::every_strategy_every_input_is_total_and_bounded`
- Two new spec assertions were over-broad (asserted falsehoods about
  *deliberately-correct* engine behaviour, separately pinned by unit
  tests): `JsonEncode` yields a complete quoted JSON string by design;
  `DoubleUrlEncode` deliberately preserves embedded `%XX` for the
  path-traversal evasion. Corrected to assert the *true* contract
  (parse the JSON value directly; exact reversibility only for inputs
  without embedded `%XX`, plus an explicit pin of the preservation
  evasion). This is asserting truth, not weakening.

## Test surface added

Workspace-wide adversarial harnesses (handwritten corpora + proptest
fuzz) that assert *no panic / bounded output* for every public transform
on hostile input — these are what found the panics above:

- `crates/grammar/tests/panic_safety_audit.rs`
- `crates/content-type/tests/panic_safety_audit.rs`
- `crates/strategy/tests/panic_safety_audit.rs`
- `crates/cli/tests/dogfood_fixes_e2e.rs` (real-binary e2e, proving + adversarial twins)
- `crates/detect/tests/vendored_rules_in_sync.rs` (drift guard)

## Known-open (named, not deferred)

- ~~CLI positional-target ergonomics (`scan <URL>` vs `--target`)~~ —
  closed 2026-05-19. `scan` and `origin-hints` now accept the URL /
  hostname as the first positional argument *and* the original
  `--target` / `--host` long flags (LAW 2 backwards-compat). clap's
  `conflicts_with` rejects "both forms at once"; `required_unless_present_any`
  preserves the `--from-discovery` escape hatch. Pinned by
  `dogfood_fixes_e2e::{scan_accepts_positional_target_url, scan_still_accepts_legacy_target_flag, scan_rejects_both_positional_and_target_flag_adversarial, scan_rejects_neither_target_nor_discovery_adversarial, origin_hints_accepts_positional_host, origin_hints_still_accepts_legacy_host_flag, origin_hints_rejects_both_positional_and_host_flag_adversarial}` (7/7).
- Per-crate sweep status: **oracle** rebuilt (LDAP de-rig above);
  **recon** swept — one HIGH panic fixed (tcp.rs), discovery parsers
  use serde/Result, no further attacker-reachable defects found;
  **smuggling** (`parser.rs`: bounded chunk count/size, every slice
  bounds-checked), **transport** (`jwt.rs`: 3-part length guard, 16 KiB
  header cap), **proxy** (`upstream.rs`: `take = len.min(remaining)`,
  bounded body), **evolution** (`selection.rs` documented `assert!`
  precondition, `summary.rs` empty-guarded before the median) were read
  on the same unicode/lossy-bytes/DoS axis and found already-hardened —
  no defects to fix, so no change rather than a cosmetic one.
