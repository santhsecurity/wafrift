# Wafrift security findings — open

Findings open against wafrift v0.2.0. Each one is real, reproducible,
and not deferred — they are open and unfinished. As they ship a fix,
move the entry to a `## Resolved` section with the commit SHA.

## Resolved (in-source — needs 0.2.1 republish)

### R-001 — IPv4-mapped IPv6 bypassed bogon filter

**Severity:** critical
**File:** `crates/proxy/src/upstream_policy.rs:16` (`ip_addr_is_bogon`)
**Class:** SSRF allowlist bypass

The IPv6 bogon arm did NOT consider IPv4-mapped IPv6 addresses
(`::ffff:127.0.0.1`, `::ffff:169.254.169.254`, `::ffff:10.0.0.1`,
etc.). `Ipv6Addr::is_loopback()` only matches `::1`; mapped form
sneaks past. An attacker pointing the proxy at `http://[::ffff:169.254.169.254]/`
hit AWS IMDS through the bogon allowlist.

**Fix.** Added `to_ipv4_mapped()` and `to_ipv4()` recursion in
the V6 arm: the embedded V4 address now flows back into
`ip_addr_is_bogon(IpAddr::V4(...))` which catches loopback /
RFC1918 / link-local. 5 new unit tests cover the regressed
shapes.

### R-002 — Stale Content-Length forwarded after evasion mutation

**Severity:** high
**File:** `crates/proxy/src/main.rs` (`forward_wafrift_request`)
**Class:** request smuggling / body truncation

Evasion can mutate the body length (encoding swaps, padding,
content-type-switching multipart wrapping). The original
`Content-Length` header was forwarded to upstream unchanged,
producing a length mismatch — either smuggling the trailing bytes
into the next request on the same connection, or upstream
truncating the body.

**Fix.** Strip `content-length` (case-insensitive) from the
forwarded header set; reqwest recalculates the correct value
from the body bytes.

### R-003 — gene-bank atomic write missing fsync

**Severity:** medium
**File:** `crates/proxy/src/main.rs` (`save_gene_bank`)
**Class:** durability / crash safety

The tempfile-rename pattern was missing `sync_all` on the file.
A system crash between write and rename could leave the renamed
file zero-length or partially flushed.

**Fix.** `File::create` + `write_all` + `sync_all` before the
`std::fs::rename`. Parent-directory fsync is left as a follow-up
(needs platform abstraction).

### R-004 — DNS rebinding bypass closed via custom resolver

**Severity:** critical
**File:** `crates/proxy/src/upstream_policy.rs`
+ `crates/proxy/src/main.rs`

`assert_forward_url_allowed` resolved DNS once and trusted the result;
reqwest re-resolved at connection time, opening the rebinding window.

**Fix.** New `BogonFilteringResolver` impls `reqwest::dns::Resolve`
and is wired into the global client via
`Client::builder().dns_resolver(...)`. Every connection-time DNS
lookup now goes through the same `ip_addr_is_bogon` filter the
policy check uses. A hostname that points at a public IP at policy
time and 169.254.169.254 / 127.0.0.1 / RFC1918 at fetch time fails
the second filter and the request is refused.

### R-005 — CONNECT tunnel byte cap

**Severity:** high
**File:** `crates/proxy/src/main.rs` (`tunnel`)

`copy_bidirectional` ran without limits — CONNECT pass-through
bypassed `MAX_PROXY_BODY_BYTES` and `max_upstream_response_bytes`.

**Fix.** Replaced `copy_bidirectional` with an explicit per-direction
copy loop bounded by `MAX_TUNNEL_BYTES_PER_DIRECTION` (2 GiB).
Either side exceeding the cap aborts the tunnel with a clean
`io::Error`.

### R-006 — Body size enforced at stream-read time

**Severity:** high
**File:** `crates/proxy/src/main.rs` (`proxy`, `mitm_plaintext_request`)

`req.body_mut().collect().await` pulled the full body into memory
before the size check fired.

**Fix.** Wrapped `req.body_mut()` in `http_body_util::Limited::new`
with `MAX_PROXY_BODY_BYTES`. The collect now fails as soon as the
limit is exceeded; memory is bounded.

### R-007 — `/_wafrift/status` per-connection peer gate

**Severity:** medium
**File:** `crates/proxy/src/main.rs` (acceptor loop)

Status endpoint was gated on the listener's bind address only; a
reverse proxy fronting wafrift on loopback would leak hosts /
winners / blocklists to external callers.

**Fix.** Per-connection peer `SocketAddr` is now captured at
`listener.accept()` and combined with the bind-loopback check;
status is exposed only when both bind AND peer are loopback.

### R-008 — Windows CA private-key ACL hardening

**Severity:** medium
**File:** `crates/proxy/src/mitm.rs` (`write_to_dir`)

CA private key was 0o600 only on Unix; Windows inherited the parent
directory's ACL.

**Fix.** Added `#[cfg(windows)]` block that runs `icacls
/inheritance:r` followed by `/grant:r %USERNAME%:F` to strip
inherited ACEs and grant exclusive access to the current user.

### R-009 — Multipart name/value sanitisation

**Severity:** high
**File:** `crates/content-type/src/content_type.rs` (`build_multipart_body`)

Quotes and CR/LF in caller-supplied keys/values were embedded raw
into multipart part headers. CR/LF let an attacker inject a fake
multipart part with a chosen Content-Disposition; quotes broke
framing.

**Fix.** New `safe_name` (escape `\\` and `"`, strip CR/LF) and
`safe_value` (strip CR/LF) helpers run on every key/value before
interpolation. Two new tests cover the regressed shapes.

### R-011 — Three panic sites in evolution selection / crossover

**Severity:** critical
**Files:**
- `crates/evolution/src/evolution/crossover/selection.rs`
  (`tournament_select_with_size`, `roulette_select`)
- `crates/evolution/src/evolution/crossover/strategies.rs`
  (`multi_point_crossover`)
- `crates/evolution/src/evolution/engine.rs` (`new_seeded`)

Three direct paths to a panic from inside the GA core: empty
population indexed by `tournament_select`, empty range passed to
`gen_range(1..max_len)` in `multi_point_crossover` when `max_len ==
1`, and `EvolutionEngine::new(0)` allocating an empty population
that downstream code then indexed.

**Fix.** `EvolutionEngine::new_seeded` now clamps `population_size`
to `[1, 10_000]`, eliminating the empty-population call site
entirely AND capping construction memory. Selection helpers added
explicit `assert!(!population.is_empty(), ...)` with a clear
contract message — failing loudly on any caller that violates the
non-empty precondition. `multi_point_crossover` early-returns the
single-gene clone path when `max_len == 1`. All 48 evolution
tests still pass.

### R-012 — NoveltySearch archive bounded at 10k

**Severity:** high
**File:** `crates/evolution/src/search/novelty.rs`

`NoveltySearch::submit_evaluations` pushed every novel candidate
into `self.archive` with no upper bound — the archive grew with
every novel candidate ever seen, OOM'ing a long-running scan.

**Fix.** New `ARCHIVE_CAP = 10_000`. When the archive is at cap,
the least-novel entry (lowest `novelty_score`) is evicted before
the new candidate is pushed.

### R-013 — HillClimbing acceptance compares same-units fitness

**Severity:** high
**File:** `crates/evolution/src/search/hill_climb.rs`

`submit_evaluations` compared `verdict.to_fitness()` (raw new
verdict) against `self.current.fitness` (an EMA accumulated over
many evaluations). As `current` accumulated history its EMA drifted
above any single new verdict, making the algorithm reject good
candidates arbitrarily.

**Fix.** Record the verdict on a clone first, then compare the
resulting EMA-smoothed fitness — both sides of the `>=` are now
in the same units.

### R-014 — TabuSearch aspiration on unevaluated candidate

**Severity:** high
**File:** `crates/evolution/src/search/tabu.rs`

`request_evaluations` checked aspiration via
`candidate.fitness > self.best.fitness`, but `candidate` was
freshly generated and had `fitness == 0.0`. The aspiration check
could never fire, so the algorithm could deadlock when every
neighbour was tabu.

**Fix.** Removed the broken aspiration from `request_evaluations`
(matches the SA / HillClimb flow). Aspiration belongs in
`submit_evaluations` where fitness is real; can be added there in
a follow-up if/when needed.

### R-015 — Custom-rules TOML size-bounded before parse

**Severity:** high
**File:** `crates/evolution/src/custom_rules.rs`

`load_rules` passed arbitrary user input to `toml::from_str` with
no length / depth limit. Malicious deeply-nested TOML could
trigger excessive allocation or stack overflow during deserialization.

**Fix.** Reject inputs > 1 MiB before parsing. Generous for any
real ruleset; bounds parse work on hostile input.

### R-017 — payload_hash upgraded to SHA-256

**Severity:** critical
**File:** `crates/evolution/src/lineage.rs` (`BypassEntry::from_chromosome`)

`payload_hash` was a 64-bit `DefaultHasher` digest, claimed to be
SHA-256 in the docstring. Birthday-collision risk at ~2³² distinct
chromosomes — well within reach of a long scan, causing
`BypassCorpus::add` to silently dedupe distinct bypass discoveries.

**Fix.** SHA-256 over a deterministic gene encoding (delimited
key/value pairs to avoid `("ab","c") == ("a","bc")`-style false
collisions). 64-char hex output. `sha2 = "0.10"` added to evolution
deps.

### R-018 — Lineage chain memory leak fixed

**Severity:** critical
**File:** `crates/evolution/src/lineage.rs`

`Lineage::Crossover` and `Lineage::Mutation` stored
`Arc<Chromosome>` snapshots of parents. Because Chromosome
contains its own `lineage: Lineage` field, every grandchild
transitively kept its grandparents alive — a long-running scan
would OOM as the ancestry chain grew without bound.

**Fix.** New `ParentSnapshot { genes: Vec<(String, String)> }`
type holds only the gene tuple — exactly what `to_trace()`
needs. Chain is severed: a parent's lineage is no longer reachable
from the child. Schema-compatible at the JSON level (only the
internal Arc shape changes).

### R-019 — EvolutionEngine batch budget cap

**Severity:** medium
**File:** `crates/evolution/src/evolution/engine.rs`
(`batch_candidates`)

`batch_candidates(n)` passed `n` to `algorithm.request_evaluations`
without capping by the remaining `budget.max_requests` headroom; a
single call could overshoot the hard request budget.

**Fix.** Clamp `n` to
`budget.max_requests.saturating_sub(request_count)` before passing
to the algorithm.

### R-020 — EvolutionEngine::clone propagates failures

**Severity:** medium
**File:** `crates/evolution/src/evolution/engine.rs` (`Clone` impl)

`clone()` silently fell back to `Self::new(20)` if the algorithm
checkpoint/restore failed, masking a state-corruption bug as a
"clone with default state".

**Fix.** Replaced silent fallback with `expect()`s carrying explicit
contract messages. A failure now panics loudly with a useful
diagnostic instead of producing a corrupt clone.

### R-021 — Differential probe authorisation contract documented

**Severity:** high (operator-side; not patchable in source)
**File:** `crates/evolution/src/differential/probe.rs` (`generate_probes`)

Probes contain genuinely exploitable payloads (`alert(1)`, `1=1`,
`/etc/passwd`). If the WAF doesn't block AND the upstream is
vulnerable, the probe IS the attack. Inert markers wouldn't trigger
the WAF and would defeat the probe's purpose.

**Fix.** Added a SAFETY/authorization-contract docstring to
`generate_probes` explaining: (a) why the payloads are not inert,
(b) the operator's responsibility to only run against owned /
authorised targets. wafrift cannot enforce; the operator must.

### R-022 — Form parser rejects invalid UTF-8 instead of lossy-decode

**Severity:** medium
**File:** `crates/content-type/src/content_type.rs` (`parse_form_body`)

`String::from_utf8_lossy` silently replaced invalid UTF-8 with
U+FFFD, producing variants whose decoded keys/values diverged from
how the upstream form decoder would have rejected the same body.
Hides real parser-discrepancy attacks (the whole point of this
crate).

**Fix.** Use `std::str::from_utf8`; on `Err`, return an empty Vec
instead of fabricating fake pairs.

### R-023 — H2 host inputs sanitised at the boundary

**Severity:** high
**File:** `crates/smuggling/src/h2_evasion.rs`
(`authority_host_mismatch`, `double_host`)

These public functions accepted caller-supplied host strings and
embedded them into pseudo/regular headers without
`sanitize_input`. Every other H2 helper in this module sanitises;
these two were inconsistent. A caller passing a CRLF-laced host
got a silently-injected header pair.

**Fix.** Both now run inputs through `sanitize_input` before
embedding. The two CRLF-injection-as-technique helpers
(`crlf_in_regular_header`, `crlf_in_pseudo_headers`) explicitly
opt out — they exist to produce the injection — and are now
documented as the deliberate exception.

### R-016 — IntelligenceLoop logs swallowed errors

**Severity:** high
**File:** `crates/evolution/src/intelligence.rs`

`record_feedback` and `record_verdict` discarded the underlying
`Result` with `let _ =`. Stale chromosome-index errors (a
state-machine bug between caller and engine) were silently
swallowed.

**Fix.** Both methods now log via `tracing::warn!(?e,
chromosome_index, ...)` on `Err`. Caller still has the same
infallible signature, but operators see the bug in logs.

### R-010 — JSON unicode escape valid for supplementary plane

**Severity:** high
**File:** `crates/content-type/src/content_type.rs` (`JsonUnicodeEscape` variant)

`\u{:04x}` produced a single 5+ digit escape for code points above
U+FFFF, which is invalid JSON per RFC 8259. The variant claimed
`Content-Type: application/json` so strict parsers rejected the
body and the attack payload never reached the application.

**Fix.** Code points >= U+10000 now emit a UTF-16 surrogate pair
(`😀` style) per RFC 8259 §7. Two new tests cover BMP +
supplementary-plane round-trip via `serde_json::from_slice`.

### R-024 — IPv6 bogon allowlist missing 6to4 + RFC 3849 docs prefix

**Severity:** high
**File:** `crates/proxy/src/upstream_policy.rs:46` (`ip_addr_is_bogon`)
**Class:** SSRF allowlist bypass (transition / documentation prefixes)

`ip_addr_is_bogon` already recursed through IPv4-mapped/compat (R-001),
but two additional escape hatches existed:

1. **6to4** (`2002::/16`, RFC 3056): the 32-bit IPv4 is embedded at
   `segs[1..3]`. An attacker controlling 6to4 routing could craft
   `2002:c0a8:0101::1` → routes to RFC1918 `192.168.1.1`, or
   `2002:a9fe:a9fe::1` → AWS IMDS via 6to4 transit.
2. **RFC 3849 documentation prefix** (`2001:db8::/32`): real services
   shouldn't live here; a target whose DNS returns docs prefix is
   misconfigured at best, attacker-controlled at worst.

**Fix.** V6 arm now decodes the 6to4 embedded V4 and recurses through
`ip_addr_is_bogon`; documentation prefix returns true outright. Five
new unit tests cover the new shapes (private V4 over 6to4, public V4
over 6to4 stays clean, `2001:db8::/32`).

### R-025 — sudo trust install hangs interactively in CI / headless

**Severity:** medium (UX)
**File:** `crates/proxy/src/mitm.rs` (`install_ca_trust`)

The Linux Debian/Ubuntu trust-install path called `sudo cp ...` and
`sudo update-ca-certificates` with stdin inherited from the parent.
On a CI runner (or any headless context) without cached sudo creds,
sudo would prompt for a password and block on stdin forever — wedging
the proxy startup with no diagnostic.

**Fix.** Added `sudo -n true` non-interactive probe before either
sudo command runs. If sudo isn't usable non-interactively, fall
through to the manual instructions block. All sudo invocations now
also redirect stdin from `/dev/null` defensively.

### R-026 — `--mitm` on a non-loopback `--listen` is a CA-key exposure

**Severity:** critical (operator footgun)
**File:** `crates/proxy/src/main.rs:484` (startup gate)

Operator runs `wafrift-proxy --listen 0.0.0.0:8080 --mitm` to share
the proxy across a lab. Anyone on the LAN can route HTTPS through
and have it re-signed by the local MITM CA — the CA is now
effectively a network-wide trust root.

**Fix.** Startup hard-aborts (exit 1) when `--mitm` is set and the
listen address isn't loopback. Operators that genuinely want a shared
proxy must bind to loopback and front it with their own ACL'd reverse
proxy.

### R-027 — `bench-diff` silently compares evade-mode vs no-evade-mode

**Severity:** medium (CI integrity)
**File:** `crates/cli/src/bench_diff.rs`

`bypass_rate()` returns `0.0` when `evaded_summary` is missing
(no-evade-mode runs lack this field). Comparing a no-evade baseline
against a with-evade current would silently pass with `drop=0`.
Comparing the reverse would pretend to show a huge regression.

**Fix.** New `evade_mode(v)` helper + warning when the two sides
disagree. Doesn't fail the run (operator may know what they're
doing) but the warning is unmissable on stderr.

### R-028 — Multipart boundary collision risk (defence in depth)

**Severity:** low
**File:** `crates/content-type/src/content_type.rs`

`random_boundary()` returns `----WafriftBoundary{32 hex}`. Birthday-
collision odds with attacker-controlled payload content are 1/2^128,
i.e. zero in practice. But the API offered no _guaranteed_-collision-
free helper.

**Fix.** New `unique_boundary(values: &[&str])` checks the candidate
against every supplied value (preceded by the framing `--`) and
regenerates if a hit appears. Bounded retry cap of 16 attempts so a
broken entropy source surfaces as the last candidate, not an infinite
loop.

### R-029 — `wafrift-recon` returned `anyhow::Error` from public API

**Severity:** low (API ergonomics)
**File:** `crates/recon/src/lib.rs`

Library callers couldn't pattern-match on transport vs status vs parse
failures because the error type was `anyhow::Error`. The audit
(`docs/REFINEMENT_AUDIT.md` §1) flagged this as a workspace
inconsistency.

**Fix.** New `ReconError` enum (`thiserror`) with three variants:
`Transport`, `BadStatus`, `Parse`. Public `Result<T>` alias added.

### R-030 — `eprintln!` in library crates polluted piped stdout/stderr

**Severity:** low (UX)
**Files:** `crates/grammar/src/grammar/{template,cmd,sql/common}.rs`,
`crates/types/src/config.rs`

Library code wrote warnings to stderr via `eprintln!`. CLI consumers
piping wafrift output into jq or other tooling got framework noise
mixed in.

**Fix.** Migrated to `tracing::warn!` at the four sites; warnings now
respect `RUST_LOG` and disappear by default unless explicitly enabled.

## Open

(R-024 → R-030 shipped fixes in this round. No findings currently open.
New findings land here as they're discovered.)
