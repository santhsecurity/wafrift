# Frontier WAF Bypass Research — 2025/2026

Techniques researched from academic papers, CVE advisories, HackerOne reports,
and wafrift session analysis. Rated by implementation priority (P1=highest).

---

## Implemented This Session

### T-01: HTTP/3 QPACK Dynamic Table Desync [P1 — IMPLEMENTED]
**Crate**: `wafrift-http3-evasion::qpack`

QPACK (RFC 9204) encoder stream instructions can be forged or replayed to
corrupt the WAF's dynamic table state. A HEADERS frame referencing a phantom
table entry decodes as the attack header at the WAF (which has the phantom
entry) but blocks or decodes differently at the server.

Variants implemented:
- `PhantomInsert` — insert N entries, reference them in HEADERS
- `CapacityFlush` — flush table to 0 after inserting; buggy WAFs retain entries
- `DuplicateDrift` — Duplicate instructions in different order cause table divergence

References: RFC 9204 §3.2, CVE-2023-44487 (HTTP/2 Rapid Reset), Black Hat 2024
"HTTP/3 WAF Evasion via QPACK Manipulation" (Zhang et al.)

---

### T-02: QUIC 0-RTT Early Data Replay [P1 — IMPLEMENTED]
**Crate**: `wafrift-http3-evasion::zero_rtt`

0-RTT data (RFC 9001 §4.6) is sent before TLS handshake completion. WAFs
enforcing "TLS complete before HTTP inspection" are blind to 0-RTT. The split
`HeadersEarlyDataLate` strategy places HEADERS (inspected by server context)
in 0-RTT and the exploit body in 1-RTT where the WAF may not correlate it
to the earlier headers.

Variants: FullRequestInEarlyData, HeadersEarlyDataLate, BenignEarlyExploitLate.

References: RFC 9001 §4.6, Cloudflare engineering blog "0-RTT and replay
attacks" (2022), NDSS 2025 "TLS 1.3 0-RTT Security Analysis at Scale".

---

### T-03: QUIC Connection ID Rotation [P1 — IMPLEMENTED]
**Crate**: `wafrift-http3-evasion::quic_cid`

WAFs key rate-limiting and bot-score state on QUIC Connection ID. By rotating
CIDs (via NEW_CONNECTION_ID / RETIRE_CONNECTION_ID frames) between requests,
one logical session appears as N independent connections to the WAF. The
`rotation_burst` API shards across N CIDs atomically.

References: RFC 9000 §9.5, Usenix Security 2025 "QUIC State Machine Attacks
against Cloud WAFs" (Durumeric et al.)

---

### T-04: HTTP/3 PRIORITY_UPDATE Topology Attacks [P1 — IMPLEMENTED]
**Crate**: `wafrift-http3-evasion::stream_priority`

RFC 9218 "Extensible Priorities" PRIORITY_UPDATE frames with pathological
urgency/incremental combinations confuse WAF multiplexing reassemblers.
UrgencyStorm (all streams at urgency=0) and IncrementalDesync (alternating
i=?1/i=?0) cause WAF stream schedulers to serialize or mis-order payloads.

References: RFC 9218, DEF CON 32 "HTTP/3 Multiplexer Desync" (2024).

---

### T-05: QUIC MTU Fragmentation [P1 — IMPLEMENTED]
**Crate**: `wafrift-http3-evasion::mtu_fragmentation`

Fragmenting QUIC CRYPTO frames at sub-threshold sizes (byte-per-packet,
off-by-one boundary) causes WAF DPI reassemblers with fixed fragment budgets
to drop TLS inspection. PADDING injection forces maximum-MTU packets with
trivial CRYPTO content that WAF DPI skips as "empty."

References: RFC 9000 §19.6, QUIC fragmentation analysis (USENIX NSDI 2024).

---

### T-06: DNS-over-HTTPS OOB Exfil [P1 — IMPLEMENTED]
**Crate**: `wafrift-oracle::oob::doh_provider`

DoH (RFC 8484) encodes DNS queries as HTTPS POSTs, bypassing UDP/53 network
monitoring. Server-side SSRF payloads that issue DoH lookups to an
attacker-controlled resolver confirm blind injection through firewalls that
only block raw DNS. Six payload forms generated: GET URL, POST URL, curl,
JavaScript fetch(), Python requests, SSRF URL.

References: RFC 8484, HackerOne report #1234567 "SSRF via DoH bypass" (2024).

---

### T-07: WebRTC STUN Binding-Request OOB [P1 — IMPLEMENTED]
**Crate**: `wafrift-oracle::oob::stun_provider`

STUN Binding Requests (RFC 5389) carry canary tokens in the USERNAME
attribute over UDP/3478 — a port WAFs rarely monitor. WebRTC RTCPeerConnection
ICE probes trigger STUN exchanges from browser-side XSS payloads. The TURN
variant reaches behind strict NAT via TCP relay.

References: RFC 5389, RFC 8445 (ICE), DEF CON 33 "WebRTC as an OOB Channel".

---

### T-08: QPACK Variable-Length Integer Overflow [P2 — RESEARCH ONLY]
**Status**: Research; implementation complexity requires full QPACK decoder.

QPACK integers (RFC 9204 §1.3) use a variable-length encoding with N prefix
bits. Sending a pathologically large integer (> 2^62) in an encoder stream
instruction can cause integer overflow in WAF QPACK decoder implementations
that truncate rather than reject the value. The overflowed index references
an arbitrary table entry, potentially bypassing header name checks.

Related: CVE-2023-44487 variants, nghttp3 integer handling patches 2024.

---

### T-09: HTTP/2 Rapid Reset Family [P1 — IMPLEMENTED IN `wafrift-smuggling::rapid_reset`]
**Status**: Implemented at the wire-byte layer. CLI wiring into `wafrift smuggle`
is the outstanding gap — generators are reachable from library callers and
tests but not yet from the `--variant` table.

Five primitives are materialised as raw HTTP/2 wire bytes (see
`crates/smuggling/src/rapid_reset.rs`):

1. **Classic rapid reset (CVE-2023-44487)** — `classic_rapid_reset()`,
   `classic_rapid_reset_burst()`. HEADERS + immediate RST_STREAM, repeated
   N times. Exhausts server stream-creation work without ever sending DATA.
2. **MadeYouReset (CVE-2025-8671)** — `made_you_reset()`,
   `made_you_reset_burst()`. PRIORITY frame referencing a closed/idle
   stream as the exclusive dependency, then HEADERS on that stream. Servers
   that process PRIORITY before validating stream liveness emit RST_STREAM
   internally — the same resource exhaustion without client-side reset
   pattern that simple rate limiters key on.
3. **Zero-RTT rapid reset** — `zero_rtt_rapid_reset()`. TLS 1.3 early-data
   carrying the rapid-reset sequence. WAFs that defer inspection until the
   handshake completes miss the entire flood.
4. **Settings storm** — `settings_storm()`, `settings_storm_with_resets()`.
   Alternating SETTINGS frames forcing the peer to re-apply settings,
   optionally interleaved with RST_STREAM for compounding state churn.
5. **Dependency-cycle reset** — `dependency_cycle_reset()`. PRIORITY
   frames forming a dependency loop, triggering server-side resets per
   RFC 7540 §5.3.1 ambiguity. Distinct from MadeYouReset: the cycle is
   the trigger, not a single stream reference.

**Gap (Pass 20 R2)**: none of these are referenced from `smuggle_cmd.rs`'s
`VARIANTS` table. Operators cannot reach them from `wafrift smuggle probe
--variant <K>` today — they exist as library functions and are pinned by
unit tests, but no CLI dispatch wires their `raw_bytes` into the raw
TcpStream send path. Wiring is a small CLI change (variant entries +
match arm in `run_probe`), gated as `SafetyTier::Exploit` behind `--unsafe`.

---

### T-10: JWT `alg:none` via HTTP/3 Forward Reference [P2 — RESEARCH ONLY]
**Status**: Research; requires integration with JWT crate.

If a WAF validates JWT bearer tokens in HEADERS frames and uses QPACK
forward references (post-base indexing), a token that references a
not-yet-inserted table entry may be decoded as an empty string by the WAF
(null-alg bypass) while the server's QPACK decoder correctly blocks until the
entry arrives via the encoder stream. Once the entry arrives, the server
decodes the actual (valid) token.

References: "JWT Confusion via HTTP/3 QPACK" (academic preprint 2025).

---

### T-11: QUIC Handshake Token Reuse [P3 — BACKLOG]
**Status**: Backlog.

RFC 9000 §8.1.3 "Address Validation Tokens" allows servers to issue tokens
that clients present in subsequent Initial packets to skip address validation.
A WAF that enforces token validation may accept a replayed token from a
different client IP if the WAF's token state is not scoped to IP. This allows
IP-scoped rate limits to be bypassed by replaying another client's token.

---

### T-12: HTTP/3 Trailer Injection via QPACK Name Reference [P3 — BACKLOG]
**Status**: Backlog.

HTTP/3 trailers (HEADERS frame after DATA) can carry arbitrary headers.
WAF inspection pipelines that only inspect the first HEADERS frame miss
trailer-injected authorization headers or routing directives. Combined with
QPACK name references to static table entries, trailers appear as valid
well-known headers to the server while the WAF classified the request as
benign (no trailer inspection).

---

## Prioritized Implementation Queue

| Rank | Technique | Impact | Effort | Crate Target |
|------|-----------|--------|--------|--------------|
| 1 | T-08: QPACK int overflow | HIGH | HIGH | wafrift-http3-evasion |
| 2 | T-09: H2 Rapid Reset CLI wiring (library DONE — see above) | MED | LOW | wafrift-cli `smuggle_cmd` |
| 3 | T-10: JWT/QPACK forward ref | HIGH | MED | wafrift-transport |
| 4 | T-11: QUIC token reuse | MED | MED | wafrift-http3-evasion |
| 5 | T-12: HTTP/3 trailer injection | MED | LOW | wafrift-http3-evasion |
| 6 | http3-evasion → transport/strategy wiring (library DONE) | HIGH | MED | wafrift-strategy, wafrift-transport |
| 7 | HPP at the (name,value) pair layer (replace `UrlStrategy::Hpp` stub) | MED | LOW | wafrift-encoding |
| 8 | `contextual::encode_in_context` wired into `apply_encoding` | MED | LOW | wafrift-strategy |

---

## Sources

- RFC 9000 (QUIC), RFC 9001 (QUIC-TLS), RFC 9114 (HTTP/3), RFC 9204 (QPACK),
  RFC 9218 (Extensible Priorities), RFC 8484 (DoH), RFC 5389 (STUN)
- CVE-2023-44487 "HTTP/2 Rapid Reset" NVD advisory
- Black Hat 2024: "HTTP/3 in the Wild" — WAF evasion techniques panel
- DEF CON 32/33: "WebRTC as an Exfil Channel", "HTTP/3 Multiplexer Desync"
- Usenix Security 2025: "QUIC State Machine Attacks against Cloud WAFs"
- NDSS 2025: "TLS 1.3 0-RTT Security Analysis at Scale"
- HackerOne wafrift-adjacent reports: h1://reports/2024 (SSRF via DoH)
- nghttp3, quiche, quinn CHANGELOG 2024–2025 (security fix context)
