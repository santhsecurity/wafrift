# wafrift-types

Foundational types shared by every crate in the [WafRift](https://github.com/santhsecurity/wafrift) workspace. Pure-data — no I/O, no async, no transitive runtime dependencies. Other wafrift crates depend on this one; this crate depends on nothing wafrift-specific.

## What's in here

| Module                 | Purpose                                                                  |
|------------------------|--------------------------------------------------------------------------|
| `request`              | `Request` / `Method` / `Header` — wire-format-neutral HTTP payload       |
| `technique`            | `Technique` enum — identifies an evasion strategy across the workspace   |
| `result`               | `EvasionResult`, `EvasionVariant`, `Outcome` — what an evasion produced  |
| `config`               | Configuration shape (canonical `EvasionConfig` lives in `wafrift-strategy`) |
| `error`                | `Error` / `Result` — single error type for the workspace                 |
| `escalation`           | `EscalationLevel` — paranoia-level scoring used by the strategy pipeline |
| `calibration`          | `CalibrationResult` — output of WAF calibration probes                   |
| `verdict`              | `Verdict` — was a payload blocked, allowed, or ambiguous?                |
| `session`              | `SessionState` — per-host state shared between scan and proxy            |
| `injection_context`    | `InjectionContext` — where in the request the payload sits               |
| `oob`                  | Out-of-band callback metadata (for SSRF, blind XSS, etc.)                |
| `discovery`            | Recon / origin-discovery records                                         |
| `explanation`          | Human-readable narrative attached to an `EvasionResult`                  |
| `format`               | Wire-format helpers (multipart boundary, etc.)                           |

## Workspace-wide tunables

Constants every wafrift crate must agree on (default HTTP timeout,
maximum request body size, MCTS budget, etc.) live at the crate root —
single source of truth so `wafrift-proxy`, `wafrift-cli`, the scan
path, and replay path can't drift.

## Stability

Public API tracks the rest of the WafRift workspace at the same minor
version. Adding fields to public structs uses `#[non_exhaustive]`
where possible so consumers can stay on a pinned `wafrift-types` even
if a downstream crate ships a feature.

## License

Dual-licensed under Apache-2.0 OR MIT. See the
[workspace root](https://github.com/santhsecurity/wafrift) for details.
