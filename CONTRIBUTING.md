# Contributing to wafrift

> Part of the [Santh](https://santh.dev) ecosystem.

## Quick Start

1. Fork and clone
2. `cargo test --workspace` to verify
3. Make changes
4. `cargo clippy --workspace --all-features --all-targets -- -D warnings` must pass
5. `cargo test --workspace` must pass
6. Open PR

## Code Standards

- Zero `unwrap()` / `expect()` in non-test code — return typed errors
- `#![warn(clippy::pedantic)]`
- Doc comments on all public types
- Actionable error messages with `Fix: ...` guidance
- Every public strategy has a reference semantic test proving it preserves payload meaning

## Contributing a New WAF Detector (No Rust Required)

WAF signatures live as TOML in `rules/detect/`. Adding a new WAF = one file, no Rust knowledge:

```toml
# rules/detect/mywaf.toml
name = "MyWAF"
vendor = "Example Corp"
confidence_weight = 0.85

# Passive signals (banner / body / cookie / status)
[[headers]]
name = "Server"
pattern = "MyWAF/\\d+"

[[cookies]]
name = "mywaf_session"

[[body_patterns]]
pattern = "(?i)request blocked by MyWAF"

[[status_codes]]
code = 403
# only fires when accompanied by another body/header signal

# Active probe signal (optional — drift-based detection)
[[active_probes]]
payload_type = "xss"
expected_response_delta = { status_changes = true, body_contains = "security rule" }

# Recommended evasion techniques for this WAF
evasions = [
  "encoding::unicode",
  "encoding::html_entity",
  "grammar::tautology_swap",
]

# Source citation (for future updates)
source = "https://github.com/EnableSecurity/wafw00f/blob/master/wafw00f/plugins/mywaf.py"
```

Drop into `rules/detect/` and the detector loads it at startup. Test with:

```bash
cargo run -- detect --headers "server: MyWAF/2.1" --status 403
```

## Contributing a New Evasion Strategy

Each evasion crate (`encoding`, `grammar`, `smuggling`, etc.) has one file per strategy under `src/`.

1. Create `crates/encoding/src/encoding/my_strategy.rs` implementing the `Strategy` trait.
2. Register it in the strategy enum + `TryFrom<&str>`.
3. Add a property test in `crates/encoding/tests/property.rs` proving round-trip correctness.
4. Add an adversarial test in `crates/encoding/tests/adversarial.rs` covering hostile inputs.
5. Document the context where the strategy is semantically safe (URL-decoded backends, JSON-parsed bodies, HTML parsers, etc.).

## Contributing a New Smuggling Probe

Smuggling probe templates live in `rules/smuggling/*.toml`. See existing entries for the schema.

## Extension Guide

To add a new capability, create a new module in the appropriate crate within `crates/`. If the feature is major (new technique family), create a new crate. Register new CLI commands in `crates/cli/src/main.rs`.

## License

Dual licensed under MIT or Apache-2.0 at the user's option (see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE)).

By submitting a contribution, you agree to license it under the same terms.
