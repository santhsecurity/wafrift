# Wafrift Cross-Crate Consistency Audit

**Date:** May 8, 2026
**Status:** Findings Report (Read-only Audit)

## 1. Error Type Consistency
Every crate should ideally use `thiserror` for internal error definitions to maintain consistency and reduce boilerplate.

- **crates/types/src/error.rs:11**: Manual `Display` and `Error` implementation for `WafRiftError`.  
  *Fix: Migrate to `#[derive(thiserror::Error)]`.*
- **crates/encoding/src/error.rs:5**: Manual `Display` and `Error` implementation for `EncodeError`.  
  *Fix: Migrate to `#[derive(thiserror::Error)]`.*
- **crates/detect/src/waf_detect/rules.rs:480**: `RulesError` is manual.  
  *Fix: Migrate to `#[derive(thiserror::Error)]`.*
- **crates/recon/src/lib.rs:10**: Using `anyhow::Result` in public library API.  
  *Fix: Define `ReconError` using `thiserror` and return `Result<T, ReconError>`.*
- **crates/content-type/src/content_type.rs**: Lacks structured error handling (returns empty `Vec` or implicitly succeeds).  
  *Fix: Implement `ContentTypeError` and return `Result` where parsing can fail.*

## 2. Timeout Defaults
Timeouts vary across the workspace and are often hardcoded.

- **crates/cli/src/scan/mod.rs:167**: Hardcoded 10s timeout in `Client::builder()`.  
  *Fix: Use a shared constant from `wafrift-types`.*
- **crates/proxy/src/main.rs:408**: Hardcoded 30s timeout.  
  *Fix: Use a shared constant from `wafrift-types`.*
- **crates/transport/src/client.rs:55**: Hardcoded 30s timeout.  
  *Fix: Use a shared constant from `wafrift-types`.*
- **crates/cli/src/bench_waf.rs:242**: Default value for `timeout_secs` is 15.  
  *Fix: Align default with workspace constant (suggested 30s for general use).*

## 3. Tracing Usage
Library crates should use `tracing` macros instead of `println!`/`eprintln!`.

- **crates/grammar/src/grammar/template.rs:118**: `eprintln!` used for TOML parse warning.  
  *Fix: Replace with `tracing::warn!`.*
- **crates/grammar/src/grammar/cmd.rs:25**: `eprintln!` used for TOML parse warning.  
  *Fix: Replace with `tracing::warn!`.*
- **crates/grammar/src/grammar/sql/common.rs:20**: `eprintln!` used for TOML parse warning.  
  *Fix: Replace with `tracing::warn!`.*
- **crates/types/src/config.rs:96**: `eprintln!` used for security warning.  
  *Fix: Replace with `tracing::warn!`.*
- **crates/types/src/config.rs:102**: `eprintln!` used for configuration warning.  
  *Fix: Replace with `tracing::warn!`.*

## 4. Async Runtime
Audit for `#[tokio::main]` and `#[tokio::test]` usage.

- **crates/cli/src/main.rs:222**: Manually creating `tokio::runtime::Runtime`.  
  *Fix: Use `#[tokio::main]` if complexity allows, or document why manual RT is required (likely for interactive TUI mode).*
- **All crates**: No usage of `flavor = "current_thread"` found where multi-thread was expected. (Compliant)

## 5. Public API Surface
Audit for leaked internal types and excessive visibility.

- **crates/detect/src/lib.rs**: `RulesError` from `waf_detect/rules.rs` is not re-exported.  
  *Fix: Add `pub use waf_detect::RulesError;` to `lib.rs`.*
- **crates/types/src/request.rs:96**: `Request` fields are `pub`.  
  *Fix: Make fields private and provide `pub fn method(&self)` etc. to protect invariants.*
- **crates/types/src/result.rs:25**: `EvasionResult` fields are `pub`.  
  *Fix: Make fields private and provide accessors.*
- **crates/encoding/src/tamper/mod.rs:188**: `TamperError` is `pub` but may benefit from being re-exported if used in public `Result`s.  
  *Fix: Ensure all public-facing errors are at crate root.*

## 6. Workspace Dependency Hygiene
Audit for inconsistent dependencies and opportunities for promotion.

- **crates/evolution/Cargo.toml:21**: `proptest = "1.11"` used directly.  
  *Fix: Use `proptest = { workspace = true }`.*
- **crates/detect/Cargo.toml:17**: `once_cell = "1"` and `aho-corasick = "1"` used directly.  
  *Fix: Promote to `workspace.dependencies` if used in 3+ crates (currently only `detect`).*
- **crates/encoding/Cargo.toml:19**: `flate2 = "1"` used directly.  
  *Fix: Promote to workspace if it becomes a common dependency (currently used in 2 crates).*

## 7. README/Docs Drift
Audit for stale API examples in READMEs.

- **crates/types/README.md**: Extremely minimal.  
  *Fix: Add basic usage example showing `Request` creation.*
- **crates/smuggling/README.md**: Mentions `wafrift_smuggling::smuggling::detect_cl_te`.  
  *Fix: (Compliant) Matches `lib.rs` structure.*
- **crates/encoding/README.md**: Example uses `encode(...).unwrap()`.  
  *Fix: (Compliant) Matches `lib.rs` and `strategy.rs` signature.*
