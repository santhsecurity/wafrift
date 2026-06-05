//! `wafrift diff <kind>` — the unified differential-analysis surface.
//!
//! WAF↔origin (and WAF↔cache, H1↔H2, browser↔browser) parser
//! disagreements are wafrift's deepest bypass seam, and they had grown
//! into **eleven** separate top-level commands plus the `attack`
//! orchestrator — twelve entries crowding `wafrift --help`. This module
//! groups the whole family under one verb:
//!
//! ```text
//! wafrift diff header  <url> …     # one probe (was: wafrift header-diff)
//! wafrift diff all     <url> …     # every core probe at once (was: attack)
//! ```
//!
//! ## Why this is pure surface consolidation (no behaviour change)
//!
//! Each [`DiffKind`] variant carries the **exact** argument struct of its
//! standalone `<kind>-diff` command and the dispatcher routes it to the
//! **same** `run_*` function. `wafrift diff header …` and the legacy
//! `wafrift header-diff …` produce byte-identical results.
//!
//! ## Backwards compatibility (CLAUDE.md LAW 2)
//!
//! The eleven flat `<kind>-diff` commands (and `attack`) remain callable —
//! they are kept as `#[command(hide = true)]` deprecated aliases in
//! [`crate::Commands`], so every existing script / pipe / doc keeps
//! working; the surface simply stops *advertising* the bloat. `diff` is
//! the one entry point `--help` now shows.

use clap::{Args, Subcommand};

/// Arguments for the `diff` parent command — a single required
/// subcommand selecting which differential probe to run.
#[derive(Args, Debug)]
pub(crate) struct DiffArgs {
    #[command(subcommand)]
    pub kind: DiffKind,
}

/// Which differential probe `wafrift diff` should run. Every variant
/// reuses the argument set of the corresponding standalone command, so
/// `diff <kind>` is a drop-in for the legacy `<kind>-diff`.
#[derive(Subcommand, Debug)]
pub(crate) enum DiffKind {
    /// URL-path parser disagreement (was: `parser-diff`).
    Path(crate::parser_diff_cmd::ParserDiffArgs),
    /// Request-header parser disagreement (was: `header-diff`).
    Header(crate::header_diff_cmd::HeaderDiffArgs),
    /// Request-body parser disagreement (was: `body-diff`).
    Body(crate::body_diff_cmd::BodyDiffArgs),
    /// Query-string parser disagreement (was: `query-diff`).
    Query(crate::query_diff_cmd::QueryDiffArgs),
    /// Cache-key confusion / poisoning surface (was: `cache-diff`).
    Cache(crate::cache_diff_cmd::CacheDiffArgs),
    /// HTTP/1.1-vs-HTTP/2 differential (was: `h2-diff`).
    #[command(name = "h2")]
    H2(crate::h2_diff_cmd::H2DiffArgs),
    /// HTTP-method parser disagreement (was: `method-diff`).
    Method(crate::method_diff_cmd::MethodDiffArgs),
    /// GraphQL parser / cost-limit differential (was: `gql-diff`).
    Gql(crate::gql_diff_cmd::GqlDiffArgs),
    /// JWT signature / claim validation scan (was: `jwt-diff`).
    Jwt(crate::jwt_diff_cmd::JwtDiffArgs),
    /// CORS misconfiguration scan (was: `cors-diff`).
    Cors(crate::cors_diff_cmd::CorsDiffArgs),
    /// HTTP chunked-trailer injection differential (was: `trailer-diff`).
    Trailer(crate::trailer_diff_cmd::TrailerDiffArgs),
    /// Run every core parser-diff probe concurrently and merge the
    /// results into one report (was: `attack`).
    All(crate::attack_cmd::AttackArgs),
    /// Per-browser TLS-fingerprint differential (was: `ja3-diff`).
    /// Requires the `tls-impersonate` build feature.
    #[cfg(feature = "tls-impersonate")]
    Ja3(crate::ja3_diff_cmd::Ja3DiffArgs),
}
