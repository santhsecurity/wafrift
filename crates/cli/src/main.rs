use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use colored::Colorize;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

mod attack_cmd;
mod bank;
mod bank_registry;
mod bench_diff;
mod bench_waf;
mod body_diff_cmd;
mod bypass_probe;
mod cache_diff_cmd;
mod callback_token;
mod compress_cmd;
mod config;
mod cors_diff_cmd;
mod detect_cmd;
mod discover_cmd;
mod distill_cmd;
mod egress_example;
mod equiv_engine;
mod evade_cmd;
mod explain;
mod gql_diff_cmd;
mod h2_diff_cmd;
mod header_diff_cmd;
mod helpers;
mod import_curl;
mod init_cmd;
mod interactive;
#[cfg(feature = "tls-impersonate")]
mod ja3_diff_cmd;
mod jwt_diff_cmd;
mod legendary;
mod listener_cmd;
mod man_cmd;
mod method_diff_cmd;
mod origin_hints;
mod parser_diff_cmd;
mod parser_diff_common;
mod probe_classify;
mod probe_cmd;
mod query_diff_cmd;
mod raw_request;
mod recon_cmd;
mod replay;
mod report;
mod retry_after;
mod safe_body;
mod scan;
mod seed;
mod session_init;
mod smuggle_cmd;
mod target_context;
mod technique_filter;
mod trailer_diff_cmd;
mod wafmodel_cmd;

// All per-command helpers are imported by their command modules now.
// main.rs is reduced to dispatch + the top-level Cli/Commands surface.

#[derive(Parser, Debug)]
#[command(
    name = "wafrift",
    about = "WAF evasion toolkit — run without arguments for interactive mode",
    long_about = "WAF evasion toolkit — run without arguments for interactive mode.\n\n\
                  Exit codes (CI-friendly):\n\
                    0  success\n\
                    1  generic error (IO failure, runtime error, etc.)\n\
                    2  argument / input error (unknown flag, contradictory selectors, malformed value, unknown technique selector, unrecognised algorithm, missing required field) — clap convention; ALSO used by bench-waf for 'zero bypasses' and by replay for 'saved bypass blocked' (legacy: per perf-hunt N01 the dual usage is documented rather than split because the bench-waf/replay overload is well-established in CI scripts)\n\
                    3  bench-diff: regression vs baseline (see --bypass-drop-pp)\n\
                    4  bench-waf --validate-only: corpus integrity errors (duplicate id, TOML parse failure, missing required field)\n\
                    5  scan: aborted — target rate-limited the probes (inconclusive, not 'no bypass')",
    version
)]
struct Cli {
    /// Suppress human-readable output — emit only machine-parseable results (JSON).
    #[arg(long, short, global = true)]
    quiet: bool,

    /// Path to a TOML config file. Default: `.wafrift.toml` in CWD or
    /// `~/.config/wafrift/config.toml`.
    #[arg(long, short, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

// large_enum_variant: the Commands enum holds heterogeneous CLI Args
// structs (some 500+ bytes for the rich scan/bench/proxy flag sets,
// others ~16 bytes for trivial subcommands). Boxing each variant
// would slow every dispatch by an indirection and complicate clap
// derive macros for no operational benefit — Commands is matched
// once per invocation, not on a hot path.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Commands {
    /// Transform a payload with evasion techniques.
    Evade(evade_cmd::EvadeArgs),
    /// Identify a WAF / CDN / origin-infrastructure from response metadata.
    ///
    /// Two invocations work:
    ///
    /// ```text
    ///   wafrift detect --url https://target.com
    ///     — fetches once, runs all four detection axes (HTTP
    ///       headers + body, DNS CNAME chain, reverse-DNS PTR,
    ///       BGP origin ASN).
    ///
    ///   wafrift detect --status 403 --headers 'Server: cloudflare'
    ///                  --headers 'CF-Ray: x' --body '<html>...'
    ///     — feed a prior curl/Burp capture's response triple
    ///       directly (no network call).
    /// ```
    ///
    /// Exactly ONE mode required; --url is mutually exclusive with
    /// --status / --headers.  Use `wafrift detect --help` for the
    /// full per-flag reference.
    #[command(arg_required_else_help = true)]
    Detect(detect_cmd::DetectArgs),
    /// Generate differential analysis probes.
    Probe(probe_cmd::ProbeArgs),
    /// Fire evasion variants against a live target and report bypass results.
    Scan(ScanArgs),
    /// Reproducible WAF benchmark: measure raw block rate AND wafrift bypass rate.
    /// Pass `--evade` to actually run the evasion engine (off by default — without it,
    /// only the WAF's raw rejection rate is measured, no bypass claim is made).
    #[command(name = "bench-waf")]
    BenchWaf(bench_waf::BenchWafArgs),
    /// Compare two `bench-waf --output` JSON blobs and gate on regression.
    #[command(name = "bench-diff")]
    BenchDiff(bench_diff::BenchDiffArgs),
    /// DNS hints for `origin_bypass` (authorized targets only).
    #[command(name = "origin-hints")]
    OriginHints(origin_hints::OriginHintsArgs),
    /// Print JSON snippets for egress presets (e.g. Tor SOCKS).
    #[command(name = "egress-example")]
    EgressExample(egress_example::EgressExampleArgs),
    /// List or explain available technique selectors for `--only`/`--exclude`.
    Techniques(TechniquesArgs),
    /// Generate shell completions for bash, zsh, fish, or PowerShell.
    Completion(CompletionArgs),
    /// Origin discovery via crt.sh + DNS (authorized targets only).
    Recon(recon_cmd::ReconArgs),
    /// Endpoint discovery: parse OpenAPI/Swagger, run GraphQL introspection,
    /// or fire differential parameter mining. Emits `DiscoveredEndpoint` JSON
    /// suitable for piping into `wafrift scan --from-discovery`.
    Discover(discover_cmd::DiscoverArgs),
    /// Replay a saved bypass against a target — proves reproducibility.
    Replay(replay::ReplayArgs),
    /// Generate a markdown findings report from the proxy gene bank.
    Report(report::ReportArgs),
    /// Scaffold a `.wafrift.toml` config in the current directory.
    Init(init_cmd::InitArgs),
    /// Pre-load a gene-bank with known-working techniques (per-WAF or per-host).
    Seed(seed::SeedArgs),
    /// Take a curl invocation (e.g. from Burp's "Copy as cURL"), run scan against the parsed target.
    #[command(name = "import-curl")]
    ImportCurl(import_curl::ImportCurlArgs),
    /// Manage gene-banks: list / export / import.
    Bank(bank::BankArgs),
    /// Differential bypass scanner against a single protected URL.
    /// Fires 230 auth-bypass header probes + path-routing-disagreement
    /// variants + HTTP method overrides; reports any probe that diverges
    /// from the baseline response. The Tsai-class vuln finder.
    #[command(name = "bypass-probe")]
    BypassProbe(bypass_probe::BypassProbeArgs),
    /// Generate a troff man page for `wafrift` (and optionally subcommands).
    Man(man_cmd::ManArgs),
    /// Decompile a CRS-class ruleset and report the holes an attacker
    /// can drive through it (the WAF X-ray). Zero-config; `--ruleset`
    /// audits a custom Tier-B config.
    Audit(wafmodel_cmd::AuditArgs),
    /// Synthesize the minimal CRS-grade rules that close the holes
    /// `audit` finds, prove zero benign false positives, and exit
    /// non-zero unless closure is proven (usable as a CI gate).
    Harden(wafmodel_cmd::HardenArgs),
    /// One-shot demo command — runs detect + fingerprint + bypass-probe
    /// (and optionally scan) against a single target, and stitches the
    /// results into one polished markdown writeup.
    Legendary(legendary::LegendaryArgs),
    /// Out-of-band callback receiver — pre-mints unique tokens to
    /// embed in payloads (blind SQLi / stored XSS / blind SSRF / OOB
    /// command injection); logs any inbound HTTP request matching a
    /// minted token. The oracle for the vuln classes that never echo
    /// a verdict on the same response.
    Listener(listener_cmd::ListenerArgs),
    /// Parser-differential fingerprinter — fires URL-shape variants
    /// that exercise known WAF↔origin parser disagreements
    /// (semicolon-strip, backslash-as-separator, NUL truncation,
    /// double-URL-decode, fullwidth slash, dot-segment, percent
    /// case, empty-segment collapse, trailing dot). A divergence
    /// from baseline is evidence the WAF and the origin disagree
    /// on what the URL means — exploit the seam without any
    /// payload mutation.
    #[command(name = "parser-diff")]
    ParserDiff(parser_diff_cmd::ParserDiffArgs),
    /// Wrap a request body in one or more `Content-Encoding` layers
    /// (gzip / deflate / brotli / chain). The compression-confusion
    /// attack: WAFs that inspect raw bytes pass over the encoded
    /// body while the origin decompresses normally. Brotli is the
    /// headline gap — many WAFs don't ship a brotli decompressor
    /// even though Chrome / nginx / Apache all do.
    Compress(compress_cmd::CompressArgs),
    /// HTTP request smuggling probes (CL.TE / TE.CL / TE.TE /
    /// CL.0 / dual-CL / multi-value-CL). Subcommands:
    /// `detect` runs the SAFE timing-differential probes that
    /// can't poison the connection pool; `probe` fires the
    /// exploit-grade payloads (requires `--unsafe`); `dry-run`
    /// renders the raw wire bytes without sending anything;
    /// `list` enumerates the variants. Built on the same engine
    /// powering the `wafrift-smuggling` library, but exposed as
    /// a first-class CLI surface so pentesters don't need to
    /// roll their own runner.
    Smuggle(smuggle_cmd::SmuggleArgs),
    /// Adversarial distillation via Zeller's ddmin: take a KNOWN-
    /// working bypass payload and find the minimum-edit-distance
    /// subset that STILL bypasses. Useful for pentest reports —
    /// shorter payloads are easier for clients to reproduce, and
    /// the reduction reveals which payload features the WAF
    /// actually objected to vs. which were noise. Typically chained
    /// from `wafrift scan --format json | jq .bypass_variants[0].payload`.
    Distill(distill_cmd::DistillArgs),
    /// Header parser-disagreement scanner — sister to `parser-diff`
    /// (which probes URL-path disagreements). Fires variants of the
    /// request header block that exercise known WAF↔origin
    /// parser disagreements (dup-header dispatch, X-Forwarded-For
    /// chain spoof, Authorization case-mix, X-HTTP-Method-Override,
    /// X-Original-Host rebind, X-Rewrite-URL, X-Real-IP localhost
    /// spoof, trailing-whitespace + NUL truncation in values). A
    /// divergence from baseline is evidence the WAF and origin
    /// disagree on what the header block means — exploit the seam
    /// without any payload mutation.
    #[command(name = "header-diff")]
    HeaderDiff(header_diff_cmd::HeaderDiffArgs),
    /// Body parser-disagreement scanner — third in the parser-diff
    /// family. Fires variant request BODIES that exercise known
    /// WAF↔origin parser disagreements (JSON dup-key precedence,
    /// JSONC/JSON5 comment tolerance, UTF-7 charset smuggling,
    /// BOM-prefixed JSON, form-urlencoded HPP in body, JSON-as-form,
    /// form-as-JSON, multipart boundary collision). The body-level
    /// seam — disagreements here let an attacker pass content the
    /// WAF declines to parse, that the origin nonetheless processes.
    #[command(name = "body-diff")]
    BodyDiff(body_diff_cmd::BodyDiffArgs),
    /// Query-string parser-disagreement scanner — fourth in the
    /// parser-diff family. Fires variant URL QUERIES that exercise
    /// known WAF↔origin parser disagreements (HPP first-vs-last,
    /// array bracket notation, comma split, empty-value HPP,
    /// missing-value, percent-encoded keys, NUL truncation,
    /// semicolon separator, encoded `#`, trailing-dot keys). The
    /// canonical place pentesters reach for first — every protected
    /// route the WAF gates by URL query is fair game.
    #[command(name = "query-diff")]
    QueryDiff(query_diff_cmd::QueryDiffArgs),
    /// Unified parser-disagreement orchestrator — runs ALL seven
    /// parser-diff family probes (URL path, headers, body, query,
    /// cache, h2, HTTP-method) against one target concurrently and
    /// merges the results into one structured report. The end-to-end
    /// pentester command — one invocation, one report, every
    /// parser-disagreement seam surfaced.
    Attack(attack_cmd::AttackArgs),
    /// Cache-key confusion / cache-poisoning surface scanner.
    /// Sends semantically-equivalent variants of the baseline
    /// request (Host header case, query parameter order, trailing
    /// slash, param case, fragment leak, X-Forwarded-Host, cookie
    /// variation, tracker-param strip) and reports which variants
    /// hit the same cache entry. Same-cache-entry = poisoning
    /// surface: attacker can poison via the variant, victims
    /// fetching the baseline get the poisoned response.
    #[command(name = "cache-diff")]
    CacheDiff(cache_diff_cmd::CacheDiffArgs),
    /// HTTP/1.1 vs HTTP/2 differential scanner. Fires the same
    /// logical request via both protocols and reports any response
    /// divergence — evidence the WAF or origin treats H1 and H2
    /// differently. Catches the common pattern of WAF rule corpus
    /// authored against H1 wire format + H2-to-H1 downgrade
    /// translation bugs.
    #[command(name = "h2-diff")]
    H2Diff(h2_diff_cmd::H2DiffArgs),
    /// HTTP method parser-disagreement scanner. Fires the same URL
    /// with N HTTP method variants (POST/PUT/DELETE/PATCH,
    /// HEAD/OPTIONS/TRACE, WebDAV PROPFIND/MKCOL/MOVE/COPY/LOCK,
    /// custom token like BANANA, lowercase `get`, H2 preface `PRI`)
    /// and reports response divergence — evidence a WAF rule only
    /// fires on GET/POST while the origin routes the unusual verb
    /// somewhere meaningful.
    #[command(name = "method-diff")]
    MethodDiff(method_diff_cmd::MethodDiffArgs),
    /// GraphQL parser / cost-limit disagreement scanner. Probes
    /// introspection leaks, alias bombing, batched operations,
    /// operation-name spoofing, mutation-as-query confusion, field
    /// duplication, fragment nesting, `application/graphql`
    /// content-type, GET-shaped queries. Targets `/graphql`-style
    /// endpoints where most REST WAFs see only `POST /graphql` and
    /// miss the structure inside.
    #[command(name = "gql-diff")]
    GqlDiff(gql_diff_cmd::GqlDiffArgs),
    /// JWT signature / claim validation scanner. Takes a KNOWN-
    /// valid bearer token (operator just logged in and captured it)
    /// and fires N mutations: alg:none case-family, kid traversal /
    /// SQL injection, jku attacker-URL, expired exp, future nbf,
    /// role elevation, empty signature with preserved alg. Any
    /// mutation accepted by the target = a JWT validation bug.
    #[command(name = "jwt-diff")]
    JwtDiff(jwt_diff_cmd::JwtDiffArgs),
    /// CORS misconfiguration scanner. Probes 10 known
    /// Access-Control-Allow-Origin validation pitfalls (arbitrary
    /// origin reflection, null origin, subdomain prefix/suffix
    /// confusion, trailing-dot host, http downgrade, userinfo `@`
    /// injection, wildcard reflection, preflight allow-arbitrary-
    /// header, preflight DELETE permission). Reflection + ACAC:true
    /// = cookie-stealing credential leak.
    #[command(name = "cors-diff")]
    CorsDiff(cors_diff_cmd::CorsDiffArgs),
    /// HTTP/1.1 chunked-trailer field injection scanner. WAFs typically
    /// inspect the initial header block but NOT trailing headers (the
    /// trailer fields after the final chunk in chunked Transfer-Encoding).
    /// This command fires two raw chunked POSTs — one baseline (no
    /// trailer sent) and one attack (payload injected as a trailer field)
    /// — and reports any response divergence. A divergence is evidence
    /// the backend processed the trailer while the WAF did not.
    #[command(name = "trailer-diff")]
    TrailerDiff(trailer_diff_cmd::TrailerDiffArgs),
    /// Per-browser-profile TLS-fingerprint differential scanner.
    /// Sends the same probe through N rquest/BoringSSL-backed browser
    /// emulations (Chrome 120/131, Firefox 133, Safari 17.5/18,
    /// Edge 131, OkHttp 5) plus a reqwest baseline and flags any
    /// profile whose status / body diverges — direct evidence the
    /// WAF in front of the target JA3/JA4-fingerprints the
    /// ClientHello. Requires `--features tls-impersonate` at build
    /// time (pulls in BoringSSL).
    #[cfg(feature = "tls-impersonate")]
    #[command(name = "ja3-diff")]
    Ja3Diff(ja3_diff_cmd::Ja3DiffArgs),
}

// Per-command structs + entry points live in their own modules:
// - `ManArgs` + `run_man`               -> crate::man_cmd
// - `EvadeArgs` + `run_evade` + helpers -> crate::evade_cmd
// - `DetectArgs` + `run_detect` + helpers -> crate::detect_cmd
// - `ProbeArgs` + `run_probe`           -> crate::probe_cmd

/// Arguments for the live WAF scan command. `pub` so sibling modules
/// (e.g. `import_curl`) can construct one and dispatch through
/// `scan::run_scan` without duplicating CLI state.
#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// Target URL to test evasion variants against (e.g.,
    /// <http://localhost:8080>). Accepted as the first positional
    /// argument (`wafrift scan <URL> --payload ...`); kept on equal
    /// footing with the long-form `--target <URL>` below for
    /// backwards-compatibility. Required unless `--from-discovery`
    /// is given (then targets come from the discovery report).
    #[arg(value_name = "URL")]
    pub target_positional: Option<String>,

    /// Long-form alias for the positional target URL — kept so every
    /// pre-existing `wafrift scan --target <URL>` invocation continues
    /// to parse. Mutually exclusive with the positional form.
    #[arg(
        long = "target",
        value_name = "URL",
        conflicts_with = "target_positional",
        required_unless_present_any = ["target_positional", "from_discovery", "raw_request"],
    )]
    pub target: Option<String>,

    /// Ingest a `wafrift discover` JSON report (file, or `-` for
    /// stdin) and scan every discovered endpoint × injection point with
    /// `--payload`. This is the gossan/recon → wafrift pipe the docs
    /// promised but never actually wired:
    /// `wafrift discover ... | wafrift scan --from-discovery - --payload '<x>'`.
    #[arg(long)]
    pub from_discovery: Option<PathBuf>,

    /// Payload to mutate and test.
    #[arg(long)]
    pub payload: String,

    /// Query parameter name to inject into.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Payload class label (`sql`, `xss`, `cmdi`, `ssti`, `path`,
    /// `ldap`, `xxe`, `ssrf`, `nosql`, `log4shell`) used for the
    /// per-class warm-start in the gene bank. When set, the pre-scan
    /// winner pool is biased toward techniques that historically
    /// beat THIS WAF on THIS payload class — a SQLi scan against
    /// Cloudflare starts from "what beat CF on SQLi yesterday", not
    /// "what beat anything on anything". When unset, the global
    /// warm-start path runs (unchanged behaviour). The post-scan
    /// merge also records the per-class breakdown so subsequent
    /// scans benefit.
    #[arg(long, value_name = "CLASS")]
    pub payload_class: Option<String>,

    /// Out-of-band callback URL — the base address of a `wafrift
    /// listener` instance. When set, every occurrence of
    /// `{{CALLBACK}}` in the payload is replaced per-variant with
    /// `<URL>/<unique-token>`. The operator then correlates any
    /// inbound callback at the listener back to a specific variant
    /// by token — the oracle for blind SQLi (time-based), stored
    /// XSS, blind SSRF, OOB command injection. The token is also
    /// surfaced in each variant's scan report.
    #[arg(long, value_name = "URL")]
    pub callback_url: Option<String>,

    /// Stateful chain mode — fire this curl-format request FIRST,
    /// capture cookies + Authorization, then re-use them on every
    /// variant. The file format is identical to `wafrift import-curl`'s
    /// input (Burp / Chromium "Copy as cURL" pastes work verbatim).
    /// Defeats WAFs that scrutinise unauthenticated traffic more —
    /// most do, by a wide margin.
    #[arg(long, value_name = "CURL_FILE")]
    pub session_init: Option<PathBuf>,

    /// Evasion intensity.
    #[arg(long, value_enum, default_value_t = Level::Heavy)]
    pub level: Level,

    /// Apply encoding only, without grammar-aware mutations.
    #[arg(long)]
    pub encoding_only: bool,

    /// Delay between requests in milliseconds (avoid rate-limit bans).
    #[arg(long, default_value_t = 50)]
    pub delay_ms: u64,

    /// Output format: text or json.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// **CLI no-op** — accepted for backwards-compatibility but does
    /// NOT engage TLS-level browser impersonation in `wafrift scan`
    /// (the CLI uses reqwest/rustls; TLS-impersonation lives only in
    /// `wafrift-proxy --tls-impersonate <profile>`, built with the
    /// `tls-impersonate` cargo feature). When set, scan emits a warning
    /// pointing operators at the proxy. Wiring real impersonation into
    /// the scan loop is the open task that would close this gap.
    #[arg(long)]
    pub stealth_browser: Option<String>,

    /// Disable TLS verification.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// With `--format json`, add a `layer_report` object (network / detection / baseline / evasion).
    #[arg(long = "report-layers", default_value_t = false)]
    pub report_layers: bool,

    /// Restrict to listed technique paths (comma-separated; e.g.
    /// `encoding/url,grammar`). Run `wafrift techniques list` for paths.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub only: Vec<String>,

    /// Drop listed technique paths (comma-separated).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Write JSON output to a file instead of stdout.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// HTTP proxy to route every wafrift request through. Typical
    /// pentest setup: point at Burp Suite on `http://127.0.0.1:8080`
    /// so every probe and bypass attempt lands in Burp's request
    /// history — copy-pasteable into Repeater, recordable into
    /// Scanner / Intruder, exportable into the final report. The
    /// proxy applies to HTTPS targets too (CONNECT tunnelling).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Extra request header in `Name: Value` form, repeatable.
    /// Equivalent to `curl -H` — applied to every probe wafrift
    /// fires. Use for bearer tokens, X-Real-User impersonation,
    /// or any custom header your target expects:
    /// `-H 'Authorization: Bearer …' -H 'X-Real-User: admin'`.
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Path to a Burp-style raw HTTP request file (the bytes from
    /// *Copy → Save raw → File* in Burp Repeater / Proxy). When set,
    /// wafrift loads the file as the request TEMPLATE and substitutes
    /// each candidate payload at every `§§` marker before firing —
    /// instead of building requests from `--target` / `--param`.
    ///
    /// Pentester workflow: intercept the real target request in Burp,
    /// save it, mark the value-to-fuzz with `§§`, then
    /// `wafrift scan -r req.txt --payload "' OR 1=1--"`. Bypasses
    /// surface with per-bypass `curl -i` reproducers in the JSON
    /// output (`bypass_variants[i].repro_curl`).
    ///
    /// The template must contain at least one `§§` marker; otherwise
    /// every variant fires the same un-mutated request (operator
    /// mistake — wafrift rejects early with an actionable error).
    #[arg(long, short = 'r', value_name = "FILE")]
    pub raw_request: Option<PathBuf>,

    /// URL scheme to assume when reconstructing the target URL from
    /// the raw request file's `Host:` header (the on-the-wire bytes
    /// don't record TLS state). `http` by default — pass `https` for
    /// TLS targets. Ignored unless `--raw-request` is set.
    #[arg(long, value_name = "SCHEME", default_value = "http")]
    pub raw_request_scheme: String,

    /// After the scan finds bypasses, automatically run Zeller's
    /// ddmin distillation on each one to surface the minimum-edit-
    /// distance payload that STILL bypasses. The minimum form is
    /// emitted in the JSON output as
    /// `bypass_variants[i].minimal_payload` alongside the original.
    ///
    /// Cost: each distillation runs O(N log N) extra HTTP fires
    /// where N = payload length. Off by default. Capped at
    /// `--auto-distill-max-fires` per bypass to defend against
    /// pathological payloads.
    ///
    /// Useful for pentest reports — shorter payloads are easier
    /// for the client to reproduce and easier for defenders to
    /// understand. Mirrors the standalone `wafrift distill`
    /// subcommand but applies to every bypass automatically.
    #[arg(long, default_value_t = false)]
    pub auto_distill: bool,

    /// Per-bypass cap on the number of HTTP fires the auto-distill
    /// pass is allowed to make. Defends against pathological inputs
    /// + rate-limiting WAFs that would otherwise drag a scan into
    /// the ground. Ignored unless `--auto-distill` is set.
    #[arg(long, default_value_t = 200)]
    pub auto_distill_max_fires: u32,

    /// Concurrent in-flight variants per batch. 0 = use the dynamic
    /// default (8 with no delay, 4 with a delay) — matches every
    /// pre-flag invocation byte-for-byte. Useful when the operator's
    /// `.wafrift.toml` sets `scan.concurrency = N` to tune throughput
    /// for a slow / stable target.
    #[arg(long, default_value_t = 0)]
    pub concurrency: usize,

    /// Per-request HTTP timeout in seconds. Reads the upstream's
    /// response budget; large values let slow origins finish, small
    /// ones cut a scan short faster against unresponsive targets.
    /// 0 = use the workspace default (`DEFAULT_REQUEST_TIMEOUT_SECS`).
    /// `.wafrift.toml`'s `http.timeout_secs` overrides this when the
    /// operator hasn't passed the flag explicitly.
    #[arg(long, default_value_t = 0)]
    pub timeout_secs: u64,

    /// Suppress the human-readable banner + per-variant progress
    /// pretty-print. `--format json` already silences pretty output
    /// in the body of the run; this flag silences the startup
    /// banner too, so a script piping the JSON to disk sees only
    /// the JSON blob.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,

    /// Seconds to wait for an OOB callback to land at the listener
    /// before reporting `NotObserved`. Only relevant with
    /// `--callback-url`. Tor / corporate-proxy / DNS-relayed callbacks
    /// can take 10–30+ s; the pre-flag default of 5 s consistently
    /// reported false-negative for those transports. Default 5 s
    /// preserves the prior behaviour.
    #[arg(long, default_value_t = 5)]
    pub callback_timeout_secs: u64,

    /// Maximum extra HTTP fires the EXPLOIT-CHAIN phase is allowed to
    /// make after the initial scan loop completes. The exploit phase
    /// chains successful bypasses into compound attacks (auth-bypass
    /// header + path-traversal + tamper) — useful but unbounded by
    /// default. Pre-flag the cap was hardcoded `500`, which at
    /// `--delay-ms 500` could silently add 250 s to a scan against a
    /// rate-limited target. Operators tuning for slow / strict targets
    /// can now lower this; aggressive pentests against fast targets
    /// can raise it.
    #[arg(long, default_value_t = 500)]
    pub exploit_cap: usize,

    /// Hard cap on the INITIAL variant set passed into the fire loop.
    /// 0 = no cap (use the level-derived count, unchanged historical
    /// behaviour). When set, the variant list is truncated AFTER the
    /// gene-bank winner re-order, so the highest-confidence variants
    /// are preserved.
    ///
    /// Note: subsequent post-fire phases (multi-vector, header-
    /// obfuscation, intelligence loop) may add MORE fires beyond
    /// the cap — they expand from successful bypasses, not from the
    /// initial pool. Use `--exploit-cap` to bound those, and check
    /// `explore_variants` (not `total_variants`) in the JSON output
    /// to see the cap took effect.
    #[arg(long, default_value_t = 0)]
    pub variants_cap: usize,
            // Forward the permission token to every per-discovery job.
            i_have_permission: args.i_have_permission.clone(),
            // Forward GraphQL probing flag to every per-discovery job.
            graphql: args.graphql,
            // Forward egress rotation settings to every per-discovery job.
            egress_socks5: args.egress_socks5.clone(),
            egress_http_proxy: args.egress_http_proxy.clone(),
            egress_tailscale_nodes: args.egress_tailscale_nodes.clone(),
            egress_tailscale_socks_addr: args.egress_tailscale_socks_addr.clone(),
            egress_challenge_threshold: args.egress_challenge_threshold,
            egress_cooldown_secs: args.egress_cooldown_secs,
            custom_rules: args.custom_rules.clone(),
        };
        last = scan::run_scan(job_args, cancel.clone()).await;
        if let Some(ref p) = tmp_path {
            match std::fs::read_to_string(p) {
                Ok(s) => match serde_json::from_str::<serde_json::Value>(&s) {
                    Ok(v) => per_job_envelopes.push(serde_json::json!({
                        "index": i + 1,
                        "url": url,
                        "param": param,
                        "result": v,
                    })),
                    Err(e) => eprintln!(
                        "warn: discovery job {} JSON parse failed: {e} (file {})",
                        i + 1,
                        p.display()
                    ),
                },
                Err(e) => eprintln!(
                    "warn: discovery job {} read failed: {e} (file {})",
                    i + 1,
                    p.display()
                ),
            }
            let _ = std::fs::remove_file(p);
        }
    }

    if want_json {
        let envelope = serde_json::json!({
            "discovery_scan": {
                "endpoints_total": endpoints.len(),
                "jobs_total": jobs.len(),
                "jobs_completed": per_job_envelopes.len(),
                "jobs": per_job_envelopes,
            }
        });
        match serde_json::to_string_pretty(&envelope) {
            Ok(s) => {
                if let Some(out_path) = args.output.as_ref() {
                    if let Err(e) = std::fs::write(out_path, &s) {
                        eprintln!(
                            "[wafrift scan] failed to write discovery output to {}: {e}",
                            out_path.display()
                        );
                        return ExitCode::from(1);
                    }
                    eprintln!(
                        "[wafrift scan] discovery results written to {}",
                        out_path.display()
                    );
                } else {
                    println!("{s}");
                }
            }
            Err(e) => {
                eprintln!("[wafrift scan] failed to serialize discovery envelope: {e}");
                return ExitCode::from(1);
            }
        }
    }

    last
}

// `run_detect` lives in `crate::detect_cmd`.

// `run_probe` lives in `crate::probe_cmd`.
