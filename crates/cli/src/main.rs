use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use colored::Colorize;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

mod attack_cmd;
mod bank;
mod bank_registry;
mod bench_diff;
mod bench_waf;
mod body_diff_cmd;
mod bypass_probe;
mod cache_diff_cmd;
mod callback_token;
mod client_deliver_cmd;
mod cluster_cmd;
mod compress_cmd;
mod config;
mod corpus_cmd;
mod corpus_recorder;
mod cors_diff_cmd;
mod detect_cmd;
mod diff_cmd;
mod discover_cmd;
mod distill_cmd;
mod egress_example;
mod equiv_engine;
mod evade_cmd;
mod exec_proof;
mod explain;
mod exploit_cmd;
mod gql_diff_cmd;
mod h2_diff_cmd;
mod harvest_cmd;
mod header_diff_cmd;
mod helpers;
mod hunt_cmd;
mod import_curl;
mod info_gain_sched;
mod init_cmd;
mod interactive;
#[cfg(feature = "tls-impersonate")]
mod ja3_diff_cmd;
mod jwt_diff_cmd;
mod legendary;
mod listener_cmd;
mod man_cmd;
mod method_diff_cmd;
mod model_evade_cmd;
mod origin_hints;
mod parser_diff_cmd;
mod parser_diff_common;
/// Target-permission gate. Refuse-by-default for non-bounty,
/// non-allowlist hosts; `--i-have-permission &lt;reason&gt;` overrides.
/// Local Docker bench targets (loopback / RFC1918) always pass.
mod permission;
mod poc_emit;
mod probe_classify;
mod probe_cmd;
mod query_diff_cmd;
mod raw_request;
mod recon_cmd;
mod replay;
mod report;
mod retry_after;
mod safe_body;
mod sanitizer_decompile_cmd;
mod sarif_cmd;
mod scan;
mod seed;
mod session_init;
mod smuggle_chain_cmd;
mod smuggle_cmd;
mod smuggle_cross_cmd;
mod smuggle_emit_cmd;
mod smuggle_fire_cmd;
mod smuggle_stats_cmd;
mod smuggle_transport;
mod split_param;
mod target_context;
mod tcp_overlap_cmd;
mod technique_filter;
mod tmin_cmd;
mod trailer_diff_cmd;
mod transform_encode;
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
                    5  scan: aborted — target rate-limited the probes (inconclusive, not 'no bypass')\n\
                    7  scan --scan-timeout-secs: wall-clock budget exceeded — partial results emitted (check truncated_by_scan_timeout in JSON output)\n\n\
                  Environment variables (R50 pass-12 I5 / CLAUDE.md §10):\n\
                    HOME, USERPROFILE      home dir for ~/.wafrift state (gene-bank, hunt, keys)\n\
                    RUST_LOG               tracing filter (e.g. RUST_LOG=wafrift=debug); default is `warn`\n\
                    NO_COLOR               if set (any value), disable ANSI colour in tracing output\n\
                    WAFRIFT_BENCH_URL      fallback target URL for bench-waf / hunt\n\
                    WAFRIFT_MODSEC_URL     legacy alias for WAFRIFT_BENCH_URL (deprecated)\n\
                    WAFRIFT_CORPUS         fallback bench corpus path\n\
                    H1_API_KEY             HackerOne API token (required by `wafrift submit`)\n\
                    H1_USERNAME            HackerOne handle (required by `wafrift submit`)\n\
                    WAFRIFT_REPLAY_AUTOEXEC  proxy/yank: if 1, replay-curl files are bash-executed\n\
                                             (operator opt-in side-channel; off by default)",
    version,
    // R44 fix (dogfood pass 4): propagate -V/--version to every
    // subcommand. Pre-fix `wafrift evade --version` errored as
    // "unexpected argument" — operator muscle memory expects the
    // flag to work on any subcommand of any clap tool.
    propagate_version = true,
)]
struct Cli {
    /// Suppress human-readable output — emit only machine-parseable results (JSON).
    #[arg(long, short, global = true)]
    quiet: bool,

    /// Path to a TOML config file. Default: `.wafrift.toml` in CWD or
    /// `~/.config/wafrift/config.toml`.
    #[arg(long, short, global = true)]
    config: Option<PathBuf>,

    /// Differential-baseline bypass verification. Credit a payload as a WAF
    /// bypass only when the UN-EVADED base is BLOCKED in the same delivery —
    /// proving the evasion is what passed it, not a payload the WAF never
    /// policed. Off by default (anti-rig: the headline bypass metric is
    /// unchanged unless you opt in). Costs ~one extra probe per delivery arm.
    ///
    /// Named `--differential-baseline` (not bare `--differential`) to stay
    /// distinct from the `diff <kind>` parser-disagreement subcommands.
    #[arg(long = "differential-baseline", global = true)]
    differential: bool,

    /// Detonation engine used whenever wafrift proves execution
    /// (`--prove-execution`, `exploit`, proxy classification): `jsdet` (default,
    /// fast QuickJS sandbox) or `chrome` (real headless Chrome — also fires
    /// mutation-XSS and browser-only handlers the sandbox cannot model). The
    /// chrome engine needs a Chrome/Chromium binary (`$WAFRIFT_CHROME_BIN`).
    #[arg(long = "detonate-engine", global = true, default_value = "jsdet",
          value_parser = ["jsdet", "chrome"])]
    detonate_engine: String,

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
    /// Detonation-guided evasion — find a payload that bypasses the WAF AND
    /// actually executes (`alert(1)` fires), proven by the `detonate` sandbox.
    Exploit(exploit_cmd::ExploitArgs),
    /// Emit the WAF-blind CLIENT-SIDE delivery plan for an XSS payload: the
    /// fragment / window.name / postMessage / storage / client-route channels
    /// whose taint source never reaches the server, so no WAF/CDN inspects them.
    /// Sends nothing — it prints a copy-pasteable browser-delivery plan (text or
    /// `wafrift.client_deliver.v1` JSON for scald) confirmed by DOM execution,
    /// not a server response. The lane modern reflected-XSS bypasses live in.
    #[command(name = "client-deliver")]
    ClientDeliver(client_deliver_cmd::ClientDeliverArgs),
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
    ///
    /// Environment variables (R50 pass-12 I5 / CLAUDE.md §10):
    ///   - `WAFRIFT_BENCH_URL` — fallback target URL when `--base-url` is omitted.
    ///   - `WAFRIFT_MODSEC_URL` — legacy alias for `WAFRIFT_BENCH_URL` (deprecated).
    ///   - `WAFRIFT_CORPUS` — fallback corpus path when `--corpus` is omitted.
    #[command(name = "bench-waf", hide = true)]
    BenchWaf(bench_waf::BenchWafArgs),
    /// Compare two `bench-waf --output` JSON blobs and gate on regression.
    #[command(name = "bench-diff", hide = true)]
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
    /// Active-learning WAF bypass: learn the target's decision boundary
    /// online (L* membership queries via HTTP), mine bypass candidates
    /// offline against the learned SFA at ~1M/sec, and verify each online.
    /// Deduces bypasses from the WAF's decision boundary — not from
    /// mutation luck. Use `--budget` to cap live queries.
    #[command(name = "model-evade")]
    ModelEvade(model_evade_cmd::ModelEvadeArgs),
    /// Decompile a CRS-class ruleset and report the holes an attacker
    /// can drive through it (the WAF X-ray). Zero-config; `--ruleset`
    /// audits a custom Tier-B config.
    Audit(wafmodel_cmd::AuditArgs),
    /// Synthesize the minimal CRS-grade rules that close the holes
    /// `audit` finds, prove zero benign false positives, and exit
    /// non-zero unless closure is proven (usable as a CI gate).
    Harden(wafmodel_cmd::HardenArgs),
    /// Fingerprint a live target's origin-normalization pipeline by
    /// reflection (which decode/normalize stages it applies), then
    /// optionally solve a TARGETED, live-verified bypass of `--attack`
    /// against that exact pipeline. The decompiler aimed at one host.
    Fingerprint(wafmodel_cmd::FingerprintArgs),
    /// Decompile a CLIENT-SIDE HTML sanitizer: recover its source from a JS
    /// source map (or raw JS), extract its allow/deny model (DOMPurify config,
    /// `sanitize-html` allowlist, hand-rolled `replace()` strips), then L*/SFA-
    /// mine the XSS vectors that survive it. The DOM-XSS dual of `fingerprint`;
    /// each surviving bypass is model-proven and flagged for scald DOM confirm.
    #[command(name = "sanitizer-decompile")]
    SanitizerDecompile(sanitizer_decompile_cmd::SanitizerDecompileArgs),
    /// Plan a target-based TCP sequence-overlap desync: overlapping TCP segments
    /// a WAF/IDS reassembles to a BENIGN stream while the origin reassembles to
    /// the ATTACK (Ptacek-Newsham / Snort stream5 class). Each plan is self-
    /// verified by simulating both reassembly policies (first/last/bsd/linux).
    /// Emits the segments (seq + bytes) for a raw-socket sender to deliver.
    #[command(name = "tcp-overlap")]
    TcpOverlap(tcp_overlap_cmd::TcpOverlapArgs),
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
    #[command(name = "parser-diff", hide = true)]
    ParserDiff(parser_diff_cmd::ParserDiffArgs),
    /// Differential analysis — surface WAF↔origin (and WAF↔cache,
    /// H1↔H2, browser↔browser) parser disagreements, wafrift's deepest
    /// bypass seam. `wafrift diff <kind>` groups the whole family in one
    /// verb: `path` / `header` / `body` / `query` / `cache` / `h2` /
    /// `method` / `gql` / `jwt` / `cors` / `trailer`. `all` runs the
    /// SEVEN original parser-diff probes concurrently (path, header, body,
    /// query, cache, h2, method) — it does NOT include `gql` / `jwt` /
    /// `cors` / `trailer`; run those individually. The legacy `<kind>-diff`
    /// commands and `attack` remain as deprecated hidden aliases (LAW 2).
    Diff(diff_cmd::DiffArgs),
    /// Wrap a request body in one or more `Content-Encoding` layers
    /// (gzip / deflate / brotli / chain). The compression-confusion
    /// attack: WAFs that inspect raw bytes pass over the encoded
    /// body while the origin decompresses normally. Brotli is the
    /// headline gap — many WAFs don't ship a brotli decompressor
    /// even though Chrome / nginx / Apache all do.
    Compress(compress_cmd::CompressArgs),
    /// HTTP request smuggling probes (CL.TE / TE.CL / TE.TE / CL.0 /
    /// dual-CL / multi-value-CL, plus the CVE-class chunk-ext-lone-lf,
    /// rapid-reset, made-you-reset, settings-storm — run `wafrift smuggle
    /// list` for the authoritative, current variant set). Subcommands:
    /// `detect` runs the SAFE timing-differential probes that
    /// can't poison the connection pool; `probe` fires the
    /// exploit-grade payloads (requires `--unsafe`); `dry-run`
    /// renders the raw wire bytes without sending anything;
    /// `list` enumerates the variants. Built on the same engine
    /// powering the `wafrift-smuggling` library, but exposed as
    /// a first-class CLI surface so pentesters don't need to
    /// roll their own runner.
    Smuggle(smuggle_cmd::SmuggleArgs),
    /// Emit every wafrift smuggle probe as JSON (one per line)
    /// across the 11 probe families: cookie, auth, range, path, host,
    /// jwt, content-type, json, capsule, quic-datagram, compression.
    /// Pipe to `jq` / Burp / `xargs curl` to drive probes through
    /// any HTTP client that reads JSON. `--family <prefix>` filters;
    /// `--kind headers|body|frames` filters by artifact shape;
    /// `--canary-header NAME` attaches an instrumentation header to
    /// each probe; exit 2 when zero probes match.
    SmuggleEmit(smuggle_emit_cmd::SmuggleEmitArgs),
    /// Emit the cartesian product of two smuggle-probe families as
    /// composed JSON artifacts. For every probe in family X × every
    /// probe in family Y, emit one merged artifact carrying both
    /// probes' wire shapes — surfaces bypass-chain interactions that
    /// no single technique produces. Bound output size with `--cap N`
    /// (default 64); exit 2 when either side matches zero probes.
    #[command(name = "smuggle-cross-product")]
    SmuggleCrossProduct(smuggle_cross_cmd::SmuggleCrossProductArgs),
    /// Operator-facing probe-budget snapshot. Counts every probe
    /// wafrift can emit across the 11 smuggle families, broken down
    /// by family and artifact kind, and reports the total wire-byte
    /// budget. Output is structured JSON suitable for piping into
    /// `jq` or CI gates. Useful for deciding whether you need to
    /// subsample before firing a scan against a rate-limited target.
    #[command(name = "smuggle-stats")]
    SmuggleStats(smuggle_stats_cmd::SmuggleStatsArgs),
    /// N-way smuggle-probe composition. Takes 2+ `--family <NAME>`
    /// flags and emits the cartesian product of probes across all
    /// N families as composed JSON artifacts. The N-way generalization
    /// of `smuggle-cross-product`. Bound output size with `--cap N`
    /// (default 64); exit 2 when any family matches zero probes.
    #[command(name = "smuggle-chain")]
    SmuggleChain(smuggle_chain_cmd::SmuggleChainArgs),
    /// Fire every smuggle probe against a live target. The
    /// end-to-end execution pipeline — converts probe artifacts to
    /// real HTTP requests, fires via reqwest, captures
    /// status/body-length/latency, and reports a `bypass_signal`
    /// vs a baseline request (`canary-reflected` / `none` /
    /// `status-diverged` / `body-diverged` / `both-diverged`).
    /// `canary-reflected` is the strongest signal: a 16-char random
    /// canary token appeared verbatim in the response (false-positive-
    /// free). Requires `--i-have-permission <REASON>` for non-
    /// allowlisted hosts. Frame-artifact probes (capsule /
    /// quic-datagram / compression) are skipped — they live below
    /// the HTTP layer.
    #[command(name = "smuggle-fire")]
    SmuggleFire(smuggle_fire_cmd::SmuggleFireArgs),
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
    #[command(name = "header-diff", hide = true)]
    HeaderDiff(header_diff_cmd::HeaderDiffArgs),
    /// Body parser-disagreement scanner — third in the parser-diff
    /// family. Fires variant request BODIES that exercise known
    /// WAF↔origin parser disagreements (JSON dup-key precedence,
    /// JSONC/JSON5 comment tolerance, UTF-7 charset smuggling,
    /// BOM-prefixed JSON, form-urlencoded HPP in body, JSON-as-form,
    /// form-as-JSON, multipart boundary collision). The body-level
    /// seam — disagreements here let an attacker pass content the
    /// WAF declines to parse, that the origin nonetheless processes.
    #[command(name = "body-diff", hide = true)]
    BodyDiff(body_diff_cmd::BodyDiffArgs),
    /// Query-string parser-disagreement scanner — fourth in the
    /// parser-diff family. Fires variant URL QUERIES that exercise
    /// known WAF↔origin parser disagreements (HPP first-vs-last,
    /// array bracket notation, comma split, empty-value HPP,
    /// missing-value, percent-encoded keys, NUL truncation,
    /// semicolon separator, encoded `#`, trailing-dot keys). The
    /// canonical place pentesters reach for first — every protected
    /// route the WAF gates by URL query is fair game.
    #[command(name = "query-diff", hide = true)]
    QueryDiff(query_diff_cmd::QueryDiffArgs),
    /// Unified parser-disagreement orchestrator — runs ALL seven
    /// parser-diff family probes (URL path, headers, body, query,
    /// cache, h2, HTTP-method) against one target concurrently and
    /// merges the results into one structured report. The end-to-end
    /// pentester command — one invocation, one report, every
    /// parser-disagreement seam surfaced.
    #[command(hide = true)]
    Attack(attack_cmd::AttackArgs),
    /// Cache-key confusion / cache-poisoning surface scanner.
    /// Sends semantically-equivalent variants of the baseline
    /// request (Host header case, query parameter order, trailing
    /// slash, param case, fragment leak, X-Forwarded-Host, cookie
    /// variation, tracker-param strip) and reports which variants
    /// hit the same cache entry. Same-cache-entry = poisoning
    /// surface: attacker can poison via the variant, victims
    /// fetching the baseline get the poisoned response.
    #[command(name = "cache-diff", hide = true)]
    CacheDiff(cache_diff_cmd::CacheDiffArgs),
    /// HTTP/1.1 vs HTTP/2 differential scanner. Fires the same
    /// logical request via both protocols and reports any response
    /// divergence — evidence the WAF or origin treats H1 and H2
    /// differently. Catches the common pattern of WAF rule corpus
    /// authored against H1 wire format + H2-to-H1 downgrade
    /// translation bugs.
    #[command(name = "h2-diff", hide = true)]
    H2Diff(h2_diff_cmd::H2DiffArgs),
    /// HTTP method parser-disagreement scanner. Fires the same URL
    /// with N HTTP method variants (POST/PUT/DELETE/PATCH,
    /// HEAD/OPTIONS/TRACE, WebDAV PROPFIND/MKCOL/MOVE/COPY/LOCK,
    /// custom token like BANANA, lowercase `get`, H2 preface `PRI`)
    /// and reports response divergence — evidence a WAF rule only
    /// fires on GET/POST while the origin routes the unusual verb
    /// somewhere meaningful.
    #[command(name = "method-diff", hide = true)]
    MethodDiff(method_diff_cmd::MethodDiffArgs),
    /// GraphQL parser / cost-limit disagreement scanner. Probes
    /// introspection leaks, alias bombing, batched operations,
    /// operation-name spoofing, mutation-as-query confusion, field
    /// duplication, fragment nesting, `application/graphql`
    /// content-type, GET-shaped queries. Targets `/graphql`-style
    /// endpoints where most REST WAFs see only `POST /graphql` and
    /// miss the structure inside.
    #[command(name = "gql-diff", hide = true)]
    GqlDiff(gql_diff_cmd::GqlDiffArgs),
    /// JWT signature / claim validation scanner. Takes a KNOWN-
    /// valid bearer token (operator just logged in and captured it)
    /// and fires N mutations: alg:none case-family, kid traversal /
    /// SQL injection, jku attacker-URL, expired exp, future nbf,
    /// role elevation, empty signature with preserved alg. Any
    /// mutation accepted by the target = a JWT validation bug.
    #[command(name = "jwt-diff", hide = true)]
    JwtDiff(jwt_diff_cmd::JwtDiffArgs),
    /// CORS misconfiguration scanner. Probes 10 known
    /// Access-Control-Allow-Origin validation pitfalls (arbitrary
    /// origin reflection, null origin, subdomain prefix/suffix
    /// confusion, trailing-dot host, http downgrade, userinfo `@`
    /// injection, wildcard reflection, preflight allow-arbitrary-
    /// header, preflight DELETE permission). Reflection + ACAC:true
    /// = cookie-stealing credential leak.
    #[command(name = "cors-diff", hide = true)]
    CorsDiff(cors_diff_cmd::CorsDiffArgs),
    /// HTTP/1.1 chunked-trailer field injection scanner. WAFs typically
    /// inspect the initial header block but NOT trailing headers (the
    /// trailer fields after the final chunk in chunked Transfer-Encoding).
    /// This command fires two raw chunked POSTs — one baseline (no
    /// trailer sent) and one attack (payload injected as a trailer field)
    /// — and reports any response divergence. A divergence is evidence
    /// the backend processed the trailer while the WAF did not.
    #[command(name = "trailer-diff", hide = true)]
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
    #[command(name = "ja3-diff", hide = true)]
    Ja3Diff(ja3_diff_cmd::Ja3DiffArgs),
    /// Corpus minimization via Zeller's ddmin — alias for `wafrift distill`.
    /// Familiar to AFL/libFuzzer users as `afl-tmin` / `tmin`. Takes a
    /// KNOWN-working bypass payload and finds the minimum-edit-distance
    /// substring that STILL bypasses. Reads payload from `--payload <P>`
    /// or stdin. Outputs: minimal payload + reduction stats (original
    /// length, final length, probes spent).
    #[command(hide = true)]
    Tmin(tmin_cmd::TminArgs),
    /// Offline bypass clustering: group a `bench-waf --output` JSON by
    /// rule_id, payload class, and edit-distance similarity. Outputs
    /// clusters with a representative technique and member count per
    /// cluster. Pure offline — no HTTP. Useful for triaging large bypass
    /// corpora and identifying duplicate root causes.
    Cluster(cluster_cmd::ClusterArgs),
    /// Emit SARIF 2.1.0 from a `bench-waf --output` or `scan --output`
    /// JSON file. SARIF is the OASIS-standardised security-tool format
    /// accepted by GitHub Code Scanning, Azure DevOps, and most
    /// enterprise SAST/DAST UIs. Pipe a wafrift result into this and
    /// the bypass findings appear as first-class alerts on a PR or
    /// dashboard. Pure offline — no HTTP. Use `-` to read from stdin.
    Sarif(sarif_cmd::SarifArgs),
    /// Long-running autonomous bypass campaign. Repeatedly runs
    /// `bench-waf --evade` rounds against a target with rotating
    /// mutators/strategies, saves every confirmed bypass to a campaign
    /// JSON at `~/.wafrift/hunt-<campaign-id>.json`, and exits cleanly
    /// on Ctrl-C. Resumable: re-run with the same `--campaign-id`.
    ///
    /// Every round records the winning payload + response evidence for each
    /// confirmed bypass to a per-target corpus under `~/.wafrift`; run
    /// `wafrift harvest` afterward to turn it into review-ready reports.
    /// `hunt` NEVER submits — filing is a separate, deliberate, one-at-a-time
    /// `wafrift submit` step (auto-/batch-submitting is a bounty-ban risk).
    ///
    /// With `--target cumulusfire`: pre-fills the CF testing endpoint and
    /// authorization reason for the CumulusFire public bug-bounty scope.
    ///
    /// Environment variables (CLAUDE.md §10):
    ///   - `WAFRIFT_BENCH_URL` — fallback target when `--base-url` / `--target` omitted.
    Hunt(hunt_cmd::HuntArgs),
    /// Inspect a `wafrift corpus` artifact (rule_corpus + edge-POP coverage
    /// maps written by `wafrift bench-waf --corpus-out`). Subcommands:
    ///
    /// `stats` — print a structured summary of rules seen, total bypasses /
    /// blocks, and edge POPs covered. Supports `--format json` for CI
    /// gate integration (if rules_seen < N, fail the hunt).
    #[command(name = "corpus", hide = true)]
    Corpus(corpus_cmd::CorpusArgs),
    /// Turn a hunt/bench bypass corpus into review-ready HackerOne reports.
    ///
    /// Reads the per-target rule-bypass corpus (`~/.wafrift/corpus-<target>.json`),
    /// drops duplicates and already-handled bypasses, RE-VERIFIES each unique
    /// candidate against the live target (so the report carries fresh proof,
    /// not a stale hit), and writes one Markdown report per still-working
    /// bypass. NEVER submits — use `wafrift submit` to file reviewed reports
    /// one at a time.
    Harvest(harvest_cmd::HarvestArgs),
    /// File a SINGLE reviewed harvest report to HackerOne (guarded).
    ///
    /// Dry-run by default; pass `--confirm` to actually file the one report.
    /// wafrift never auto-submits and never batch-submits — mass-filing
    /// machine-generated reports at a bounty program is a ban risk.
    Submit(harvest_cmd::SubmitArgs),
}

// Per-command structs + entry points live in their own modules:
// - `ManArgs` + `run_man`               -> crate::man_cmd
// - `EvadeArgs` + `run_evade` + helpers -> crate::evade_cmd
// - `DetectArgs` + `run_detect` + helpers -> crate::detect_cmd
// - `ProbeArgs` + `run_probe`           -> crate::probe_cmd

/// Default inter-request delay in milliseconds for scan/tmin/bench loops.
/// Must agree with `#[arg(default_value_t)]` on [`ScanArgs::delay_ms`] and
/// with every other site that constructs a [`ScanArgs`] inline. Changing
/// the default requires updating ALL sites — this const is the canonical source.
pub(crate) const DEFAULT_DELAY_MS: u64 = 50;

/// Default per-bypass fire cap for the auto-distill pass.
/// Must agree with `#[arg(default_value_t)]` on [`ScanArgs::auto_distill_max_fires`]
/// and with the hardcoded fallback in `import_curl.rs`. Changing the default
/// requires updating ALL three sites — this const is the canonical source.
pub(crate) const DEFAULT_AUTO_DISTILL_MAX_FIRES: u32 = 200;

/// Default OOB-callback wait in seconds.
/// Must agree with `#[arg(default_value_t)]` on [`ScanArgs::callback_timeout_secs`]
/// and with the hardcoded fallback in `import_curl.rs`.
pub(crate) const DEFAULT_CALLBACK_TIMEOUT_SECS: u64 = 5;

/// Default cap on extra HTTP fires in the exploit-chain phase.
/// Must agree with `#[arg(default_value_t)]` on [`ScanArgs::exploit_cap`]
/// and with the hardcoded fallback in `import_curl.rs`.
pub(crate) const DEFAULT_EXPLOIT_CAP: usize = 500;

/// Default global total-fire budget across ALL scan phases.
/// Must agree with `#[arg(default_value_t)]` on [`ScanArgs::max_fires`]
/// and with every [`ScanArgs`] literal in the codebase. 0 = unlimited.
pub(crate) const DEFAULT_MAX_FIRES: usize = 10_000;

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
    /// or `--raw-request` is given (then targets come from those).
    //
    // Issue-5 fix (dogfood R29 cohort): the requirement marker lives
    // on the positional form so the no-args error reads
    //   error: the following required arguments were not provided:
    //     <URL>
    // matching the `Usage: wafrift scan <URL> --payload ...` banner
    // and teaching the discoverable invocation form, not the legacy
    // `--target` alias.
    #[arg(
        value_name = "URL",
        required_unless_present_any = ["target", "from_discovery", "raw_request"],
    )]
    pub target_positional: Option<String>,

    /// Long-form alias for the positional target URL — kept so every
    /// pre-existing `wafrift scan --target <URL>` invocation continues
    /// to parse. Mutually exclusive with the positional form.
    #[arg(
        long = "target",
        value_name = "URL",
        conflicts_with = "target_positional"
    )]
    pub target: Option<String>,

    /// Ingest a `wafrift discover` JSON report (file, or `-` for
    /// stdin) and scan every discovered endpoint × injection point with
    /// `--payload`. This is the gossan/recon → wafrift pipe the docs
    /// promised but never actually wired:
    /// `wafrift discover ... | wafrift scan --from-discovery - --payload '<x>'`.
    #[arg(long)]
    pub from_discovery: Option<PathBuf>,

    /// Run a corpus-wide bench measurement instead of a single-payload scan:
    /// fire every payload in this corpus directory/file at the target and
    /// report the block-rate + verified bypass-rate — the same measurement
    /// `bench-waf` performs ("scan pointed at bench"). `--payload` is ignored
    /// in this mode. Metric-safe: delegates to the unchanged bench engine.
    #[arg(long)]
    pub corpus: Option<PathBuf>,

    /// Payload to mutate and test. Empty/omitted is an input error in
    /// single-payload mode; ignored when `--corpus` is set.
    #[arg(long, default_value = "")]
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
    ///
    /// Unknown values are rejected at parse time (exit 2) so a
    /// typo (`--payload-class slq`) is caught immediately instead
    /// of silently falling through to the unclassed warm-start path.
    #[arg(
        long,
        value_name = "CLASS",
        value_parser = [
            "sql", "xss", "cmdi", "ssti", "path",
            "ldap", "xxe", "ssrf", "nosql", "log4shell",
        ],
    )]
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

    /// Evasion intensity. Approximate variant counts on an XSS
    /// payload to set expectations: light ~12, medium ~58, heavy
    /// ~1500. Heavy can produce 100x the variants of light — pair
    /// with `--dry-run` to preview the firing budget before
    /// committing to a rate-limited target. Heavy also triples the
    /// wall-clock at a fixed `--delay-ms`; use `--concurrency` to
    /// amortise.
    #[arg(long, value_enum, default_value_t = Level::Heavy)]
    pub level: Level,

    /// Apply encoding only, without grammar-aware mutations.
    #[arg(long)]
    pub encoding_only: bool,

    /// Generate variants and print the count + estimated runtime,
    /// then EXIT WITHOUT sending any requests. Rate-limit-bound
    /// pentesters (Cloudflare allows ~50 req/min on the public
    /// scope; some bug bounties cap stricter) need to preview the
    /// firing budget before committing. Pair with `--level light /
    /// medium / heavy` to compare variant counts across intensity
    /// tiers without burning the rate budget. Exit 0. Text mode prints
    /// `dry-run: N variants (explore phase) · …`; the estimate covers the
    /// EXPLORE phase only — the exploit/multi-vector phase fires more,
    /// uncounted, so treat it as a LOWER BOUND. For reliable machine parsing
    /// use `--format json`: a stable object with `variants`,
    /// `estimated_seconds`, and `estimate_scope`.
    #[arg(long)]
    pub dry_run: bool,

    /// Delay between requests in milliseconds (avoid rate-limit bans).
    #[arg(long, default_value_t = DEFAULT_DELAY_MS)]
    pub delay_ms: u64,

    /// Output format: text or json.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Select a canonical stealth browser profile for scan HTTP headers.
    ///
    /// This changes the browser HTTP identity sent by the reqwest/rustls scan path.
    /// Wire-identical TLS still lives in `wafrift-proxy --tls-impersonate
    /// <profile>`, built with the `tls-impersonate` cargo feature.
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
    #[arg(long, default_value_t = DEFAULT_AUTO_DISTILL_MAX_FIRES)]
    pub auto_distill_max_fires: u32,

    /// Concurrent in-flight variants per batch. 0 = use the dynamic
    /// default (8 with no delay, 4 with a delay) — matches every
    /// pre-flag invocation byte-for-byte. Useful when the operator's
    /// `.wafrift.toml` sets `scan.concurrency = N` to tune throughput
    /// for a slow / stable target.
    #[arg(long, default_value_t = 0)]
    pub concurrency: usize,

    /// **Per-request** HTTP timeout in seconds. Controls how long wafrift
    /// waits for a single HTTP response before giving up on that request.
    /// Large values let slow origins finish; small ones cut through faster
    /// against unresponsive targets. 0 = use the workspace default
    /// (`DEFAULT_REQUEST_TIMEOUT_SECS`). `.wafrift.toml`'s
    /// `http.timeout_secs` overrides this when the operator hasn't passed
    /// the flag explicitly.
    ///
    /// For a wall-clock cap on the WHOLE scan loop, see `--scan-timeout-secs`.
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
    #[arg(long, default_value_t = DEFAULT_CALLBACK_TIMEOUT_SECS)]
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
    #[arg(long, default_value_t = DEFAULT_EXPLOIT_CAP)]
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

    /// Explicit authorization statement for this scan target. Required
    /// for any target that is NOT on wafrift's built-in allowlist
    /// (localhost, 127.0.0.1, ::1, waf.cumulusfire.net, testing.santh.dev,
    /// ginandjuice.shop) and NOT in the operator's
    /// `~/.wafrift/permission.toml`. Supply any non-empty justification
    /// string — e.g. `--i-have-permission "HackerOne #12345 pentest scope"`.
    ///
    /// This guard is wafrift's refuse-by-default posture: the tool is
    /// a real attack engine and the operator must assert authorization
    /// explicitly for each non-lab target. Private/RFC1918 targets are
    /// always allowed (your own Docker bench, internal pentest target).
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// Force GraphQL evasion probing — inject the full
    /// `wafrift-graphql` payload battery (alias-flood, introspection,
    /// op-name-mismatch, depth-bomb, batch) into the scan regardless
    /// of whether auto-detection identifies a GraphQL endpoint.
    ///
    /// Without this flag, wafrift probes `/graphql`, `/api/graphql`,
    /// and `/v1/graphql` automatically; if a GraphQL response is
    /// detected there the payload battery is injected for that path
    /// automatically. Use `--graphql` to override when the endpoint
    /// lives at a non-standard path or behind a redirect.
    #[arg(long, default_value_t = false)]
    pub graphql: bool,

    // ─── Egress rotation ─────────────────────────────────────────────────────
    /// SOCKS5 proxy URL for egress rotation (repeatable).
    #[arg(long = "socks5", value_name = "URL", num_args = 0..)]
    pub egress_socks5: Vec<String>,

    /// HTTP proxy URL for egress rotation (repeatable).
    #[arg(long = "http-proxy", value_name = "URL", num_args = 0..)]
    pub egress_http_proxy: Vec<String>,

    /// Tailscale exit-node name for egress rotation (repeatable).
    #[arg(long = "tailscale-exit-node", value_name = "NODE", num_args = 0..)]
    pub egress_tailscale_nodes: Vec<String>,

    /// Tailscale SOCKS listener address. Default: `127.0.0.1:1055`.
    #[arg(long = "tailscale-socks-addr", value_name = "ADDR", default_value = crate::config::DEFAULT_TAILSCALE_SOCKS_ADDR)]
    pub egress_tailscale_socks_addr: String,

    /// Consecutive challenges before cooling an egress entry. Default: 3.
    #[arg(long = "egress-challenge-threshold", default_value_t = wafrift_types::DEFAULT_EGRESS_CHALLENGE_THRESHOLD)]
    pub egress_challenge_threshold: u32,

    /// Seconds a cooled egress entry stays out of rotation. Default: 300.
    #[arg(long = "egress-cooldown-secs", default_value_t = wafrift_types::DEFAULT_EGRESS_COOLDOWN_SECS)]
    pub egress_cooldown_secs: u64,

    /// **Wall-clock budget for the WHOLE scan loop** in seconds.  When
    /// the budget expires, wafrift breaks out of the probe loop, emits
    /// whatever partial results it has, and exits with code **7**
    /// ("scan-timeout-secs budget exceeded — partial results emitted").
    ///
    /// This is a cap on TOTAL scan runtime, distinct from `--timeout-secs`
    /// which is a per-request HTTP timeout.  Use `--scan-timeout-secs` to
    /// hard-bound a CI job that runs against a rate-limited target —
    /// e.g. `--scan-timeout-secs 120` caps the scan at 2 minutes and
    /// guarantees the CI step exits cleanly regardless of WAF latency.
    ///
    /// Default: no wall-clock cap (0 = unlimited).
    #[arg(long = "scan-timeout-secs", value_name = "SECS", default_value_t = 0)]
    pub scan_timeout_secs: u64,

    /// Hard cap on TOTAL HTTP fires across ALL phases (explore + differential +
    /// equivalence-moat/CEGIS + multi-vector + header-obfuscation + exploit
    /// chain + intelligence loop). When the counter reaches N, every subsequent
    /// phase is skipped and a one-line notice is emitted on stderr.
    ///
    /// Use this to bound request volume against strict rate-limit targets where
    /// `--variants-cap` and `--exploit-cap` alone are insufficient (those only
    /// cap individual phase pools, not the global total).
    ///
    /// Default: 10 000 — a generous ceiling that leaves normal scans entirely
    /// unaffected while preventing runaway fires on deeply recursive payloads.
    /// Special value 0 = unlimited (preserves pre-flag behaviour byte-identical
    /// to omitting the flag; backward-compatible).
    #[arg(long = "max-fires", value_name = "N", default_value_t = DEFAULT_MAX_FIRES)]
    pub max_fires: usize,

    /// When WAF engagement assessment finds the injection point is not
    /// inspected (benign and attack responses are identical), skip the
    /// expensive evasion phases and do not count pass-through as bypass.
    /// Pass this flag to preserve the pre-0.3.1 behaviour (fire all
    /// variants anyway; `bypass_rate_pct` includes unguarded pass-through).
    #[arg(long)]
    pub full_scan_unguarded: bool,

    /// Harvest forms/API paths from the target HTML and preflight each
    /// candidate surface (lightweight engagement check). Emits
    /// `surface_probe` in JSON output with ranked alternatives.
    /// Default: on when `--auto-escalate` is enabled.
    #[arg(long)]
    pub probe_surfaces: bool,

    /// Before baseline, probe HTML surfaces and pivot to the best WAF-guarded
    /// injection point when the CLI `param` is unguarded (default: on).
    /// Disable with `--no-auto-escalate`.
    #[arg(long, default_value_t = true)]
    pub auto_escalate: bool,

    /// Disable automatic surface escalation (keeps scanning only `param` on the CLI URL).
    #[arg(long = "no-auto-escalate")]
    pub no_auto_escalate: bool,

    /// Disable surface harvest/preflight entirely.
    #[arg(long = "no-probe-surfaces")]
    pub no_probe_surfaces: bool,

    /// Max alternative surfaces to preflight when surface probing is enabled.
    #[arg(long = "surface-cap", default_value_t = 12)]
    pub surface_cap: usize,
}

impl ScanArgs {
    /// Resolved target URL — the positional form if supplied, else the
    /// long-form `--target` flag, else `None` (only possible when
    /// `--from-discovery` is in play; clap's
    /// `required_unless_present_any` guarantees the user-facing
    /// invariant).
    #[must_use]
    pub fn resolved_target(&self) -> Option<&str> {
        self.target_positional.as_deref().or(self.target.as_deref())
    }
}

#[derive(clap::Args, Debug)]
struct TechniquesArgs {
    #[command(subcommand)]
    action: TechniquesAction,
}

#[derive(Subcommand, Debug)]
enum TechniquesAction {
    /// Print the technique tree.
    List(TechniquesListArgs),
    /// Print the explanation for a single technique selector
    /// (e.g. `wafrift techniques explain tamper/json_unicode_alnum`).
    /// Dogfood B4 fix: previously the only way to see per-technique
    /// docs was to scan with `--explain`.
    ///
    /// Issue-1 fix (dogfood R43 cohort): `show` aliased as the
    /// natural cargo/git verb for the same operation.
    #[command(alias = "show")]
    Explain(TechniquesExplainArgs),
}

#[derive(clap::Args, Debug)]
struct TechniquesListArgs {
    /// Output format. `tree` (default) prints the ASCII tree;
    /// `json` emits the list as a structured array for downstream
    /// tooling. Dogfood B4 fix: previously no machine-readable form.
    #[arg(long, default_value = "tree", value_parser = ["tree", "json"])]
    format: String,
}

#[derive(clap::Args, Debug)]
struct TechniquesExplainArgs {
    /// Selector to explain (e.g. `tamper/json_unicode_alnum`,
    /// `encoding/url/single`).
    selector: String,

    /// Output format. `text` (default) prints a human-readable
    /// summary; `json` emits a structured object. Issue-5 fix
    /// (dogfood R43 cohort): every other subcommand honours
    /// --format and global -q, so explain matches now.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    format: String,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Light,
    Medium,
    Heavy,
}
/// Arguments for `wafrift completion <SHELL>`.
#[derive(clap::Args, Debug)]
struct CompletionArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    shell: Shell,
}
fn main() -> ExitCode {
    // Structured tracing — honours RUST_LOG (e.g. `RUST_LOG=wafrift=debug`).
    // Compact single-line format on stderr; target field on; fallback to `warn`
    // when RUST_LOG is unset.
    // Issue-9/10 fix (dogfood R43 cohort): tracing output now
    // disables ANSI escapes when (a) NO_COLOR=1 is set (per the
    // NO_COLOR.org convention) OR (b) stderr is not a terminal
    // (piped output, log file, CI). Pre-fix `wafrift legendary 2>&1
    // | grep WARN` carried raw `[2m...[33m WARN[0m` escape codes
    // through the pipe and broke downstream consumers; the colored
    // tracing decoration is operator-UX, not part of the log
    // contract.
    let stderr_is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let want_ansi = stderr_is_tty && std::env::var_os("NO_COLOR").is_none();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(true)
        .with_ansi(want_ansi)
        .compact()
        .with_writer(std::io::stderr)
        .try_init();

    // Install the process-wide rustls crypto provider once, up front.
    // rustls 0.23 requires a default `CryptoProvider` to be installed
    // before any `ClientConfig::builder()` call. The raw-TLS commands
    // (trailer-diff, ja3-diff, scan's TLS probes) build a `ClientConfig`
    // directly and would otherwise panic ("no process-level
    // CryptoProvider available") on the FIRST https target — a 100%
    // crash on `trailer-diff --url https://…`. reqwest installs its own
    // internally, so this may already be set; ignore AlreadyInstalled.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    // Pentesters routinely pipe wafrift's output to `head`, `jq`, `grep
    // -m 1`, etc. Rust's default behaviour is to ignore SIGPIPE and
    // panic on EPIPE the next time stdout is written, which surfaces
    // as `thread 'main' panicked at 'failed printing to stdout: Broken
    // pipe'`. Reset the SIGPIPE handler to SIG_DFL so the process
    // exits silently when the consumer closes the pipe — the canonical
    // CLI idiom that `cat`, `ls`, `grep`, etc. all use.
    #[cfg(unix)]
    {
        // SAFETY: signal(2) is async-signal-safe; we install SIG_DFL
        // before any I/O so no concurrent writers race the handler
        // change.
        #[allow(unsafe_code)]
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }

    // Keep the raw `ArgMatches` (not just the derived struct) so the
    // scan path can ask clap whether each field came from the command
    // line vs a compiled default — required to layer `.wafrift.toml`
    // underneath CLI flags with correct precedence.
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    // Store quiet flag for use in subcommands.
    if cli.quiet {
        // In quiet mode, disable colored output entirely.
        colored::control::set_override(false);
    }

    // R44-I7 fix (dogfood pass 4): surface stale `.corrupt-<epoch>`
    // learning-cache siblings on startup. Pre-fix a mid-write
    // crash left e.g. `~/.wafrift/learning_cache.corrupt-1779065925`
    // sitting on disk indefinitely with NO user-facing notice.
    // Three gates so the advisory does not become noise:
    //   * --quiet skips entirely (machine consumers)
    //   * stderr-is-not-TTY skips (CI / piped stderr)
    //   * any of the diff/status subcommands skip (the advisory
    //     belongs on interactive sessions, not bench-diff in CI)
    let interactive_stderr = std::io::IsTerminal::is_terminal(&std::io::stderr());
    if !cli.quiet
        && interactive_stderr
        && let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
    {
        let dir = std::path::PathBuf::from(home).join(".wafrift");
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let stale: Vec<String> = entries
                .filter_map(Result::ok)
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if name.contains(".corrupt-") {
                        Some(name)
                    } else {
                        None
                    }
                })
                .collect();
            if !stale.is_empty() {
                use colored::Colorize;
                eprintln!(
                    "{} {} quarantined cache file(s) in {}: {}\n  \
                     Tip: these came from a mid-write crash and are NOT \
                     active. Remove with `rm ~/.wafrift/*.corrupt-*` after \
                     inspecting if needed.",
                    "advisory:".yellow().bold(),
                    stale.len(),
                    dir.display(),
                    stale.join(", ").bright_black()
                );
            }
        }
    }

    // Load config file (--config flag overrides default search paths).
    let cfg = if let Some(ref path) = cli.config {
        match config::WafRiftConfig::load_from(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{} {e}", "Config error:".red().bold());
                return ExitCode::from(1);
            }
        }
    } else {
        config::WafRiftConfig::load()
    };

    // Publish the operator's User-Agent override to the process-wide
    // OnceLock that every command's HTTP-client builder reads. Prior
    // to this wiring the `http.user_agent` field in `.wafrift.toml`
    // was parsed-and-ignored — `.user_agent("Mozilla/5.0 …")` was
    // hardcoded at every call site. Now setting the config field
    // actually changes the wire bytes for detect / cors-diff /
    // header-diff / body-diff / query-diff / cache-diff / h2-diff /
    // gql-diff / distill / scan. `bench-waf` keeps its own
    // fingerprint-rotation path (different concern: bypass impact).
    config::install_user_agent(cfg.http.user_agent.clone());

    // Publish the differential-baseline toggle (global `--differential`) to
    // the process-wide OnceLock the equiv engine reads. Off → crediting is
    // byte-for-byte the legacy metric; on → a variant counts only when the
    // un-evaded base is blocked in the same delivery (anti-rig §12).
    config::install_differential(cli.differential);

    // Publish the detonation-engine selector (global `--detonate-engine`) so
    // every `detonate` subprocess wafrift spawns (prove-execution / exploit /
    // proxy) uses the requested oracle — `chrome` for the browser-accurate
    // mutation-XSS path, `jsdet` (default) for the fast sandbox.
    config::install_detonate_engine(&cli.detonate_engine);

    let quiet = cli.quiet;

    // §7 DEDUP / §4 ELEGANCE: every diff-family command (the flat `<kind>-diff`
    // aliases AND the consolidated `diff <kind>`) shares one shape — layer
    // `.wafrift.toml` http defaults under the CLI flags (CLI wins), then
    // block-on the async runner. Pre-extract this was copy-pasted at 22 call
    // sites; now it lives in ONE place and each arm is a one-line dispatch, so
    // a change to the layering rule is a single edit. The only per-arm variation
    // is the args struct, the sub-command name (for explicit-flag detection),
    // and the runner fn. (`path`/`ja3` diffs are sync + Result-shaped, so they
    // stay bespoke below.)
    fn run_http_diff<A, F, Fut>(
        cfg: &config::WafRiftConfig,
        args: A,
        sub_matches: Option<&clap::ArgMatches>,
        run: F,
    ) -> ExitCode
    where
        A: config::HasHttpConfig,
        F: FnOnce(A) -> Fut,
        Fut: std::future::Future<Output = ExitCode>,
    {
        let args = cfg.apply_http_defaults(args, sub_matches);
        helpers::block_on_with_runtime(async move { run(args).await })
    }

    match cli.command {
        None => interactive::run_interactive(),
        Some(Commands::Evade(args)) => evade_cmd::run_evade(args, quiet),
        Some(Commands::Exploit(args)) => exploit_cmd::run_exploit(args),
        Some(Commands::ClientDeliver(args)) => client_deliver_cmd::run_client_deliver(args),
        Some(Commands::SanitizerDecompile(args)) => {
            sanitizer_decompile_cmd::run_sanitizer_decompile(args)
        }
        Some(Commands::TcpOverlap(args)) => tcp_overlap_cmd::run_tcp_overlap(args),
        Some(Commands::Detect(args)) => {
            // R48 pass-10 I1 (CLAUDE.md §9 WIRING): consume
            // http.timeout_secs / http.insecure from .wafrift.toml
            // when the operator did not pass the flag explicitly.
            let args = cfg.apply_http_defaults(args, matches.subcommand_matches("detect"));
            detect_cmd::run_detect(args, quiet)
        }
        Some(Commands::Probe(args)) => {
            probe_cmd::run_probe(args);
            ExitCode::SUCCESS
        }
        Some(Commands::Scan(args)) => {
            // Layer .wafrift.toml under the CLI flags (CLI wins).
            let args = cfg.apply_to_scan(args, matches.subcommand_matches("scan"));
            // "scan pointed at bench": `--corpus` runs the corpus-wide bench
            // measurement (block-rate + verified bypass-rate) instead of a
            // single-payload scan. Metric-safe — it delegates to the UNCHANGED
            // `run_bench_waf` engine (mapping target / timeout / permission
            // across); `--payload` is irrelevant here. Gated like the bench-waf
            // CLI arm (§15 least-privilege).
            if let Some(corpus) = args.corpus.clone() {
                let Some(base_url) = args.resolved_target().map(str::to_string) else {
                    return helpers::input_error(
                        "`scan --corpus` needs a target URL (positional or --target)",
                    );
                };
                permission::assert_permitted(&base_url, args.i_have_permission.as_deref());
                let bench_args = bench_waf::BenchWafArgs {
                    base_url: Some(base_url),
                    corpus,
                    evade: true,
                    variants: 5,
                    strategies: vec!["heavy".into(), "equiv-cegis".into()],
                    timeout_secs: args.timeout_secs,
                    i_have_permission: args.i_have_permission.clone(),
                    format: "text".into(),
                    adaptive_pause_after_errors: 50,
                    adaptive_pause_secs: 2,
                    ..Default::default()
                };
                return bench_waf::run_bench_waf(bench_args);
            }
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: failed to start tokio runtime: {e}");
                    return ExitCode::from(1);
                }
            };
            rt.block_on(async {
                // Install graceful Ctrl+C handler so gene bank can be saved on interrupt.
                let cancel = tokio_util::sync::CancellationToken::new();
                let cancel_clone = cancel.clone();
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!(
                            "\n{}",
                            "⚠ Ctrl+C received — finishing current request and saving results..."
                                .yellow()
                                .bold()
                        );
                        cancel_clone.cancel();
                    }
                });
                if args.from_discovery.is_some() {
                    run_scan_from_discovery(args, cancel).await
                } else {
                    scan::run_scan(args, cancel).await
                }
            })
        }
        Some(Commands::Distill(args)) => {
            let args = cfg.apply_http_defaults(args, matches.subcommand_matches("distill"));
            helpers::block_on_with_runtime(async {
                let cancel = tokio_util::sync::CancellationToken::new();
                let cancel_clone = cancel.clone();
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!(
                            "\n{}",
                            "⚠ Ctrl+C received — finishing current request and exiting..."
                                .yellow()
                                .bold()
                        );
                        cancel_clone.cancel();
                    }
                });
                distill_cmd::run_distill(args, cancel).await
            })
        }
        Some(Commands::HeaderDiff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("header-diff"),
            header_diff_cmd::run_header_diff,
        ),
        Some(Commands::BodyDiff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("body-diff"),
            body_diff_cmd::run_body_diff,
        ),
        Some(Commands::QueryDiff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("query-diff"),
            query_diff_cmd::run_query_diff,
        ),
        Some(Commands::Attack(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("attack"),
            attack_cmd::run_attack,
        ),
        Some(Commands::CacheDiff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("cache-diff"),
            cache_diff_cmd::run_cache_diff,
        ),
        Some(Commands::H2Diff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("h2-diff"),
            h2_diff_cmd::run_h2_diff,
        ),
        Some(Commands::MethodDiff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("method-diff"),
            method_diff_cmd::run_method_diff,
        ),
        Some(Commands::GqlDiff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("gql-diff"),
            gql_diff_cmd::run_gql_diff,
        ),
        Some(Commands::JwtDiff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("jwt-diff"),
            jwt_diff_cmd::run_jwt_diff,
        ),
        Some(Commands::TrailerDiff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("trailer-diff"),
            trailer_diff_cmd::run_trailer_diff,
        ),
        Some(Commands::CorsDiff(args)) => run_http_diff(
            &cfg,
            args,
            matches.subcommand_matches("cors-diff"),
            cors_diff_cmd::run_cors_diff,
        ),
        #[cfg(feature = "tls-impersonate")]
        Some(Commands::Ja3Diff(args)) => ja3_diff_cmd::run_ja3_diff(args),
        Some(Commands::BenchWaf(args)) => {
            // R48 pass-10 I1 (CLAUDE.md §9 WIRING): consume
            // http.timeout_secs / http.insecure from config.
            let args = cfg.apply_http_defaults(args, matches.subcommand_matches("bench-waf"));
            // §15 / least-privilege: bench-waf fires real attack payloads, so
            // (like scan/hunt) refuse a non-allowlisted explicit `--base-url`
            // unless the operator acknowledges via `--i-have-permission`. Lab /
            // CI / CumulusFire targets are allowlisted; the env/default URL is
            // local + operator-trusted, so only an explicit target is gated.
            if let Some(ref target) = args.base_url {
                permission::assert_permitted(target, args.i_have_permission.as_deref());
            }
            bench_waf::run_bench_waf(args)
        }
        Some(Commands::BenchDiff(mut args)) => {
            // R50 pass-12 I1 (CLAUDE.md §9 WIRING): apply
            // config.output.format default to bench-diff. Pre-fix
            // operators saw .wafrift.toml's [output] format = "json"
            // respected by every command except bench-diff.
            if matches.subcommand_matches("bench-diff").is_none_or(|m| {
                !matches!(
                    m.value_source("format"),
                    Some(clap::parser::ValueSource::CommandLine)
                )
            }) {
                args.format.clone_from(&cfg.output.format);
            }
            bench_diff::run_bench_diff(args)
        }
        Some(Commands::OriginHints(args)) => origin_hints::run_origin_hints(args),
        Some(Commands::EgressExample(args)) => egress_example::run_egress_example(args),
        Some(Commands::Techniques(args)) => match args.action {
            TechniquesAction::List(sub) => match sub.format.as_str() {
                "json" => {
                    let names = wafrift_encoding::all_tamper_names();
                    let strategies: Vec<String> = wafrift_encoding::all_strategies()
                        .iter()
                        .map(|s| technique_filter::strategy_path(*s).to_string())
                        .collect();
                    // HTTP/3 + QUIC evasion technique names.
                    let http3_techniques: Vec<&'static str> =
                        wafrift_http3_evasion::EvasionTechnique::all()
                            .iter()
                            .map(|t| t.description())
                            .collect();
                    let payload = serde_json::json!({
                        "tampers": names,
                        "encoding_strategies": strategies,
                        "http3_techniques": http3_techniques,
                    });
                    println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                    ExitCode::SUCCESS
                }
                _ => {
                    print!("{}", technique_filter::render_tree());
                    ExitCode::SUCCESS
                }
            },
            TechniquesAction::Explain(sub) => {
                // Look up the selector and print its description. Tamper
                // selectors hit the TamperRegistry; encoding selectors
                // hit the Strategy enum.
                //
                // Issue-5 fix (dogfood R43 cohort): --format json (or
                // global -q) emits a structured object instead of the
                // text summary. Every other subcommand honours --format;
                // explain matches now.
                let want_json = sub.format == "json" || cli.quiet;
                let sel = sub.selector.trim_matches('/').to_string();
                if let Some(name) = sel.strip_prefix("tamper/") {
                    let reg = wafrift_encoding::TamperRegistry::with_defaults();
                    if let Some(s) = reg.get(name) {
                        if want_json {
                            let obj = serde_json::json!({
                                "schema_version": 1,
                                "selector": sel,
                                "kind": "tamper",
                                "name": s.name(),
                                "description": s.description(),
                                "aggressiveness": s.aggressiveness(),
                            });
                            println!("{}", serde_json::to_string(&obj).unwrap_or_default());
                        } else {
                            println!("{}: {}", s.name(), s.description());
                            println!("aggressiveness: {:.2}", s.aggressiveness());
                        }
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "unknown tamper `{name}`. Tip: `wafrift techniques list` to enumerate."
                        );
                        ExitCode::from(2)
                    }
                } else if sel.starts_with("encoding/") {
                    // Find any strategy whose path matches.
                    let found = wafrift_encoding::all_strategies()
                        .iter()
                        .copied()
                        .find(|s| technique_filter::strategy_path(*s) == sel);
                    if let Some(s) = found {
                        if want_json {
                            let obj = serde_json::json!({
                                "schema_version": 1,
                                "selector": sel,
                                "kind": "encoding",
                                "aggressiveness": wafrift_encoding::aggressiveness(s),
                            });
                            println!("{}", serde_json::to_string(&obj).unwrap_or_default());
                        } else {
                            println!(
                                "{}: encoding strategy (aggressiveness {:.2})",
                                sel,
                                wafrift_encoding::aggressiveness(s)
                            );
                        }
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "unknown encoding selector `{sel}`. Tip: `wafrift techniques list`."
                        );
                        ExitCode::from(2)
                    }
                } else {
                    eprintln!(
                        "selector must start with `tamper/` or `encoding/`; got `{sel}`. \
                         Tip: `wafrift techniques list`."
                    );
                    ExitCode::from(2)
                }
            }
        },
        Some(Commands::Completion(args)) => {
            let mut cmd = Cli::command();
            generate(args.shell, &mut cmd, "wafrift", &mut io::stdout());
            ExitCode::SUCCESS
        }
        Some(Commands::Recon(args)) => recon_cmd::run_recon(args),
        Some(Commands::Discover(args)) => discover_cmd::run_discover(
            // R56 pass-20 I1 (CLAUDE.md §9 WIRING): discover was the last
            // network-capable subcommand that silently ignored
            // `.wafrift.toml`'s http.timeout_secs / http.insecure.
            cfg.apply_http_defaults(args, matches.subcommand_matches("discover")),
        ),
        Some(Commands::Replay(args)) => replay::run_replay(
            // R68 pass-21: route through apply_http_defaults so
            // `.wafrift.toml` http.timeout / http.insecure reach the
            // replay engine (pre-fix the only network subcommand
            // without this wiring).
            cfg.apply_http_defaults(args, matches.subcommand_matches("replay")),
        ),
        Some(Commands::Report(args)) => report::run_report(args),
        Some(Commands::Init(args)) => init_cmd::run_init(args),
        Some(Commands::Seed(args)) => seed::run_seed(args),
        Some(Commands::ImportCurl(args)) => import_curl::run_import_curl(args),
        Some(Commands::Bank(args)) => bank::run_bank(args),
        Some(Commands::BypassProbe(args)) => match bypass_probe::run_bypass_probe(
            cfg.apply_http_defaults(args, matches.subcommand_matches("bypass-probe")),
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("bypass-probe failed: {e}");
                ExitCode::from(1)
            }
        },
        Some(Commands::Man(args)) => man_cmd::run_man(args),
        Some(Commands::ModelEvade(args)) => model_evade_cmd::run_model_evade(args),
        Some(Commands::Audit(args)) => wafmodel_cmd::run_audit(args),
        Some(Commands::Harden(args)) => wafmodel_cmd::run_harden(args),
        Some(Commands::Fingerprint(args)) => wafmodel_cmd::run_fingerprint(args),
        Some(Commands::Legendary(args)) => legendary::run_legendary(args),
        Some(Commands::Listener(args)) => listener_cmd::run_listener(args),
        Some(Commands::ParserDiff(args)) => match parser_diff_cmd::run_parser_diff(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("parser-diff failed: {e}");
                ExitCode::from(1)
            }
        },
        // §7 DEDUPLICATION / sharper-knife: the parser-diff family
        // (eleven `<kind>-diff` commands + `attack`) is grouped under one
        // advertised `diff` verb. Each arm reuses the SAME Args + run_*
        // function as the (now hidden, deprecated) flat command, so
        // behaviour is byte-identical — pure surface consolidation. The
        // nested `subcommand_matches("diff").and_then(... <kind>)` lookup
        // feeds each probe the same config-default detection it gets as a
        // top-level command.
        Some(Commands::Diff(d)) => {
            let dm = matches.subcommand_matches("diff");
            match d.kind {
                diff_cmd::DiffKind::Path(args) => match parser_diff_cmd::run_parser_diff(args) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("parser-diff failed: {e}");
                        ExitCode::from(1)
                    }
                },
                diff_cmd::DiffKind::Header(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("header")),
                    header_diff_cmd::run_header_diff,
                ),
                diff_cmd::DiffKind::Body(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("body")),
                    body_diff_cmd::run_body_diff,
                ),
                diff_cmd::DiffKind::Query(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("query")),
                    query_diff_cmd::run_query_diff,
                ),
                diff_cmd::DiffKind::Cache(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("cache")),
                    cache_diff_cmd::run_cache_diff,
                ),
                diff_cmd::DiffKind::H2(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("h2")),
                    h2_diff_cmd::run_h2_diff,
                ),
                diff_cmd::DiffKind::Method(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("method")),
                    method_diff_cmd::run_method_diff,
                ),
                diff_cmd::DiffKind::Gql(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("gql")),
                    gql_diff_cmd::run_gql_diff,
                ),
                diff_cmd::DiffKind::Jwt(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("jwt")),
                    jwt_diff_cmd::run_jwt_diff,
                ),
                diff_cmd::DiffKind::Cors(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("cors")),
                    cors_diff_cmd::run_cors_diff,
                ),
                diff_cmd::DiffKind::Trailer(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("trailer")),
                    trailer_diff_cmd::run_trailer_diff,
                ),
                diff_cmd::DiffKind::All(args) => run_http_diff(
                    &cfg,
                    args,
                    dm.and_then(|m| m.subcommand_matches("all")),
                    attack_cmd::run_attack,
                ),
                #[cfg(feature = "tls-impersonate")]
                diff_cmd::DiffKind::Ja3(args) => ja3_diff_cmd::run_ja3_diff(args),
            }
        }
        Some(Commands::Compress(args)) => compress_cmd::run_compress(args),
        Some(Commands::Smuggle(args)) => smuggle_cmd::run_smuggle(args),
        Some(Commands::SmuggleEmit(args)) => smuggle_emit_cmd::run_smuggle_emit(args),
        Some(Commands::SmuggleCrossProduct(args)) => {
            smuggle_cross_cmd::run_smuggle_cross_product(args)
        }
        Some(Commands::SmuggleStats(args)) => smuggle_stats_cmd::run_smuggle_stats(args),
        Some(Commands::SmuggleChain(args)) => smuggle_chain_cmd::run_smuggle_chain(args),
        Some(Commands::SmuggleFire(args)) => smuggle_fire_cmd::run_smuggle_fire(args),
        Some(Commands::Tmin(args)) => {
            let args = cfg.apply_http_defaults(args, matches.subcommand_matches("tmin"));
            helpers::block_on_with_runtime(async {
                let cancel = tokio_util::sync::CancellationToken::new();
                let cancel_clone = cancel.clone();
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!(
                            "\n{}",
                            "⚠ Ctrl+C received — finishing current probe and exiting..."
                                .yellow()
                                .bold()
                        );
                        cancel_clone.cancel();
                    }
                });
                tmin_cmd::run_tmin(args, cancel).await
            })
        }
        Some(Commands::Cluster(args)) => cluster_cmd::run_cluster(args),
        Some(Commands::Sarif(args)) => sarif_cmd::run_sarif(args),
        Some(Commands::Hunt(args)) => hunt_cmd::run_hunt(args),
        Some(Commands::Corpus(args)) => corpus_cmd::run_corpus(args),
        Some(Commands::Harvest(args)) => harvest_cmd::run_harvest(args),
        Some(Commands::Submit(args)) => harvest_cmd::run_submit(args),
    }
}

// (interactive TUI body lives in `crate::interactive::run_interactive`;
//  `run_man` lives in `crate::man_cmd`.)

// `run_evade` + `resolve_payload` live in `crate::evade_cmd`.

// `DetectFetch`, `fetch_for_detect`, `infra_markers` live in
// `crate::detect_cmd` and are re-exported pub(crate) for use by
// `crate::legendary`.

/// Expand a `wafrift discover` JSON report into one `run_scan` per
/// (endpoint URL × injection-point name) and run them in sequence with
/// the operator's `--payload`. This is the recon → wafrift pipe the
/// help text advertised for releases but never actually implemented
/// (`scan --from-discovery` was a documented flag that did not exist).
async fn run_scan_from_discovery(
    args: ScanArgs,
    cancel: tokio_util::sync::CancellationToken,
) -> ExitCode {
    let Some(ref src) = args.from_discovery else {
        unreachable!("caller checked from_discovery.is_some()");
    };
    let raw = if src.as_os_str() == "-" {
        // Bounded read: an unbounded stdin().read_to_string() would OOM
        // on `wafrift scan --from-discovery - < /dev/zero`. Discovery
        // JSON reports are compact; GENE_BANK_FILE_MAX_BYTES (64 MiB) is
        // far above any real report and prevents memory exhaustion.
        match safe_body::read_bounded_text_stdin(safe_body::GENE_BANK_FILE_MAX_BYTES) {
            Ok(s) => s,
            Err(e) => {
                return helpers::input_error(format!("read discovery report from stdin: {e}"));
            }
        }
    } else {
        // Bounded read: operator-supplied path may be /dev/zero or symlink.
        match safe_body::read_bounded_text_file(src, safe_body::GENE_BANK_FILE_MAX_BYTES) {
            Ok(s) => s,
            Err(e) => {
                return helpers::input_error(format!("read {}: {e}", src.display()));
            }
        }
    };
    let report: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return helpers::input_error(format!("parse discovery report: {e}"));
        }
    };
    let endpoints = report
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if endpoints.is_empty() {
        // R48-I3 fix (dogfood pass 9): wrong schema / no endpoints
        // is an input-format error, exit 2 (clap convention).
        eprintln!(
            "{} discovery report has no `endpoints` — nothing to scan (is this `wafrift discover` JSON?)",
            "error:".red()
        );
        return ExitCode::from(2);
    }

    // N1 fix (dogfood R29 cohort): `discover --spec` historically
    // emitted PATH-ONLY URLs (Swagger 2.0 with no host, OpenAPI 3.x
    // before we read servers[0].url). The scan pipeline then fired
    // at literal `https:///login` (empty host). The discover side
    // now synthesizes absolute URLs when the spec carries enough
    // info; this side joins any remaining relative entry against
    // the operator's `--target` base. Both layers belt + braces.
    let base_target = args.target.clone().or(args.target_positional.clone());
    let resolve_url = |raw: &str| -> Option<String> {
        if raw.contains("://") {
            Some(raw.to_string())
        } else if let Some(ref base) = base_target {
            // Trim trailing `/` on base, ensure exactly one `/` join.
            let b = base.trim_end_matches('/');
            let suffix = if raw.starts_with('/') {
                raw.to_string()
            } else {
                format!("/{raw}")
            };
            Some(format!("{b}{suffix}"))
        } else {
            // No scheme and no --target base — unresolvable.
            None
        }
    };

    // Flatten to concrete (url, param) jobs. An endpoint with no
    // injection points still gets scanned on the default param so a
    // bare URL list is usable.
    let mut jobs: Vec<(String, String)> = Vec::new();
    let mut unresolved = 0usize;
    for ep in &endpoints {
        let Some(raw_url) = ep.get("url").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(url) = resolve_url(raw_url) else {
            unresolved += 1;
            continue;
        };
        let points: Vec<String> = ep
            .get("injection_points")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        p.get("name")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();
        if points.is_empty() {
            jobs.push((url.clone(), args.param.clone()));
        } else {
            for name in points {
                jobs.push((url.clone(), name));
            }
        }
    }
    if unresolved > 0 {
        eprintln!(
            "[wafrift scan] {unresolved} discovered endpoint(s) had path-only URLs and no \
             `--target` base was given — those endpoints were skipped. Re-run with \
             `--target https://your-target/` to resolve them."
        );
    }

    eprintln!(
        "[wafrift scan] --from-discovery: {} endpoint(s) → {} scan job(s)",
        endpoints.len(),
        jobs.len()
    );

    // When the operator asked for `--format json`, each underlying
    // `scan::run_scan` would write its own JSON object to stdout.
    // For N jobs that produces N back-to-back JSON objects — invalid
    // JSON (multiple root values) so `wafrift scan --from-discovery
    // X.json --format json | jq .` failed at the second object. Fix:
    // when JSON mode + discovery mode, redirect every sub-job to a
    // tmpfile, then read them all back and emit a single
    // `{"discovery_scan": {"jobs": [...]}}` envelope. Text mode is
    // unchanged — per-job streaming output is the right shape there.
    let want_json = args.format == "json";

    // --dry-run is a SAFETY CONTRACT: preview the blast radius, fire nothing.
    // Without this gate the loop below fires LIVE against every discovered
    // endpoint — an operator sizing a scan with `--from-discovery X --dry-run`
    // would unexpectedly hit the target N jobs × per-job-variant times (the
    // single-target scan path honours --dry-run; this multi-job path did not).
    if args.dry_run {
        if want_json {
            println!(
                r#"{{"schema_version":1,"dry_run":true,"discovery_scan":{{"endpoints":{},"jobs":{}}}}}"#,
                endpoints.len(),
                jobs.len()
            );
        } else {
            println!(
                "dry-run: {} discovery endpoint(s) → {} scan job(s) · delay={}ms — re-run \
                 without --dry-run to fire (each job then fires its own variant budget)",
                endpoints.len(),
                jobs.len(),
                args.delay_ms,
            );
        }
        return ExitCode::SUCCESS;
    }

    let mut per_job_envelopes: Vec<serde_json::Value> = Vec::new();
    let mut last = ExitCode::SUCCESS;
    for (i, (url, param)) in jobs.iter().enumerate() {
        if cancel.is_cancelled() {
            eprintln!(
                "[wafrift scan] cancelled — {} job(s) not run",
                jobs.len() - i
            );
            break;
        }
        eprintln!(
            "\n[wafrift scan] ── job {}/{}: {url} (param={param}) ──",
            i + 1,
            jobs.len()
        );
        // Build a per-job tmpfile path when collecting JSON. Cleaned
        // up unconditionally after the read attempt so a panic in
        // run_scan can't leak a tmpfile, and we don't bother allocating
        // the path in text mode (where each job streams to stdout).
        let tmp_path: Option<PathBuf> = if want_json {
            Some(crate::helpers::secure_tmp_path(
                &format!("wafrift-discovery-job-{i}"),
                "json",
            ))
        } else {
            None
        };
        let job_args = ScanArgs {
            target_positional: None,
            target: Some(url.clone()),
            from_discovery: None,
            corpus: None,
            payload: args.payload.clone(),
            param: param.clone(),
            payload_class: args.payload_class.clone(),
            callback_url: args.callback_url.clone(),
            session_init: args.session_init.clone(),
            level: args.level,
            encoding_only: args.encoding_only,
            dry_run: false,
            delay_ms: args.delay_ms,
            format: args.format.clone(),
            stealth_browser: args.stealth_browser.clone(),
            insecure: args.insecure,
            report_layers: args.report_layers,
            only: args.only.clone(),
            exclude: args.exclude.clone(),
            // Per-job: in JSON mode, a tmpfile we drain into the array;
            // in text mode, None so the existing per-job text streams
            // straight to stdout.
            output: tmp_path.clone(),
            proxy: args.proxy.clone(),
            header: args.header.clone(),
            // --from-discovery jobs always come from URL discovery,
            // never from a raw request template — those modes are
            // alternative inputs, not stackable.
            raw_request: None,
            raw_request_scheme: args.raw_request_scheme.clone(),
            // Forward the operator's auto-distill choice to every
            // discovered-endpoint scan job — they almost certainly
            // want consistent reporting across all hosts.
            auto_distill: args.auto_distill,
            auto_distill_max_fires: args.auto_distill_max_fires,
            concurrency: args.concurrency,
            timeout_secs: args.timeout_secs,
            // N8 fix (dogfood R29 cohort): suppress each per-job
            // banner box — the from-discovery driver already prints
            // a `── job N/M: <url> ──` boundary line, so the inner
            // banner would just repeat the WafRift logo, target,
            // and variant count N times in a row. Quiet is forced;
            // operator-supplied --quiet is still respected (forcing
            // quiet=true only ever DROPS noise, never silences a
            // request the operator wanted to see).
            quiet: true,
            callback_timeout_secs: args.callback_timeout_secs,
            exploit_cap: args.exploit_cap,
            variants_cap: args.variants_cap,
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
            // Forward the wall-clock budget to every per-discovery job.
            scan_timeout_secs: args.scan_timeout_secs,
            // Forward the global fire budget to every per-discovery job.
            max_fires: args.max_fires,
            full_scan_unguarded: args.full_scan_unguarded,
            probe_surfaces: args.probe_surfaces,
            auto_escalate: args.auto_escalate,
            no_auto_escalate: args.no_auto_escalate,
            no_probe_surfaces: args.no_probe_surfaces,
            surface_cap: args.surface_cap,
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
                    // Atomic write: tmp sibling → rename, so a kill mid-write
                    // never leaves a truncated JSON file on disk.
                    let tmp = out_path.with_extension("json.tmp");
                    let write_result =
                        std::fs::write(&tmp, &s).and_then(|()| std::fs::rename(&tmp, out_path));
                    if let Err(e) = write_result {
                        let _ = std::fs::remove_file(&tmp);
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
