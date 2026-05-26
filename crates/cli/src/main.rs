use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use colored::Colorize;
use std::io;
use std::io::IsTerminal;
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
mod compress_cmd;
mod config;
mod cors_diff_cmd;
mod detect_cmd;
mod discover_cmd;
mod distill_cmd;
mod corpus_cmd;
mod corpus_recorder;
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
/// Target-permission gate. Refuse-by-default for non-bounty,
/// non-allowlist hosts; `--i-have-permission &lt;reason&gt;` overrides.
/// Local Docker bench targets (loopback / RFC1918) always pass.
mod permission;
mod parser_diff_cmd;
mod parser_diff_common;
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
mod scan;
mod seed;
mod session_init;
mod smuggle_cmd;
mod target_context;
mod technique_filter;
mod trailer_diff_cmd;
mod model_evade_cmd;
mod wafmodel_cmd;
mod tmin_cmd;
mod cluster_cmd;
mod hunt_cmd;

// All per-command helpers are imported by their command modules now.
// main.rs is reduced to dispatch + the top-level Cli/Commands surface.

#[derive(Parser, Debug)]
#[command(
    name = "wafrift",
    about = "WAF evasion toolkit — run without arguments for interactive mode",
    long_about = "WAF evasion toolkit — run without arguments for interactive mode.\n\n\
                  Exit codes (CI-friendly):\n\
                    0  success\n\
                    1  generic error (bad input, IO, transport failure, etc.)\n\
                    2  bench-waf: zero bypasses on any case in --evade mode\n\
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
    #[command(long_about = "Transform a payload with evasion techniques.\n\nExample:\n  wafrift evade --payload \"' OR 1=1--\" --level heavy")]
    Evade(EvadeArgs),
    /// Identify a WAF from response metadata.
    #[command(long_about = "Identify a WAF from response metadata.\n\nExample:\n  wafrift detect --status 403 --headers \"server: cloudflare\"")]
    Detect(DetectArgs),
    /// Generate differential analysis probes.
    #[command(long_about = "Generate differential analysis probes.\n\nExample:\n  wafrift probe --quick")]
    Probe(ProbeArgs),
    /// Fire evasion variants against a live target and report bypass results.
    #[command(long_about = "Fire evasion variants against a live target and report bypass results.\n\nExample:\n  wafrift scan --target http://localhost:8080 --payload \"' OR 1=1--\" --level heavy")]
    Scan(ScanArgs),
    /// Reproducible WAF benchmark: measure raw block rate AND wafrift bypass rate.
    /// Pass `--evade` to actually run the evasion engine (off by default — without it,
    /// only the WAF's raw rejection rate is measured, no bypass claim is made).
    #[command(
        name = "bench-waf",
        long_about = "Reproducible WAF benchmark: measure raw block rate AND wafrift bypass rate.\nPass `--evade` to actually run the evasion engine (off by default).\n\nExample:\n  wafrift bench-waf --base-url http://127.0.0.1:18081 --evade --format json"
    )]
    BenchWaf(bench_waf::BenchWafArgs),
    /// Compare two `bench-waf --output` JSON blobs and gate on regression.
    #[command(
        name = "bench-diff",
        long_about = "Compare two `bench-waf --output` JSON blobs and gate on regression.\n\nExample:\n  wafrift bench-diff --current run.json --baseline baseline.json"
    )]
    BenchDiff(bench_diff::BenchDiffArgs),
    /// DNS hints for `origin_bypass` (authorized targets only).
    #[command(
        name = "origin-hints",
        long_about = "DNS hints for `origin_bypass` (authorized targets only).\n\nExample:\n  wafrift origin-hints --host api.example.com --format json"
    )]
    OriginHints(origin_hints::OriginHintsArgs),
    /// Print JSON snippets for egress presets (e.g. Tor SOCKS).
    #[command(
        name = "egress-example",
        long_about = "Print JSON snippets for egress presets (e.g. Tor SOCKS).\n\nExample:\n  wafrift egress-example --preset tor"
    )]
    EgressExample(egress_example::EgressExampleArgs),
    /// List or explain available technique selectors for `--only`/`--exclude`.
    #[command(long_about = "List or explain available technique selectors for `--only`/`--exclude`.\n\nExample:\n  wafrift techniques list")]
    Techniques(TechniquesArgs),
    /// Generate shell completions for bash, zsh, fish, or PowerShell.
    #[command(long_about = "Generate shell completions for bash, zsh, fish, or PowerShell.\n\nExample:\n  wafrift completion bash > /etc/bash_completion.d/wafrift")]
    Completion(CompletionArgs),
    /// Origin discovery via crt.sh + DNS (authorized targets only).
    #[command(long_about = "Origin discovery via crt.sh + DNS (authorized targets only).\n\nExample:\n  wafrift recon --domain example.com")]
    Recon(recon_cmd::ReconArgs),
    /// Endpoint discovery: parse OpenAPI/Swagger, run GraphQL introspection,
    /// or fire differential parameter mining. Emits `DiscoveredEndpoint` JSON
    /// suitable for piping into `wafrift scan --from-discovery`.
    Discover(discover_cmd::DiscoverArgs),
    /// Replay a saved bypass against a target — proves reproducibility.
    #[command(long_about = "Replay a saved bypass against a target — proves reproducibility.\n\nExample:\n  wafrift replay --target https://api.example.com/search --payload \"' OR 1=1--\" --from-host api.example.com")]
    Replay(replay::ReplayArgs),
    /// Generate a markdown findings report from the proxy gene bank.
    #[command(long_about = "Generate a markdown findings report from the proxy gene bank.\n\nExample:\n  wafrift report --proxy-bank ~/.wafrift/gene-bank.json --output findings.md")]
    Report(report::ReportArgs),
    /// Scaffold a `.wafrift.toml` config in the current directory.
    #[command(long_about = "Scaffold a `.wafrift.toml` config in the current directory.\n\nExample:\n  wafrift init --force")]
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
    /// Corpus minimization via Zeller's ddmin — alias for `wafrift distill`.
    /// Familiar to AFL/libFuzzer users as `afl-tmin` / `tmin`. Takes a
    /// KNOWN-working bypass payload and finds the minimum-edit-distance
    /// substring that STILL bypasses. Reads payload from `--payload <P>`
    /// or stdin. Outputs: minimal payload + reduction stats (original
    /// length, final length, probes spent).
    Tmin(tmin_cmd::TminArgs),
    /// Offline bypass clustering: group a `bench-waf --output` JSON by
    /// rule_id, payload class, and edit-distance similarity. Outputs
    /// clusters with a representative technique and member count per
    /// cluster. Pure offline — no HTTP. Useful for triaging large bypass
    /// corpora and identifying duplicate root causes.
    Cluster(cluster_cmd::ClusterArgs),
    /// Long-running autonomous bypass campaign. Repeatedly runs
    /// `bench-waf --evade` rounds against a target with rotating
    /// mutators/strategies, saves every confirmed bypass to a campaign
    /// JSON at `~/.wafrift/hunt-<campaign-id>.json`, and exits cleanly
    /// on Ctrl-C. Resumable: re-run with the same `--campaign-id`.
    ///
    /// With `--auto-submit`: every newly verified bypass is queued for
    /// HackerOne submission (requires `H1_API_KEY` env var). The first
    /// 24 h of any campaign is always dry-run (corpus builds but nothing
    /// is filed). Use `--dry-run-submit` to keep dry-run permanently.
    ///
    /// With `--target cumulusfire`: pre-fills the CF testing endpoint and
    /// authorization reason for the CumulusFire public bug-bounty scope.
    Hunt(hunt_cmd::HuntArgs),
    /// Inspect a `wafrift corpus` artifact (rule_corpus + edge-POP coverage
    /// maps written by `wafrift bench-waf --corpus-out`). Subcommands:
    ///
    /// `stats` — print a structured summary of rules seen, total bypasses /
    /// blocks, and edge POPs covered. Supports `--format json` for CI
    /// gate integration (if rules_seen < N, fail the hunt).
    #[command(name = "corpus")]
    Corpus(corpus_cmd::CorpusArgs),
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
    #[arg(long = "tailscale-socks-addr", value_name = "ADDR", default_value = "127.0.0.1:1055")]
    pub egress_tailscale_socks_addr: String,

    /// Consecutive challenges before cooling an egress entry. Default: 3.
    #[arg(long = "egress-challenge-threshold", default_value_t = 3u32)]
    pub egress_challenge_threshold: u32,

    /// Seconds a cooled egress entry stays out of rotation. Default: 300.
    #[arg(long = "egress-cooldown-secs", default_value_t = 300u64)]
    pub egress_cooldown_secs: u64,
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
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(true)
        .compact()
        .with_writer(std::io::stderr)
        .try_init();

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

    // Disable colored output when --quiet is set or stdout is not a TTY
    // (so pipes don't get polluted with ANSI escape sequences).
    if cli.quiet || !io::stdout().is_terminal() {
        colored::control::set_override(false);
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

    let quiet = cli.quiet;
    match cli.command {
        None => interactive::run_interactive(),
        Some(Commands::Evade(args)) => evade_cmd::run_evade(args, quiet),
        Some(Commands::Detect(args)) => detect_cmd::run_detect(args, quiet),
        Some(Commands::Probe(args)) => {
            run_probe(args, quiet);
            ExitCode::SUCCESS
        }
        Some(Commands::Scan(args)) => {
            // Layer .wafrift.toml under the CLI flags (CLI wins).
            let args = cfg.apply_to_scan(args, matches.subcommand_matches("scan"));
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
                        eprintln!("\nCtrl+C received — finishing current request and saving results...");
                        cancel_clone.cancel();
                    }
                });
                scan::run_scan(args, cancel, quiet).await
            })
        }
        Some(Commands::BenchWaf(args)) => bench_waf::run_bench_waf(args, quiet),
        Some(Commands::BenchDiff(args)) => bench_diff::run_bench_diff(args, quiet),
        Some(Commands::OriginHints(args)) => origin_hints::run_origin_hints(args, quiet),
        Some(Commands::EgressExample(args)) => egress_example::run_egress_example(args, quiet),
        Some(Commands::Techniques(args)) => match args.action {
            TechniquesAction::List => {
                if quiet {
                    let tree = technique_filter::render_tree();
                    let lines: Vec<&str> = tree.lines().collect();
                    println!("{}", json!({ "schema_version": 1, "techniques": lines }));
                } else {
                    print!("{}", technique_filter::render_tree());
                }
                ExitCode::SUCCESS
            }
        },
        Some(Commands::Completion(args)) => {
            let mut cmd = Cli::command();
            generate(args.shell, &mut cmd, "wafrift", &mut io::stdout());
            ExitCode::SUCCESS
        }
        Some(Commands::Recon(args)) => recon_cmd::run_recon(args, quiet),
        Some(Commands::Replay(args)) => replay::run_replay(args, quiet),
        Some(Commands::Report(args)) => report::run_report(args, quiet),
        Some(Commands::Init(args)) => init_cmd::run_init(args, quiet),
    }
}
/// Interactive TUI — the default experience when running `wafrift` with no args.
fn run_interactive() -> ExitCode {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    };

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
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = io::stdin().read_to_string(&mut buf) {
            eprintln!("{} read discovery report from stdin: {e}", "error:".red());
            return ExitCode::from(1);
        }
        buf
    } else {
        match std::fs::read_to_string(src) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{} read {}: {e}", "error:".red(), src.display());
                return ExitCode::from(1);
            }
        }
    };
    let report: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} parse discovery report: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    let endpoints = report
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if endpoints.is_empty() {
        eprintln!(
            "{} discovery report has no `endpoints` — nothing to scan (is this `wafrift discover` JSON?)",
            "error:".red()
        );
        return ExitCode::from(1);
    }

    // Set up terminal.
    let Ok(()) = enable_raw_mode() else {
        eprintln!("Failed to enable raw mode — try using a subcommand instead.");
        return ExitCode::from(1);
    };
    let mut stdout = io::stdout();
    let _ = execute!(stdout, EnterAlternateScreen);
    let backend = CrosstermBackend::new(stdout);
    let Ok(mut terminal) = Terminal::new(backend) else {
        let _ = disable_raw_mode();
        eprintln!("Failed to create terminal.");
        return ExitCode::from(1);
    };

    // State.
    let mut selected_menu = 0_usize;
    let menu_items = [
        (
            "Scan",
            "Fire evasion variants against a live WAF target",
        ),
        ("Gene Bank", "Browse learned WAF bypass genomes"),
        (
            "Evade",
            "Transform a single payload with evasion techniques",
        ),
        ("Detect", "Identify a WAF from response headers"),
        ("Probe", "Generate differential analysis probes"),
    ];

    // Load gene bank stats.
    let gene_bank_info = match GeneBank::open_default() {
        Ok(bank) => {
            let wafs = bank.list_wafs();
            if wafs.is_empty() {
                "No learned genomes yet — scan a target to start learning".to_string()
            } else {
                format!("{} WAF genomes stored: {}", wafs.len(), wafs.join(", "))
            }
        }
        Err(_) => "Gene bank not initialized".to_string(),
    };

    loop {
        let _ = terminal.draw(|frame| {
            let size = frame.area();

            // Main layout: header + body + footer.
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(6), // header
                    Constraint::Min(10),   // body
                    Constraint::Length(3), // footer
                ])
                .split(size);

            // ── Header ──
            let header_text = vec![
                Line::from(vec![Span::styled(
                    "  ██╗    ██╗ █████╗ ███████╗██████╗ ██╗███████╗████████╗",
                    Style::default().fg(Color::Cyan),
                )]),
                Line::from(vec![Span::styled(
                    "  ██║    ██║██╔══██╗██╔════╝██╔══██╗██║██╔════╝╚══██╔══╝",
                    Style::default().fg(Color::Cyan),
                )]),
                Line::from(vec![Span::styled(
                    "  ██║ █╗ ██║███████║█████╗  ██████╔╝██║█████╗     ██║   ",
                    Style::default().fg(Color::LightCyan),
                )]),
                Line::from(vec![Span::styled(
                    "  ╚██╔╝██╔╝██╔══██║██╔══╝  ██╔══██╗██║██╔══╝     ██║   ",
                    Style::default().fg(Color::Blue),
                )]),
                Line::from(vec![Span::styled(
                    "   ╚═╝  ╚═╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚═══════╝     ╚═╝   ",
                    Style::default().fg(Color::DarkGray),
                )]),
                Line::from(vec![
                    Span::styled(
                        "  Evolutionary WAF Evasion Engine",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::ITALIC),
                    ),
                    Span::raw("   ·   "),
                    Span::styled("v0.1.0", Style::default().fg(Color::DarkGray)),
                ]),
            ];
            let header = Paragraph::new(header_text);
            frame.render_widget(header, chunks[0]);

            // ── Body: menu + info panel ──
            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(chunks[1]);

            // Menu.
            let items: Vec<ListItem> = menu_items
                .iter()
                .enumerate()
                .map(|(i, (name, _))| {
                    let style = if i == selected_menu {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    ListItem::new(Line::from(Span::styled(format!("  {name}  "), style)))
                })
                .collect();
            let menu = List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Actions ")
                    .border_style(Style::default().fg(Color::Cyan)),
            );
            frame.render_widget(menu, body_chunks[0]);

            // Info panel.
            let (_, desc) = menu_items[selected_menu];
            let info_text = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  {desc}"),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  ── Gene Bank ──",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    format!("  {gene_bank_info}"),
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press Enter to launch · q to quit",
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                )),
            ];
            let info = Paragraph::new(info_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Details ")
                    .border_style(Style::default().fg(Color::Cyan)),
            );
            frame.render_widget(info, body_chunks[1]);

            // ── Footer ──
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(" ↑↓ ", Style::default().fg(Color::Black).bg(Color::Cyan)),
                Span::raw(" Navigate  "),
                Span::styled(" Enter ", Style::default().fg(Color::Black).bg(Color::Cyan)),
                Span::raw(" Select  "),
                Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Red)),
                Span::raw(" Quit  "),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            frame.render_widget(footer, chunks[2]);
        });

        // Handle input.
        #[allow(clippy::collapsible_match)]
        if event::poll(Duration::from_millis(100)).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Up | KeyCode::Char('k') => {
                    selected_menu = selected_menu.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if selected_menu < menu_items.len() - 1 {
                        selected_menu += 1;
                    }
                }
                KeyCode::Enter => {
                    // Exit TUI and print guidance for the selected action.
                    let _ = disable_raw_mode();
                    let _ = execute!(io::stdout(), LeaveAlternateScreen);
                    match selected_menu {
                        0 => {
                            println!("{}", "\nLaunch a scan with:".bold().cyan());
                            println!(
                                "  {} {}",
                                "wafrift scan".bold().green(),
                                "--target <URL> --payload <PAYLOAD>".yellow()
                            );
                            println!("\n  {}", "Example:".bold());
                            println!(
                                "  {} {}",
                                "wafrift scan".green(),
                                "--target http://localhost:8080 --payload \"' OR 1=1--\"".yellow()
                            );
                        }
                        1 => {
                            // Show gene bank contents inline.
                            println!("\n{}", "Gene Bank Contents:".bold().cyan());
                            match GeneBank::open_default() {
                                Ok(mut bank) => {
                                    let wafs = bank.list_wafs();
                                    if wafs.is_empty() {
                                        println!(
                                            "  {}",
                                            "No genomes yet — scan a target to start learning."
                                                .yellow()
                                        );
                                    } else {
                                        for waf in &wafs {
                                            println!(
                                                "\n  {} {}",
                                                "WAF:".bold(),
                                                waf.bold().yellow()
                                            );
                                            if let Some(genome) = bank.load(waf) {
                                                println!(
                                                    "    {} {}",
                                                    "Targets scanned:".cyan(),
                                                    genome.targets_scanned
                                                );
                                                let winners = genome.seed_winners();
                                                if winners.is_empty() {
                                                    println!(
                                                        "    {}",
                                                        "No proven winners yet".bright_black()
                                                    );
                                                } else {
                                                    println!(
                                                        "    {} {}",
                                                        "Proven bypasses:".green(),
                                                        winners.join(", ").yellow()
                                                    );
                                                }
                                                for tech in genome.top_techniques(5, 1) {
                                                    println!(
                                                        "    {} {:>5.0}% ({}/{}) {}",
                                                        "·".bright_black(),
                                                        tech.success_rate() * 100.0,
                                                        tech.total_successes,
                                                        tech.total_attempts,
                                                        tech.name,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => println!("  {}", format!("Error: {e}").red()),
                            }
                        }
                        2 => {
                            println!("\n{}", "Transform a payload:".bold().cyan());
                            println!(
                                "  {} {}",
                                "wafrift evade".bold().green(),
                                "--payload <PAYLOAD> --level heavy".yellow()
                            );
                        }
                        3 => {
                            println!("\n{}", "Detect a WAF:".bold().cyan());
                            println!(
                                "  {} {}",
                                "wafrift detect".bold().green(),
                                "--status 403 --headers \"server: cloudflare\"".yellow()
                            );
                        }
                        4 => {
                            println!("\n{}", "Generate probes:".bold().cyan());
                            println!(
                                "  {} {}",
                                "wafrift probe".bold().green(),
                                "[--quick]".yellow()
                            );
                        }
                        _ => {}
                    }
                    return ExitCode::SUCCESS;
                }
                _ => {}
            }
        }
    }

    // Clean up terminal.
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    ExitCode::SUCCESS
}

fn run_evade(args: EvadeArgs, quiet: bool) -> ExitCode {
    let filter = match TechniqueFilter::parse(&args.only, &args.exclude) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{} {msg}", "Filter error:".red().bold());
            return ExitCode::from(1);
        }
    };
    let payload_type = grammar::classify(&args.payload);
    let strategies = filter.filter_strategies(strategies_for_level(args.level));
    let max_mutations = max_mutations_for_level(args.level);
    let encoding_only = args.encoding_only || !filter.grammar_enabled();
    let variants = build_variants(
        &args.payload,
        payload_type,
        encoding_only,
        &strategies,
        max_mutations,
    );

    if variants.is_empty() {
        if quiet {
            println!(
                "{}",
                json!({ "schema_version": 1, "error": "no variants generated", "payload_type": payload_type_label(payload_type) })
            );
        } else {
            eprintln!(
                "[wafrift scan] cancelled — {} job(s) not run",
                jobs.len() - i
            );
            break;
        }
        return ExitCode::from(1);
    }

    if quiet {
        // JSON output: one object per line (NDJSON)
        for variant in &variants {
            let obj = json!({
                "schema_version": 1,
                "payload": variant.payload,
                "techniques": variant.techniques,
                "confidence": variant.confidence,
            });
            println!("{obj}");
        }
    } else {
        println!(
            "{} {}",
            "Payload Type:".bold().cyan(),
            payload_type_label(payload_type).bold()
        );
        // Build a per-job tmpfile path when collecting JSON. Cleaned
        // up unconditionally after the read attempt so a panic in
        // run_scan can't leak a tmpfile, and we don't bother allocating
        // the path in text mode (where each job streams to stdout).
        let tmp_path: Option<PathBuf> = if want_json {
            Some(std::env::temp_dir().join(format!(
                "wafrift-discovery-job-{}-{i}.json",
                std::process::id()
            )))
        } else {
            None
        };
        let job_args = ScanArgs {
            target_positional: None,
            target: Some(url.clone()),
            from_discovery: None,
            payload: args.payload.clone(),
            param: param.clone(),
            payload_class: args.payload_class.clone(),
            callback_url: args.callback_url.clone(),
            session_init: args.session_init.clone(),
            level: args.level,
            encoding_only: args.encoding_only,
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
            quiet: args.quiet,
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

    ExitCode::SUCCESS
}

fn run_detect(args: DetectArgs, quiet: bool) -> ExitCode {
    let headers = match parse_headers(&args.headers) {
        Ok(headers) => headers,
        Err(message) => {
            eprintln!("{} {}", "Header parse error:".red().bold(), message);
            return ExitCode::from(1);
        }
    };

    let detected = waf_detect::detect(args.status, &headers, args.body.as_bytes());
    if quiet {
        let results: Vec<_> = detected
            .iter()
            .map(|r| {
                json!({
                    "name": r.name,
                    "confidence": r.confidence,
                    "indicators": r.indicators,
                })
            })
            .collect();
        println!("{}", json!({ "schema_version": 1, "detected": results }));
        ExitCode::SUCCESS
    } else if let Some(result) = detected.first() {
        println!("{} {}", "Detected WAF:".bold().green(), result.name.bold());
        println!(
            "{} {:.0}%",
            "Confidence:".bold().cyan(),
            (result.confidence * 100.0).round()
        );
        println!("{}", "Indicators:".bold().cyan());
        for indicator in &result.indicators {
            println!("  {} {}", "-".bright_black(), indicator.yellow());
        }
        ExitCode::SUCCESS
    } else {
        println!("{}", "No WAF confidently detected.".yellow().bold());
        ExitCode::SUCCESS
    }
}

fn run_probe(args: ProbeArgs, quiet: bool) {
    let probes = if args.quick {
        differential::generate_quick_probes()
    } else {
        differential::generate_probes()
    };

    for probe in probes {
        let line = json!({
            "schema_version": 1,
            "payload": probe.payload,
            "tests": probe_target_label(&probe.tests),
            "description": probe.description,
            "expected_blocked": probe.expected_blocked,
        });
        if quiet {
            println!("{}", line);
        } else {
            println!("{}", line.to_string().blue());
        }
    }

    last
}

// `run_detect` lives in `crate::detect_cmd`.

// `run_probe` lives in `crate::probe_cmd`.
