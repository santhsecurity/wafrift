//! Sign / verify / pull / submit / trust subcommands under `wafrift bank`.
//!
//! Builds on `wafrift-genome-registry` for the wire format and crypto;
//! this module is the operator-facing CLI glue.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use wafrift_genome_registry::{
    Genome, GenomeBundle, RegistryError, SignedBundle, SigningKey, TrustList,
};

/// Default upper bound on bundle age for the freshness/replay check,
/// in days. A signed bundle older than this is refused unless the
/// operator passes `--allow-stale` (or raises `--max-age-days`). The
/// window is the replay defence: a bundle captured from a key that has
/// since been revoked cannot be re-imported indefinitely.
pub(crate) const DEFAULT_BUNDLE_MAX_AGE_DAYS: u64 = 30;

/// Clock-skew tolerance (seconds) for the future-dating guard. A bundle
/// dated more than this far ahead of the local clock is rejected
/// (defends against a publisher with a wildly-wrong clock or a forged
/// future timestamp that would dodge the age check).
pub(crate) const BUNDLE_FUTURE_SKEW_SECS: u64 = 300;

/// Map a freshness/clock error to a friendly operator message + exit.
/// All other errors fall through to the caller's generic handler.
fn freshness_die(e: &RegistryError) -> Option<ExitCode> {
    match e {
        RegistryError::BundleTooOld {
            age_secs,
            max_age_secs,
            ..
        } => Some(die(format!(
            "bundle is stale: age {age_secs}s exceeds the {max_age_secs}s freshness window \
             (replay defence). Re-fetch a fresh bundle, raise --max-age-days, or pass \
             --allow-stale if you knowingly want this archived bundle."
        ))),
        RegistryError::BundleFutureDated { skew_secs, .. } => Some(die(format!(
            "bundle is dated more than {skew_secs}s in the future — refusing (system clock \
             skew or forged timestamp). Check the local clock, or pass --allow-stale to override."
        ))),
        _ => None,
    }
}

#[derive(Args, Debug)]
pub(crate) struct BankRegistryArgs {
    #[command(subcommand)]
    pub action: RegistryAction,
}

#[derive(Subcommand, Debug)]
pub(crate) enum RegistryAction {
    /// Generate a fresh ed25519 signing keypair and write the secret
    /// hex to disk (mode 0600). Public key is printed to stdout.
    GenKey(GenKeyArgs),
    /// Sign a bank-export envelope and write a `*.signed.json` next
    /// to it (or to `--output`).
    Sign(SignArgs),
    /// Verify a `*.signed.json` against the local trust list.
    Verify(VerifyArgs),
    /// HTTP GET a signed bundle from `URL`, verify, write to disk.
    Pull(PullArgs),
    /// Sign a local export envelope and HTTP POST to `URL`.
    Submit(SubmitArgs),
    /// Manage the trust list at `~/.wafrift/trusted-keys.toml`.
    Trust(TrustArgs),
}

#[derive(Args, Debug)]
pub(crate) struct GenKeyArgs {
    /// Path to write the secret hex to. Created with mode 0600 on
    /// Unix; never logged. Default `~/.wafrift/signing-key.hex`.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct SignArgs {
    /// Path to a bank-export envelope (`wafrift bank export`).
    pub envelope: PathBuf,
    /// Bundle name embedded in the signed payload. Default = the
    /// envelope's filename stem.
    #[arg(long)]
    pub bundle_name: Option<String>,
    /// Output path. Default = `<envelope>.signed.json`.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Path to the secret-key hex file. Default
    /// `~/.wafrift/signing-key.hex`.
    #[arg(long)]
    pub signing_key: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct VerifyArgs {
    /// Path to a signed bundle (`*.signed.json`).
    pub signed: PathBuf,
    /// Trust-list path. Default `~/.wafrift/trusted-keys.toml`.
    #[arg(long)]
    pub trust_list: Option<PathBuf>,
    /// Reject bundles older than this many days (replay defence: a
    /// captured bundle from a since-revoked key cannot be re-imported
    /// indefinitely). Default 30.
    #[arg(long, default_value_t = DEFAULT_BUNDLE_MAX_AGE_DAYS)]
    pub max_age_days: u64,
    /// Accept stale bundles (disable the age/clock-skew freshness
    /// check). Off by default — the freshness window is a security
    /// control, only opt out when you knowingly import an archived bundle.
    #[arg(long, default_value_t = false)]
    pub allow_stale: bool,
}

#[derive(Args, Debug)]
pub(crate) struct PullArgs {
    /// Registry URL serving a `SignedBundle` JSON.
    pub url: String,
    /// Output path for the verified bundle. Default = the URL's
    /// terminal segment under `~/.wafrift/pulled/`.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Trust-list path. Default `~/.wafrift/trusted-keys.toml`.
    #[arg(long)]
    pub trust_list: Option<PathBuf>,
    /// HTTP timeout in seconds.
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,
    /// Reject bundles older than this many days (replay defence).
    /// Default 30.
    #[arg(long, default_value_t = DEFAULT_BUNDLE_MAX_AGE_DAYS)]
    pub max_age_days: u64,
    /// Accept stale bundles (disable the age/clock-skew freshness
    /// check). Off by default.
    #[arg(long, default_value_t = false)]
    pub allow_stale: bool,
}

#[derive(Args, Debug)]
pub(crate) struct SubmitArgs {
    /// Registry URL accepting POST of a `SignedBundle` JSON.
    pub url: String,
    /// Path to a bank-export envelope to sign + submit.
    pub envelope: PathBuf,
    /// Bundle name embedded in the signed payload.
    #[arg(long)]
    pub bundle_name: Option<String>,
    /// Path to the secret-key hex file.
    #[arg(long)]
    pub signing_key: Option<PathBuf>,
    /// HTTP timeout in seconds.
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,
}

#[derive(Args, Debug)]
pub(crate) struct TrustArgs {
    #[command(subcommand)]
    pub action: TrustAction,
}

#[derive(Subcommand, Debug)]
pub(crate) enum TrustAction {
    /// Print every trusted publisher.
    List(TrustListArgs),
    /// Allowlist a public key (hex) under `--name`.
    Add(TrustAddArgs),
    /// Drop a publisher from the allowlist.
    Remove(TrustRemoveArgs),
}

#[derive(Args, Debug)]
pub(crate) struct TrustListArgs {
    #[arg(long)]
    pub trust_list: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct TrustAddArgs {
    /// Hex-encoded ed25519 public key (64 chars).
    pub public_key_hex: String,
    /// Operator-facing display name.
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub trust_list: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct TrustRemoveArgs {
    pub public_key_hex: String,
    #[arg(long)]
    pub trust_list: Option<PathBuf>,
}

// ── dispatch ────────────────────────────────────────────────────────

pub(crate) fn run(args: BankRegistryArgs) -> ExitCode {
    match args.action {
        RegistryAction::GenKey(a) => run_gen_key(a),
        RegistryAction::Sign(a) => run_sign(a),
        RegistryAction::Verify(a) => run_verify(a),
        RegistryAction::Pull(a) => run_pull(a),
        RegistryAction::Submit(a) => run_submit(a),
        RegistryAction::Trust(a) => run_trust(a),
    }
}

fn home_subpath(rest: &str) -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".wafrift").join(rest))
}

fn default_signing_key_path() -> Option<PathBuf> {
    home_subpath("signing-key.hex")
}

fn default_trust_list_path() -> Option<PathBuf> {
    home_subpath("trusted-keys.toml")
}

fn die(message: impl AsRef<str>) -> ExitCode {
    eprintln!("error: {}", message.as_ref());
    ExitCode::from(1)
}

/// Bounded binary read for `--envelope` files.
///
/// Replaces the former `std::fs::read(&args.envelope)` which was
/// unbounded — `--envelope /dev/zero` would silently OOM the host.
/// The 64 MiB cap matches `GENE_BANK_FILE_MAX_BYTES` (same rationale:
/// any realistic bank export fits; multi-GB accidents / hostile
/// symlinks are rejected before memory is exhausted).
fn read_bounded_envelope(path: &std::path::Path) -> Result<Vec<u8>, String> {
    const ENVELOPE_MAX_BYTES: usize = crate::safe_body::GENE_BANK_FILE_MAX_BYTES;
    let f = std::fs::File::open(path).map_err(|e| format!("open: {e}"))?;
    crate::safe_body::read_bounded_from(f, ENVELOPE_MAX_BYTES).map_err(|e| match e {
        crate::safe_body::ReadError::Transport(m) => m,
        crate::safe_body::ReadError::Overrun {
            cap_bytes,
            observed_bytes,
        } => {
            format!(
                "envelope exceeds {cap_bytes}-byte cap ({observed_bytes} bytes seen) — \
                     is --envelope pointing at the right file?"
            )
        }
    })
}

fn read_signing_key(path: &std::path::Path) -> Result<SigningKey, String> {
    warn_if_world_readable(path);
    // §15 TOCTOU: read_bounded_text_file opens+reads in one fd — no stat() race.
    // A signing key is a 64-char hex string; 1 KiB is generous and catches
    // /dev/zero typos or hostile symlinks without OOM.
    const MAX_KEY_BYTES: usize = 1024;
    let raw = crate::safe_body::read_bounded_text_file(path, MAX_KEY_BYTES)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let trimmed = raw.trim();
    SigningKey::from_secret_hex(trimmed).map_err(|e| format!("{e}"))
}

/// Loud warning if a signing key file is group- or world-readable.
///
/// R55 pass-17 I4 (CLAUDE.md §15 AUDIT, least-privilege secrets):
/// new keys ship as `0600` via [`set_secret_perms`], but a key
/// generated by an older wafrift (pre-R49) — or one staged externally
/// — may still be `0644`. On the NFS share (exported to the full
/// Tailscale mesh under `100.64.0.0/10`) every node that can reach
/// the export can read the file. Surface the gap on every read so the
/// operator can fix it themselves; we do *not* auto-`chmod` because
/// the operator may have intentionally widened the mode for a shared
/// key.
fn warn_if_world_readable(_path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(_path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "warn: signing key {} has mode 0{:o} (group/world-readable). \
                     Run `chmod 600 {}` — anyone with read access on this \
                     filesystem can forge signed gene-bank bundles.",
                    _path.display(),
                    mode,
                    _path.display(),
                );
            }
        }
    }
}

/// Atomic create-or-error sibling of [`write_secret_hex`]. Uses
/// `O_CREAT | O_EXCL` so a concurrent writer cannot win the race
/// between an `exists()` check and the write. AlreadyExists returns
/// the same "refuse to overwrite a key file" message as before so
/// the operator-facing UX is unchanged. R49 pass-11 I7.
fn write_secret_hex_atomic(path: &std::path::Path, secret_hex: &str) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    // §15 TOCTOU: `create_new(true)` (O_EXCL) blocks symlink pre-plant +
    // overwrite, but on Unix the file is still born with the umask default
    // (typically 0644 — world-readable) and only chmod'd to 0600 AFTER the
    // secret bytes are written, leaving a window where the ed25519 secret is
    // readable by other local users. Set `.mode(0o600)` on the open so the
    // file is created owner-only from the first byte (create_new always
    // creates fresh, so the mode always applies) — no window. (Same fix as
    // the MITM CA key in proxy::mitm::write_to_dir.)
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(format!(
                "{} already exists; refuse to overwrite a key file",
                path.display()
            ));
        }
        Err(e) => return Err(format!("create {}: {e}", path.display())),
    };
    f.write_all(format!("{secret_hex}\n").as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    drop(f);
    // Belt-and-suspenders: reaffirm 0600 (no-op on Unix after the atomic
    // create above; the canonical perms-setter for any non-Unix path).
    set_secret_perms(path);
    Ok(())
}

#[cfg(unix)]
fn set_secret_perms(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_secret_perms(_path: &std::path::Path) {
    // No-op on non-Unix; document in README that operators should
    // restrict file ACLs themselves on Windows.
}

fn envelope_to_genome(envelope_bytes: &[u8], bundle_name: &str) -> GenomeBundle {
    // Carry the entire envelope as one Genome payload — keeps the
    // wire format simple and forwards-compatible. Future rev can
    // split per-host genomes; for v1 we transport bundles atomically.
    let payload = String::from_utf8_lossy(envelope_bytes).into_owned();
    let g = Genome::new(format!("{bundle_name}-envelope-v1"), payload);
    GenomeBundle::new(bundle_name, vec![g])
}

// ── gen-key ────────────────────────────────────────────────────────

fn run_gen_key(args: GenKeyArgs) -> ExitCode {
    let key = SigningKey::generate();
    let path = match args.output.or_else(default_signing_key_path) {
        Some(p) => p,
        None => return die("--output not given and $HOME unset"),
    };
    // R49 (pass-11 I7, CLAUDE.md §15 AUDIT/TOCTOU): atomic
    // create-or-error via OpenOptions::create_new(true). Pre-fix
    // the exists() check + write was racy — a concurrent agent on
    // the NFS-shared workspace could create the file in the gap
    // between the stat and the write, silently overwriting the
    // attacker's pre-staged key. POSIX O_EXCL closes the race.
    if let Err(e) = write_secret_hex_atomic(&path, key.secret_hex()) {
        return die(e);
    }
    println!("public_key_hex = {}", key.verifying_key_hex());
    eprintln!("secret written to {} (mode 0600)", path.display());
    ExitCode::SUCCESS
}

// ── sign ──────────────────────────────────────────────────────────

fn run_sign(args: SignArgs) -> ExitCode {
    let key_path = match args.signing_key.or_else(default_signing_key_path) {
        Some(p) => p,
        None => return die("--signing-key not given and $HOME unset"),
    };
    let key = match read_signing_key(&key_path) {
        Ok(k) => k,
        Err(e) => return die(e),
    };
    // §15 OOM guard: switch from unbounded `std::fs::read` (which would
    // OOM on `--envelope /dev/zero` or a hostile symlink to a multi-GB
    // file) to the same bounded reader used by every other module.
    let envelope_bytes = match read_bounded_envelope(&args.envelope) {
        Ok(b) => b,
        Err(e) => {
            return crate::helpers::input_error(format!("read {}: {e}", args.envelope.display()));
        }
    };
    let bundle_name = args.bundle_name.unwrap_or_else(|| {
        args.envelope
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("wafrift-bundle")
            .to_string()
    });
    let bundle = envelope_to_genome(&envelope_bytes, &bundle_name);
    let signed = match bundle.sign(&key) {
        Ok(s) => s,
        Err(e) => return die(format!("sign: {e}")),
    };
    let json = match signed.to_json() {
        Ok(s) => s,
        Err(e) => return die(format!("serialise: {e}")),
    };
    let out = args.output.unwrap_or_else(|| {
        let mut p = args.envelope.clone();
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("bundle")
            .to_string();
        p.set_file_name(format!("{stem}.signed.json"));
        p
    });
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // R50 pass-12 I2 (CLAUDE.md §15 AUDIT): use canonical
    // write_atomic so a crashed sign leaves either the old envelope
    // or the new one — never a torn JSON file that breaks
    // downstream verification. Signed genomes are the distribution
    // trust anchor; partial writes corrupt the chain.
    if let Err(e) = wafrift_types::loaders::write_atomic(&out, json.as_bytes()) {
        return die(format!("atomic write {}: {e}", out.display()));
    }
    eprintln!("signed → {} ({} bytes)", out.display(), json.len());
    ExitCode::SUCCESS
}

// ── verify ─────────────────────────────────────────────────────────

fn run_verify(args: VerifyArgs) -> ExitCode {
    // §15 OOM guard: a signed bundle is a JSON object — 1 MiB cap covers
    // any realistic bank export; /dev/zero symlinks are rejected at open+read.
    let raw = match crate::safe_body::read_bounded_text_file(
        &args.signed,
        crate::safe_body::GENE_BANK_FILE_MAX_BYTES,
    ) {
        Ok(s) => s,
        Err(e) => return die(format!("read {}: {e}", args.signed.display())),
    };
    let signed = match SignedBundle::from_json(&raw) {
        Ok(s) => s,
        Err(e) => return die(format!("parse: {e}")),
    };
    let trust_path = match args.trust_list.or_else(default_trust_list_path) {
        Some(p) => p,
        None => return die("--trust-list not given and $HOME unset"),
    };
    let trust = match TrustList::load(&trust_path) {
        Ok(t) => t,
        Err(e) => return die(format!("trust list {}: {e}", trust_path.display())),
    };
    // Freshness/replay defence: refuse stale or future-dated bundles
    // unless the operator explicitly opts out with --allow-stale. The
    // signature + trust-list membership are checked first inside both
    // verify paths — freshness never leaks anything about unsigned input.
    let verify_result = if args.allow_stale {
        signed.verify(&trust)
    } else {
        signed.verify_fresh(
            &trust,
            args.max_age_days.saturating_mul(86_400),
            BUNDLE_FUTURE_SKEW_SECS,
        )
    };
    match verify_result {
        Ok(bundle) => {
            println!(
                "OK: bundle '{}' from a trusted publisher",
                bundle.bundle_name
            );
            println!(
                "    {} genome(s), created {}",
                bundle.genomes.len(),
                bundle.created_unix
            );
            ExitCode::SUCCESS
        }
        Err(RegistryError::SignatureInvalid) => {
            die("signature invalid (bundle tampered or wrong key)")
        }
        Err(RegistryError::UntrustedPublisher { public_key_hex }) => die(format!(
            "publisher key not trusted: {public_key_hex} \
             (add via `wafrift bank trust add {public_key_hex} --name <NAME>`)"
        )),
        Err(e) => freshness_die(&e).unwrap_or_else(|| die(format!("verify: {e}"))),
    }
}

// ── pull ──────────────────────────────────────────────────────────

fn run_pull(args: PullArgs) -> ExitCode {
    let trust_path = match args.trust_list.or_else(default_trust_list_path) {
        Some(p) => p,
        None => return die("--trust-list not given and $HOME unset"),
    };
    let trust = match TrustList::load(&trust_path) {
        Ok(t) => t,
        Err(e) => return die(format!("trust list {}: {e}", trust_path.display())),
    };

    let body = match http_get_blocking(&args.url, args.timeout_secs) {
        Ok(b) => b,
        Err(e) => return die(format!("GET {}: {e}", args.url)),
    };
    let signed = match SignedBundle::from_json(&body) {
        Ok(s) => s,
        Err(e) => return die(format!("parse signed bundle: {e}")),
    };
    // Freshness/replay defence (mirrors `run_verify`): a network-pulled
    // bundle is the highest-risk import path — refuse stale/future-dated
    // bundles unless the operator passes --allow-stale.
    let verify_result = if args.allow_stale {
        signed.verify(&trust)
    } else {
        signed.verify_fresh(
            &trust,
            args.max_age_days.saturating_mul(86_400),
            BUNDLE_FUTURE_SKEW_SECS,
        )
    };
    let verified = match verify_result {
        Ok(b) => b,
        Err(e) => return freshness_die(&e).unwrap_or_else(|| die(format!("verify: {e}"))),
    };

    let out = match args.output {
        Some(p) => p,
        None => {
            let stem = args
                .url
                .rsplit('/')
                .find(|s| !s.is_empty())
                .unwrap_or("pulled-bundle.json")
                .to_string();
            match home_subpath(&format!("pulled/{stem}")) {
                Some(p) => p,
                None => return die("$HOME unset; supply --output"),
            }
        }
    };
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = match serde_json::to_string_pretty(&verified) {
        Ok(s) => s,
        Err(e) => return die(format!("serialise: {e}")),
    };
    // R50 pass-12 I2: write_atomic for crash-safe pull output.
    if let Err(e) = wafrift_types::loaders::write_atomic(&out, json.as_bytes()) {
        return die(format!("write {}: {e}", out.display()));
    }
    eprintln!(
        "pulled + verified '{}' ({} genome(s)) → {}",
        verified.bundle_name,
        verified.genomes.len(),
        out.display()
    );
    ExitCode::SUCCESS
}

// ── submit ─────────────────────────────────────────────────────────

fn run_submit(args: SubmitArgs) -> ExitCode {
    let key_path = match args.signing_key.or_else(default_signing_key_path) {
        Some(p) => p,
        None => return die("--signing-key not given and $HOME unset"),
    };
    let key = match read_signing_key(&key_path) {
        Ok(k) => k,
        Err(e) => return die(e),
    };
    // §15 OOM guard: same bounded read as run_sign — see comment there.
    let envelope_bytes = match read_bounded_envelope(&args.envelope) {
        Ok(b) => b,
        Err(e) => {
            return crate::helpers::input_error(format!("read {}: {e}", args.envelope.display()));
        }
    };
    let bundle_name = args.bundle_name.unwrap_or_else(|| {
        args.envelope
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("wafrift-bundle")
            .to_string()
    });
    let bundle = envelope_to_genome(&envelope_bytes, &bundle_name);
    let signed = match bundle.sign(&key) {
        Ok(s) => s,
        Err(e) => return die(format!("sign: {e}")),
    };
    let json = match signed.to_json() {
        Ok(s) => s,
        Err(e) => return die(format!("serialise: {e}")),
    };

    match http_post_blocking(&args.url, &json, args.timeout_secs) {
        Ok(resp) => {
            eprintln!(
                "submitted '{}' ({} bytes) — server: {}",
                bundle_name,
                json.len(),
                resp
            );
            ExitCode::SUCCESS
        }
        Err(e) => die(format!("POST {}: {e}", args.url)),
    }
}

// ── trust ─────────────────────────────────────────────────────────

fn run_trust(args: TrustArgs) -> ExitCode {
    match args.action {
        TrustAction::List(a) => {
            let path = match a.trust_list.or_else(default_trust_list_path) {
                Some(p) => p,
                None => return die("--trust-list not given and $HOME unset"),
            };
            let tl = match TrustList::load(&path) {
                Ok(t) => t,
                Err(e) => return die(format!("load: {e}")),
            };
            if tl.publishers().is_empty() {
                println!(
                    "(no trusted publishers — add with `wafrift bank trust add HEX --name NAME`)"
                );
            } else {
                for p in tl.publishers() {
                    println!(
                        "{}  {}{}",
                        p.public_key_hex,
                        p.name,
                        if p.note.is_empty() {
                            String::new()
                        } else {
                            format!("  // {}", p.note)
                        }
                    );
                }
            }
            ExitCode::SUCCESS
        }
        TrustAction::Add(a) => {
            let path = match a.trust_list.or_else(default_trust_list_path) {
                Some(p) => p,
                None => return die("--trust-list not given and $HOME unset"),
            };
            let mut tl = match TrustList::load(&path) {
                Ok(t) => t,
                Err(e) => return die(format!("load: {e}")),
            };
            tl.allow_hex(&a.public_key_hex, &a.name);
            if let Err(e) = tl.save(&path) {
                return die(format!("save: {e}"));
            }
            eprintln!("trusted {} ({})", a.name, a.public_key_hex);
            ExitCode::SUCCESS
        }
        TrustAction::Remove(a) => {
            let path = match a.trust_list.or_else(default_trust_list_path) {
                Some(p) => p,
                None => return die("--trust-list not given and $HOME unset"),
            };
            let mut tl = match TrustList::load(&path) {
                Ok(t) => t,
                Err(e) => return die(format!("load: {e}")),
            };
            tl.revoke_hex(&a.public_key_hex);
            if let Err(e) = tl.save(&path) {
                return die(format!("save: {e}"));
            }
            eprintln!("revoked {}", a.public_key_hex);
            ExitCode::SUCCESS
        }
    }
}

// ── HTTP helpers ───────────────────────────────────────────────────
//
// We use reqwest::blocking via tokio runtime build so this module
// stays callable from `run_bank` (which is sync). A local runtime is
// cheap for this command — startup-time overhead, not request-time.

/// Shared HTTP client construction for registry GET / POST blocking
/// helpers. R53 pass-15 §7-A (CLAUDE.md §7 DEDUP): the prior
/// `reqwest::Client::builder().timeout(...).build()` block was
/// duplicated across `http_get_blocking` and `http_post_blocking`
/// and bypassed the workspace's `base_client_builder` (so the
/// MIN_TIMEOUT clamp + insecure / UA wiring were missing from
/// both). One canonical helper now.
///
/// R56 pass-21 §15 AUDIT (SSRF redirect): registry URLs are
/// operator-supplied; a hostile registry that returns
/// `302 → http://169.254.169.254/` would be followed by the
/// default reqwest redirect policy. Apply `safe_redirect_policy`
/// so bogon-IP redirects are refused.
fn build_registry_client(timeout_secs: u64) -> Result<reqwest::Client, String> {
    wafrift_transport::base_client_builder(timeout_secs, false, None)
        .redirect(crate::helpers::safe_redirect_policy(5))
        .build()
        .map_err(|e| format!("client build: {e}"))
}

/// Build a single-threaded Tokio runtime for use in blocking HTTP
/// helpers. R56 pass-21 §7 DEDUP: the identical 4-line
/// `new_current_thread().enable_all().build()` block was duplicated
/// in both `http_get_blocking` and `http_post_blocking`; extracted
/// here so drift is impossible.
fn build_blocking_rt() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))
}

fn http_get_blocking(url: &str, timeout_secs: u64) -> Result<String, String> {
    let rt = build_blocking_rt()?;
    rt.block_on(async {
        let client = build_registry_client(timeout_secs)?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| crate::helpers::walk_reqwest_error(&e))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        // Bounded read — even an operator-controlled registry can
        // have a bug; cap at the headroom limit (64 MiB), much
        // larger than any sane gene-bank export but still bounded.
        match crate::safe_body::read_bounded_text(
            resp,
            crate::safe_body::HEADROOM_MAX_RESPONSE_BYTES,
        )
        .await
        {
            Ok(t) => Ok(t),
            Err(e) => Err(format!("body: {e}")),
        }
    })
}

fn http_post_blocking(url: &str, body: &str, timeout_secs: u64) -> Result<String, String> {
    let rt = build_blocking_rt()?;
    rt.block_on(async {
        let client = build_registry_client(timeout_secs)?;
        let resp = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| crate::helpers::walk_reqwest_error(&e))?;
        let status = resp.status();
        // Bounded read on the registry's POST response.
        let txt = crate::safe_body::read_bounded_text(
            resp,
            crate::safe_body::HEADROOM_MAX_RESPONSE_BYTES,
        )
        .await
        .unwrap_or_default();
        if !status.is_success() {
            return Err(format!("HTTP {status} {txt}"));
        }
        Ok(format!("HTTP {} ({} bytes)", status, txt.len()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wafrift-bank-registry-{}-{}",
            label,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let dir = fresh_dir("rt");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, br#"{"hosts":["api.example.com"]}"#).unwrap();

        // gen-key
        let key_path = dir.join("signing.hex");
        let code = run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        // sign
        let signed_path = dir.join("envelope.signed.json");
        let code = run_sign(SignArgs {
            envelope: env_path.clone(),
            bundle_name: Some("rt-bundle".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path.clone()),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(signed_path.exists());

        // Trust the signing public key, verify.
        let pk = SigningKey::from_secret_hex(std::fs::read_to_string(&key_path).unwrap().trim())
            .unwrap()
            .verifying_key_hex();
        let trust_path = dir.join("trust.toml");
        let mut tl = TrustList::new();
        tl.allow_hex(&pk, "tester");
        tl.save(&trust_path).unwrap();

        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_rejects_untrusted_publisher() {
        let dir = fresh_dir("untrusted");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, b"{}").unwrap();
        let key_path = dir.join("signing.hex");
        run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        let signed_path = dir.join("envelope.signed.json");
        run_sign(SignArgs {
            envelope: env_path,
            bundle_name: Some("u".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path),
        });
        // Empty trust list — must reject.
        let trust_path = dir.join("trust.toml");
        TrustList::new().save(&trust_path).unwrap();
        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "verify must fail under empty trust list"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_rejects_tampered_signed_bundle() {
        let dir = fresh_dir("tampered");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, br#"{"a":1}"#).unwrap();
        let key_path = dir.join("signing.hex");
        run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        let signed_path = dir.join("envelope.signed.json");
        run_sign(SignArgs {
            envelope: env_path,
            bundle_name: Some("t".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path.clone()),
        });

        // Tamper the genome payload after signing — parse the signed
        // bundle JSON, mutate the inner payload bytes, write it back.
        // String-replace on the raw bytes is brittle (depends on the
        // exact serde-json key order), so deserialize / mutate /
        // re-serialize.
        let raw = std::fs::read_to_string(&signed_path).unwrap();
        let mut signed: SignedBundle = serde_json::from_str(&raw).expect("parse signed bundle");
        signed.bundle.genomes[0].payload = format!("EVIL_{}", signed.bundle.genomes[0].payload);
        std::fs::write(&signed_path, serde_json::to_string_pretty(&signed).unwrap()).unwrap();

        // Trust the publisher anyway.
        let pk = SigningKey::from_secret_hex(std::fs::read_to_string(&key_path).unwrap().trim())
            .unwrap()
            .verifying_key_hex();
        let trust_path = dir.join("trust.toml");
        let mut tl = TrustList::new();
        tl.allow_hex(&pk, "tester");
        tl.save(&trust_path).unwrap();

        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "verify must reject tampered signed bundle"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// §15 replay defence: a signed bundle from a still-trusted key whose
    /// `created_unix` is older than the freshness window must be REFUSED by
    /// the default `run_verify` path (the production import path previously
    /// called the unprotected `verify()`, so a captured bundle replayed
    /// forever). `--allow-stale` is the documented opt-out.
    #[test]
    fn verify_rejects_stale_bundle_but_allow_stale_overrides() {
        let dir = fresh_dir("stale");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, br#"{"hosts":["api.example.com"]}"#).unwrap();
        let key_path = dir.join("signing.hex");
        run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        let signed_path = dir.join("envelope.signed.json");
        run_sign(SignArgs {
            envelope: env_path,
            bundle_name: Some("stale-bundle".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path.clone()),
        });

        // Back-date created_unix to 60 days ago — beyond the 30-day default.
        let raw = std::fs::read_to_string(&signed_path).unwrap();
        let mut signed: SignedBundle = serde_json::from_str(&raw).expect("parse signed bundle");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        signed.bundle.created_unix = now.saturating_sub(60 * 86_400);
        // Re-sign so the signature matches the back-dated payload (the
        // timestamp is inside the signed canonical bytes, so we must
        // re-sign to isolate the FRESHNESS check from the signature check).
        let sk = SigningKey::from_secret_hex(std::fs::read_to_string(&key_path).unwrap().trim())
            .unwrap();
        let resigned = signed.bundle.sign(&sk).expect("re-sign back-dated bundle");
        std::fs::write(
            &signed_path,
            serde_json::to_string_pretty(&resigned).unwrap(),
        )
        .unwrap();

        // Trust the publisher.
        let pk = sk.verifying_key_hex();
        let trust_path = dir.join("trust.toml");
        let mut tl = TrustList::new();
        tl.allow_hex(&pk, "tester");
        tl.save(&trust_path).unwrap();

        // Default path (freshness ON) must REFUSE the stale bundle.
        let code = run_verify(VerifyArgs {
            signed: signed_path.clone(),
            trust_list: Some(trust_path.clone()),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "default verify must reject a 60-day-old bundle (replay defence)"
        );

        // --allow-stale opts out → the same bundle verifies (signature +
        // trust still hold, only the freshness window is waived).
        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: true,
        });
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "--allow-stale must accept the otherwise-valid stale bundle"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// §15 clock-skew guard: a bundle dated far in the FUTURE (forged
    /// timestamp that would otherwise dodge the age check) is refused.
    #[test]
    fn verify_rejects_future_dated_bundle() {
        let dir = fresh_dir("future");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, br#"{"hosts":["api.example.com"]}"#).unwrap();
        let key_path = dir.join("signing.hex");
        run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        let signed_path = dir.join("envelope.signed.json");
        run_sign(SignArgs {
            envelope: env_path,
            bundle_name: Some("future-bundle".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path.clone()),
        });

        let raw = std::fs::read_to_string(&signed_path).unwrap();
        let mut signed: SignedBundle = serde_json::from_str(&raw).expect("parse signed bundle");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        signed.bundle.created_unix = now.saturating_add(86_400); // +1 day, ≫ 300s skew
        let sk = SigningKey::from_secret_hex(std::fs::read_to_string(&key_path).unwrap().trim())
            .unwrap();
        let resigned = signed.bundle.sign(&sk).expect("re-sign future bundle");
        std::fs::write(
            &signed_path,
            serde_json::to_string_pretty(&resigned).unwrap(),
        )
        .unwrap();

        let pk = sk.verifying_key_hex();
        let trust_path = dir.join("trust.toml");
        let mut tl = TrustList::new();
        tl.allow_hex(&pk, "tester");
        tl.save(&trust_path).unwrap();

        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "verify must reject a bundle dated a day in the future (clock-skew/forgery guard)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trust_add_then_list_round_trip() {
        let dir = fresh_dir("trust");
        let trust_path = dir.join("trust.toml");
        let code = run_trust(TrustArgs {
            action: TrustAction::Add(TrustAddArgs {
                public_key_hex: "abcdef".into(),
                name: "alice".into(),
                trust_list: Some(trust_path.clone()),
            }),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let tl = TrustList::load(&trust_path).unwrap();
        assert!(tl.contains("abcdef"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trust_remove_drops_publisher() {
        let dir = fresh_dir("trust-rm");
        let trust_path = dir.join("trust.toml");
        run_trust(TrustArgs {
            action: TrustAction::Add(TrustAddArgs {
                public_key_hex: "abc".into(),
                name: "alice".into(),
                trust_list: Some(trust_path.clone()),
            }),
        });
        run_trust(TrustArgs {
            action: TrustAction::Remove(TrustRemoveArgs {
                public_key_hex: "abc".into(),
                trust_list: Some(trust_path.clone()),
            }),
        });
        let tl = TrustList::load(&trust_path).unwrap();
        assert!(!tl.contains("abc"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gen_key_refuses_to_overwrite_existing_file() {
        let dir = fresh_dir("nokoverwrite");
        let key_path = dir.join("signing.hex");
        std::fs::write(&key_path, "preexisting").unwrap();
        let code = run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "must refuse to overwrite an existing key file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── pure helpers ──────────────────────────────────────────

    #[test]
    fn envelope_to_genome_wraps_bytes_under_envelope_v1_name() {
        let bytes = br#"{"hosts":["api.example.com"]}"#;
        let bundle = envelope_to_genome(bytes, "test-bundle");
        // Exactly one genome — the v1 atomic-envelope shape.
        assert_eq!(bundle.genomes.len(), 1);
        let g = &bundle.genomes[0];
        // The genome name is `<bundle_name>-envelope-v1`.
        assert!(g.name.contains("envelope-v1"));
        assert!(g.name.contains("test-bundle"));
        // The payload is the envelope bytes as UTF-8.
        assert!(g.payload.contains("api.example.com"));
    }

    #[test]
    fn envelope_to_genome_handles_empty_envelope() {
        let bundle = envelope_to_genome(b"", "empty");
        assert_eq!(bundle.genomes.len(), 1);
        assert!(bundle.genomes[0].payload.is_empty());
    }

    #[test]
    fn envelope_to_genome_preserves_non_utf8_bytes_via_lossy_decode() {
        // Non-UTF8 input survives via lossy decode (replacement chars
        // appear). Anti-rig: we don't panic on hostile-shaped envelopes.
        let bytes: Vec<u8> = vec![0xFF, b'a', 0xFE, b'b'];
        let bundle = envelope_to_genome(&bytes, "bin");
        assert_eq!(bundle.genomes.len(), 1);
        // Replacement chars present.
        assert!(bundle.genomes[0].payload.contains('\u{FFFD}'));
        assert!(bundle.genomes[0].payload.contains('a'));
        assert!(bundle.genomes[0].payload.contains('b'));
    }

    #[test]
    fn write_secret_hex_writes_trailing_newline() {
        // Operators inspect the file directly with `cat`; a trailing
        // newline is the right cat-friendly shape and the file-format
        // contract.
        let dir = fresh_dir("hex-trail");
        let path = dir.join("secret.hex");
        write_secret_hex_atomic(&path, "deadbeef").unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.ends_with('\n'), "must end with newline: {raw:?}");
        assert!(raw.starts_with("deadbeef"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_secret_hex_creates_parent_directories() {
        // If the parent dir doesn't exist, create it. Operators pass
        // `~/.wafrift/signing.hex` on a fresh box.
        let dir = fresh_dir("hex-mkdir");
        let nested = dir.join("a").join("b").join("c");
        let path = nested.join("secret.hex");
        write_secret_hex_atomic(&path, "feedface").unwrap();
        assert!(path.exists());
        assert!(nested.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_signing_key_round_trips_through_disk() {
        let dir = fresh_dir("read-key");
        let path = dir.join("signing.hex");
        let key = SigningKey::generate();
        let hex = key.secret_hex();
        write_secret_hex_atomic(&path, hex).unwrap();
        let loaded = read_signing_key(&path).expect("must load");
        assert_eq!(loaded.secret_hex(), hex);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_secret_hex_atomic_is_owner_only_0600() {
        // §15 least-privilege regression: the ed25519 signing key must land
        // on disk 0600, never world/group readable — even transiently. A
        // leaked signing key lets an attacker forge gene-bank envelopes the
        // operator trusts. The atomic `.mode(0o600)` create eliminates the
        // write-then-chmod window; pin the resulting mode here.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = fresh_dir("key-perms");
        let path = dir.join("signing.hex");
        let key = SigningKey::generate();
        write_secret_hex_atomic(&path, key.secret_hex()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "signing key must be 0600, got {:o}",
            mode & 0o777
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_signing_key_strips_trailing_whitespace() {
        // The file ends with `\n` from write_secret_hex; read_signing_key
        // must `.trim()` before calling SigningKey::from_secret_hex,
        // otherwise the from_secret_hex parser rejects the input.
        let dir = fresh_dir("trim");
        let path = dir.join("signing.hex");
        let key = SigningKey::generate();
        let hex = key.secret_hex();
        std::fs::write(&path, format!("  {hex}\n\n  ")).unwrap();
        let loaded = read_signing_key(&path).expect("trimming must succeed");
        assert_eq!(loaded.secret_hex(), hex);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_signing_key_rejects_malformed_hex() {
        let dir = fresh_dir("bad-hex");
        let path = dir.join("signing.hex");
        std::fs::write(&path, "not-real-hex").unwrap();
        let err = read_signing_key(&path).expect_err("malformed must error");
        // Error should describe what went wrong, not panic.
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_signing_key_handles_missing_file() {
        let path = std::env::temp_dir().join(format!(
            "wafrift-bank-registry-missing-{}-{}",
            std::process::id(),
            line!()
        ));
        // path intentionally not created.
        let err = read_signing_key(&path).expect_err("missing must error");
        assert!(err.contains("read") || err.to_lowercase().contains("system cannot"));
    }
}
