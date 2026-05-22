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

#[derive(Args, Debug)]
pub struct BankRegistryArgs {
    #[command(subcommand)]
    pub action: RegistryAction,
}

#[derive(Subcommand, Debug)]
pub enum RegistryAction {
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
pub struct GenKeyArgs {
    /// Path to write the secret hex to. Created with mode 0600 on
    /// Unix; never logged. Default `~/.wafrift/signing-key.hex`.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SignArgs {
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
pub struct VerifyArgs {
    /// Path to a signed bundle (`*.signed.json`).
    pub signed: PathBuf,
    /// Trust-list path. Default `~/.wafrift/trusted-keys.toml`.
    #[arg(long)]
    pub trust_list: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct PullArgs {
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
}

#[derive(Args, Debug)]
pub struct SubmitArgs {
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
pub struct TrustArgs {
    #[command(subcommand)]
    pub action: TrustAction,
}

#[derive(Subcommand, Debug)]
pub enum TrustAction {
    /// Print every trusted publisher.
    List(TrustListArgs),
    /// Allowlist a public key (hex) under `--name`.
    Add(TrustAddArgs),
    /// Drop a publisher from the allowlist.
    Remove(TrustRemoveArgs),
}

#[derive(Args, Debug)]
pub struct TrustListArgs {
    #[arg(long)]
    pub trust_list: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct TrustAddArgs {
    /// Hex-encoded ed25519 public key (64 chars).
    pub public_key_hex: String,
    /// Operator-facing display name.
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub trust_list: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct TrustRemoveArgs {
    pub public_key_hex: String,
    #[arg(long)]
    pub trust_list: Option<PathBuf>,
}

// ── dispatch ────────────────────────────────────────────────────────

pub fn run(args: BankRegistryArgs) -> ExitCode {
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

fn read_signing_key(path: &std::path::Path) -> Result<SigningKey, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let trimmed = raw.trim();
    SigningKey::from_secret_hex(trimmed).map_err(|e| format!("{e}"))
}

fn write_secret_hex(path: &std::path::Path, secret_hex: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, format!("{secret_hex}\n"))
        .map_err(|e| format!("write {}: {e}", path.display()))?;
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
    if path.exists() {
        return die(format!(
            "{} already exists; refuse to overwrite a key file",
            path.display()
        ));
    }
    if let Err(e) = write_secret_hex(&path, key.secret_hex()) {
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
    let envelope_bytes = match std::fs::read(&args.envelope) {
        Ok(b) => b,
        Err(e) => return die(format!("read {}: {e}", args.envelope.display())),
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
    if let Err(e) = std::fs::write(&out, &json) {
        return die(format!("write {}: {e}", out.display()));
    }
    eprintln!("signed → {} ({} bytes)", out.display(), json.len());
    ExitCode::SUCCESS
}

// ── verify ─────────────────────────────────────────────────────────

fn run_verify(args: VerifyArgs) -> ExitCode {
    let raw = match std::fs::read_to_string(&args.signed) {
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
    match signed.verify(&trust) {
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
        Err(e) => die(format!("verify: {e}")),
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
    let verified = match signed.verify(&trust) {
        Ok(b) => b,
        Err(e) => return die(format!("verify: {e}")),
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
    if let Err(e) = std::fs::write(&out, &json) {
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
    let envelope_bytes = match std::fs::read(&args.envelope) {
        Ok(b) => b,
        Err(e) => return die(format!("read {}: {e}", args.envelope.display())),
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

fn http_get_blocking(url: &str, timeout_secs: u64) -> Result<String, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| format!("client build: {e}"))?;
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
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| format!("client build: {e}"))?;
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
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "verify must reject tampered signed bundle"
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
        write_secret_hex(&path, "deadbeef").unwrap();
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
        write_secret_hex(&path, "feedface").unwrap();
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
        write_secret_hex(&path, &hex).unwrap();
        let loaded = read_signing_key(&path).expect("must load");
        assert_eq!(loaded.secret_hex(), hex);
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
