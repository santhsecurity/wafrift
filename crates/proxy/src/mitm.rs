//! MITM (Man-in-the-Middle) functionality for HTTPS interception.
//!
//! Provides a local CA that signs per-host TLS certificates so clients can
//! trust one root (`wafrift-mitm-ca.pem`) while the proxy terminates TLS.

use anyhow::Context;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

const CA_CERT_FILE: &str = "wafrift-mitm-ca.pem";
const CA_KEY_FILE: &str = "wafrift-mitm-ca-key.pem";

/// A certificate authority for generating on-the-fly TLS certificates.
pub struct CertificateAuthority {
    /// PEM of the CA certificate (install this in clients).
    cert_pem: String,
    /// PEM of the CA private key (keep secret).
    key_pair: KeyPair,
}

impl CertificateAuthority {
    /// Generate a new self-signed CA certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation fails.
    pub fn generate() -> anyhow::Result<Self> {
        let mut ca_params = CertificateParams::new(vec!["WAF Rift MITM CA".to_string()])
            .context("CA CertificateParams::new")?;
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "WafRift");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        // Bounded CA validity (397 days, the CA/B forum max for leafs
        // — conservative even for a root). A locally-issued MITM CA
        // is a network-wide trust root for any client that imports
        // it, so a security-tool-shipped CA must not default to the
        // 10-year-root rcgen default. Practitioners regenerate per
        // engagement via `wafrift-proxy --write-mitm-ca-dir`.
        let now = time::OffsetDateTime::now_utc();
        ca_params.not_before = now - time::Duration::minutes(5);
        ca_params.not_after = now + time::Duration::days(397);

        let ca_key =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate CA key")?;
        let ca_cert = ca_params.self_signed(&ca_key).context("self_signed CA")?;

        Ok(Self {
            cert_pem: ca_cert.pem(),
            key_pair: ca_key,
        })
    }

    /// Load CA material written by [`Self::write_to_dir`].
    pub fn load_from_dir(dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = dir.as_ref();
        let cert_pem = std::fs::read_to_string(dir.join(CA_CERT_FILE))
            .with_context(|| format!("read {}", dir.join(CA_CERT_FILE).display()))?;
        let key_pem = std::fs::read_to_string(dir.join(CA_KEY_FILE))
            .with_context(|| format!("read {}", dir.join(CA_KEY_FILE).display()))?;
        let key_pair = KeyPair::from_pem(&key_pem).context("parse CA private key PEM")?;
        Ok(Self { cert_pem, key_pair })
    }

    /// Write CA cert and key for installation in clients (authorized testing only).
    pub fn write_to_dir(&self, dir: impl AsRef<Path>) -> anyhow::Result<()> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        std::fs::write(dir.join(CA_CERT_FILE), self.cert_pem.as_bytes())
            .with_context(|| format!("write {}", dir.join(CA_CERT_FILE).display()))?;
        let key_path = dir.join(CA_KEY_FILE);
        std::fs::write(&key_path, self.key_pair.serialize_pem().as_bytes())
            .with_context(|| format!("write {}", key_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms)
                .with_context(|| format!("chmod {}", key_path.display()))?;
        }
        #[cfg(windows)]
        {
            // Strip inherited ACL entries and grant the current user
            // exclusive read/write. Without this the key inherits the
            // parent dir's ACL, leaving it potentially readable by
            // other users on a shared host. icacls is documented and
            // ships with every supported Windows version since Vista.
            //
            // Audit (2026-05-10): pre-fix the icacls status was
            // discarded with `let _ = ...`. A silent failure here
            // would leave the CA private key world-readable on a
            // multi-user box without any operator-visible signal.
            // We now hard-error if either icacls invocation fails or
            // exits non-zero.
            use std::process::Command;
            let user = std::env::var("USERNAME").unwrap_or_else(|_| "%USERNAME%".to_string());
            let inherit = Command::new("icacls")
                .arg(&key_path)
                .arg("/inheritance:r")
                .status()
                .with_context(|| format!("icacls /inheritance:r on {}", key_path.display()))?;
            if !inherit.success() {
                anyhow::bail!(
                    "icacls /inheritance:r on {} failed with status {inherit:?}",
                    key_path.display()
                );
            }
            let grant = Command::new("icacls")
                .arg(&key_path)
                .arg("/grant:r")
                .arg(format!("{user}:F"))
                .status()
                .with_context(|| format!("icacls /grant:r on {}", key_path.display()))?;
            if !grant.success() {
                anyhow::bail!(
                    "icacls /grant:r {user}:F on {} failed with status {grant:?}",
                    key_path.display()
                );
            }
        }
        Ok(())
    }

    /// Issue a leaf server certificate for `tls_server_name` (SNI / Host).
    ///
    /// # Errors
    ///
    /// Returns an error if signing or key generation fails.
    pub fn issue_server_cert(&self, tls_server_name: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, &self.key_pair)
            .context("Issuer::from_ca_cert_pem")?;
        let leaf_params = leaf_params_for(tls_server_name)?;
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("leaf key")?;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .context("sign leaf cert")?;

        Ok((
            leaf_cert.pem().into_bytes(),
            leaf_key.serialize_pem().into_bytes(),
        ))
    }

    /// Issue a leaf server certificate for `tls_server_name` (SNI / Host) in DER format.
    ///
    /// # Errors
    ///
    /// Returns an error if signing or key generation fails.
    pub fn issue_server_cert_der(
        &self,
        tls_server_name: &str,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, &self.key_pair)
            .context("Issuer::from_ca_cert_pem")?;
        let leaf_params = leaf_params_for(tls_server_name)?;
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("leaf key")?;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .context("sign leaf cert")?;
        Ok((leaf_cert.der().to_vec(), leaf_key.serialize_der()))
    }

    /// Get the CA certificate as PEM bytes.
    #[must_use]
    pub fn cert_pem(&self) -> Vec<u8> {
        self.cert_pem.as_bytes().to_vec()
    }

    /// Get the CA private key as PEM bytes.
    #[must_use]
    pub fn key_pem(&self) -> Vec<u8> {
        self.key_pair.serialize_pem().into_bytes()
    }

    /// Create a TLS server acceptor for `tls_server_name`.
    ///
    /// # Errors
    ///
    /// Returns an error if certificate or acceptor creation fails.
    pub fn create_tls_acceptor(&self, tls_server_name: &str) -> anyhow::Result<TlsAcceptor> {
        let (cert_der, key_der) = self.issue_server_cert_der(tls_server_name)?;

        let cert = vec![cert_der.into()];
        let key = rustls_pki_types::PrivateKeyDer::try_from(key_der)
            .map_err(|e| anyhow::anyhow!("no private key found: {e}"))?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

/// Build the leaf-cert params with a 397-day validity window pinned
/// to `now - 5 min` .. `now + 397 days`.
///
/// Audit (2026-05-10): pre-fix the leaf inherited rcgen's default
/// 10-year validity. Modern browsers reject leafs over ~398 days, so
/// any practitioner who installed the wafrift CA in a real browser
/// would see TLS errors on every MITM session before traffic flowed.
fn leaf_params_for(tls_server_name: &str) -> anyhow::Result<CertificateParams> {
    // Refuse to mint a wildcard leaf — the MITM CA must never sign a
    // cert that covers more than the specific SNI it was asked for.
    // A malformed CONNECT authority or a hostile-source SNI containing
    // `*` would otherwise produce a wildcard dNSName SAN, and any
    // client that accepts the wafrift CA would then accept that cert
    // for every subdomain. Reject explicitly so a `CONNECT *.evil.tld`
    // can't widen the CA's blast radius.
    if tls_server_name.contains('*') {
        anyhow::bail!(
            "refusing to issue wildcard cert for SNI {tls_server_name:?} — \
             MITM CA must mint host-specific leaves only"
        );
    }
    // Also reject obviously malformed inputs that would produce an
    // invalid cert: bare `[` (unclosed IPv6), embedded null/CR/LF
    // (header smuggling into the cert name).
    if tls_server_name.is_empty()
        || tls_server_name.contains(['\0', '\r', '\n'])
        || (tls_server_name.starts_with('[') && !tls_server_name.contains(']'))
    {
        anyhow::bail!("refusing malformed SNI {tls_server_name:?}");
    }
    let mut leaf_params =
        CertificateParams::new(vec![tls_server_name.to_string()]).context("leaf params")?;
    // Browsers (and rustls) require iPAddress SAN for IP literals; dNSName
    // SANs that look like IPs are rejected per RFC 2818 §3.1.
    if let Ok(ip) = tls_server_name.parse::<std::net::IpAddr>() {
        leaf_params.subject_alt_names = vec![SanType::IpAddress(ip)];
    }
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    let now = time::OffsetDateTime::now_utc();
    leaf_params.not_before = now - time::Duration::minutes(5);
    leaf_params.not_after = now + time::Duration::days(397);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, tls_server_name);
    leaf_params.distinguished_name = dn;
    Ok(leaf_params)
}

/// Check if a request is a CONNECT request for HTTPS proxying.
#[must_use]
pub fn is_connect_request(req: &hyper::Request<hyper::body::Incoming>) -> bool {
    req.method() == hyper::Method::CONNECT
}

/// Extract the host and port from a CONNECT request.
#[must_use]
pub fn extract_connect_host(req: &hyper::Request<hyper::body::Incoming>) -> Option<String> {
    req.uri().authority().map(std::string::ToString::to_string)
}

/// TLS certificate name from CONNECT authority (e.g. `example.com:443` → `example.com`).
#[must_use]
pub fn tls_server_name_from_authority(authority: &str) -> String {
    if authority.starts_with('[')
        && let Some(end) = authority.find(']')
    {
        return authority[1..end].to_string();
    }
    authority
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|_| host.to_string()))
        .unwrap_or_else(|| authority.to_string())
}

/// Create a self-signed certificate for testing.
///
/// # Errors
///
/// Returns an error if certificate generation fails.
pub fn generate_test_cert() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;

    Ok((
        cert.cert.pem().into_bytes(),
        cert.signing_key.serialize_pem().into_bytes(),
    ))
}

// ──────────────────────────────────────────────
//  OS trust store helpers
// ──────────────────────────────────────────────

/// Default directory for the auto-generated MITM CA.
///
/// Returns `~/.wafrift/mitm-ca/`.
pub fn default_mitm_ca_dir() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".wafrift").join("mitm-ca"))
}

/// Result of an OS trust store installation attempt.
#[derive(Debug)]
pub enum TrustResult {
    /// CA was installed automatically.
    Installed {
        /// How it was installed (e.g. "update-ca-certificates").
        method: String,
    },
    /// Auto-install not possible — manual instructions provided.
    ManualRequired {
        /// Platform-specific instructions.
        instructions: String,
    },
    /// Auto-install failed — fallback to manual.
    Failed {
        /// What went wrong.
        error: String,
        /// Manual instructions as fallback.
        instructions: String,
    },
}

/// Attempt to install a CA certificate in the OS trust store.
///
/// On Linux, tries `update-ca-certificates` (Debian/Ubuntu) or
/// `trust anchor` (Fedora/RHEL) automatically.
///
/// On macOS and Windows, provides copy-paste terminal commands.
///
/// # Arguments
///
/// * `ca_cert_path` — Path to the CA PEM file to trust.
pub fn install_ca_trust(ca_cert_path: &std::path::Path) -> TrustResult {
    let cert_display = ca_cert_path.display().to_string();

    #[cfg(target_os = "linux")]
    {
        // sudo without cached creds prompts on stdin and would hang in a
        // CI/headless context. Probe non-interactively first.
        let sudo_available = std::process::Command::new("sudo")
            .args(["-n", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());

        // Try Debian/Ubuntu path first.
        let debian_dir = std::path::Path::new("/usr/local/share/ca-certificates");
        if sudo_available && debian_dir.is_dir() {
            let dest = debian_dir.join("wafrift-mitm-ca.crt");
            let cp = std::process::Command::new("sudo")
                .args(["-n", "cp", &cert_display, &dest.display().to_string()])
                .stdin(std::process::Stdio::null())
                .status();
            if let Ok(status) = cp
                && status.success()
            {
                let update = std::process::Command::new("sudo")
                    .args(["-n", "update-ca-certificates"])
                    .stdin(std::process::Stdio::null())
                    .status();
                if let Ok(s) = update
                    && s.success()
                {
                    return TrustResult::Installed {
                        method: "update-ca-certificates (Debian/Ubuntu)".into(),
                    };
                }
            }
            // Fall through to manual.
        }

        // Try Fedora/RHEL trust(1) — does NOT need sudo, can run as user.
        if let Ok(status) = std::process::Command::new("trust")
            .args(["anchor", "--store", &cert_display])
            .stdin(std::process::Stdio::null())
            .status()
            && status.success()
        {
            return TrustResult::Installed {
                method: "trust anchor (Fedora/RHEL)".into(),
            };
        }

        TrustResult::ManualRequired {
            instructions: format!(
                "Install the CA certificate in your OS trust store:\n\n\
                 Debian/Ubuntu:\n\
                 \x20 sudo cp {cert_display} /usr/local/share/ca-certificates/wafrift-mitm-ca.crt\n\
                 \x20 sudo update-ca-certificates\n\n\
                 Fedora/RHEL:\n\
                 \x20 sudo trust anchor --store {cert_display}\n\n\
                 Arch:\n\
                 \x20 sudo trust anchor {cert_display}\n\n\
                 Firefox (all platforms):\n\
                 \x20 Settings → Privacy & Security → Certificates → View Certificates → Import"
            ),
        }
    }

    #[cfg(target_os = "macos")]
    {
        TrustResult::ManualRequired {
            instructions: format!(
                "Install the CA certificate in the macOS Keychain:\n\n\
                 \x20 sudo security add-trusted-cert -d -r trustRoot \\\n\
                 \x20   -k /Library/Keychains/System.keychain {cert_display}\n\n\
                 Or open Keychain Access → File → Import Items → select the .pem → Always Trust"
            ),
        }
    }

    #[cfg(target_os = "windows")]
    {
        TrustResult::ManualRequired {
            instructions: format!(
                "Install the CA certificate in the Windows trust store:\n\n\
                 \x20 certutil -addstore -f \"ROOT\" \"{cert_display}\"\n\n\
                 Or double-click the .pem file → Install Certificate → Local Machine → \
                 Trusted Root Certification Authorities"
            ),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        TrustResult::ManualRequired {
            instructions: format!(
                "Manually install {cert_display} in your OS certificate trust store."
            ),
        }
    }
}

/// Ensure a MITM CA exists at `dir`, generating one if needed.
///
/// Returns the loaded `CertificateAuthority`.
///
/// Race-free: attempts the load directly and only falls through to
/// `generate()` on `ErrorKind::NotFound`. The prior `exists() &&
/// exists() → load_from_dir` pattern had two windows for a symlink
/// swap to redirect the load to an attacker-controlled cert file
/// between the checks and the open.
pub fn ensure_ca(dir: &std::path::Path) -> anyhow::Result<CertificateAuthority> {
    match CertificateAuthority::load_from_dir(dir) {
        Ok(ca) => Ok(ca),
        Err(err) => {
            // Treat any I/O NotFound on cert OR key as "needs generation".
            // Other errors (permission denied, malformed PEM, parse failure)
            // surface as-is so we never silently overwrite a real CA.
            let is_missing = err
                .chain()
                .filter_map(|e| e.downcast_ref::<std::io::Error>())
                .any(|io| io.kind() == std::io::ErrorKind::NotFound);
            if !is_missing {
                return Err(err);
            }
            tracing::info!(dir = %dir.display(), "generating new MITM CA");
            let ca = CertificateAuthority::generate()?;
            ca.write_to_dir(dir)?;
            Ok(ca)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_generation_succeeds() {
        let ca = CertificateAuthority::generate();
        assert!(ca.is_ok());
    }

    #[test]
    fn ca_signed_leaf_differs_from_ca() {
        let ca = CertificateAuthority::generate().unwrap();
        let (leaf_pem, _) = ca.issue_server_cert("example.com").unwrap();
        assert_ne!(ca.cert_pem.as_bytes(), leaf_pem.as_slice());
    }

    #[test]
    fn leaf_params_refuses_wildcard_sni() {
        // Regression for F66: a wildcard SNI must not produce a
        // wildcard leaf cert. Any client trusting the wafrift CA
        // would then accept the cert for every matching subdomain
        // — widens the MITM blast radius beyond the specific host
        // the operator targeted.
        let err = leaf_params_for("*.evil.example.com")
            .expect_err("wildcard SNI must be rejected");
        assert!(format!("{err}").contains("wildcard"));
    }

    #[test]
    fn leaf_params_refuses_empty_or_malformed_sni() {
        assert!(leaf_params_for("").is_err());
        assert!(leaf_params_for("host\nwith-newline").is_err());
        assert!(leaf_params_for("host\rcr").is_err());
        assert!(leaf_params_for("host\0nul").is_err());
        // Unclosed IPv6 bracket.
        assert!(leaf_params_for("[::1").is_err());
    }

    #[test]
    fn leaf_params_accepts_normal_hostname_and_ipv6() {
        assert!(leaf_params_for("api.example.com").is_ok());
        assert!(leaf_params_for("[::1]").is_ok());
        assert!(leaf_params_for("127.0.0.1").is_ok());
    }

    #[test]
    fn tls_server_name_strips_port() {
        assert_eq!(
            tls_server_name_from_authority("example.com:443"),
            "example.com"
        );
    }

    #[test]
    fn write_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("wafrift_mitm_ca_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = CertificateAuthority::generate().unwrap();
        ca.write_to_dir(&dir).unwrap();
        let loaded = CertificateAuthority::load_from_dir(&dir).unwrap();
        assert_eq!(loaded.cert_pem, ca.cert_pem);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ca_generate_cert_for_domain() {
        let ca = CertificateAuthority::generate().unwrap();
        let (cert, key) = ca.issue_server_cert("example.com").unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
        let cert_str = String::from_utf8(cert).unwrap();
        assert!(cert_str.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_cert_generation() {
        let (cert, key) = generate_test_cert().unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
    }

    #[test]
    fn default_mitm_ca_dir_is_under_wafrift() {
        if let Some(dir) = default_mitm_ca_dir() {
            assert!(dir.ends_with("mitm-ca"));
            let parent = dir.parent().unwrap();
            assert!(parent.ends_with(".wafrift"));
        }
    }

    #[test]
    fn ensure_ca_generates_and_reloads() {
        let dir = std::env::temp_dir().join(format!("wafrift_ensure_ca_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // First call: generates.
        let ca1 = ensure_ca(&dir).unwrap();
        assert!(!ca1.cert_pem.is_empty());

        // Second call: loads existing.
        let ca2 = ensure_ca(&dir).unwrap();
        assert_eq!(ca1.cert_pem, ca2.cert_pem);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
