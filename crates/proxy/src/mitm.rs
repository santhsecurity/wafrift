//! MITM (Man-in-the-Middle) functionality for HTTPS interception.
//!
//! Provides a local CA that signs per-host TLS certificates so clients can
//! trust one root (`wafrift-mitm-ca.pem`) while the proxy terminates TLS.

use anyhow::Context;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
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
            use std::process::Command;
            let user = std::env::var("USERNAME").unwrap_or_else(|_| "%USERNAME%".to_string());
            let _ = Command::new("icacls")
                .arg(&key_path)
                .arg("/inheritance:r")
                .status();
            let _ = Command::new("icacls")
                .arg(&key_path)
                .arg("/grant:r")
                .arg(format!("{user}:F"))
                .status();
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
        let mut leaf_params =
            CertificateParams::new(vec![tls_server_name.to_string()]).context("leaf params")?;
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, tls_server_name);
        leaf_params.distinguished_name = dn;

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
    pub fn issue_server_cert_der(&self, tls_server_name: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, &self.key_pair)
            .context("Issuer::from_ca_cert_pem")?;
        let mut leaf_params =
            CertificateParams::new(vec![tls_server_name.to_string()]).context("leaf params")?;
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, tls_server_name);
        leaf_params.distinguished_name = dn;

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("leaf key")?;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .context("sign leaf cert")?;

        Ok((
            leaf_cert.der().to_vec(),
            leaf_key.serialize_der(),
        ))
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

/// Check if a request is a CONNECT request for HTTPS proxying.
#[must_use]
pub fn is_connect_request(req: &hyper::Request<hyper::body::Incoming>) -> bool {
    req.method() == hyper::Method::CONNECT
}

/// Extract the host and port from a CONNECT request.
#[must_use]
pub fn extract_connect_host(req: &hyper::Request<hyper::body::Incoming>) -> Option<String> {
    req.uri().authority().map(|a| a.to_string())
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
        // Try Debian/Ubuntu path first.
        let debian_dir = std::path::Path::new("/usr/local/share/ca-certificates");
        if debian_dir.is_dir() {
            let dest = debian_dir.join("wafrift-mitm-ca.crt");
            let cp = std::process::Command::new("sudo")
                .args(["cp", &cert_display, &dest.display().to_string()])
                .status();
            if let Ok(status) = cp
                && status.success()
            {
                let update = std::process::Command::new("sudo")
                    .args(["update-ca-certificates"])
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

        // Try Fedora/RHEL trust(1).
        if let Ok(status) = std::process::Command::new("trust")
            .args(["anchor", "--store", &cert_display])
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
pub fn ensure_ca(dir: &std::path::Path) -> anyhow::Result<CertificateAuthority> {
    let cert_path = dir.join(CA_CERT_FILE);
    let key_path = dir.join(CA_KEY_FILE);

    if cert_path.exists() && key_path.exists() {
        return CertificateAuthority::load_from_dir(dir);
    }

    tracing::info!(dir = %dir.display(), "generating new MITM CA");
    let ca = CertificateAuthority::generate()?;
    ca.write_to_dir(dir)?;
    Ok(ca)
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
