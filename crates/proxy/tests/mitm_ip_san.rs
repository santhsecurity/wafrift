//! Proving + adversarial tests for MITM leaf-cert SAN handling.
//!
//! Defect: leaf_params_for used CertificateParams::new() which creates
//! dNSName SANs for all strings. Browsers (and rustls) require
//! iPAddress SANs for IP literals per RFC 2818 §3.1. A pentester
//! proxying https://127.0.0.1 would see a TLS handshake failure.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use wafrift_proxy::mitm::CertificateAuthority;

static PROVIDER_INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();

fn ensure_rustls_provider() {
    PROVIDER_INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

async fn start_leaf_server(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let cert = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::try_from(key_der).expect("private key parse");
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind test tls server");
    let port = listener.local_addr().expect("listener local addr").port();

    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept tls stream");
        let _tls = acceptor.accept(stream).await.expect("complete tls handshake");
    });
    (port, handle)
}

#[tokio::test]
async fn mitm_leaf_cert_ipv4_validates_with_rustls() {
    ensure_rustls_provider();
    let host = "127.0.0.1";
    let ca = CertificateAuthority::generate().expect("generate ca");
    let (leaf_cert, leaf_key) = ca.issue_server_cert_der(host).expect("issue leaf");
    let (server_port, handle) = start_leaf_server(leaf_cert, leaf_key).await;

    let ca_cert = CertificateDer::from_pem_slice(&ca.cert_pem()).expect("parse ca cert");
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert).expect("add ca cert to root store");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
        .await
        .expect("connect server");
    let server_name = ServerName::IpAddress(std::net::Ipv4Addr::new(127, 0, 0, 1).into());
    let _tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client handshake must succeed when cert carries iPAddress SAN");
    sleep(Duration::from_millis(25)).await;
    handle.abort();
}

#[tokio::test]
async fn mitm_leaf_cert_ipv6_loopback_validates_with_rustls() {
    ensure_rustls_provider();
    let host = "::1";
    let ca = CertificateAuthority::generate().expect("generate ca");
    let (leaf_cert, leaf_key) = ca.issue_server_cert_der(host).expect("issue leaf");
    let (server_port, handle) = start_leaf_server(leaf_cert, leaf_key).await;

    let ca_cert = CertificateDer::from_pem_slice(&ca.cert_pem()).expect("parse ca cert");
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert).expect("add ca cert to root store");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
        .await
        .expect("connect server");
    let server_name = ServerName::IpAddress(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into());
    let _tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client handshake must succeed for IPv6 loopback iPAddress SAN");
    sleep(Duration::from_millis(25)).await;
    handle.abort();
}

#[tokio::test]
async fn mitm_leaf_cert_dns_name_still_validates() {
    // Negative twin: DNS names must still produce dNSName SANs and
    // validate normally — the IP-literal fix must not break the
    // common case.
    ensure_rustls_provider();
    let host = "example.com";
    let ca = CertificateAuthority::generate().expect("generate ca");
    let (leaf_cert, leaf_key) = ca.issue_server_cert_der(host).expect("issue leaf");
    let (server_port, handle) = start_leaf_server(leaf_cert, leaf_key).await;

    let ca_cert = CertificateDer::from_pem_slice(&ca.cert_pem()).expect("parse ca cert");
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert).expect("add ca cert to root store");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
        .await
        .expect("connect server");
    let server_name = ServerName::try_from(host).expect("server name");
    let _tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client handshake for DNS name must still work");
    sleep(Duration::from_millis(25)).await;
    handle.abort();
}
