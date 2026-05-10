use std::sync::Arc;
use std::sync::OnceLock;

use rustls::{client::ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use wafrift_proxy::mitm::CertificateAuthority;

static PROVIDER_INSTALL: OnceLock<()> = OnceLock::new();

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
        let _tls = acceptor
            .accept(stream)
            .await
            .expect("complete tls handshake");
    });
    (port, handle)
}

#[tokio::test]
async fn mitm_cert_chain_must_generate_and_validate_chain() {
    ensure_rustls_provider();
    let host = "example.com";
    let ca = CertificateAuthority::generate().expect("generate ca");
    let (leaf_cert, leaf_key) = ca.issue_server_cert_der(host).expect("issue leaf");
    let (server_port, handle) = start_leaf_server(leaf_cert, leaf_key).await;

    let ca_cert = CertificateDer::from_pem_slice(&ca.cert_pem()).expect("parse ca cert");
    let mut roots = RootCertStore::empty();
    roots
        .add(ca_cert)
        .expect("add ca cert to root store");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
        .await
        .expect("connect server");
    let _tls = connector
        .connect(ServerName::try_from(host).expect("server name"), tcp)
        .await
        .expect("client handshake");
    sleep(Duration::from_millis(25)).await;
    handle.abort();
}

#[tokio::test]
async fn mitm_cert_chain_must_not_validate_with_wrong_root() {
    ensure_rustls_provider();
    let host = "example.com";
    let ca = CertificateAuthority::generate().expect("generate good ca");
    let wrong = CertificateAuthority::generate().expect("generate wrong ca");
    let (leaf_cert, leaf_key) = ca.issue_server_cert_der(host).expect("issue leaf");
    let (server_port, handle) = start_leaf_server(leaf_cert, leaf_key).await;

    let wrong_root = CertificateDer::from_pem_slice(&wrong.cert_pem()).expect("parse wrong ca");
    let mut roots = RootCertStore::empty();
    roots
        .add(wrong_root)
        .expect("add wrong ca to root store");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
        .await
        .expect("connect server");

    let err = connector
        .connect(ServerName::try_from(host).expect("server name"), tcp)
        .await
        .expect_err("handshake should fail with wrong root");
    assert!(!err.to_string().is_empty());

    handle.abort();
}
