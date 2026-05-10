//! Tokio `TcpListener` serves one-line banners; recon classifies SSH / HTTP / SMTP (+ negative).

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use wafrift_recon::active::{
    probe_tcp_banner, ActiveProbeConfig, ReconProbeError, TcpServiceClass,
};

fn tcp_config() -> ActiveProbeConfig {
    ActiveProbeConfig {
        tcp_connect_timeout: Duration::from_secs(2),
        tcp_read_timeout: Duration::from_secs(2),
        max_banner_bytes: 512,
        ..ActiveProbeConfig::default()
    }
}

async fn one_shot_banner(banner: &'static [u8]) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = stream.write_all(banner).await;
        let _ = stream.shutdown().await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    addr
}

#[tokio::test]
async fn ssh_banner_detected() {
    let addr = one_shot_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n").await;
    let snap = probe_tcp_banner(addr, &tcp_config()).await.unwrap();
    assert_eq!(snap.service, TcpServiceClass::Ssh);
    assert!(snap.line.to_ascii_lowercase().contains("ssh-2.0"));
}

#[tokio::test]
async fn http_status_line_detected() {
    let addr = one_shot_banner(b"HTTP/1.1 400 Bad Request\r\n").await;
    let snap = probe_tcp_banner(addr, &tcp_config()).await.unwrap();
    assert_eq!(snap.service, TcpServiceClass::Http);
}

#[tokio::test]
async fn smtp_greeting_detected() {
    let addr = one_shot_banner(b"220 mock.smtp.test ESMTP ready\r\n").await;
    let snap = probe_tcp_banner(addr, &tcp_config()).await.unwrap();
    assert_eq!(snap.service, TcpServiceClass::Smtp);
}

#[tokio::test]
async fn non_protocol_banner_stays_unknown() {
    let addr = one_shot_banner(b"Welcome to the telnet service\r\n").await;
    let snap = probe_tcp_banner(addr, &tcp_config()).await.unwrap();
    assert_eq!(snap.service, TcpServiceClass::Unknown);
}

#[tokio::test]
async fn smtp_multiline_negative_still_classifies_first_line() {
    // First line is 220 → SMTP; proves we only classify the first line, not later junk.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = stream
            .write_all(b"220 mx.test ESMTP\r\n500 bad continuation\r\n")
            .await;
        let _ = stream.shutdown().await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let snap = probe_tcp_banner(addr, &tcp_config()).await.unwrap();
    assert_eq!(snap.service, TcpServiceClass::Smtp);
}

#[tokio::test]
async fn closed_port_negative_returns_io_not_panic() {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let err = probe_tcp_banner(addr, &tcp_config()).await.unwrap_err();
    assert!(matches!(err, ReconProbeError::Io(_)));
}
