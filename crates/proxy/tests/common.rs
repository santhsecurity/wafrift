use std::io;
use std::process::Stdio;
use std::process::Output;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;

pub fn pick_free_port() -> io::Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.local_addr().map(|addr| addr.port())
}

pub async fn start_proxy_with_output(port: u16, args: &[&str]) -> io::Result<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafrift-proxy"));
    cmd.arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().await
}

pub async fn start_proxy(port: u16, args: &[&str]) -> io::Result<Child> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafrift-proxy"));
    cmd.arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn()
}

pub async fn start_proxy_and_wait(port: u16, args: &[&str]) -> io::Result<Child> {
    let mut child = start_proxy(port, args).await?;
    wait_for_listen(&mut child, port, Duration::from_secs(5)).await?;
    Ok(child)
}

pub async fn wait_for_listen(
    child: &mut Child,
    port: u16,
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Err(io::Error::other(format!(
                "proxy exited during startup on port {port}"
            )));
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out waiting for proxy on 127.0.0.1:{port}"),
            ));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

pub fn proxy_client(port: u16) -> Result<reqwest::Client, reqwest::Error> {
    let proxy = format!("http://127.0.0.1:{port}");
    reqwest::Client::builder().proxy(reqwest::Proxy::all(proxy)?).build()
}

pub async fn stop_proxy(child: &mut Child) {
    if child.try_wait().ok().and_then(|s| s).is_none() {
        let _ = child.kill().await;
    }
    let _ = child.wait().await;
}
