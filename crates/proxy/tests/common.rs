use std::io;
use std::process::Output;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;

pub fn pick_free_port() -> io::Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.local_addr().map(|addr| addr.port())
}

#[allow(dead_code)]
pub async fn start_proxy_with_output(port: u16, args: &[&str]) -> io::Result<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafrift-proxy"));
    cmd.arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().await
}

#[allow(dead_code)]
pub async fn start_proxy(port: u16, args: &[&str]) -> io::Result<Child> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafrift-proxy"));
    cmd.arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn()
}

#[allow(dead_code)]
pub async fn start_proxy_and_wait(port: u16, args: &[&str]) -> io::Result<Child> {
    let mut child = start_proxy(port, args).await?;
    wait_for_listen(&mut child, port, Duration::from_secs(5)).await?;
    Ok(child)
}

#[allow(dead_code)]
pub async fn wait_for_listen(child: &mut Child, port: u16, timeout: Duration) -> io::Result<()> {
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

#[allow(dead_code)]
pub fn proxy_client(port: u16) -> Result<reqwest::Client, reqwest::Error> {
    let proxy = format!("http://127.0.0.1:{port}");
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy)?)
        .build()
}

#[allow(dead_code)]
pub async fn stop_proxy(child: &mut Child) {
    if child.try_wait().ok().and_then(|s| s).is_none() {
        let _ = child.kill().await;
    }
    let _ = child.wait().await;
}

/// Confirm a just-started proxy actually *owns* the port it appeared to listen
/// on, rather than us having connected to another test's proxy that won the
/// pick→bind race.
///
/// `wait_for_listen` returns as soon as *some* process answers on the port. Two
/// processes can never bind the same port, so if our child lost the race it
/// failed to bind `--listen` and exits within a few ms of startup — and by the
/// time the listener answered, that exit has usually already happened. A short
/// grace catches the rare in-flight exit without padding healthy starts. `true`
/// means the child is still alive and therefore is the listener we reached.
async fn child_still_alive_after_grace(child: &mut Child) -> bool {
    for _ in 0..3 {
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }
        sleep(Duration::from_millis(15)).await;
    }
    child.try_wait().ok().flatten().is_none()
}

/// Pick a free port, spawn the proxy, and wait for it to listen — retrying
/// with a fresh port if the spawn loses the pick→bind race.
///
/// `pick_free_port` binds `:0`, reads the assigned port, then *releases* it
/// before the proxy subprocess re-binds. Under parallel test load another test
/// can grab that port in the gap. Two failure modes follow: (1) our proxy fails
/// to bind and exits, which `wait_for_listen` reports as Err; or (2) the winning
/// proxy answers our readiness probe, so `wait_for_listen` returns Ok against
/// the *wrong* process (one likely lacking `--allow-private-upstream`, which
/// then rejects the loopback upstream and fails the test on response status —
/// not on startup). `child_still_alive_after_grace` closes the second hole, and
/// re-picking the port closes both. Returns the live child and its bound port.
#[allow(dead_code)]
pub async fn start_proxy_on_free_port(args: &[&str]) -> io::Result<(Child, u16)> {
    let mut last_err: Option<io::Error> = None;
    for _ in 0..8 {
        let port = pick_free_port()?;
        match start_proxy_and_wait(port, args).await {
            Ok(mut child) => {
                if child_still_alive_after_grace(&mut child).await {
                    return Ok((child, port));
                }
                let _ = child.kill().await;
                last_err = Some(io::Error::other(format!(
                    "proxy exited just after listen on port {port} — lost pick→bind race"
                )));
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("start_proxy_on_free_port: no attempt made")))
}

/// Like `start_proxy_on_free_port` but pipes stderr (so the caller can read the
/// proxy's log output) and applies the given env vars before spawning.
///
/// The same pick→bind race applies, and here losing it is worse than a flake:
/// a manually-spawned proxy that fails to bind exits, but the test's connect
/// loop would then reach *another* test's proxy on that port and silently pass
/// against the wrong process. The `child_still_alive_after_grace` check plus a
/// fresh-port retry keep the log-capture tests sound. Returns the live child
/// (with `stderr` piped) and its port.
#[allow(dead_code)]
pub async fn start_proxy_piped_on_free_port(
    args: &[&str],
    envs: &[(&str, &str)],
) -> io::Result<(Child, u16)> {
    let mut last_err: Option<io::Error> = None;
    for _ in 0..8 {
        let port = pick_free_port()?;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafrift-proxy"));
        cmd.arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        let mut child = cmd.spawn()?;
        match wait_for_listen(&mut child, port, Duration::from_secs(5)).await {
            Ok(()) => {
                if child_still_alive_after_grace(&mut child).await {
                    return Ok((child, port));
                }
                let _ = child.kill().await;
                last_err = Some(io::Error::other(format!(
                    "proxy exited just after listen on port {port} — lost pick→bind race"
                )));
            }
            Err(e) => {
                let _ = child.kill().await;
                last_err = Some(e);
            }
        }
    }
    Err(last_err
        .unwrap_or_else(|| io::Error::other("start_proxy_piped_on_free_port: no attempt made")))
}
