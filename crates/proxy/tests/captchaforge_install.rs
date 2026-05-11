mod common;
use common::{pick_free_port, start_proxy_and_wait, stop_proxy};
#[cfg(not(feature = "captchaforge"))]
use common::start_proxy_with_output;
#[cfg(not(feature = "captchaforge"))]
use std::process::Output;

#[cfg(not(feature = "captchaforge"))]
fn combined_output(output: &Output) -> String {
    let mut combined = String::with_capacity(output.stdout.len() + output.stderr.len() + 1);
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push('\n');
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    combined
}

// Only meaningful when the feature is OFF — the test asserts the binary
// rejects --captchaforge with an actionable hint at startup. With the
// feature ON the flag installs the solver and the proxy runs indefinitely,
// so cmd.output().await would hang. Skip the test in that build.
#[cfg(not(feature = "captchaforge"))]
#[tokio::test]
async fn captchaforge_install_must_fail_with_actionable_hint() {
    let port = pick_free_port().expect("pick proxy port");
    let output = start_proxy_with_output(port, &["--captchaforge"])
        .await
        .expect("collect proxy output");

    assert!(!output.status.success(), "captchaforge without feature should fail");
    let output = combined_output(&output);
    assert!(
        output.contains("--captchaforge requires the binary to be built with `--features captchaforge`"),
        "output must include actionable hint: {output}"
    );
}

#[tokio::test]
async fn captchaforge_install_must_not_fail_without_flag() {
    let port = pick_free_port().expect("pick proxy port");
    let mut proxy = start_proxy_and_wait(port, &["--allow-private-upstream"])
        .await
        .expect("start proxy");

    let running = proxy.try_wait().expect("check proxy status");
    assert!(running.is_none(), "proxy should be running without --captchaforge");

    stop_proxy(&mut proxy).await;
}
