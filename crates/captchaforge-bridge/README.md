# wafrift-captchaforge-bridge

Optional adapter that connects [wafrift](https://github.com/santhsecurity/wafrift)'s
managed-challenge flow to the [captchaforge](https://github.com/santhsecurity/captchaforge)
headless-browser solver.

## What it does

When wafrift detects a `Verdict::ChallengeRequired` (Cloudflare managed
challenge, Turnstile, hCaptcha, reCAPTCHA, AWS WAF Captcha, Akamai BMP
sensor) AND no clearance cookie is on file:

1. Spin up a chromiumoxide page from the captured challenge HTML.
2. Run captchaforge's detection + solver chain (Behavioural / VLM /
   Audio / Crowd-sourced).
3. Capture the resulting clearance cookie.
4. Hand it back to wafrift's `ChallengeStore` so subsequent requests
   to the same host attach it automatically.

## Why a separate crate

The bridge pulls in `chromiumoxide` (and transitively a chromium
runtime requirement). That's fine for operators who want full
challenge automation but a heavyweight dep for everyone else.
Putting it in its own crate keeps `wafrift-proxy` lean for the
default install.

## Use it

Add as a dep in your wafrift fork or downstream binary:

```toml
[dependencies]
wafrift-proxy = "0.2"
wafrift-captchaforge-bridge = "0.2"
```

```rust,no_run
use wafrift_captchaforge_bridge::install_global_solver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tells wafrift-transport to consult captchaforge before falling
    // back to the operator-prompt path on ChallengeRequired.
    install_global_solver().await?;
    // ... start wafrift-proxy as usual
    Ok(())
}
```

## License

MIT OR Apache-2.0. Copyright 2026 CORUM COLLECTIVE LLC.
