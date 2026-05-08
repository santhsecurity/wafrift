# Proxy tooling (sqlmap, ffuf, browsers)

Use **`wafrift-proxy`** as an HTTP forward proxy so any tool that supports `HTTP_PROXY` / `-x` can send traffic through WafRift’s evasion pipeline.

## Quick start

```bash
cargo run -p wafrift-proxy -- --listen 127.0.0.1:8080 --fingerprint-rotation
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

Then run your scanner with proxy settings (examples):

- **ffuf:** `ffuf -x http://127.0.0.1:8080 -u https://target/FUZZ …`
- **sqlmap:** `sqlmap -u "https://target/x?id=1" --proxy="http://127.0.0.1:8080"`

## HTTPS today

- **Plain HTTP** requests through the proxy are rewritten with evasion.
- **Default `CONNECT`:** traffic is **tunneled** (no decryption).
- **Optional MITM:** terminate TLS on the client leg, apply evasion, then forward over **HTTPS** to the origin.

### MITM quick start (authorized testing only)

```bash
# 1) Generate and write a local CA
cargo run -p wafrift-proxy -- --write-mitm-ca-dir ./mitm-ca

# 2) Install ./mitm-ca/wafrift-mitm-ca.pem in your OS or browser trust store

# 3) Run the proxy with interception enabled
cargo run -p wafrift-proxy -- --listen 127.0.0.1:8080 --mitm --mitm-ca-dir ./mitm-ca
```

Point clients at `http://127.0.0.1:8080`; HTTPS sites use `CONNECT`, which the proxy terminates using a **CA-signed certificate** for the requested host. The inner HTTP/1.1 request is processed like a normal forward-proxy request (evade + `reqwest` to `https://…`).

Limitations (v1): client↔proxy leg is **HTTP/1.1** after TLS; some sites that assume HTTP/2-only behavior may differ from a direct connection.

Security notes (v1, not a substitute for network policy):

- **MITM upstream URL** is pinned to the **CONNECT** authority; an inner `Host:` that disagrees is rejected with `400`.
- **Default upstream policy:** literal **and** DNS-resolved addresses must be “public” (no RFC1918 / loopback / ULA / link-local) unless you pass **`--allow-private-upstream`**. **`--insecure-open-upstream`** disables these checks (lab only).
- **`CONNECT`** runs the same policy **before** the tunnel is established.
- **Hop-by-hop:** fixed list plus tokens from the client **`Connection`** header are stripped on forward and on responses; upstream bodies are capped (**`--max-upstream-response-bytes`**, default 32 MiB).
- **Concurrency:** **`--max-concurrent-connections`** (default 4096) limits parallel clients.
- **`/_wafrift/status`:** exposed only when the listen address is **loopback-only** (e.g. `127.0.0.1:8080`); on `0.0.0.0` / public binds it returns **404** so per-host stats are not leaked across the network. JSON includes **`status_schema_version`** for consumers.
- **Learning feedback:** upstream “block” detection uses the same **`is_waf_block`** rules as the CLI transport (status + body preview), after buffering the response up to the configured size cap.

## Tor / SOCKS egress

`EvasionConfig` accepts upstream proxies (see transport `proxy-pool` feature). Generate a Tor-oriented snippet:

```bash
cargo run -p wafrift-cli -- egress-example --preset tor
```

This prints `socks5h://127.0.0.1:9050` (DNS via Tor). Tor is not bundled; run Tor locally first, then merge the JSON into your config.

## Origin bypass

Resolve candidate IPs and merge into `origin_bypass`:

```bash
cargo run -p wafrift-cli -- origin-hints --host api.example.com --format json
```

See the roadmap for scope limits of DNS-only hints vs full “origin discovery.”
