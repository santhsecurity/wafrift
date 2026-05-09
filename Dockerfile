# wafrift release Dockerfile.
#
# Builds a slim runtime image with both the `wafrift` CLI and the
# `wafrift-proxy` binary on the PATH so a practitioner with Docker
# (and no Rust toolchain) can run either with a single command:
#
#   docker run --rm santhsecurity/wafrift wafrift evade --payload "' OR 1=1--"
#   docker run --rm -p 8080:8080 santhsecurity/wafrift \
#       wafrift-proxy --listen 0.0.0.0:8080
#
# The image is multi-arch (linux/amd64, linux/arm64) so the same tag
# works on Apple-silicon laptops and x86 CTF VMs. Build via:
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#       -t santhsecurity/wafrift:0.2.1 -t santhsecurity/wafrift:latest --push .

ARG RUST_VERSION=1.89

FROM rust:${RUST_VERSION}-slim AS builder

# Build deps. libssl-dev for native-tls fallback (rustls is the default
# but reqwest's TLS backend feature can be flipped at compile time);
# pkg-config because some transitive crates link against system libs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy the workspace metadata first so dependency layers cache. Skipping
# the lockfile-only layer because the wafrift workspace ships path
# dependencies that change every commit; the savings would be minimal.
COPY . .

# Build only the two binaries practitioners need. Skipping `--all-targets`
# means tests / benches / fuzz crates don't compile in the release image.
RUN cargo build --release -p wafrift-cli -p wafrift-proxy \
    && strip /src/target/release/wafrift /src/target/release/wafrift-proxy || true

# ── Runtime image — Debian slim is the smallest base that ships full
# libstdc++ + ca-certificates without Alpine's musl C-library quirks.
FROM debian:bookworm-slim

# Minimal runtime deps: TLS root certs (so reqwest can verify upstream
# cert chains), curl (so a practitioner can probe the in-container
# proxy with `docker exec`), tini (clean PID 1 for signal handling).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/wafrift /usr/local/bin/wafrift
COPY --from=builder /src/target/release/wafrift-proxy /usr/local/bin/wafrift-proxy

# Non-root user — the proxy doesn't need root to bind to non-privileged
# ports, and running as root inside a container is a defence-in-depth
# foot-gun if the practitioner accidentally `--cap-add` something.
RUN useradd --system --shell /usr/sbin/nologin --home /var/lib/wafrift wafrift \
    && mkdir -p /var/lib/wafrift /home/wafrift/.wafrift \
    && chown -R wafrift:wafrift /var/lib/wafrift /home/wafrift
USER wafrift
ENV HOME=/home/wafrift
WORKDIR /home/wafrift

# tini reaps zombies and forwards signals so Ctrl+C in `docker run -it`
# triggers wafrift-proxy's graceful-shutdown path (gene-bank flush).
ENTRYPOINT ["/usr/bin/tini", "--"]
# Default to the CLI's interactive TUI. Practitioners override:
#   docker run santhsecurity/wafrift wafrift scan --target ...
#   docker run santhsecurity/wafrift wafrift-proxy --listen 0.0.0.0:8080
CMD ["wafrift"]

# Documentation labels (OCI image spec). Set by the release workflow.
LABEL org.opencontainers.image.title="wafrift" \
      org.opencontainers.image.description="Programmable WAF-evasion engine — CLI + transparent forward proxy. Lawful use only." \
      org.opencontainers.image.url="https://github.com/santhsecurity/wafrift" \
      org.opencontainers.image.source="https://github.com/santhsecurity/wafrift" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.vendor="Santh Security"
