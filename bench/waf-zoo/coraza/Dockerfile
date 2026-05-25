# Coraza + Caddy — build from source.
#
# Caddy does not ship a coraza_waf module in its official binary. We use
# xcaddy to compile a custom Caddy binary with the coraza-caddy plugin and
# the Coraza CRS module embedded.
#
# Pinned versions:
#   golang         1.22-bookworm  (Go toolchain)
#   xcaddy         0.4.2          https://github.com/caddyserver/xcaddy
#   Caddy          v2.8.4         https://github.com/caddyserver/caddy
#   coraza-caddy   v2.0.0         https://github.com/corazawaf/coraza-caddy
#                                 (module path is corazawaf/coraza-caddy/v2;
#                                  the release version is v2.x.x not v0.x.x)
ARG GO_IMAGE=golang:1.22-bookworm
ARG CADDY_VERSION=v2.8.4
ARG CORAZA_CADDY_VERSION=v2.0.0

# ── Stage 1: build Caddy with coraza_waf ──────────────────────────────────────
FROM ${GO_IMAGE} AS build
ARG CADDY_VERSION
ARG CORAZA_CADDY_VERSION

# xcaddy is the official Caddy build tool for custom modules.
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.2

# Build Caddy at the pinned version with the coraza-caddy plugin.
# coraza-caddy pulls OWASP CRS (corazawaf/coraza-coreruleset) as a Go module
# at build time so no network access is needed at runtime.
# The module path is github.com/corazawaf/coraza-caddy/v2 — the /v2 suffix
# is the Go major version path for v2.x releases (not v0.3.x).
RUN xcaddy build "${CADDY_VERSION}" \
    --with "github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY_VERSION}"

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /go/caddy /usr/local/bin/caddy

# The Caddyfile is bind-mounted at runtime from the compose volume.
# Default location Caddy looks for if not specified in CMD.
RUN mkdir -p /etc/caddy /var/log/caddy

EXPOSE 80
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
