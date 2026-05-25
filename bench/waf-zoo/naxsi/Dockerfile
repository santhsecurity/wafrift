# nginx + naxsi built from source. Pinned versions ensure reproducible builds.
# Build-args are exposed so the bench can sweep nginx/naxsi release pairs.
ARG NGINX_VERSION=1.27.4
ARG NAXSI_VERSION=1.6

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS build
ARG NGINX_VERSION
ARG NAXSI_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl git \
        libpcre3-dev libpcre2-dev libssl-dev zlib1g-dev \
        libxml2-dev libxslt1-dev libgeoip-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar xz

# wargio/naxsi requires --recurse-submodules: the release tarball ships an
# empty libinjection/ directory which breaks the nginx configure step.
RUN git clone --depth 1 --branch "${NAXSI_VERSION}" --recurse-submodules \
        --shallow-submodules https://github.com/wargio/naxsi.git \
        "naxsi-${NAXSI_VERSION}"

WORKDIR "/src/nginx-${NGINX_VERSION}"
RUN ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --with-http_ssl_module \
        --with-http_realip_module \
        --add-module="/src/naxsi-${NAXSI_VERSION}/naxsi_src" \
    && make -j"$(nproc)" \
    && make install

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim
ARG NAXSI_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcre3 libpcre2-8-0 libssl3 zlib1g libxml2 libxslt1.1 libgeoip1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/sbin/nginx /usr/sbin/nginx
COPY --from=build /etc/nginx /etc/nginx
COPY --from=build "/src/naxsi-${NAXSI_VERSION}/naxsi_rules" /etc/nginx/naxsi_rules

RUN mkdir -p /var/log/nginx /var/cache/nginx

# Bench-specific config: LearningMode OFF, backend=backend:80, port=8080.
COPY nginx.conf  /etc/nginx/nginx.conf
COPY naxsi.conf  /etc/nginx/naxsi.conf

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
