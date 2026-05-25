# Shadow Daemon bench app — nginx + PHP-FPM with the shadowd-php connector.
#
# The connector library (zecure/shadowd_php) is cloned from GitHub since it is
# not published on Packagist. The echo.php app reflects all GET/POST parameters
# back so the bench harness can distinguish blocked (403) from allowed (200 + echo).
#
# Pinned base image (2026-05-25):
#   php:8.2-fpm-bookworm
FROM php:8.2-fpm-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Composer.
RUN curl -fsSL https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

WORKDIR /app

# shadowd_php is not on Packagist — clone the source from GitHub.
# The library has no build step; just copy src/ and inc/ alongside a minimal
# composer.json that sets up the PSR-4 autoloader and polyfill.
RUN git clone --depth 1 https://github.com/zecure/shadowd_php.git /shadowd_php_src

# Write a minimal composer.json that points the autoloader at the cloned src/.
# This avoids any network dependency at install time (no registry fetch needed).
RUN cat > /app/composer.json <<'EOF'
{
    "require": {
        "symfony/polyfill-mbstring": "^1.22"
    },
    "autoload": {
        "files": ["/shadowd_php_src/inc/Constants.php"],
        "psr-4": {
            "shadowd\\": "/shadowd_php_src/src/"
        }
    },
    "config": {
        "optimize-autoloader": true,
        "classmap-authoritative": true
    }
}
EOF

RUN composer install --no-dev --no-interaction --prefer-dist

# ── Runtime ────────────────────────────────────────────────────────────────────
FROM php:8.2-fpm-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        nginx \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/vendor /app/vendor
# The autoloader references the source at /shadowd_php_src — keep it in runtime.
COPY --from=build /shadowd_php_src /shadowd_php_src
COPY echo.php /app/public/index.php
COPY shadowd.ini /etc/shadowd/shadowd.ini
COPY nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /var/log/shadowd /run/php

EXPOSE 80

# Start PHP-FPM and nginx together.
CMD ["sh", "-c", "php-fpm -D && nginx -g 'daemon off;'"]
