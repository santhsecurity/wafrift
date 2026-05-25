# Shadow Daemon bench app — nginx + PHP-FPM with the shadowd-php connector.
#
# The connector library (shadowd/php_connector) is installed via Composer.
# The echo.php app reflects all GET/POST parameters back so the bench harness
# can distinguish blocked (403) from allowed (200 + echo) responses.
#
# Pinned base image (2026-05-24):
#   php:8.2-fpm-bookworm
FROM php:8.2-fpm-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip curl git \
    && rm -rf /var/lib/apt/lists/*

# Install Composer.
RUN curl -fsSL https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

WORKDIR /app

# shadowd/php_connector is the official PHP connector for Shadow Daemon.
# https://packagist.org/packages/shadowd/php_connector
COPY composer.json .
RUN composer install --no-dev --no-interaction --prefer-dist

# ── Runtime ────────────────────────────────────────────────────────────────────
FROM php:8.2-fpm-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        nginx \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/vendor /app/vendor
COPY echo.php /app/public/index.php
COPY shadowd.ini /etc/shadowd/shadowd.ini
COPY nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /var/log/shadowd /run/php

EXPOSE 80

# Start PHP-FPM and nginx together.
CMD ["sh", "-c", "php-fpm -D && nginx -g 'daemon off;'"]
