#!/bin/sh
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Validates the server-config hardening bundles from `rhythm-tuner fix`
# (checks-pack C6) against the testbed's front ends: nginx -t and
# apachectl -t in throwaway containers. `make testbed-config` calls this
# once C6 ships; until then the Makefile skips it.
#
# It writes each bundle beside the testbed config and runs the matching
# container's own syntax check, so a snippet that doesn't parse fails the
# benchmark instead of only showing up in production.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# nginx bundle: include it from a minimal server block and run nginx -t.
go run "$here/../cmd/rhythm-tuner" fix --server nginx > "$tmp/harden.conf"
cat > "$tmp/nginx.conf" <<NGINX
events {}
http {
    server {
        listen 80;
        root /var/www/html;
        include /etc/nginx/harden.conf;
    }
}
NGINX
docker run --rm -v "$tmp/nginx.conf:/etc/nginx/nginx.conf:ro" \
	-v "$tmp/harden.conf:/etc/nginx/harden.conf:ro" \
	nginx:1.27.3-alpine nginx -t

# Apache bundle: drop it in a .htaccess and run apachectl -t with the
# config that allows .htaccess overrides.
go run "$here/../cmd/rhythm-tuner" fix --server apache > "$tmp/.htaccess"
docker run --rm -v "$tmp/.htaccess:/var/www/html/.htaccess:ro" \
	httpd:2.4.62 apachectl -t

echo "server-config bundles validate against nginx and Apache"
