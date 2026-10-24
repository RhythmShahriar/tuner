#!/bin/sh
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Validates the server-config hardening bundles from `rhythm-tuner fix`
# (checks-pack C6) against the testbed's front ends in throwaway
# containers. `make testbed-config` calls this once C6 ships; until then
# the Makefile skips it.
#
#   validate-config.sh                         bundles from rhythm-tuner fix
#   validate-config.sh <nginx.conf> <.htaccess>  these bundles instead
#
# nginx: the bundle is included in a server block and nginx -t parses it.
# Apache: the bundle is a .htaccess, which apachectl -t never reads, so
# it is checked twice. httpd -t parses it inside the docroot's
# <Directory> (testbed/apache/validate.conf), then a live httpd with
# AllowOverride All serves a page from a docroot holding it as .htaccess:
# a broken .htaccess answers 500. validate-config-test.sh proves both
# halves fail on broken fixtures.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
# Pinned by tag and digest, like testbed/docker-compose.yml.
# TESTBED_NGINX_IMAGE and TESTBED_HTTPD_IMAGE override them.
NGINX_IMAGE=${TESTBED_NGINX_IMAGE:-nginx:1.27.3-alpine@sha256:814a8e88df978ade80e584cc5b333144b9372a8e3c98872d07137dbf3b44d0e4}
HTTPD_IMAGE=${TESTBED_HTTPD_IMAGE:-httpd:2.4.62@sha256:4c7788695c832bf415a662dfb5160f1895e65fc65c025e85f436ee2c9e7d7f3e}
# Loopback port for the live Apache check.
port=${TESTBED_CONFIG_PORT:-20256}

tmp=$(mktemp -d)
cid=
cleanup() {
	[ -z "$cid" ] || docker rm -f "$cid" > /dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

if [ $# -eq 2 ]; then
	cp "$1" "$tmp/harden.nginx.conf"
	cp "$2" "$tmp/harden.htaccess"
elif [ $# -eq 0 ]; then
	go run "$here/../cmd/rhythm-tuner" fix --server nginx > "$tmp/harden.nginx.conf"
	go run "$here/../cmd/rhythm-tuner" fix --server apache > "$tmp/harden.htaccess"
else
	echo "usage: validate-config.sh [<nginx bundle> <apache bundle>]" >&2
	exit 2
fi
# The containers read these as other users.
chmod 644 "$tmp/harden.nginx.conf" "$tmp/harden.htaccess"

# nginx bundle: include it from a minimal server block and run nginx -t.
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
chmod 644 "$tmp/nginx.conf"
docker run --rm -v "$tmp/nginx.conf:/etc/nginx/nginx.conf:ro" \
	-v "$tmp/harden.nginx.conf:/etc/nginx/harden.conf:ro" \
	"$NGINX_IMAGE" nginx -t

conf=/usr/local/apache2/conf
apache_mounts="-v $here/apache/httpd.conf:$conf/testbed.conf:ro -v $here/apache/validate.conf:$conf/httpd.conf:ro"

# Apache, server-config parse of the bundle.
# shellcheck disable=SC2086 # apache_mounts is a list of flags
docker run --rm $apache_mounts -v "$tmp/harden.htaccess:$conf/harden.conf:ro" \
	"$HTTPD_IMAGE" httpd -t -D SYNTAX

# Apache, the bundle as a real .htaccess under a live server.
site="$tmp/site"
mkdir "$site"
echo ok > "$site/index.html"
cp "$tmp/harden.htaccess" "$site/.htaccess"
chmod 755 "$site"
chmod 644 "$site/index.html" "$site/.htaccess"
# shellcheck disable=SC2086
cid=$(docker run -d $apache_mounts -v "$site:/var/www/html:ro" \
	-p "127.0.0.1:$port:80" "$HTTPD_IMAGE")
code=000
for _ in $(seq 1 50); do
	code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/index.html" || true)
	[ "$code" = 000 ] || break
	sleep 0.2
done
case "$code" in
000)
	echo "validate-config: Apache didn't answer on 127.0.0.1:$port" >&2
	docker logs "$cid" >&2
	exit 1
	;;
5*)
	echo "validate-config: Apache answered $code with the bundle as .htaccess" >&2
	docker logs "$cid" >&2
	exit 1
	;;
esac
echo "Apache served a page under the .htaccess bundle ($code)"

echo "server-config bundles validate against nginx and Apache"
