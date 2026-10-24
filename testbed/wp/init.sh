#!/bin/sh
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Seeds the broken state into the WordPress volume. The testbed's seed
# service (wordpress:cli, as root) runs it once the wp container has
# unpacked core and written wp-config.php: it installs WordPress, copies
# in the stub plugins and activates the active ones, writes the exposed
# files and leaves a copy of the tree in /site for local scans. Running it
# again changes nothing. Everything it does is a fixture: no real secret
# and no working exploit.
set -eu
root=/var/www/html
truth=/ground-truth.yaml

wp() { command wp --allow-root --path="$root" "$@"; }

if ! wp core is-installed 2>/dev/null; then
	wp core install --url="$TESTBED_URL" --title="Tuner testbed" \
		--admin_user=testbed --admin_password=testbed-not-a-secret \
		--admin_email=testbed@example.invalid --skip-email
fi

# Stub plugins from ground-truth.yaml (built by make-plugins.sh, mounted
# read-only). A plugin the image ships (akismet) is replaced whole, so
# only the stub's version is on disk.
[ -d /plugins-src ] && [ -n "$(ls /plugins-src)" ] || {
	echo "testbed: no stub plugins in /plugins-src; run sh testbed/wp/make-plugins.sh first" >&2
	exit 1
}
for dir in /plugins-src/*/; do
	slug=$(basename "$dir")
	rm -rf "$root/wp-content/plugins/$slug"
	cp -R "$dir" "$root/wp-content/plugins/$slug"
done
active=$(sed -n 's/^  - {slug: *\([a-z0-9-]*\),.*active: *true.*/\1/p' "$truth")
# shellcheck disable=SC2086 # one word per slug
wp plugin activate $active

# Files left on show, the exposed[] ground truth.
cat > "$root/.env" <<'ENV'
APP_ENV=production
DB_PASSWORD=testbed-not-a-secret
ENV
cat > "$root/wp-content/debug.log" <<'LOG'
[24-Oct-2026 01:02:03 UTC] PHP Warning:  Undefined array key "x" in /var/www/html/wp-content/themes/t/functions.php on line 3
LOG
# A tiny "backup" and a composer.lock, both just enough to be recognised.
printf 'PK\003\004testbed backup, not a real archive' > "$root/backup.zip"
cat > "$root/composer.lock" <<'LOCK'
{"packages":[{"name":"monolog/monolog","version":"1.0.0"}]}
LOCK
mkdir -p "$root/.git"
cat > "$root/.git/config" <<'GIT'
[remote "origin"]
	url = https://example.invalid/testbed.git
GIT

# Local-only ground truth (L7/L8): a modified core file and an uploads
# webshell. Reachable only in a local scan of the copy in /site.
marker='// testbed: one line added to a core file'
grep -qF "$marker" "$root/wp-includes/pluggable.php" || echo "$marker" >> "$root/wp-includes/pluggable.php"
mkdir -p "$root/wp-content/uploads/2026/01"
cat > "$root/wp-content/uploads/2026/01/thumbs.php" <<'SHELL'
<?php /* testbed webshell marker, inert */ echo 'tb'; ?>
SHELL

# php-fpm runs as the Debian image's www-data.
chown -R 33:33 "$root"

# The copy for local scans, owned by whoever started the testbed.
find /site -mindepth 1 -delete
cp -a "$root/." /site/
chown -R "$TESTBED_UID:$TESTBED_GID" /site

echo "testbed: seeded broken state" >&2
