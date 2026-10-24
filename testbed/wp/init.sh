#!/bin/sh
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Seeds the broken state into the WordPress volume once, on first boot.
# The official entrypoint runs every /docker-entrypoint-init.d/*.sh after
# it has unpacked core and written wp-config.php. Everything it does is a
# fixture: no real secret and no working exploit.
set -eu
root=/var/www/html

# Stub plugins from ground-truth.yaml (mounted read-only; copy in so they
# are writable and discoverable like installed plugins).
cp -r "$root/mu-plugins-src/." "$root/wp-content/plugins/" 2>/dev/null || true

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
# webshell. Reachable only in a local scan over the bind mount.
echo '// testbed: one line added to a core file' >> "$root/wp-includes/pluggable.php"
mkdir -p "$root/wp-content/uploads/2026/01"
cat > "$root/wp-content/uploads/2026/01/thumbs.php" <<'SHELL'
<?php /* testbed webshell marker, inert */ echo 'tb'; ?>
SHELL

echo "testbed: seeded broken state" >&2
