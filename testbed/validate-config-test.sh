#!/bin/sh
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: AGPL-3.0-only

# Proves validate-config.sh can fail: a good pair of bundles passes and
# each broken fixture in testbed/config-fixtures fails it. Without this a
# check that never reads the bundle (as apachectl -t alone never reads a
# .htaccess) would look green forever.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fx="$here/config-fixtures"
status=0

run() { # <want: pass|fail> <name> <nginx bundle> <apache bundle>
	if sh "$here/validate-config.sh" "$3" "$4" > "${TMPDIR:-/tmp}/validate-config-test.log" 2>&1; then
		got=pass
	else
		got=fail
	fi
	if [ "$got" = "$1" ]; then
		echo "ok    $2 ($got)"
	else
		echo "FAIL  $2: want $1, got $got"
		cat "${TMPDIR:-/tmp}/validate-config-test.log"
		status=1
	fi
}

run pass "good bundles" "$fx/good.nginx.conf" "$fx/good.htaccess"
run fail "broken nginx bundle" "$fx/broken.nginx.conf" "$fx/good.htaccess"
run fail "broken Apache bundle" "$fx/good.nginx.conf" "$fx/broken.htaccess"
run fail "directive not allowed in .htaccess" "$fx/good.nginx.conf" "$fx/htaccess-only.htaccess"
rm -f "${TMPDIR:-/tmp}/validate-config-test.log"
exit "$status"
