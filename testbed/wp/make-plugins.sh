#!/bin/sh
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Builds the testbed's plugin tree under wp/content/plugins from
# ground-truth.yaml, so the 30 plugins don't have to live in the repo.
# Each plugin is a stub: a main file that loads one script, the script
# and (for "readme" plugins) a readme.txt with a Stable tag, at the
# version the manifest names. No
# plugin holds a working exploit; the "vulnerable" ones only carry a
# version that public advisories flag.
#
#   sh testbed/wp/make-plugins.sh            # into testbed/wp/content
#   sh testbed/wp/make-plugins.sh <dir>
#
# "make testbed" runs it before docker compose up.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
truth="$here/../ground-truth.yaml"
dest=${1:-"$here/content"}
plugins="$dest/plugins"

rm -rf "$plugins"
mkdir -p "$plugins"

# Read "- {slug: x, version: y, discoverable: z, ...}" lines from the
# plugins: block. Kept to POSIX sh and sed so it runs in the WordPress
# image's shell too.
in_plugins=0
while IFS= read -r line; do
	case "$line" in
	plugins:*) in_plugins=1; continue ;;
	esac
	[ "$in_plugins" = 1 ] || continue
	case "$line" in
	"  - "*) ;;
	*) continue ;;
	esac
	slug=$(printf '%s\n' "$line" | sed -n 's/.*slug: *\([a-z0-9-]*\).*/\1/p')
	version=$(printf '%s\n' "$line" | sed -n 's/.*version: *\([0-9.]*\).*/\1/p')
	disc=$(printf '%s\n' "$line" | sed -n 's/.*discoverable: *\([a-z]*\).*/\1/p')
	if [ -z "$slug" ] || [ -z "$version" ]; then
		echo "skipping: $line" >&2
		continue
	fi

	dir="$plugins/$slug"
	mkdir -p "$dir"
	# An active plugin loads its asset on every page, with ?ver=, which is
	# what asset-based detection reads.
	mkdir -p "$dir/assets"
	printf '/* testbed stub asset for %s %s */\n' "$slug" "$version" > "$dir/assets/$slug.js"
	cat > "$dir/$slug.php" <<PHP
<?php
/*
Plugin Name: ${slug}
Version: ${version}
*/
// Testbed stub. Not a real plugin and holds no exploit.
add_action('wp_enqueue_scripts', function () {
	wp_enqueue_script('testbed-${slug}', plugins_url('assets/${slug}.js', __FILE__), array(), '${version}');
});
PHP
	# A readable readme only for "readme" plugins; REST and asset plugins
	# deliberately have none, so only those detection methods find them.
	if [ "$disc" = readme ]; then
		cat > "$dir/readme.txt" <<TXT
=== ${slug} ===
Stable tag: ${version}
Testbed stub plugin. Not real and holds no exploit.
TXT
	fi
done < "$truth"

echo "wrote stub plugins to $plugins" >&2
