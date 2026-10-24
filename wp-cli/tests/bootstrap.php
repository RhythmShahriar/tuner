<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Loads the package's classes for the unit tests. These tests cover the
// download, verification and argument building, none of which needs
// WP-CLI. The smoke test in the wp-cli workflow runs the command in a
// pinned WP-CLI inside a pinned PHP container.

$autoload = __DIR__ . '/../vendor/autoload.php';
if ( is_file( $autoload ) ) {
	require $autoload;
}

spl_autoload_register(
	function ( $class ) {
		$prefix = 'RhythmShahriar\\Tuner\\';
		if ( strpos( $class, $prefix ) !== 0 ) {
			return;
		}
		$rel  = substr( $class, strlen( $prefix ) );
		$path = __DIR__ . '/../src/' . str_replace( '\\', '/', $rel ) . '.php';
		if ( is_file( $path ) ) {
			require $path;
		}
	}
);

// ScanCommand references WP_CLI classes only in methods the unit tests
// don't call. Loading the file defines the Utils_get helper they need.
require __DIR__ . '/../src/ScanCommand.php';
