<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Registers `wp tuner scan` when this package is loaded by WP-CLI.

if ( ! class_exists( 'WP_CLI' ) ) {
	return;
}

WP_CLI::add_command( 'tuner scan', 'RhythmShahriar\Tuner\ScanCommand' );
