<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

namespace RhythmShahriar\Tuner;

use WP_CLI;
use WP_CLI\Utils;

/**
 * ScanCommand implements `wp tuner scan`: it installs a verified
 * rhythm-tuner release and runs a local scan of this site's files
 * (ABSPATH). It never runs the site's PHP beyond WP-CLI itself.
 *
 * WP-CLI's global --path picks the install and sets ABSPATH before
 * this command runs. The command has no --path of its own because WP-CLI
 * would consume it as the global flag anyway.
 */
class ScanCommand {

	/**
	 * Scans this WordPress install's files with Tuner.
	 *
	 * ## OPTIONS
	 *
	 * [--integrity]
	 * : Also verify WordPress core and plugin files against the official checksums. Needs a Tuner release with integrity checking; an older one is refused with a message.
	 *
	 * [--format=<format>]
	 * : Render results as a table or raw Tuner JSON.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * [--fail-on=<severity>]
	 * : Exit non-zero when a finding is at or above this severity.
	 * ---
	 * default: high
	 * options:
	 *   - critical
	 *   - high
	 *   - medium
	 *   - low
	 *   - info
	 *   - none
	 * ---
	 *
	 * [--version=<version>]
	 * : Tuner version to install, e.g. 0.4.0. Default the latest release.
	 *
	 * [--[no-]verify-signature]
	 * : Check the release's cosign signature when cosign is on PATH. On by default; --no-verify-signature skips it (checksums are still verified).
	 *
	 * ## EXAMPLES
	 *
	 *     wp tuner scan
	 *     wp tuner scan --integrity --fail-on=medium
	 *     wp tuner scan --format=json > tuner.json
	 *     wp --path=/srv/www/blog tuner scan
	 *
	 * @when before_wp_load
	 *
	 * @param array $args       Positional arguments (none).
	 * @param array $assoc_args Flags.
	 */
	public function __invoke( $args, $assoc_args ) {
		$target = ABSPATH;
		$format = Utils\get_flag_value( $assoc_args, 'format', 'table' );

		$downloader = new Downloader(
			array(
				'version'          => Utils\get_flag_value( $assoc_args, 'version', 'latest' ),
				'cache_dir'        => Utils\get_cache_dir() . '/rhythm-tuner',
				'verify_signature' => (bool) Utils\get_flag_value( $assoc_args, 'verify-signature', true ),
				'base_url'         => (string) getenv( 'TUNER_DOWNLOAD_URL' ),
			)
		);
		try {
			$binary = $downloader->ensure();
		} catch ( \RuntimeException $e ) {
			WP_CLI::error( 'installing Tuner: ' . $e->getMessage() );
			return;
		}

		if ( ! empty( $assoc_args['integrity'] ) ) {
			$help = self::runBinary( $binary, array( 'scan', '--help' ) );
			if ( ! self::helpHasFlag( $help['stdout'] . $help['stderr'], 'integrity' ) ) {
				WP_CLI::error( 'This Tuner release has no integrity checking yet, so --integrity is not available. Install a release that has it with --version, or leave --integrity off.' );
				return;
			}
		}

		$scanArgs = self::buildScanArgs( $target, $assoc_args );
		$result   = self::runBinary( $binary, $scanArgs );

		// A usage or scan error (2, 3) often leaves no report. Show Tuner's
		// own reason and keep its code, instead of failing on the missing
		// report with exit 1, which reads as "findings at --fail-on".
		$failure = self::scanFailure( $result );
		if ( null !== $failure ) {
			WP_CLI::error( $failure, false );
			WP_CLI::halt( $result['code'] );
			return;
		}

		if ( 'json' === $format ) {
			try {
				WP_CLI::line( self::jsonReport( $result['stdout'] ) );
			} catch ( \RuntimeException $e ) {
				WP_CLI::error( $e->getMessage() );
			}
		} else {
			self::renderTable( $result['stdout'] );
		}

		// Tuner's own exit code: 0 ok, 1 findings at --fail-on, 2 usage,
		// 3 a target couldn't be scanned. Pass it on so CI gates work.
		if ( 0 !== $result['code'] ) {
			if ( '' !== trim( $result['stderr'] ) ) {
				WP_CLI::warning( trim( $result['stderr'] ) );
			}
			WP_CLI::halt( $result['code'] );
		}
	}

	/**
	 * buildScanArgs turns the flags into rhythm-tuner scan arguments. It
	 * always asks for JSON so the command can render it and for a local
	 * scan of the target folder.
	 *
	 * @return string[] arguments after "scan".
	 */
	public static function buildScanArgs( $target, array $assoc_args ) {
		$argv = array( 'scan', $target, '--json', '--plain', '--quiet' );

		$failOn = Utils_get( $assoc_args, 'fail-on', 'high' );
		if ( 'none' !== $failOn && '' !== $failOn ) {
			$argv[] = '--fail-on';
			$argv[] = $failOn;
		}
		if ( ! empty( $assoc_args['integrity'] ) ) {
			$argv[] = '--integrity';
		}
		return $argv;
	}

	/**
	 * jsonReport returns Tuner's JSON report as it should reach stdout.
	 * Tuner already wrote JSON, so it is passed on as is: encoding it
	 * again (as WP_CLI::print_value does) would print one escaped string.
	 *
	 * @throws \RuntimeException when stdout holds no JSON object or array.
	 */
	public static function jsonReport( $stdout ) {
		$json = trim( (string) $stdout );
		if ( ! is_array( json_decode( $json, true ) ) ) {
			throw new \RuntimeException( 'Tuner produced no readable report.' );
		}
		return $json;
	}

	/**
	 * scanFailure returns the message to show when Tuner exited with a
	 * usage or scan error (2 or more) and wrote no report, or null when
	 * there is a report to render. The message is Tuner's stderr, or its
	 * exit code when stderr is empty.
	 */
	public static function scanFailure( array $result ) {
		if ( $result['code'] < 2 || is_array( json_decode( trim( (string) $result['stdout'] ), true ) ) ) {
			return null;
		}
		$stderr = trim( (string) $result['stderr'] );
		if ( '' === $stderr ) {
			return sprintf( 'Tuner exited with code %d and wrote no report.', $result['code'] );
		}
		return $stderr;
	}

	/**
	 * helpHasFlag reports whether a `rhythm-tuner scan --help` text lists
	 * --<name>, so a flag added in a later release is only passed to a
	 * binary that knows it.
	 */
	public static function helpHasFlag( $help, $name ) {
		return 1 === preg_match( '/(^|[\s,])--' . preg_quote( $name, '/' ) . '\b(?!-)/m', (string) $help );
	}

	/** runBinary runs rhythm-tuner and captures stdout, stderr and the code. */
	private static function runBinary( $binary, array $scanArgs ) {
		$result = self::run( array_merge( array( $binary ), $scanArgs ) );
		if ( null === $result ) {
			WP_CLI::error( "couldn't run $binary" );
		}
		return $result;
	}

	/**
	 * run runs argv without a shell and returns its stdout, stderr and
	 * exit code, or null when it can't start. stderr goes to a temporary
	 * file: with both on pipes, a child that fills the stderr pipe while
	 * this side still reads stdout would block both processes.
	 */
	public static function run( array $argv ) {
		$errFile = tempnam( sys_get_temp_dir(), 'tuner-stderr-' );
		if ( false === $errFile ) {
			return null;
		}
		$descriptors = array(
			1 => array( 'pipe', 'w' ),
			2 => array( 'file', $errFile, 'w' ),
		);
		$proc = proc_open( $argv, $descriptors, $pipes );
		if ( ! is_resource( $proc ) ) {
			unlink( $errFile );
			return null;
		}
		$stdout = stream_get_contents( $pipes[1] );
		fclose( $pipes[1] );
		$code   = proc_close( $proc );
		$stderr = (string) file_get_contents( $errFile );
		unlink( $errFile );
		return array( 'stdout' => $stdout, 'stderr' => $stderr, 'code' => $code );
	}

	/**
	 * renderTable prints a Tuner JSON report as a WP-CLI table of findings.
	 */
	private static function renderTable( $json ) {
		$report = json_decode( trim( $json ), true );
		if ( ! is_array( $report ) ) {
			WP_CLI::error( 'Tuner produced no readable report.' );
			return;
		}
		$findings = isset( $report['findings'] ) ? $report['findings'] : array();
		$rows     = array();
		foreach ( $findings as $f ) {
			$rows[] = array(
				'severity'   => isset( $f['severity'] ) ? $f['severity'] : '',
				'id'         => isset( $f['id'] ) ? $f['id'] : '',
				'title'      => isset( $f['title'] ) ? $f['title'] : '',
				'confidence' => isset( $f['confidence'] ) ? $f['confidence'] : '',
			);
		}
		$score = isset( $report['score'] ) ? $report['score'] : '?';
		if ( empty( $rows ) ) {
			WP_CLI::success( "No findings. Tune score $score/100." );
			return;
		}
		Utils\format_items( 'table', $rows, array( 'severity', 'id', 'title', 'confidence' ) );
		WP_CLI::log( sprintf( '%d finding(s). Tune score %s/100.', count( $rows ), $score ) );
	}
}

/**
 * Utils_get reads a flag whether or not WP-CLI's Utils is loaded, so
 * buildScanArgs can be unit-tested without WP-CLI.
 */
function Utils_get( array $assoc_args, $key, $default ) {
	return array_key_exists( $key, $assoc_args ) ? $assoc_args[ $key ] : $default;
}
