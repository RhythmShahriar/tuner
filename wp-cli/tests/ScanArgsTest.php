<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

namespace RhythmShahriar\Tuner\Tests;

use PHPUnit\Framework\TestCase;
use RhythmShahriar\Tuner\ScanCommand;

class ScanArgsTest extends TestCase {

	public function test_run_survives_a_full_stderr() {
		// More than a pipe buffer on stderr while stdout is still open.
		$code   = 'fwrite(STDERR, str_repeat("e", 300000)); echo "{\"ok\":true}"; exit(3);';
		$result = ScanCommand::run( array( PHP_BINARY, '-r', $code ) );
		$this->assertNotNull( $result );
		$this->assertSame( '{"ok":true}', $result['stdout'] );
		$this->assertSame( 300000, strlen( $result['stderr'] ) );
		$this->assertSame( 3, $result['code'] );
	}

	public function test_defaults() {
		$argv = ScanCommand::buildScanArgs( '/var/www/html', array() );
		$this->assertSame(
			array( 'scan', '/var/www/html', '--json', '--plain', '--quiet', '--fail-on', 'high' ),
			$argv
		);
	}

	public function test_integrity_and_fail_on() {
		$argv = ScanCommand::buildScanArgs( '/srv/site', array( 'integrity' => true, 'fail-on' => 'medium' ) );
		$this->assertContains( '--integrity', $argv );
		$i = array_search( '--fail-on', $argv, true );
		$this->assertSame( 'medium', $argv[ $i + 1 ] );
	}

	public function test_fail_on_none_adds_no_flag() {
		$argv = ScanCommand::buildScanArgs( '/srv', array( 'fail-on' => 'none' ) );
		$this->assertNotContains( '--fail-on', $argv );
	}

	public function test_always_local_json() {
		$argv = ScanCommand::buildScanArgs( '/srv', array() );
		$this->assertContains( '--json', $argv );
		$this->assertSame( '/srv', $argv[1] );
	}

	public function test_json_report_is_passed_on_unescaped() {
		$stdout = "{\"target\":\"/srv\",\"findings\":[{\"id\":\"local-dotenv\"}]}\n";
		$out    = ScanCommand::jsonReport( $stdout );
		$report = json_decode( $out, true );
		$this->assertIsArray( $report, 'the output must be the report, not a JSON string' );
		$this->assertSame( 'local-dotenv', $report['findings'][0]['id'] );
		$this->assertSame( trim( $stdout ), $out );
	}

	public function test_json_report_refuses_non_json() {
		$this->expectException( \RuntimeException::class );
		ScanCommand::jsonReport( 'flag provided but not defined: -integrity' );
	}

	public function test_json_report_refuses_a_bare_string() {
		$this->expectException( \RuntimeException::class );
		ScanCommand::jsonReport( '"{\\"findings\\":[]}"' );
	}

	public function test_help_has_flag() {
		$help = "  -q, --quiet              findings only\n      --integrity          verify checksums\n";
		$this->assertTrue( ScanCommand::helpHasFlag( $help, 'integrity' ) );
		$this->assertTrue( ScanCommand::helpHasFlag( $help, 'quiet' ) );
		$this->assertFalse( ScanCommand::helpHasFlag( "      --integrity-only  x\n", 'integrity' ) );
		$this->assertFalse( ScanCommand::helpHasFlag( "      --json   JSON report\n", 'integrity' ) );
	}

	public function test_scan_error_without_report_shows_tuner_stderr() {
		$result = array( 'code' => 3, 'stdout' => '', 'stderr' => "rhythm tuner: /srv/site: permission denied\n" );
		$this->assertSame( 'rhythm tuner: /srv/site: permission denied', ScanCommand::scanFailure( $result ) );
	}

	public function test_scan_error_with_empty_stderr_names_the_code() {
		$result = array( 'code' => 2, 'stdout' => '', 'stderr' => '' );
		$this->assertSame( 'Tuner exited with code 2 and wrote no report.', ScanCommand::scanFailure( $result ) );
	}

	public function test_report_is_rendered_even_on_scan_error() {
		// Exit 3 with a report (one target failed): render it, then pass 3 on.
		$result = array( 'code' => 3, 'stdout' => '{"findings":[]}', 'stderr' => 'x' );
		$this->assertNull( ScanCommand::scanFailure( $result ) );
	}

	public function test_findings_at_fail_on_are_no_scan_failure() {
		$this->assertNull( ScanCommand::scanFailure( array( 'code' => 1, 'stdout' => '', 'stderr' => '' ) ) );
		$this->assertNull( ScanCommand::scanFailure( array( 'code' => 0, 'stdout' => '{}', 'stderr' => '' ) ) );
	}
}
