<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

namespace RhythmShahriar\Tuner\Tests;

use PHPUnit\Framework\TestCase;
use RhythmShahriar\Tuner\ScanCommand;

class ScanArgsTest extends TestCase {

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
}
