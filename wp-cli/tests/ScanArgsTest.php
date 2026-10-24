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
}
