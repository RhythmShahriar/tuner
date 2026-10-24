<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

namespace RhythmShahriar\Tuner\Tests;

use PHPUnit\Framework\TestCase;
use RhythmShahriar\Tuner\Platform;

class PlatformTest extends TestCase {

	public function test_archive_names() {
		$cases = array(
			array( 'Linux', 'x86_64', 'rhythm-tuner_linux_amd64.tar.gz', 'rhythm-tuner' ),
			array( 'Linux', 'aarch64', 'rhythm-tuner_linux_arm64.tar.gz', 'rhythm-tuner' ),
			array( 'Darwin', 'arm64', 'rhythm-tuner_darwin_arm64.tar.gz', 'rhythm-tuner' ),
			array( 'Windows NT', 'amd64', 'rhythm-tuner_windows_amd64.zip', 'rhythm-tuner.exe' ),
		);
		foreach ( $cases as $c ) {
			list( $os, $machine, $archive, $binary ) = $c;
			$p = new Platform( $os, $machine );
			$this->assertSame( $archive, $p->archiveName(), "$os/$machine archive" );
			$this->assertSame( $binary, $p->binaryName(), "$os/$machine binary" );
		}
	}

	public function test_unknown_os() {
		$this->expectException( \RuntimeException::class );
		( new Platform( 'SunOS', 'x86_64' ) )->os();
	}

	public function test_unknown_arch() {
		$this->expectException( \RuntimeException::class );
		( new Platform( 'Linux', 'mips' ) )->arch();
	}
}
