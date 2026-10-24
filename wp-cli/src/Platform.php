<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

namespace RhythmShahriar\Tuner;

/**
 * Platform maps the running machine to a Tuner release archive, using the
 * same names GoReleaser writes: rhythm-tuner_<os>_<arch>.<tar.gz|zip>.
 */
class Platform {

	/** @var string php_uname('s'), lower-cased, e.g. "linux". */
	private $os;

	/** @var string php_uname('m'), e.g. "x86_64". */
	private $machine;

	public function __construct( $os = null, $machine = null ) {
		$this->os      = strtolower( $os !== null ? $os : php_uname( 's' ) );
		$this->machine = $machine !== null ? $machine : php_uname( 'm' );
	}

	/**
	 * os returns the Go GOOS: linux, darwin or windows.
	 *
	 * @throws \RuntimeException when the OS has no Tuner build.
	 */
	public function os() {
		if ( strpos( $this->os, 'linux' ) !== false ) {
			return 'linux';
		}
		if ( strpos( $this->os, 'darwin' ) !== false ) {
			return 'darwin';
		}
		if ( strpos( $this->os, 'win' ) !== false ) {
			return 'windows';
		}
		throw new \RuntimeException( "Tuner has no build for this OS ({$this->os})" );
	}

	/**
	 * arch returns the Go GOARCH: amd64 or arm64.
	 *
	 * @throws \RuntimeException when the architecture has no Tuner build.
	 */
	public function arch() {
		$m = strtolower( $this->machine );
		if ( in_array( $m, array( 'x86_64', 'amd64', 'x64' ), true ) ) {
			return 'amd64';
		}
		if ( in_array( $m, array( 'arm64', 'aarch64' ), true ) ) {
			return 'arm64';
		}
		throw new \RuntimeException( "Tuner has no build for this architecture ({$this->machine})" );
	}

	/** binaryName is the extracted binary's file name. */
	public function binaryName() {
		return 'windows' === $this->os() ? 'rhythm-tuner.exe' : 'rhythm-tuner';
	}

	/** archiveName is the release archive for this platform. */
	public function archiveName() {
		$ext = 'windows' === $this->os() ? 'zip' : 'tar.gz';
		return sprintf( 'rhythm-tuner_%s_%s.%s', $this->os(), $this->arch(), $ext );
	}

	/** isWindows reports whether the archive is a zip. */
	public function isWindows() {
		return 'windows' === $this->os();
	}
}
