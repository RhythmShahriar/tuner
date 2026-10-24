<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

namespace RhythmShahriar\Tuner\Tests;

use PHPUnit\Framework\TestCase;
use RhythmShahriar\Tuner\Downloader;
use RhythmShahriar\Tuner\Platform;

class DownloaderTest extends TestCase {

	/** @var string */
	private $cache;

	protected function setUp(): void {
		$this->cache = sys_get_temp_dir() . '/tuner-wp-cli-test-' . uniqid();
	}

	protected function tearDown(): void {
		self::rmrf( $this->cache );
	}

	public function test_checksum_for() {
		$sums = "aa11  rhythm-tuner_linux_amd64.tar.gz\nbb22 *checksums.txt\n";
		$this->assertSame( 'aa11', Downloader::checksumFor( $sums, 'rhythm-tuner_linux_amd64.tar.gz' ) );
		$this->assertSame( 'bb22', Downloader::checksumFor( $sums, 'checksums.txt' ) );
		$this->assertNull( Downloader::checksumFor( $sums, 'missing' ) );
	}

	public function test_downloads_and_extracts_verified_binary() {
		$release = $this->fakeRelease( 'tuner body v1' );
		$calls   = array();
		$d       = new Downloader(
			array(
				'version'          => '0.4.0',
				'cache_dir'        => $this->cache,
				'platform'         => new Platform( 'Linux', 'x86_64' ),
				'base_url'         => 'https://example.invalid/download/v0.4.0',
				'verify_signature' => true,
				'fetch'            => $this->fetcher( $release, 'https://example.invalid/download/v0.4.0' ),
				'run'             => function ( array $argv ) use ( &$calls ) {
					$calls[] = $argv;
					return array( 0, '' ); // cosign present and happy
				},
			)
		);
		$bin = $d->ensure();
		$this->assertFileExists( $bin );
		$this->assertSame( 'tuner body v1', file_get_contents( $bin ) );

		// cosign was asked to verify, pinning the repository and the tag.
		$verify = $this->findCall( $calls, 'verify-blob' );
		$this->assertNotNull( $verify, 'cosign verify-blob was not called' );
		$this->assertContains( '--certificate-github-workflow-repository', $verify );
		$this->assertContains( 'RhythmShahriar/tuner', $verify );
		$this->assertContains( 'refs/tags/v0.4.0', $verify );
	}

	public function test_checksum_mismatch_is_refused() {
		$release = $this->fakeRelease( 'real body' );
		// Corrupt the archive the server returns, leaving checksums.txt.
		$release['rhythm-tuner_linux_amd64.tar.gz'] = 'tampered';
		$d = new Downloader(
			array(
				'version'          => '0.4.0',
				'cache_dir'        => $this->cache,
				'platform'         => new Platform( 'Linux', 'x86_64' ),
				'base_url'         => 'https://example.invalid/d',
				'verify_signature' => false,
				'fetch'            => $this->fetcher( $release, 'https://example.invalid/d' ),
			)
		);
		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessageMatches( '/checksum mismatch/' );
		$d->ensure();
	}

	public function test_missing_archive_is_an_error() {
		$d = new Downloader(
			array(
				'version'          => '0.4.0',
				'cache_dir'        => $this->cache,
				'platform'         => new Platform( 'Linux', 'x86_64' ),
				'base_url'         => 'https://example.invalid/d',
				'verify_signature' => false,
				'fetch'            => function () {
					return null; // nothing is served
				},
			)
		);
		$this->expectException( \RuntimeException::class );
		$d->ensure();
	}

	public function test_signature_skipped_when_cosign_absent() {
		$release = $this->fakeRelease( 'body' );
		$ran     = false;
		$warned  = array();
		$d       = new Downloader(
			array(
				'version'          => '0.4.0',
				'cache_dir'        => $this->cache,
				'platform'         => new Platform( 'Linux', 'x86_64' ),
				'base_url'         => 'https://example.invalid/d',
				'verify_signature' => true,
				'fetch'            => $this->fetcher( $release, 'https://example.invalid/d' ),
				'run'             => function () use ( &$ran ) {
					$ran = true;
					return array( 127, 'cosign: not found' ); // cosign missing
				},
				'warn'             => function ( $message ) use ( &$warned ) {
					$warned[] = $message;
				},
			)
		);
		$bin = $d->ensure();
		$this->assertFileExists( $bin );
		$this->assertTrue( $ran, 'cosign presence should have been probed' );
		$this->assertSame( array( 'cosign not found; checked the SHA-256 against checksums.txt only.' ), $warned );
	}

	public function test_no_cosign_warning_when_verification_is_off() {
		$release = $this->fakeRelease( 'body' );
		$warned  = array();
		$d       = new Downloader(
			array(
				'version'          => '0.4.0',
				'cache_dir'        => $this->cache,
				'platform'         => new Platform( 'Linux', 'x86_64' ),
				'base_url'         => 'https://example.invalid/d',
				'verify_signature' => false,
				'fetch'            => $this->fetcher( $release, 'https://example.invalid/d' ),
				'warn'             => function ( $message ) use ( &$warned ) {
					$warned[] = $message;
				},
			)
		);
		$d->ensure();
		$this->assertSame( array(), $warned, '--no-verify-signature asked for no signature check' );
	}

	public function test_cached_binary_is_reused_without_a_download() {
		$release = $this->fakeRelease( 'cached body' );
		$this->downloader( $release, '0.4.0' )->ensure();

		$fetched = 0;
		$d       = $this->downloader( $release, '0.4.0', $fetched );
		$bin     = $d->ensure();
		$this->assertSame( 'cached body', file_get_contents( $bin ) );
		$this->assertSame( 0, $fetched, 'a verified cache must not download again' );
	}

	public function test_damaged_cache_is_downloaded_again() {
		$release = $this->fakeRelease( 'whole body' );
		$bin     = $this->downloader( $release, '0.4.0' )->ensure();

		// An interrupted write: the binary is cut short.
		file_put_contents( $bin, 'whole' );
		$this->assertSame( 'whole body', file_get_contents( $this->downloader( $release, '0.4.0' )->ensure() ) );

		// A binary with no recorded hash, as an older package left it.
		unlink( $bin . '.sha256' );
		file_put_contents( $bin, 'stale' );
		$this->assertSame( 'whole body', file_get_contents( $this->downloader( $release, '0.4.0' )->ensure() ) );
	}

	public function test_install_leaves_no_temporary_files() {
		$release = $this->fakeRelease( 'body' );
		$bin     = $this->downloader( $release, '0.4.0' )->ensure();
		$names   = array_values( array_diff( scandir( dirname( $bin ) ), array( '.', '..' ) ) );
		sort( $names );
		$this->assertSame( array( 'rhythm-tuner', 'rhythm-tuner.sha256' ), $names );
	}

	public function test_mirror_latest_follows_the_release_it_serves() {
		$first = $this->fakeRelease( 'release one' );
		$this->assertSame( 'release one', file_get_contents( $this->downloader( $first, 'latest' )->ensure() ) );

		// The mirror now serves a newer release at the same URL.
		$second = $this->fakeRelease( 'release two' );
		$this->assertSame( 'release two', file_get_contents( $this->downloader( $second, 'latest' )->ensure() ) );
	}

	/**
	 * downloader serves a fake release from a mirror base without cosign,
	 * counting the archive downloads in $fetched.
	 */
	private function downloader( array $release, $version, &$fetched = null ) {
		$fetched = 0;
		$serve   = $this->fetcher( $release, 'https://example.invalid/d' );
		return new Downloader(
			array(
				'version'          => $version,
				'cache_dir'        => $this->cache,
				'platform'         => new Platform( 'Linux', 'x86_64' ),
				'base_url'         => 'https://example.invalid/d',
				'verify_signature' => false,
				'fetch'            => function ( $url ) use ( $serve, &$fetched ) {
					if ( substr( $url, -7 ) === '.tar.gz' ) {
						$fetched++;
					}
					return $serve( $url );
				},
			)
		);
	}

	/**
	 * fakeRelease builds a tar.gz holding one rhythm-tuner binary and a
	 * matching checksums.txt (and a dummy cosign bundle).
	 *
	 * @return array<string,string> file name => body.
	 */
	private function fakeRelease( $body ) {
		$archive = 'rhythm-tuner_linux_amd64.tar.gz';
		$dir     = $this->cache . '/make-' . uniqid(); // phar caches archives by path
		mkdir( $dir, 0755, true );
		$tar = $dir . '/rhythm-tuner_linux_amd64.tar';
		$p   = new \PharData( $tar );
		$p->addFromString( 'rhythm-tuner', $body );
		$p->compress( \Phar::GZ );
		unset( $p );
		\Phar::unlinkArchive( $tar );
		$gz = file_get_contents( $tar . '.gz' );
		self::rmrf( $dir );

		$sums = sprintf( "%s  %s\n", hash( 'sha256', $gz ), $archive );
		return array(
			$archive                          => $gz,
			'checksums.txt'                   => $sums,
			'checksums.txt.sigstore.json'     => '{"fake":"bundle"}',
		);
	}

	/** fetcher serves the fake release by URL under a base. */
	private function fetcher( array $release, $base ) {
		return function ( $url ) use ( $release, $base ) {
			$name = basename( parse_url( $url, PHP_URL_PATH ) );
			return isset( $release[ $name ] ) ? $release[ $name ] : null;
		};
	}

	private function findCall( array $calls, $first ) {
		foreach ( $calls as $c ) {
			if ( in_array( $first, $c, true ) ) {
				return $c;
			}
		}
		return null;
	}

	private static function rmrf( $path ) {
		if ( is_file( $path ) || is_link( $path ) ) {
			@unlink( $path );
			return;
		}
		if ( ! is_dir( $path ) ) {
			return;
		}
		foreach ( scandir( $path ) as $e ) {
			if ( '.' !== $e && '..' !== $e ) {
				self::rmrf( $path . '/' . $e );
			}
		}
		@rmdir( $path );
	}
}
