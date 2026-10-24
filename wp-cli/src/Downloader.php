<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

namespace RhythmShahriar\Tuner;

/**
 * Downloader fetches a verified rhythm-tuner binary into the WP-CLI cache
 * and returns its path. It downloads the release archive and
 * checksums.txt, checks the archive's SHA-256 against checksums.txt and,
 * when cosign is on PATH, verifies checksums.txt's signature first. The
 * only network call is the GitHub download; it never runs the site's PHP.
 *
 * The binary is written to a temporary file and renamed into place only
 * once it is verified, with its SHA-256 beside it. A cached binary is
 * reused only while it still matches that hash, so an interrupted
 * download or a damaged file is fetched again instead of run.
 *
 * A Fetcher and a Runner are injected so the tests can use a fake release
 * server and record the cosign call without a real one.
 */
class Downloader {

	const REPO = 'RhythmShahriar/tuner';

	/** @var string version to install, without a leading v, or "latest". */
	private $version;

	/** @var string directory to cache binaries in. */
	private $cacheDir;

	/** @var Platform */
	private $platform;

	/** @var callable (string $url): ?string: the body, or null on a miss. */
	private $fetch;

	/** @var callable (array $argv): array{int,string}: the exit code and output. */
	private $run;

	/** @var string base URL for release files; overrides GitHub (tests, mirrors). */
	private $baseUrl;

	/** @var bool verify checksums.txt's cosign signature when cosign is present. */
	private $verifySignature;

	/**
	 * @param array $opts version, cache_dir, platform, fetch, run, base_url, verify_signature.
	 */
	public function __construct( array $opts = array() ) {
		$this->version         = isset( $opts['version'] ) ? ltrim( (string) $opts['version'], 'v' ) : 'latest';
		$this->cacheDir        = isset( $opts['cache_dir'] ) ? $opts['cache_dir'] : sys_get_temp_dir() . '/rhythm-tuner';
		$this->platform        = isset( $opts['platform'] ) ? $opts['platform'] : new Platform();
		$this->fetch           = isset( $opts['fetch'] ) ? $opts['fetch'] : array( $this, 'httpGet' );
		$this->run             = isset( $opts['run'] ) ? $opts['run'] : array( $this, 'execv' );
		$this->baseUrl         = isset( $opts['base_url'] ) ? rtrim( $opts['base_url'], '/' ) : '';
		$this->verifySignature = isset( $opts['verify_signature'] ) ? (bool) $opts['verify_signature'] : true;
	}

	/**
	 * ensure returns a path to a verified rhythm-tuner, downloading it
	 * once per version into the cache.
	 *
	 * @throws \RuntimeException on a download, signature or checksum failure.
	 */
	public function ensure() {
		$archive = $this->platform->archiveName();
		$binary  = $this->platform->binaryName();
		$version = $this->resolveVersion();
		$base    = $this->base( $version );

		// A mirror's "latest" changes under the same URL, so it is keyed by
		// the checksums.txt it serves now instead of being cached forever.
		$checksums = null;
		$key       = $version;
		if ( 'latest' === $version ) {
			$checksums = $this->must( "$base/checksums.txt", 'checksums.txt' );
			$key       = 'latest-' . substr( hash( 'sha256', $checksums ), 0, 16 );
		}
		$dir     = $this->cacheDir . '/' . $key;
		$binPath = $dir . '/' . $binary;
		if ( self::cachedOk( $binPath ) ) {
			return $binPath;
		}
		if ( ! is_dir( $dir ) && ! mkdir( $dir, 0755, true ) && ! is_dir( $dir ) ) {
			throw new \RuntimeException( "can't create the cache folder $dir" );
		}

		$archiveB = $this->must( "$base/$archive", $archive );
		if ( null === $checksums ) {
			$checksums = $this->must( "$base/checksums.txt", 'checksums.txt' );
		}

		if ( $this->verifySignature && $this->cosignAvailable() ) {
			$this->verifyCosign( $base, $version, $dir, $checksums );
		}

		$this->verifyChecksum( $archive, $archiveB, $checksums );
		$this->extract( $archive, $archiveB, $binary, $binPath );
		return $binPath;
	}

	/**
	 * cachedOk reports whether a cached binary is there and still has the
	 * SHA-256 recorded when it was installed.
	 */
	private static function cachedOk( $binPath ) {
		if ( ! is_file( $binPath ) || ! is_file( $binPath . '.sha256' ) ) {
			return false;
		}
		$want = trim( (string) file_get_contents( $binPath . '.sha256' ) );
		$got  = hash_file( 'sha256', $binPath );
		return '' !== $want && false !== $got && hash_equals( $want, $got );
	}

	/** base is where the release files live for a version. */
	private function base( $version ) {
		if ( '' !== $this->baseUrl ) {
			return $this->baseUrl;
		}
		return 'https://github.com/' . self::REPO . "/releases/download/v$version";
	}

	/**
	 * resolveVersion turns "latest" into a concrete version, so every file
	 * comes from one release and the signature can name the tag.
	 */
	private function resolveVersion() {
		if ( 'latest' !== $this->version ) {
			return $this->version;
		}
		if ( '' !== $this->baseUrl ) {
			return 'latest'; // a mirror serves one release at a fixed base
		}
		$body = call_user_func( $this->fetch, 'https://api.github.com/repos/' . self::REPO . '/releases/latest' );
		if ( null === $body || '' === $body ) {
			throw new \RuntimeException( "couldn't find Tuner's latest release" );
		}
		$data = json_decode( $body, true );
		if ( ! isset( $data['tag_name'] ) || ! preg_match( '/^v?([0-9][0-9A-Za-z.\-]*)$/', $data['tag_name'], $m ) ) {
			throw new \RuntimeException( "couldn't read Tuner's latest release tag" );
		}
		return $m[1];
	}

	private function must( $url, $name ) {
		$body = call_user_func( $this->fetch, $url );
		if ( null === $body ) {
			throw new \RuntimeException( "couldn't download $name from $url" );
		}
		return $body;
	}

	/**
	 * verifyChecksum checks the archive against its line in checksums.txt.
	 *
	 * @throws \RuntimeException when the file is absent or the hash differs.
	 */
	private function verifyChecksum( $archive, $archiveBody, $checksums ) {
		$want = self::checksumFor( $checksums, $archive );
		if ( null === $want ) {
			throw new \RuntimeException( "$archive is not listed in checksums.txt" );
		}
		$got = hash( 'sha256', $archiveBody );
		if ( ! hash_equals( $want, $got ) ) {
			throw new \RuntimeException( "checksum mismatch for $archive: checksums.txt has $want, the download is $got" );
		}
	}

	/**
	 * checksumFor returns the hex SHA-256 for a file name in a
	 * "<hash>  <name>" checksums.txt, or null.
	 */
	public static function checksumFor( $checksums, $name ) {
		foreach ( preg_split( '/\r?\n/', $checksums ) as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$parts = preg_split( '/\s+/', $line, 2 );
			if ( count( $parts ) !== 2 ) {
				continue;
			}
			if ( ltrim( $parts[1], '*' ) === $name ) {
				return strtolower( $parts[0] );
			}
		}
		return null;
	}

	private function cosignAvailable() {
		list( $code ) = call_user_func( $this->run, array( 'cosign', 'version' ) );
		return 0 === $code;
	}

	/**
	 * verifyCosign checks checksums.txt's keyless signature. It pins the
	 * repository and, for a concrete version, the release tag, like the
	 * Action and the installers.
	 *
	 * @throws \RuntimeException when verification fails.
	 */
	private function verifyCosign( $base, $version, $dir, $checksums ) {
		$bundle = $this->must( "$base/checksums.txt.sigstore.json", 'checksums.txt.sigstore.json' );
		$sumsPath   = $dir . '/checksums.txt';
		$bundlePath = $dir . '/checksums.txt.sigstore.json';
		file_put_contents( $sumsPath, $checksums );
		file_put_contents( $bundlePath, $bundle );

		$argv = array(
			'cosign',
			'verify-blob',
			$sumsPath,
			'--bundle',
			$bundlePath,
			'--certificate-oidc-issuer',
			'https://token.actions.githubusercontent.com',
			'--certificate-identity-regexp',
			'^https://github\.com/RhythmShahriar/\.github/\.github/workflows/release-go\.yml@',
			'--certificate-github-workflow-repository',
			self::REPO,
		);
		if ( 'latest' !== $version ) {
			$argv[] = '--certificate-github-workflow-ref';
			$argv[] = "refs/tags/v$version";
		}
		list( $code, $out ) = call_user_func( $this->run, $argv );
		if ( 0 !== $code ) {
			throw new \RuntimeException( "cosign couldn't verify checksums.txt: $out" );
		}
	}

	/**
	 * extract pulls the one binary out of the archive, writes it to a
	 * temporary file in the cache folder, makes it executable and renames
	 * it into place, so a reader never sees a half-written binary. Its
	 * SHA-256 goes beside it for cachedOk.
	 *
	 * @throws \RuntimeException when the binary isn't in the archive or
	 *                           can't be written.
	 */
	private function extract( $archive, $archiveBody, $binary, $binPath ) {
		$dir         = dirname( $binPath );
		$archivePath = $dir . '/' . uniqid( 'download-', true ) . '-' . $archive;
		if ( false === file_put_contents( $archivePath, $archiveBody ) ) {
			throw new \RuntimeException( "can't write $archivePath" );
		}

		try {
			if ( $this->platform->isWindows() ) {
				$zip = new \ZipArchive();
				if ( true !== $zip->open( $archivePath ) ) {
					throw new \RuntimeException( "couldn't open $archive" );
				}
				$data = $zip->getFromName( $binary );
				$zip->close();
			} else {
				$phar = new \PharData( $archivePath );
				$data = isset( $phar[ $binary ] ) ? file_get_contents( $phar[ $binary ]->getPathname() ) : false;
				unset( $phar );
			}
		} finally {
			@unlink( $archivePath );
		}
		if ( false === $data ) {
			throw new \RuntimeException( "$binary is not in $archive" );
		}

		$tmp = $binPath . '.' . uniqid( 'tmp', true );
		if ( false === file_put_contents( $tmp, $data ) ) {
			@unlink( $tmp );
			throw new \RuntimeException( "can't write $tmp" );
		}
		@chmod( $tmp, 0755 );
		@unlink( $binPath . '.sha256' ); // stale until the new binary is in place
		if ( ! @rename( $tmp, $binPath ) ) {
			@unlink( $tmp );
			throw new \RuntimeException( "can't move the binary into $binPath" );
		}
		file_put_contents( $binPath . '.sha256', hash( 'sha256', $data ) . "\n" );
	}

	/** httpGet is the default Fetcher. Returns null on a non-200 or error. */
	private function httpGet( $url ) {
		$ctx  = stream_context_create(
			array(
				'http' => array(
					'header'        => "User-Agent: tuner-wp-cli\r\n",
					'ignore_errors' => true,
					'timeout'       => 60,
				),
			)
		);
		$body = @file_get_contents( $url, false, $ctx );
		if ( false === $body ) {
			return null;
		}
		if ( isset( $http_response_header ) ) {
			foreach ( $http_response_header as $h ) {
				if ( preg_match( '#^HTTP/\S+\s+(\d+)#', $h, $m ) ) {
					$status = (int) $m[1];
				}
			}
			if ( isset( $status ) && $status >= 400 ) {
				return null;
			}
		}
		return $body;
	}

	/** execv is the default Runner: run a command, return its code and output. */
	private function execv( array $argv ) {
		$cmd = implode( ' ', array_map( 'escapeshellarg', $argv ) ) . ' 2>&1';
		$out = array();
		$code = 1;
		exec( $cmd, $out, $code );
		return array( $code, implode( "\n", $out ) );
	}
}
