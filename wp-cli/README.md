# Tuner for WP-CLI

Run Tuner's local WordPress and PHP scan from a tool you already have:

```sh
wp package install rhythm-shahriar/tuner-wp-cli
wp tuner scan
```

`wp tuner scan` installs a verified `rhythm-tuner` release into the WP-CLI
cache and scans this site's files (ABSPATH) in place. It never runs the
site's PHP beyond WP-CLI itself, and the only network call is the GitHub
download.

## Options

| Flag | Default | Meaning |
|---|---|---|
| `--integrity` | off | also verify core and plugin files against the official checksums |
| `--format=<table\|json>` | `table` | a table of findings, or raw Tuner JSON on stdout |
| `--fail-on=<severity>` | `high` | exit non-zero on a finding at or above this severity; `none` never fails |
| `--version=<version>` | `latest` | Tuner version to install, e.g. `0.4.0` |
| `--path=<path>` | ABSPATH | scan this folder instead |
| `--no-verify-signature` | off | skip the cosign check (checksums are still verified); for mirrors only |

Examples:

```sh
wp tuner scan --integrity --fail-on=medium
wp tuner scan --format=json > tuner.json
```

## How the download is trusted

1. The release archive for this OS and architecture
   (`rhythm-tuner_<os>_<arch>.<tar.gz|zip>`) and `checksums.txt` are
   downloaded from the GitHub release.
2. When `cosign` is on PATH, `checksums.txt`'s keyless signature is
   verified first, pinned to `RhythmShahriar/tuner` and the release tag.
3. The archive's SHA-256 is checked against `checksums.txt`.
4. The one binary is extracted into the WP-CLI cache and reused next time.

The exit code is Tuner's own: 0 ok, 1 findings at `--fail-on`, 2 a usage
error, 3 a target could not be scanned.

`TUNER_DOWNLOAD_URL` overrides the download base for a mirror or a test;
it must hold the archive and `checksums.txt` (and the signature bundle
when verifying).

## Developing

```sh
composer install
composer test        # PHPUnit: download, verification, argument building
```

The exposed-file and plugin checks are shared with the `rhythm-tuner`
binary; this package only installs and runs it. Nothing here holds a real
secret or an exploit.
