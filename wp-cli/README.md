# Tuner for WP-CLI

Run Tuner's local WordPress and PHP scan from a tool you already have:

```sh
wp package install rhythm-shahriar/tuner-wp-cli
wp tuner scan
```

`wp tuner scan` installs a verified `rhythm-tuner` release into the WP-CLI
cache and scans this site's files (ABSPATH) in place. It never runs the
site's PHP beyond WP-CLI itself. Its own network calls are the GitHub
download and the vulnerability data the scan looks up.

## Options

| Flag | Default | Meaning |
|---|---|---|
| `--integrity` | off | also verify core and plugin files against the official checksums; needs a Tuner release with integrity checking (an older one is refused with a message) |
| `--format=<table\|json>` | `table` | a table of findings, or Tuner's JSON report on stdout exactly as Tuner wrote it |
| `--fail-on=<severity>` | `high` | exit non-zero on a finding at or above this severity; `none` never fails |
| `--version=<version>` | `latest` | Tuner version to install, e.g. `0.4.0` |
| `--no-verify-signature` | off | skip the cosign check (checksums are still verified); for mirrors only |

To scan another install, use WP-CLI's global `--path`:
`wp --path=/srv/www/blog tuner scan`.

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
   Without cosign the command warns `cosign not found; checked the
   SHA-256 against checksums.txt only.` and goes on.
3. The archive's SHA-256 is checked against `checksums.txt`.
4. The one binary is written to a temporary file in the WP-CLI cache,
   renamed into place and its SHA-256 recorded beside it. Later runs
   reuse it only while it still matches that hash; an interrupted or
   damaged install is downloaded again.

The exit code is Tuner's own: 0 ok, 1 findings at `--fail-on`, 2 a usage
error, 3 a target could not be scanned. When Tuner stops with 2 or 3
before writing a report, its own error is shown and its code kept.

`TUNER_DOWNLOAD_URL` overrides the download base for a mirror or a test
(an `https://` or `file://` URL). It must hold the archive and
`checksums.txt`, plus the signature bundle when verifying. With a mirror
and no `--version`, `checksums.txt` is read on every run and a new
release at the same URL is installed when it changes.

## Developing

```sh
composer install
composer test        # PHPUnit: download, verification, argument building
```

The exposed-file and plugin checks are shared with the `rhythm-tuner`
binary; this package only installs and runs it. Nothing here holds a real
secret or an exploit.
