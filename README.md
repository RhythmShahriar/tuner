<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
    <img alt="rhythm tuner" src="docs/assets/banner-light.svg" width="100%">
  </picture>
</p>

<p align="center">
  <b>A fast, open-source security scanner for WordPress &amp; PHP sites.</b><br>
  Leaked secrets · exposed files · known CVEs · weak configuration. One binary, no API key, no limits.
</p>

<p align="center">
  <a href="https://github.com/RhythmShahriar/tuner/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/RhythmShahriar/tuner?style=flat-square&color=ff7c52&label=release"></a>
  <a href="https://github.com/RhythmShahriar/tuner/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/RhythmShahriar/tuner/ci.yml?branch=master&style=flat-square&label=ci"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0-100f0d?style=flat-square"></a>
  <a href="go.mod"><img alt="Go" src="https://img.shields.io/github/go-mod/go-version/RhythmShahriar/tuner?style=flat-square&color=100f0d"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#scan">Scan</a> ·
  <a href="#what-it-finds">What it finds</a> ·
  <a href="docs/usage.md">Docs</a> ·
  <a href="docs/ci.md">CI</a> ·
  <a href="docs/checks.md">Write a check</a>
</p>

<br>

<p align="center">
  <img alt="A Tuner scan of a WordPress site: findings grouped by severity, with masked secrets, known CVEs and a fix for each, ending in a Tune score" src="docs/assets/scan.svg" width="720">
</p>

<br>

## Install

**macOS · Linux**

```sh
curl -fsSL https://rythm.sh/install | sh
```

**Windows** (PowerShell)

```powershell
irm https://rythm.sh/install.ps1 | iex
```

**Go**

```sh
go install github.com/RhythmShahriar/tuner/cmd/rhythm-tuner@latest
```

The installers check every download against the release checksums, which are [signed with cosign](https://github.com/RhythmShahriar/rhythm#verify-a-release). Prefer a manual install? Grab a binary from [Releases](https://github.com/RhythmShahriar/tuner/releases/latest).

## Scan

```sh
rhythm tuner scan yoursite.com
```

That's it. Tuner fingerprints the site, learns how it answers "not found", runs every check, matches versions against known vulnerabilities, and prints a fix for each finding. A typical scan takes 15–30 seconds.

| You want to… | Run |
|---|---|
| Save a report for a client or an issue | `rhythm tuner scan yoursite.com -o report.md` |
| A quick look (about 30 requests) | `rhythm tuner scan yoursite.com --profile quick` |
| Scan a staging site behind basic auth | `rhythm tuner scan staging.yoursite.com -H "Authorization: Basic …"` |
| Go gentle on a fragile host or firewall | `rhythm tuner scan yoursite.com --rate 2` |
| Scan all your clients' sites | `rhythm tuner scan -l sites.txt -o all.md` |
| Fail a CI build on serious findings | `rhythm tuner scan yoursite.com --fail-on high` |

Every flag is in the [usage guide](docs/usage.md).

> [!IMPORTANT]
> Scan only sites you own or have permission to test. Tuner is non-intrusive (plain GET requests, no exploit payloads, 5 requests a second by default), but a scan of someone else's site without permission may still be illegal.

## What it finds

<table>
<tr>
<td width="50%" valign="top">

### 🔑 Leaks
`.env` files, `.git` and `.svn` directories, `wp-config.php` backups, SQL dumps, backup archives, error and debug logs, `phpinfo()`, `.htpasswd`, Composer auth tokens. Secrets are detected and **always masked**.

</td>
<td width="50%" valign="top">

### 🧩 Known vulnerabilities
WordPress core, plugins, themes, PHP, nginx and Apache, matched against CVE, Wordfence, WPScan and Patchstack data. Each finding lists CVEs, the fixed version, and flags anything **actively exploited** (CISA KEV).

</td>
</tr>
<tr>
<td valign="top">

### 🪶 WordPress &amp; PHP
User enumeration, XML-RPC, admin-ajax, directory listing, `display_errors`, Laravel logs and Ignition. Outdated, closed and abandoned plugins and end-of-life PHP.

</td>
<td valign="top">

### 🛡️ Server &amp; TLS
Security headers, cookie flags, version leaks, plain HTTP, expired or untrusted certificates, and obsolete TLS 1.0/1.1.

</td>
</tr>
</table>

## Why Tuner

- **No key, no limits.** Vulnerability data is free and public domain, cached locally and refreshed daily. Works offline from cache.
- **Low false positives.** Every file check is compared against how the server answers a random path, so sites that return "200 OK" for everything don't flood you with noise. Versions a Linux distribution may have patched are marked *likely*, not confirmed.
- **Tells you how to fix it.** Every finding comes with the exact nginx, Apache or WordPress change.
- **Built for CI.** JSON, JSONL, [SARIF](docs/ci.md) for GitHub code scanning, Markdown, `--fail-on` and baselines.
- **Extensible.** Checks are [YAML files](docs/checks.md), each with tests. Adding one takes no Go code.
- **Polite by default.** Rate limited, slows down on `429`/`503`, honest user agent.

## CI

Show findings in your repository's **Security** tab:

```yaml
- run: curl -fsSL https://rythm.sh/install | sh
- run: rhythm tuner scan https://staging.yoursite.com --sarif -o tuner.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: tuner.sarif
```

More in the [CI guide](docs/ci.md).

## Docs

| | |
|---|---|
| [Usage](docs/usage.md) | every flag, profiles, the Tune score, exit codes |
| [CI](docs/ci.md) | GitHub code scanning, `--fail-on`, baselines |
| [Writing checks](docs/checks.md) | the YAML format and fixtures |

## Contributing

```sh
git clone https://github.com/RhythmShahriar/tuner && cd tuner
make hooks   # Conventional Commits check
make check   # lint + tests; every check runs against its own fixtures
```

New checks are the most welcome contribution. See [CONTRIBUTING](https://github.com/RhythmShahriar/.github/blob/master/CONTRIBUTING.md).

## License

The scanner is [AGPL-3.0](LICENSE). The checks in [`checks/`](checks) are [MIT](checks/LICENSE), so anyone can reuse them.<br>
Vulnerability data: [WPVulnerability](https://www.wpvulnerability.com/) (CC0) and the wordpress.org API.

<p align="center"><sub>Part of <a href="https://github.com/RhythmShahriar/rhythm"><b>rhythm</b></a> · Useful ideas. Working systems.</sub></p>
