# Usage

```sh
rhythm tuner                         # interactive picker
rhythm tuner scan example.com        # scan a site
rhythm tuner checks                  # list checks
```

`rhythm tuner scan --help` lists every flag. This page explains them.

## What a scan does

1. **Fingerprint.** Fetches the home page, following redirects, and detects WordPress (with version), Laravel, PHP, the server, and the plugins and themes it loads. Plugin versions come from `readme.txt` and theme versions from `style.css`. The PHP version comes from `X-Powered-By`, or a `PHP/x.y.z` token in `Server`; when a page cache strips both from the home page, Tuner asks a few uncacheable PHP endpoints instead (`/xmlrpc.php`, `/wp-admin/admin-ajax.php`, `/wp-login.php` on WordPress, `/index.php` elsewhere), stopping at the first that answers. That's at most three extra requests, in every profile, and the checks reuse the responses. The JSON report's `php_source` says where the version was found.
2. **TLS.** For https sites, reads the certificate's expiry and trust and tests whether TLS 1.0/1.1 are still accepted.
3. **Baseline.** Requests random paths to learn how the server answers "not found", so sites that return 200 for everything don't produce false findings.
4. **Checks.** Runs each check's requests, without following redirects, and streams findings as they're found.
5. **Known vulnerabilities.** Matches the WordPress, plugin, theme, PHP, nginx and Apache versions it found against public advisories (see below). This runs alongside the checks.

Tuner only sends plain GET requests to public URLs. It never sends exploit payloads.

## Choosing checks

| Flag | Effect |
|---|---|
| `--profile quick` | the top checks, about 30 requests; skips plugin version lookups |
| `--profile default` | every polite check (default) |
| `--profile deep` | adds aggressive enumeration |
| `--tags leak,wordpress` | only checks with any of these tags |
| `--exclude-tags headers` | skip checks with these tags |
| `--id 'leak-*'` | only these checks (globs allowed); ignores the profile |
| `--exclude-id wp-readme` | skip these checks |
| `--severity medium` | skip checks below this severity |
| `--checks ./my-checks` | load checks from a directory |

`rhythm tuner checks` accepts the same flags, so you can preview a selection.

## Known vulnerabilities

Tuner reports one finding per vulnerable component, listing every advisory that applies, with its CVE, severity, the version that fixes it, and whether it's in CISA's Known Exploited Vulnerabilities catalog:

```
✖ CRITICAL  WordPress 6.9.3: 22 known vulnerabilities
■ MEDIUM    elementor 3.20.1: 26 known vulnerabilities
              MEDIUM CVE-2024-54444 Elementor Website Builder <= 3.25.10 - …
```

It also reports:

| ID | When |
|---|---|
| `vuln-core`, `vuln-plugin-<slug>`, `vuln-theme-<slug>` | published vulnerabilities affect the installed version |
| `vuln-php`, `vuln-nginx`, `vuln-apache` | the server software version has known vulnerabilities |
| `php-eol`, `nginx-eol`, `apache-eol` | the branch no longer gets security fixes (`php-eol` is high: see below) |
| `php-version-hidden` | the site runs PHP but its version couldn't be read, and recent critical PHP flaws exist (see below) |
| `wp-core-outdated`, `wp-components-outdated` | a newer release exists |
| `wp-plugin-closed`, `wp-theme-closed` | removed from wordpress.org, often for an unfixed security issue |
| `wp-components-abandoned` | no release in over two years |
| `wp-components-unverified` | known vulnerabilities exist but the installed version couldn't be read |

**Hidden PHP versions.** Hiding the PHP version is good practice, but then Tuner can't tell whether the site is patched. `php-version-hidden` lists the critical or actively exploited PHP advisories published in the last 180 days for every supported branch, with the release that fixes each one, and tells you how to check the version yourself (`php -v`, your hosting panel, or WordPress Site Health). It's medium severity with low confidence, so it counts half in the score, and it isn't reported at all when no such advisories exist. The supported branches come from [php.net](https://www.php.net/releases/states.php), so the next big PHP flaw shows up without a Tuner update.

**End-of-life PHP.** Branches past end of life (e.g. 8.1, 7.4) never get fixes, so vulnerability databases stop listing new flaws for them. Tuner infers them: an advisory for the oldest supported branch with no lower version bound reaches every older release too. Those disclosed after the branch's end of life are added to `vuln-php` with no fixed version ("no fix for this branch"), and `php-eol` is raised to high.

Versions reported by distribution packages (e.g. `PHP/7.4.3-4ubuntu2.19`, `Apache/2.4.41 (Ubuntu)`) get low confidence: distributions backport security fixes without changing the version number.

**Data.** Advisories come from [WPVulnerability](https://www.wpvulnerability.com/), which aggregates CVE, Wordfence, WPScan and Patchstack and publishes them as public domain (CC0). Latest-release information comes from the wordpress.org API, and PHP's supported branches from php.net. No API key is needed.

**Updates are automatic.** Each component's data is cached under your user cache directory (`~/.cache/rhythm/tuner/vulns` on Linux) and refreshed during a scan once it's a day old. If the data services can't be reached, Tuner uses the cached copy and says so.

| | |
|---|---|
| `rhythm tuner update` | refresh all cached data now |
| `rhythm tuner update --clear` | delete the cache |
| `--offline` | use cached data only; never contact the data services |
| `--no-vulns` | skip vulnerability matching |
| `--id 'vuln-*'` | only vulnerability matching |
| `TUNER_VULN_API`, `TUNER_WPORG_API`, `TUNER_PHPNET_API` | use mirrors of WPVulnerability, api.wordpress.org and php.net |

## Updating Tuner

`rhythm update` updates rhythm, every installed tool, and their data. Each download is checked against the release's `checksums.txt` before anything is replaced. `rhythm update --check` only reports.

After a scan, Tuner mentions when a newer release is out. It checks GitHub at most once a day, never in CI, and never when `RHYTHM_NO_UPDATE_CHECK=1` is set. Binaries are never replaced without you running `rhythm update`.

## Requests

| Flag | Default | |
|---|---|---|
| `--rate` | `5` | requests per second per site; `0` is unlimited |
| `-c, --concurrency` | `10` | requests in flight per site |
| `--timeout` | `10s` | per request |
| `--retries` | `2` | after network errors, or a `429`/`503` reply |
| `--max-time` | none | stop the whole run after this long |
| `-A, --user-agent` | `rhythm-tuner/<version> (+https://rythm.sh/tuner)` | |
| `-H, --header` | | `"Name: value"`, repeatable; `Host:` sets the virtual host |
| `--cookie` | | e.g. `"wordpress_logged_in_x=…"` to scan as a logged-in user |
| `--proxy` | `$HTTPS_PROXY` | `http://`, `https://` or `socks5://`; also used for vulnerability data |
| `-k, --insecure` | off | scan sites with invalid certificates (still reported) |

**Throttling.** When a site answers `429 Too Many Requests` or `503`, Tuner waits as long as `Retry-After` asks (up to 30s), retries, and halves its request rate for the rest of the scan. The summary shows how often that happened.

**Scanning behind auth.** Staging sites behind basic auth: `-H "Authorization: Basic $(printf user:pass | base64)"`.

## Output

| Flag | Output |
|---|---|
| none | live terminal view |
| `--json` | one report object; an array when scanning several sites |
| `--jsonl` | one finding per line, streamed as found |
| `--sarif` | SARIF 2.1.0 for GitHub code scanning |
| `--md` | Markdown for issues and PRs |
| `-o file` | writes the report to a file (format from the extension, or the flag) and keeps the live view |
| `-q, --quiet` | findings only |
| `--plain` | no color, boxes or glyphs; used automatically when output isn't a terminal |
| `--no-color` | no color (`NO_COLOR` also works) |
| `-v, --verbose` | log every request to stderr |

Secrets are always masked, in every format.

## Several sites

```sh
rhythm tuner scan a.com b.com
rhythm tuner scan -l sites.txt --parallel 8 --json > results.json
cat sites.txt | rhythm tuner scan --stdin --jsonl
```

List files take one target per line; blank lines and `# comments` are ignored, and duplicates are removed. Each site gets its own rate limit.

## Tune score

Each scan gets a score out of 100. Every distinct failing check subtracts points by its worst severity: critical 30, high 15, medium 6, low 2, info 0. A check that fires on several paths counts once, and a check whose findings are all low confidence (marked "likely") counts half.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done (or findings below `--fail-on`) |
| 1 | a finding at or above `--fail-on` |
| 2 | usage error |
| 3 | a site couldn't be scanned (other sites' reports are still written) |
| 130 | interrupted; partial results are written |
