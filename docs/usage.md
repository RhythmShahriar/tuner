# Usage

```sh
rhythm tuner                         # interactive picker
rhythm tuner scan example.com        # scan a site
rhythm tuner scan /var/www/site      # scan a site's files on the server
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
| `--profile deep` | reserved for checks that send many requests; today it runs the same checks as `default` |
| `--tags leak,wordpress` | only checks with any of these tags |
| `--exclude-tags headers` | skip checks with these tags |
| `--id 'leak-*'` | only these checks (globs allowed); ignores the profile |
| `--exclude-id wp-readme` | skip these checks |
| `--severity medium` | skip checks below this severity |
| `--checks ./my-checks` | load checks from a directory |
| `--no-check-updates` | use the built-in checks, not the latest check pack |

`rhythm tuner checks` accepts the same flags, so you can preview a selection, and says which checks are in use.

**Checks update like data.** New checks are published as a *check pack* on Tuner's GitHub releases whenever they land, and scans pick up the newest one within a day, without a new binary. Packs are checksum-verified, contain only declarative YAML checks (GET requests to the scanned site and response matching, no code), and are used only when they're newer than the checks built into your binary. Any problem with a pack falls back to the last good pack or the built-in checks, with a warning. JSON reports name the checks used in `check_set` (`built-in`, `pack` or `directory`) and `check_pack` (the pack version). Pin a run to your binary's checks with `--no-check-updates`, or to your own with `--checks`. See [Check packs](checks.md#check-packs) for details.

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
| `rhythm tuner update` | refresh the check pack and all cached data now, and show which checks are in use |
| `rhythm tuner update --clear` | delete the cached check pack and data |
| `--offline` | use cached data and check pack only; never contact the data services |
| `--no-vulns` | skip vulnerability matching |
| `--id 'vuln-*'` | only vulnerability matching |
| `TUNER_VULN_API`, `TUNER_WPORG_API`, `TUNER_PHPNET_API` | use mirrors of WPVulnerability, api.wordpress.org and php.net |
| `TUNER_CHECKS_URL` | fetch check packs from a mirror of the `checks-latest` release assets |

## Local scans

Point Tuner at a directory instead of a URL to scan a site's files in place, usually on the server itself:

```sh
rhythm tuner scan /var/www/example.com
rhythm tuner scan . --php /usr/bin/php8.3 --fail-on high
```

A target is local when it starts with `.`, `/` or `~`, or names an existing directory. From the outside Tuner has to guess versions, and many servers hide PHP's; on the machine it reads them:

| What | Where it comes from |
|---|---|
| PHP | `php -n -r 'echo PHP_VERSION;'` using the `php` on `PATH`, or `--php <binary>` |
| WordPress | `$wp_version` in `wp-includes/version.php` |
| Plugins | the `Version:` header of each plugin's main file: the installed version, not readme.txt's Stable tag |
| Themes | the `Version:` header of each theme's `style.css` |
| Composer packages | `composer.lock` |

These go through the same known-vulnerability matching as remote scans (`vuln-*`, `php-eol`, `wp-components-outdated`…), with `file://` locations. Composer packages are matched against [OSV.dev](https://osv.dev/) (GitHub Advisory Database and FriendsOfPHP), reported as `vuln-composer-<vendor>-<package>`, and cached with the rest of the vulnerability data; `TUNER_OSV_API` points at a mirror.

The command line `php` can differ from the PHP your web server runs (PHP-FPM pools often use another version). If several are installed, pass the one that serves the site with `--php`. If no `php` is found, Tuner says so and skips the PHP check. Must-use plugins are listed but not matched: they're usually custom code.

**wp-config.php** is read as text, never run. Settings that come from `getenv()` or other code aren't judged, and when wp-config.php includes other files, findings about missing settings are marked "likely".

| ID | Severity | When |
|---|---|---|
| `local-wp-salts` | medium | keys and salts missing, left as the sample placeholder, empty, or duplicated. WordPress then falls back to salts stored in the database, so a database leak lets an attacker forge login cookies |
| `local-wp-debug` | medium | `WP_DEBUG` on and errors shown to visitors, or logged to the public `wp-content/debug.log` |
| | low | `WP_DEBUG` on, but errors hidden and logged elsewhere |
| `local-wp-file-edit` | low | `DISALLOW_FILE_EDIT` not true: an admin account takeover becomes code execution. Defense in depth, so low |
| `local-wp-config-perms` | low | wp-config.php readable by every user on the server |
| `local-wp-table-prefix` | info | the default `wp_` table prefix. Obscurity only, so no score penalty |
| `local-wp-force-ssl-admin` | info | `FORCE_SSL_ADMIN` not true. Most sites redirect to HTTPS at the server anyway |
| `local-laravel-debug` | medium | `APP_DEBUG=true` in a Laravel project's `.env` |

**Files that don't belong in a web root.** A local scan can't tell whether the server actually serves a file; the remote checks confirm that. So most are rated a level below their remote counterparts (an `.env` confirmed downloadable is critical; one sitting in the web root is high). PHP tools like phpinfo and Adminer keep their remote severity: in a web root they almost always run.

| ID | Severity | What |
|---|---|---|
| `local-dotenv` | high (medium without secrets) | `.env`, `.env.production`… (not `.env.example`) |
| `local-wp-config-backup` | high | `wp-config.php.bak`, `.old`, `.save`, `~`, `.swp`… served as plain text |
| `local-sql-dump` | high | `*.sql`, `*.sql.gz` and other dumps, SQLite files |
| `local-backup-archive` | high | backup-looking archives, `.wpress`, any archive at the top level |
| `local-composer-auth` | high | Composer `auth.json` with tokens |
| `local-private-key` | high | private keys (`*.pem`, `*.key`, `id_rsa`) |
| `local-vcs-dir` | medium | `.git`, `.svn`, `.hg` |
| `local-php-backup` | medium | backup copies of PHP files, e.g. `functions.php~` |
| `local-log-file` | medium | `debug.log`, `error_log` |
| `local-phpinfo` | medium | a PHP file that calls `phpinfo()` |
| `local-db-admin` | medium | Adminer or phpMyAdmin |

Secrets found in these files are shown masked, as everywhere else. For a Laravel project (an `artisan` file and a `public/` folder), only `public/` is the web root, so the project's own `.env` and `.git` aren't reported.

**Session upload progress (CVE-2026-115560).** This unpatched PHP flaw is only reachable when all four hold: `session.serialize_handler` is `php_binary` or `php_serialize`; the application switches it to `php` with `ini_set()`; it does so before `session_start()`; and `session.upload_progress.enabled` is on (the default). A local scan checks each one and shows ✓, ✗ or ? with the file or setting behind it:

- **Settings** come from what `php` itself reports and, because the CLI's settings often differ from the web server's, from the web server's own ini files and PHP-FPM pools (Debian/Ubuntu `/etc/php/<v>/{fpm,apache2,cgi}`, `/etc/php-fpm.d`, Alpine `/etc/php*/php-fpm.d`, the official Docker images' `/usr/local/etc/php-fpm.d`) and `.user.ini`/`.htaccess` overrides in the site. When the web server's settings are found, the CLI's don't count.
- **Code** is every PHP file in the site, `vendor/` included (libraries manage sessions too). Comments and text inside strings are ignored.

| Result | Severity |
|---|---|
| all four conditions confirmed | high |
| configuration unsafe, but the order of calls couldn't be confirmed from one file | high, *likely* |
| the code switches the handler but PHP's configuration couldn't be read | medium, *likely* |
| the code switches the handler, but the configured handler is `php` | low |
| upload progress is off everywhere checked | info: mitigated |

Sites whose code never switches the handler get no finding: PHP says they aren't affected. The fix, until PHP releases one, is `session.upload_progress.enabled = 0` in php.ini or the FPM pool (`php_admin_flag[session.upload_progress.enabled] = off`).

From outside, Tuner can only see the two settings, and only when a `phpinfo()` page is exposed: `php-session-upload-progress` reports that, at low confidence, alongside `php-phpinfo`.

**What it reads.** Tuner never changes the scanned files and never runs the site's code. The version query runs `php -n`, so no php.ini (and no `auto_prepend_file`) is loaded; the session-settings query loads php.ini, to see the real values, with `auto_prepend_file` and `auto_append_file` forced empty. The stray-file walk skips `node_modules`, `vendor`, `wp-content/cache` and the media folders in `wp-content/uploads/<year>`; it doesn't follow symlinks, reads at most 1 MB of any file, and stops after 250,000 entries. Request flags (`--rate`, `-H`, `--proxy` for the site…) don't apply, and the HTTP checks don't run; select local findings with `--id 'local-*'` or `--tags local`.

## Updating Tuner

`rhythm update` updates rhythm, every installed tool, and their data, including the check pack. Each download is checked against the release's `checksums.txt` before anything is replaced. `rhythm update --check` only reports.

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
