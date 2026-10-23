# Usage

```sh
rhythm tuner                         # interactive picker
rhythm tuner scan example.com        # scan a site
rhythm tuner checks                  # list checks
```

`rhythm tuner scan --help` lists every flag. This page explains them.

## What a scan does

1. **Fingerprint.** Fetches the home page, following redirects, and detects WordPress (with version), Laravel, PHP, the server, and the plugins and themes it loads. Plugin versions come from `readme.txt` and theme versions from `style.css`.
2. **TLS.** For https sites, reads the certificate's expiry and trust and tests whether TLS 1.0/1.1 are still accepted.
3. **Baseline.** Requests random paths to learn how the server answers "not found", so sites that return 200 for everything don't produce false findings.
4. **Checks.** Runs each check's requests, without following redirects, and streams findings as they're found.

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
| `--proxy` | `$HTTPS_PROXY` | `http://`, `https://` or `socks5://` |
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

Each scan gets a score out of 100. Every distinct failing check subtracts points by its worst severity: critical 30, high 15, medium 6, low 2, info 0. A check that fires on several paths counts once.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done (or findings below `--fail-on`) |
| 1 | a finding at or above `--fail-on` |
| 2 | usage error |
| 3 | a site couldn't be scanned (other sites' reports are still written) |
| 130 | interrupted; partial results are written |
