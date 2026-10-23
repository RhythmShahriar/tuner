# Tuner

Find what's out of tune in your WordPress & PHP sites, before attackers do.

```sh
curl -fsSL rythm.sh/install | sh
rhythm install tuner
rhythm tuner scan example.com
```

- **Leaks first:** `.env`, `.git`, wp-config backups, SQL dumps, archives, logs and phpinfo, with secrets masked
- **WordPress, Laravel and PHP:** user enumeration, XML-RPC, admin-ajax, debug logs, Ignition, display_errors, plus plugin and theme detection with versions
- **Known vulnerabilities:** core, plugin, theme, PHP, nginx and Apache versions matched against CVE, Wordfence, WPScan and Patchstack advisories, with fixed versions and CISA known-exploited flags; plus outdated, closed and abandoned plugins
- **Always current:** vulnerability data refreshes itself daily and works offline from cache; `rhythm update` updates the binaries, checksum-verified
- **Server and TLS:** security headers, cookie flags, version leaks, certificate expiry and trust, obsolete TLS
- **Low false positives:** soft-404 baselining on every file check
- **Polite:** rate limited, backs off on 429/503, plain GETs only
- **CI-ready:** JSON, JSONL, SARIF, Markdown, `--fail-on`, baselines, batch scans

Vulnerability data: [WPVulnerability](https://www.wpvulnerability.com/) (CC0).

Scan only sites you own or are authorised to test.

## Docs

- [Usage](docs/usage.md): every flag, profiles, exit codes
- [CI](docs/ci.md): GitHub code scanning, `--fail-on`, baselines
- [Writing checks](docs/checks.md): the YAML format and fixtures

## Development

```sh
make hooks   # Conventional Commits check
make check   # lint + tests (every check runs against its fixtures)
```

## License

The scanner is [AGPL-3.0](LICENSE); the checks in [`checks/`](checks) are [MIT](checks/LICENSE), so anyone can reuse them.
Copyright 2026 Rhythm Shahriar.
