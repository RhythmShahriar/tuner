# Tuner

Find what's out of tune in your WordPress & PHP sites, before attackers do.

```sh
curl -fsSL rythm.sh/install | sh
rhythm install tuner
rhythm tuner scan example.com
```

- **Leaks first:** `.env`, `.git`, wp-config backups, SQL dumps, archives, logs and phpinfo, with secrets masked
- **WordPress, Laravel and PHP:** user enumeration, XML-RPC, admin-ajax, debug logs, Ignition, display_errors, plus plugin and theme detection with versions
- **Server and TLS:** security headers, cookie flags, version leaks, certificate expiry and trust, obsolete TLS
- **Low false positives:** soft-404 baselining on every file check
- **Polite:** rate limited, backs off on 429/503, plain GETs only
- **CI-ready:** JSON, JSONL, SARIF, Markdown, `--fail-on`, baselines, batch scans

Scan only sites you own or are authorised to test.

## Docs

- [Usage](docs/usage.md): every flag, profiles, exit codes
- [CI](docs/ci.md): GitHub code scanning, `--fail-on`, baselines
- [Writing checks](docs/checks.md): the YAML format and fixtures
- [Product plan](docs/PRD.md)

## Development

```sh
make hooks   # Conventional Commits check
make check   # lint + tests (every check runs against its fixtures)
```
