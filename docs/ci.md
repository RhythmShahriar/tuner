# CI

## GitHub code scanning

Findings show up in the repository's **Security** tab:

```yaml
name: tuner
on:
  schedule: [{cron: "0 6 * * 1"}]   # weekly
  workflow_dispatch:
permissions:
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL rythm.sh/install | sh && rhythm install tuner
      - run: rhythm tuner scan https://staging.example.com --sarif -o tuner.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tuner.sarif
```

## Failing a build

```sh
rhythm tuner scan https://staging.example.com --fail-on high
```

The scan exits 1 if any finding is high or critical. Exit 3 means the site couldn't be reached.

## Accepting known findings

Save a report once, then pass it as a baseline. Only new findings are reported and counted for `--fail-on`:

```sh
rhythm tuner scan example.com -o tuner-baseline.json
rhythm tuner scan example.com --baseline tuner-baseline.json --fail-on medium
```

Findings are matched by check ID and URL. Commit the baseline so reviews show what was accepted.
