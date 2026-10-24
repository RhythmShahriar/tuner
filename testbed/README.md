# Tuner testbed

A deliberately broken WordPress site for proving what Tuner finds, plus a
reproducible benchmark against WPScan, wpprobe and Nuclei. Everything is
self-contained and thrown away on `make testbed-down`. Nothing here is a
real secret and no plugin holds a working exploit.

## Layout

- `docker-compose.yml`  WordPress (php-fpm) behind nginx and Apache, a
  subfolder install and a WAF-challenge front. Images are pinned by tag
  and digest.
- `ground-truth.yaml`   what is really installed and really exposed. The
  benchmark scores every tool against this. Change the testbed and change
  this in the same commit.
- `wp/make-plugins.sh`  builds the 30 stub plugins from the manifest, so
  they don't live in the repo.
- `wp/init.sh`          run by the one-shot `seed` service (WP-CLI): installs
  WordPress, copies in the stub plugins and activates the active ones,
  seeds the exposed files, a modified core file and an uploads webshell
  marker, then copies the tree to `wp/site` for local scans.
- `nginx/`, `apache/`   the two front ends, both deliberately open.
- `validate-config.sh`  checks `rhythm-tuner fix` bundles with nginx and
  Apache (`make testbed-config`); `validate-config-test.sh` proves it
  fails on the broken bundles in `config-fixtures/`
  (`make testbed-config-test`). Ports: 20256 for the live Apache check.
- `bench/`              the benchmark (build tag `testbed`). It builds
  Tuner, runs each tool once per site and writes `docs/benchmark.md`.

## Running it

```sh
make testbed        # make-plugins.sh, then docker compose up (needs Docker)
rhythm-tuner scan testbed/wp/site --integrity   # the local ground truth
make benchmark      # go run -tags testbed ./testbed/bench -> docs/benchmark.md
make testbed-down   # docker compose down -v
```

The benchmark needs `wpprobe` and `nuclei` on PATH and Docker for the
WPScan image; a tool that is missing is marked "error" in the table, not
a failure. PRs do not run the benchmark (they run the scenario suite in
`scenarios/`); a nightly workflow does and publishes the table.

## Ports

Loopback only, 20280 to 20283: main (nginx), Apache, blog (nginx :81) and
the WAF front. Override with `TESTBED_MAIN_PORT` and friends.

## Scoring, without Docker

`go test -tags testbed ./testbed/bench/` checks the manifest loader, the
scoring and the scoreboard against synthetic tool output. It needs no
Docker and no network, so CI runs it on every change to the harness.
