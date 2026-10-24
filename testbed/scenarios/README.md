# Scenario suite

Hermetic end-to-end scenarios for the real-world failure modes in the
October 2026 QA review ("Test coverage gaps", items 1 to 19). Each folder
holds an `expect.yaml`. The Go tests here build `rhythm-tuner` from this
checkout, start loopback fixture servers and fixture trees, run the
binary and check what happened.

```sh
make testbed-fast                     # just this suite
go test -run 'TestScenarios/06-' -v ./testbed/scenarios/   # one group, with logs
```

`go test ./...` runs it too (CI does, on Linux, macOS and Windows, which
covers QA gap 14). `-short` skips it.

## Hermetic by construction

- Fixture servers listen only on 127.0.0.1 or [::1], on ports
  20240 to 20259 (`TUNER_SCENARIO_PORTS=30000-30019` to move them).
- Every run gets its own home, cache and config folders. On Unix it
  also gets an empty `PATH` (no php from the machine).
- Every data service (`TUNER_VULN_API`, `TUNER_WPORG_API`,
  `TUNER_PHPNET_API`, `TUNER_OSV_API`, `TUNER_CHECKS_URL`,
  `RHYTHM_GITHUB_API`) points at a fake on loopback. So do
  `HTTP_PROXY` and `HTTPS_PROXY`. Go never proxies loopback, so any
  request for another host lands on the fake and fails the scenario with
  "tried to leave the machine".
- `TUNER_SCENARIO_BIN=/path/to/rhythm-tuner` tests a release build
  instead of building one.

## expect.yaml

```yaml
title: a cross-host redirect does not move the scan
qa: [1]          # QA gap numbers
xfail: E1        # roadmap items whose fix this waits for (optional)
xfail_covers: ['exit 0, want 3']   # problems the xfail is about (optional)
skip_on: [windows]
servers:
  - name: site
    listen: 127.0.0.1        # or ::1
    tls: ""                  # or self-signed, h2-only
    routes:                  # path, /prefix/*, or * for the rest
      /: {body: "<html>...</html>", headers: {X-A: b}}
      /.env: {type: text/plain, file: env.txt}
      /slow: {delay: 300ms}
      /big: {body: "x", repeat: 2000000}
      /dead: {hang: true}
      /cut: {reset: true, body: "half of this arrives"}
data:
  state: v1      # v1, v2 (adds a critical KEV advisory), down, hang, slow, html
tree:            # build the work folder
  - copy: ../_fixtures/wordpress
    to: site
  - write: site/.env
    content: "A=b\n"
  - mkfifo: site/auth.json          # also: socket, symlink + target, mkdir,
  - chmod: site/private              # remove, chmod + mode
    mode: "000"
steps:
  - name: optional label
    data_state: v2                   # switch the fake data services first
    tree: [...]                      # change the work folder first
    args: [scan, "{{url:site}}", --no-vulns, --rate, "0", -o, report.json]
    env: {TUNER_CHECKS_URL: "{{url:other}}"}
    signals: [{after: 2s, signal: INT}]   # INT, TERM or KILL
    timeout: 60s                     # kill the run (fails the step)
    expect:
      exit: 3                        # or a list; -1 is killed by a signal
      max_time: 5s
      stdout: {contains: [], not_contains: [], matches: [], not_matches: []}
      stderr: {...}
      output: {...}                  # stdout and stderr together
      files:
        report.json:
          exists: true
          min_size: 10
          contains: [...]            # and the other text checks
          json: {target: "{{url:site}}", findings.#: 0, complete: false}
          finding_ids: [leak-dotenv]
          no_finding_ids: [...]
      requests:                      # what each server saw in this step
        site: {min: 1, max: 70, paths: [/], not_paths: [/.env],
               path_max: {/: 1}, hosts: ["{{host:site}}"],
               no_headers: [Authorization], protos: [HTTP/2.0]}
        data: {max: 0}               # the fake data services
```

Placeholders work in arguments, env, bodies, headers, tree paths,
contents and expectations: `{{url:name}}`, `{{host:name}}` (host:port),
`{{port:name}}`, `{{work}}` (the run's folder), `{{home}}`, `{{cache}}`
(rhythm-tuner's cache folder on this OS) and `{{x:N}}` (N x's, for long
lines). YAML escapes such as `"\e"` give control bytes.

Shared fixture trees live in `_fixtures/`. Nothing in them is a real
secret.

## xfail

A scenario whose fix is still on an unmerged lane carries
`xfail: <item ids>`. While it fails, the test is skipped and the summary
says `xfail`. When it starts passing it is reported as `XPASS`: remove the
`xfail` line in the same change that merges the fix. Set
`TUNER_SCENARIO_SUMMARY` to a file (CI uses `$GITHUB_STEP_SUMMARY`) for a
table of every scenario and why each xfail still fails.

`xfail_covers` narrows an xfail to the problems it is about: a list of Go
regular expressions matched against each problem line the harness
prints. Any other problem fails the scenario even while the xfail stands,
so a part that already works can't regress unseen. Without it the xfail
covers every problem.

| Scenario | QA gap | Waits for |
|---|---|---|
| 01-redirect-cross-host | 1 | E1 |
| 02-waf-cloudflare, 02-waf-sucuri, 02-waf-wordfence | 2 | E7 |
| 03-soft404-near-size | 3 | E8 |
| 04-dotenv-unlisted-keys | 4 | C2 |
| 05-control-chars-body, 05-control-chars-filename | 5 | E3, R1 |
| 06-fifo | 6 | L2 |
| 06-unreadable-dir | 6 | L4 |
| 07-cache-null, 07-cache-foreign, 07-cache-old-format | 7 | V1 |
| 08-baseline-new-advisory | 8 | R2 |
| 09-data-hang | 9 | V4, U4 |
| 09-data-down, 09-data-html | 9 | U4 |
| 10-pack-host-hang | 10 | C4 |
| 11-interrupted, 11-max-time | 11, 15 | U4, R3 |
| 11-killed | 11 | U2 |
| 12-target-list | 12 | U3 |
| 13-bare-target-folder | 13 | U1 |
| 15-timeout-message | 15 | U3, E11 |
| 19-same-site-twice | 19 | U3 |

Passing today: 00-sanity, 01-redirect-bad-cert, 03-soft404-huge-catchall,
06-special-files, 09-data-slow, 16-ipv6, 16-idn, 17-http2-only,
17-connection-reset and 18-wordpress-subfolder. QA gap 14 (Windows and
macOS) is the CI test matrix running this suite on all three systems.
