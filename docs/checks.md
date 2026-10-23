# Writing checks

A check is one YAML file in `checks/<category>/`. Adding a check takes no Go code.

```yaml
id: leak-dotenv                 # unique, kebab-case
name: .env file exposed
severity: critical              # critical | high | medium | low | info
confidence: high                # optional, defaults to high
profile: quick                  # quick | default | deep: the cheapest profile that runs it
tags: [leak, secrets]
requires: [wordpress]           # optional: only run when the fingerprint finds this
request:
  method: GET                   # optional, defaults to GET
  path: ["/.env", "/{{host}}.zip"]   # {{host}} expands to the target hostname
match:
  all:                          # every matcher must hold
    - status: 200               # an int or a list
    - regex: '(?m)^[A-Z_]+=.+'
    - not_baseline: true        # must differ from the server's soft-404 reply
  any:                          # optional: at least one must hold
    - magic: "504b0304"
extract:
  secrets: true                 # report masked secrets found in the body
impact: Anyone can read database passwords.
fix: |
  First line is shown in the terminal; the rest is in JSON and Markdown output.
references:
  - https://example.com/advisory
```

## Matchers

Each list item is one matcher, and every field set on it must hold.

| Field | Holds when |
|---|---|
| `status` | the status code is one of the given values |
| `regex` / `not_regex` | the body matches / doesn't match ([RE2 syntax](https://github.com/google/re2/wiki/Syntax)) |
| `words` | the body contains any of the strings |
| `magic` | the body starts with these bytes (hex) |
| `header` / `not_header` | `{Name: regex}` matches / doesn't match a header value |
| `missing_header` | none of the listed headers are present |
| `scheme` | the final URL is `http` or `https` |
| `cookie` | `{name: regex, missing_flag: secure\|httponly\|samesite}`: a cookie lacks the flag (values are never printed) |
| `tls` | `{expired, expires_within_days: N, untrusted, legacy}`: certificate and protocol state, for `/` on https |
| `not_baseline` | the response differs from a random path of the same shape |

Check requests never follow redirects. The home page (`/`) is fetched once, following redirects, and shared by every check that requests `/`.

Use `not_baseline` on any check for a file path. Many servers answer `200` for every URL, and the baseline stops that from becoming a finding.

## Fixtures

Every check needs `<name>_test.yaml` next to it, with at least one positive and one negative case. `go test ./engine` serves each case from a mock server and runs the check against it.

```yaml
positive:
  - name: env readable
    expect_secrets: true        # assert masked secrets are extracted
    routes:
      /.env: {body: "DB_PASSWORD=hunter22\n"}
negative:
  - name: blocked
    routes:
      /.env: {status: 403}
  - name: soft-404 catch-all
    default: {status: 200, body: "<html>{{path}} not found</html>"}
```

A route takes `status` (default 200), `headers`, and `body` or `body_hex`. Paths without a route return 404, or `default` if it's set; `{{path}}` in a default body echoes the requested path. Set `tls: true` to serve over HTTPS, `tls_min: "1.0"` to accept obsolete TLS, or
`cert: {expires_in_days: N, untrusted: true}` for a custom certificate (negative days for expired).

Good negatives cover the ways a check could misfire: the file blocked, a soft-404 catch-all, a similar-looking page.

## Profiles

`quick` is for the highest-value checks that cost few requests; `rhythm tuner scan --profile quick`
should stay around 30 requests. Most checks belong in `default`. `deep` is for aggressive
enumeration that sends many requests.

## Rules

- Detect, never exploit. Requests are plain GETs of public URLs with no payloads.
- Never print a secret unmasked. Use `extract.secrets`; evidence is redacted automatically.
- Try a check locally with `rhythm tuner scan <url> --checks ./checks`.
