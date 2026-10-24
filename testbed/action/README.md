# Action fixtures

Fixtures for `.github/workflows/action-test.yml`, which runs the Tuner
Action against them on Linux, macOS and Windows.

- `site/` is served by `python3 -m http.server` on 127.0.0.1. Its `.env`
  is a fake leak that Tuner reports as high or worse, so `fail-on: high`
  must fail the step.
- `header_log.py` serves `site/` again and logs every request header, so
  the workflow can check that the `headers` and `cookie` inputs reach the
  site whole.
- `wordpress/` is a site folder for a local scan: default salts and
  `WP_DEBUG` on, which Tuner reports below high.

Nothing here is a real secret.
