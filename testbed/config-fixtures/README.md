# Server-config fixtures

Bundles for `testbed/validate-config-test.sh`, which proves that
`testbed/validate-config.sh` passes a good bundle and fails a broken one.

- `good.nginx.conf`, `good.htaccess`: valid hardening snippets.
- `broken.nginx.conf`: an unknown nginx directive (`nginx -t` fails).
- `broken.htaccess`: an unknown Apache directive (the syntax check fails).
- `htaccess-only.htaccess`: `AllowOverride` is fine in a `<Directory>`
  block but not in a `.htaccess`, so only the live request (a 500) catches
  it.
