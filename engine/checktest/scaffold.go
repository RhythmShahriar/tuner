// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checktest

import (
	"errors"
	"strings"
)

// Scaffold returns a new check with the given ID and its fixture file,
// ready to edit. Both pass Lint and Run as they are, so a contributor
// starts from green and changes one thing at a time.
func Scaffold(id string) (check, fixture []byte, err error) {
	if msg := lintID(id); msg != "" {
		return nil, nil, errors.New(msg)
	}
	prefix, rest, _ := strings.Cut(id, "-")
	file := rest + ".txt"
	r := strings.NewReplacer("{{id}}", id, "{{tag}}", Prefixes[prefix], "{{file}}", file)
	return []byte(r.Replace(checkTemplate)), []byte(r.Replace(fixtureTemplate)), nil
}

// The template asks for the parts a reviewer looks at first: a matcher
// only the real file satisfies and not_baseline, so a site that answers
// every URL with the same page stays quiet.
const checkTemplate = `# A check sends GET requests to the paths below and reports a finding
# when a reply matches. Format:
# https://github.com/RhythmShahriar/rhythm/wiki/Tuner-Writing-Checks
id: {{id}}
name: TODO what is exposed, e.g. Backup file exposed
severity: medium # critical, high, medium, low or info
profile: default # quick only for the most valuable checks
tags: [{{tag}}]
request:
  path: ["/{{file}}"]
match:
  all:
    - status: 200
    # Replace with text only the real file contains.
    - words: ["TODO-text-only-the-real-file-has"]
    - not_baseline: true
impact: TODO what someone gains from it.
fix: TODO how to fix it.
fix_server:
  nginx: |
    location = /{{file}} { deny all; }
  apache: |
    <Files "{{file}}">
      Require all denied
    </Files>
references:
  - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
`

// fixtureTemplate is the fixture file new writes next to a scaffolded check.
const fixtureTemplate = `# Mock sites for {{id}}: it must fire on every positive case and stay
# quiet on every negative one. Run them with: rhythm tuner checks test
positive:
  - name: file served
    routes:
      /{{file}}: {body: "TODO-text-only-the-real-file-has"}
negative:
  - name: blocked
    routes:
      /{{file}}: {status: 403, body: Forbidden}
  - name: soft-404 catch-all
    default: {status: 200, body: "<html><title>Not found</title><p>{{path}} does not exist</p></html>"}
  - name: catch-all that serves the same text for every path
    default: {status: 200, body: "TODO-text-only-the-real-file-has"}
`
