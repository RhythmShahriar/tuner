GOLANGCI := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
ACTIONLINT := go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
GORELEASER := go run github.com/goreleaser/goreleaser/v2@v2.18.3

# Files whose uses: lines must name a full commit SHA with a version
# comment, e.g. uses: actions/checkout@<40 hex> # v7.0.1.
PIN_FILES ?= $(wildcard .github/workflows/*.yml .github/workflows/*.yaml action.yml)
# Lines allowed to stay unpinned, each for a reason:
#   release-go.yml@master  the release signature's identity names this ref
#                          (see release.yml); changing it is a separate decision
#   checks-pack.yml        maintained with the check pack; remove once pinned
PIN_EXEMPT := release-go\.yml@master$$|^\.github/workflows/checks-pack\.yml:

.PHONY: build test lint fmt check hooks pack pins actionlint release-check

build: ## build bin/rhythm-tuner
	go build -o bin/rhythm-tuner ./cmd/rhythm-tuner

test: ## run tests, including every check's fixtures
	go test -race ./...

lint:
	$(GOLANGCI) run ./...

fmt:
	gofmt -w .

check: lint test ## everything CI runs

pack: ## build the check pack into dist/checks-pack, byte for byte as CI publishes it
	go run ./internal/packbuild -commit "$$(git rev-parse HEAD)" -time "$$(git log -1 --format=%cI)"

hooks: ## enable the Conventional Commits hook
	git config core.hooksPath .githooks

pins: ## fail on any action or reusable workflow not pinned to a commit SHA
	@bad=$$(grep -HnE '^[[:space:]]*(-[[:space:]]+)?uses:' $(PIN_FILES) /dev/null | \
		grep -vE 'uses:[[:space:]]*(\./[^[:space:]]*|docker://[^[:space:]]+@sha256:[0-9a-f]{64}|[^[:space:]@]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*[^[:space:]].*)$$' | \
		grep -vE '$(PIN_EXEMPT)'); \
	if [ -n "$$bad" ]; then \
		printf '%s\n' "$$bad"; \
		echo "pin each of these to a full commit SHA with its version in a comment"; \
		exit 1; \
	fi; \
	echo "every uses: is pinned"

actionlint: ## lint the workflows (and their run: scripts when shellcheck is installed)
	$(ACTIONLINT)

release-check: ## validate .goreleaser.yaml with the pinned GoReleaser
	$(GORELEASER) check
