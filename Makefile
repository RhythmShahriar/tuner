GOLANGCI := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

.PHONY: build test lint fmt check hooks

build: ## build bin/rhythm-tuner
	go build -o bin/rhythm-tuner ./cmd/rhythm-tuner

test: ## run tests, including every check's fixtures
	go test -race ./...

lint:
	$(GOLANGCI) run ./...

fmt:
	gofmt -w .

check: lint test ## everything CI runs

hooks: ## enable the Conventional Commits hook
	git config core.hooksPath .githooks
