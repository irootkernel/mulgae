GO ?= go
TEST_TIMEOUT ?= 90m
UNIT_PACKAGES := $(shell $(GO) list ./... | grep -v '/internal/architecture$$')

.PHONY: test test-prepare test-unit test-int test-e2e

test:
	@$(MAKE) test-prepare
	@$(MAKE) test-unit
	@$(MAKE) test-int
	@$(MAKE) test-e2e
	@printf '%s\n' '[test] completed'

test-prepare:
	$(GO) generate ./internal/app/init
	$(GO) generate ./internal/builtin
	@unformatted="$$(find . -type f -name '*.go' -not -path './vendor/*' -exec gofmt -l {} +)"; \
		test -z "$$unformatted" || { printf '%s\n' "$$unformatted" >&2; exit 1; }
	$(GO) mod verify
	$(GO) tool golangci-lint run ./...
	$(GO) vet ./...
	$(GO) test -race -count=1 ./internal/architecture
	@printf '%s\n' '[test-prepare] completed'

test-unit:
	$(GO) test -timeout $(TEST_TIMEOUT) -race -count=1 -skip '^TestIntegration' $(UNIT_PACKAGES)
	@printf '%s\n' '[test-unit] completed'

test-int:
	$(GO) test -timeout $(TEST_TIMEOUT) -race -count=1 -run '^TestIntegration' ./...
	@printf '%s\n' '[test-int] completed'

test-e2e:
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-e2e requires darwin/arm64" >&2; exit 1; }
	@e2e_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$e2e_tmp"' EXIT; \
	e2e_base="$${TMPDIR:-/tmp}"; \
	e2e_project="$$(mktemp -d "$${e2e_base%/}/kar-e2e-project.XXXXXX")"; \
	chmod 700 "$$e2e_project"; \
	KAR_E2E_BINARY="$$e2e_tmp/kar"; \
	KAR_E2E_COMMIT="$$(git rev-parse HEAD)"; \
	$(GO) build -trimpath -ldflags "-X main.buildProduct=kar -X main.buildVersion=v1.11.0 -X main.buildCommit=$$KAR_E2E_COMMIT" -o "$$KAR_E2E_BINARY" ./cmd/kar; \
	if KAR_E2E_BINARY="$$KAR_E2E_BINARY" KAR_E2E_PROJECT_ROOT="$$e2e_project" KAR_REQUIRE_ARTIST_E2E=1 PLAYWRIGHT_CHANNEL="$${PLAYWRIGHT_CHANNEL:-chrome}" $(GO) test -v -tags=live_e2e -timeout $(TEST_TIMEOUT) -count=1 -run '^Test(E2E|Live)' ./cmd/kar; then \
		rm -rf "$$e2e_project"; \
	else \
		status=$$?; \
		printf '%s\n' "[test-e2e] failed; preserved private project: $$e2e_project" >&2; \
		exit $$status; \
	fi
	@printf '%s\n' '[test-e2e] completed'
