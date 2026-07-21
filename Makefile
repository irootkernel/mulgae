GO ?= go
TEST_TIMEOUT ?= 10m
UNIT_PACKAGES := $(shell $(GO) list ./... | grep -v '/internal/architecture$$')

.PHONY: test test-prepare test-unit test-int test-e2e test-race

test:
	@$(MAKE) test-prepare
	@$(MAKE) test-unit
	@$(MAKE) test-int
	@$(MAKE) test-e2e
	@$(MAKE) test-race
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
	$(GO) test -timeout $(TEST_TIMEOUT) -skip '^Test(Integration|E2E)' $(UNIT_PACKAGES)
	@printf '%s\n' '[test-unit] completed'

test-int:
	$(GO) test -timeout $(TEST_TIMEOUT) -race -count=1 -run '^TestIntegration' ./...
	@printf '%s\n' '[test-int] completed'

test-e2e:
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-e2e requires darwin/arm64" >&2; exit 1; }
	@e2e_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$e2e_tmp"' EXIT; \
	KAR_E2E_BINARY="$$e2e_tmp/kar"; \
	$(GO) build -trimpath -ldflags '-X main.buildProduct=kar -X main.buildVersion=v1.4.2 -X main.buildCommit=0123456789abcdef0123456789abcdef01234567' -o "$$KAR_E2E_BINARY" ./cmd/kar; \
	KAR_E2E_BINARY="$$KAR_E2E_BINARY" $(GO) test -timeout $(TEST_TIMEOUT) -count=1 -run '^TestE2E' ./...
	@printf '%s\n' '[test-e2e] completed'

test-race:
	$(GO) test -timeout $(TEST_TIMEOUT) -race -count=1 ./...
	@printf '%s\n' '[test-race] completed'
