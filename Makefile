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
	$(GO) tool govulncheck ./...
	$(GO) tool golangci-lint run ./...
	$(GO) vet ./...
	$(GO) test -race -count=1 ./internal/architecture
	@printf '%s\n' '[test-prepare] completed'

test-unit:
	$(GO) test -p 1 -timeout $(TEST_TIMEOUT) -race -count=1 -skip '^TestIntegration' $(UNIT_PACKAGES)
	@printf '%s\n' '[test-unit] completed'

test-int:
	$(GO) test -p 1 -timeout $(TEST_TIMEOUT) -race -count=1 -run '^TestIntegration' ./...
	@printf '%s\n' '[test-int] completed'

test-e2e:
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-e2e requires darwin/arm64" >&2; exit 1; }
	@e2e_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$e2e_tmp"' EXIT; \
	KAR_E2E_BINARY="$$e2e_tmp/kar"; \
	KAR_E2E_COMMIT="$$(git rev-parse HEAD)"; \
	$(GO) build -trimpath -ldflags "-X main.buildProduct=kar -X main.buildVersion=v1.14.0 -X main.buildCommit=$$KAR_E2E_COMMIT" -o "$$KAR_E2E_BINARY" ./cmd/kar; \
	kimi_bin="$${KAR_E2E_KIMI_EXECUTABLE:-$$(command -v kimi)}"; \
	test -n "$$kimi_bin" && test -x "$$kimi_bin" || { echo "test-e2e requires the Kimi executable" >&2; exit 1; }; \
	case "$$kimi_bin" in /*) ;; *) echo "test-e2e requires an absolute Kimi executable" >&2; exit 1;; esac; \
	kimi_data_home="$${KAR_E2E_KIMI_DATA_HOME:-$${HOME}/.kimi-code}"; \
	test -d "$$kimi_data_home" || { echo "test-e2e requires the Kimi data home" >&2; exit 1; }; \
	zcode_node="$${KAR_E2E_ZCODE_NODE_EXECUTABLE:-$$(command -v node)}"; \
	test -n "$$zcode_node" && test -x "$$zcode_node" || { echo "test-e2e requires the ZCode Node executable" >&2; exit 1; }; \
	case "$$zcode_node" in /*) ;; *) echo "test-e2e requires an absolute ZCode Node executable" >&2; exit 1;; esac; \
	zcode_launcher="$${KAR_E2E_ZCODE_LAUNCHER:-/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs}"; \
	test -f "$$zcode_launcher" && test -r "$$zcode_launcher" || { echo "test-e2e requires the ZCode launcher" >&2; exit 1; }; \
	case "$$zcode_launcher" in /*) ;; *) echo "test-e2e requires an absolute ZCode launcher" >&2; exit 1;; esac; \
	agy_bin="$${KAR_E2E_AGY_EXECUTABLE:-$$(command -v agy)}"; \
	test -n "$$agy_bin" && test -x "$$agy_bin" || { echo "test-e2e requires the AGY executable" >&2; exit 1; }; \
	case "$$agy_bin" in /*) ;; *) echo "test-e2e requires an absolute AGY executable" >&2; exit 1;; esac; \
	KAR_LIVE_KIMI_BIN="$$kimi_bin" KAR_LIVE_KIMI_DATA_HOME="$$kimi_data_home" \
	KAR_LIVE_ZCODE_NODE_BIN="$$zcode_node" KAR_LIVE_ZCODE_LAUNCHER="$$zcode_launcher" \
	KAR_LIVE_AGY_BIN="$$agy_bin" $(GO) test -v -tags=liveprovider -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^TestLive(Kimi|ZCode|Agy)Capability$$' ./internal/adapters/providercli
	@printf '%s\n' '[test-e2e] completed'
