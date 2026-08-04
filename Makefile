GO ?= go
TEST_TIMEOUT ?= 90m
RELEASE_VERSION := v0.1.2
UNIT_PACKAGES := $(shell $(GO) list ./... | grep -v '/internal/architecture$$')

.PHONY: test test-prepare test-unit test-int test-release test-e2e test-kimi

test:
	@$(MAKE) test-prepare
	@$(MAKE) test-unit
	@$(MAKE) test-int
	@$(MAKE) test-release
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

test-release:
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-release requires darwin/arm64" >&2; exit 1; }
	@release_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$release_tmp"' EXIT; \
	release_gobin="$$release_tmp/bin"; \
	mkdir -p "$$release_gobin"; \
	release_commit="$$(git rev-parse HEAD)"; \
	GOBIN="$$release_gobin" $(GO) install -trimpath \
		-ldflags "-X main.buildVersion=$(RELEASE_VERSION) -X main.buildRevision=$$release_commit" .; \
	MULGAE_RELEASE_BINARY="$$release_gobin/mulgae" \
		MULGAE_RELEASE_GOBIN="$$release_gobin" \
		MULGAE_RELEASE_VERSION="$(RELEASE_VERSION)" \
		MULGAE_RELEASE_REVISION="$$release_commit" \
		$(GO) test -tags=releasecheck -count=1 ./internal/releasecheck
	@printf '%s\n' '[test-release] completed'

test-e2e:
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-e2e requires darwin/arm64" >&2; exit 1; }
	@e2e_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$e2e_tmp"' EXIT; \
	e2e_base="$${TMPDIR:-/tmp}"; \
	e2e_project="$$(mktemp -d "$${e2e_base%/}/mulgae-e2e-project.XXXXXX")"; \
	chmod 700 "$$e2e_project"; \
	MULGAE_E2E_BINARY="$$e2e_tmp/mulgae"; \
	MULGAE_E2E_COMMIT="$$(git rev-parse HEAD)"; \
	$(GO) build -trimpath -ldflags "-X main.buildVersion=$(RELEASE_VERSION) -X main.buildRevision=$$MULGAE_E2E_COMMIT" -o "$$MULGAE_E2E_BINARY" .; \
	zcode_node="$${MULGAE_E2E_ZCODE_NODE_EXECUTABLE:-$$(command -v node)}"; \
	test -n "$$zcode_node" && test -x "$$zcode_node" || { echo "test-e2e requires the ZCode Node executable" >&2; exit 1; }; \
	case "$$zcode_node" in /*) ;; *) echo "test-e2e requires an absolute ZCode Node executable" >&2; exit 1;; esac; \
	zcode_launcher="$${MULGAE_E2E_ZCODE_LAUNCHER:-/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs}"; \
	test -f "$$zcode_launcher" && test -r "$$zcode_launcher" || { echo "test-e2e requires the ZCode launcher" >&2; exit 1; }; \
	case "$$zcode_launcher" in /*) ;; *) echo "test-e2e requires an absolute ZCode launcher" >&2; exit 1;; esac; \
	agy_bin="$${MULGAE_E2E_AGY_EXECUTABLE:-$$(command -v agy)}"; \
	test -n "$$agy_bin" && test -x "$$agy_bin" || { echo "test-e2e requires the AGY executable" >&2; exit 1; }; \
	case "$$agy_bin" in /*) ;; *) echo "test-e2e requires an absolute AGY executable" >&2; exit 1;; esac; \
	if MULGAE_E2E_BINARY="$$MULGAE_E2E_BINARY" MULGAE_E2E_PROJECT_ROOT="$$e2e_project" \
		MULGAE_E2E_ZCODE_NODE_EXECUTABLE="$$zcode_node" MULGAE_E2E_ZCODE_LAUNCHER="$$zcode_launcher" \
		MULGAE_E2E_AGY_EXECUTABLE="$$agy_bin" $(GO) test -v -tags=live_e2e -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^Test(E2E|Live)' .; then \
		:; \
	else \
		status=$$?; \
		printf '%s\n' "[test-e2e] failed; preserved private project: $$e2e_project" >&2; \
		exit $$status; \
	fi; \
	MULGAE_LIVE_ZCODE_NODE_BIN="$$zcode_node" MULGAE_LIVE_ZCODE_LAUNCHER="$$zcode_launcher" \
	MULGAE_LIVE_AGY_BIN="$$agy_bin" $(GO) test -v -tags=liveprovider -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^TestLive(ZCode|Agy)Capability$$' ./internal/adapters/providercli || { \
		status=$$?; \
		printf '%s\n' "[test-e2e] failed; preserved private project: $$e2e_project" >&2; \
		exit $$status; \
	}; \
	rm -rf "$$e2e_project"
	@printf '%s\n' '[test-e2e] completed'

test-kimi:
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-kimi requires darwin/arm64" >&2; exit 1; }
	@kimi_bin="$${MULGAE_LIVE_KIMI_BIN:-$$(command -v kimi)}"; \
	test -n "$$kimi_bin" && test -x "$$kimi_bin" || { echo "test-kimi requires the Kimi executable" >&2; exit 1; }; \
	case "$$kimi_bin" in /*) ;; *) echo "test-kimi requires an absolute Kimi executable" >&2; exit 1;; esac; \
	kimi_data_home="$${MULGAE_LIVE_KIMI_DATA_HOME:-$${HOME}/.kimi-code}"; \
	test -d "$$kimi_data_home" || { echo "test-kimi requires the Kimi data home" >&2; exit 1; }; \
	MULGAE_LIVE_KIMI_BIN="$$kimi_bin" MULGAE_LIVE_KIMI_DATA_HOME="$$kimi_data_home" \
		$(GO) test -v -tags=liveprovider -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^TestLiveKimiCapability$$' ./internal/adapters/providercli
	@printf '%s\n' '[test-kimi] completed'
