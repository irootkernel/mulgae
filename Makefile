GO ?= go
TEST_TIMEOUT ?= 90m
RELEASE_VERSION := v0.1.22
UNIT_PACKAGES := $(shell $(GO) list ./... | grep -v '/internal/architecture$$')

.PHONY: test test-prepare test-unit test-int test-release test-e2e test-e2e-opt-in test-grok test-mcp-clients

test:
	@$(MAKE) test-prepare
	@$(MAKE) test-unit
	@$(MAKE) test-int
	@$(MAKE) test-release
	@$(MAKE) test-e2e
	@$(MAKE) test-e2e-opt-in
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
	@release_base="$${TMPDIR:-/tmp}"; \
	release_base="$$(cd "$$release_base" && pwd -P)" || exit 1; \
	case "$$release_base" in /*) ;; *) exit 1;; esac; \
	test "$$release_base" != / || exit 1; \
	release_uid="$$(/usr/bin/id -u)" || exit 1; \
	release_base_identity="$$(/usr/bin/stat -f '%u:%Lp' "$$release_base")" || exit 1; \
	release_base_owner="$${release_base_identity%%:*}"; release_base_mode="$${release_base_identity#*:}"; \
	if test "$$release_base_owner" = "$$release_uid" && test "$$((0$$release_base_mode & 022))" = 0; then :; \
	elif test "$$release_base_owner" = 0 && test "$$((0$$release_base_mode & 01000))" != 0; then :; \
	else exit 1; fi; \
	release_tmp="$$(/usr/bin/mktemp -d "$${release_base%/}/mulgae-release.XXXXXX")" || exit 1; \
	release_tmp="$$(cd "$$release_tmp" && pwd -P)" || exit 1; \
	case "$$release_tmp" in "$$release_base"/mulgae-release.*) ;; *) exit 1;; esac; \
	test "$$(dirname "$$release_tmp")" = "$$release_base" || exit 1; \
	release_tmp_identity="$$(/usr/bin/stat -f '%d:%i:%u' "$$release_tmp")" || exit 1; \
	release_tmp_mode="$$(/usr/bin/stat -f '%Lp' "$$release_tmp")" || exit 1; \
	case "$$release_tmp_identity:$$release_tmp_mode" in *:"$$release_uid":700) ;; *) exit 1;; esac; \
	release_gobin="$$release_tmp/bin"; \
	release_fixture_binary="$$release_tmp/mulgae-isolated-release-fixture"; \
	release_fixture_home="$$release_fixture_binary.native-home"; \
	release_gobin_owned=0; release_fixture_binary_owned=0; release_fixture_home_owned=0; \
	release_tmp_matches() { test "$$(/usr/bin/stat -f '%d:%i:%u' "$$release_tmp" 2>/dev/null)" = "$$release_tmp_identity"; }; \
	cleanup_release_tmp() { \
		release_status=$$?; cleanup_status=0; \
		if release_tmp_matches; then \
			test "$$(/usr/bin/stat -f '%Lp' "$$release_tmp" 2>/dev/null)" = 700 || { cleanup_status=1; chmod 700 "$$release_tmp" 2>/dev/null || :; }; \
			test "$$release_fixture_binary_owned" = 0 || { release_tmp_matches && /bin/rm -f "$$release_fixture_binary"; } || cleanup_status=1; \
			test "$$release_fixture_home_owned" = 0 || { release_tmp_matches && /bin/rm -rf "$$release_fixture_home"; } || cleanup_status=1; \
			test "$$release_gobin_owned" = 0 || { release_tmp_matches && /bin/rm -rf "$$release_gobin"; } || cleanup_status=1; \
			release_tmp_matches && rmdir "$$release_tmp" 2>/dev/null || cleanup_status=1; \
		else cleanup_status=1; fi; \
		trap - EXIT; \
		test "$$release_status" = 0 || exit "$$release_status"; \
		exit "$$cleanup_status"; \
	}; \
	trap cleanup_release_tmp EXIT; \
	test ! -e "$$release_gobin" && mkdir -m 700 "$$release_gobin" && release_gobin_owned=1 && \
	test ! -e "$$release_fixture_home" && mkdir -m 700 "$$release_fixture_home" && release_fixture_home_owned=1 && \
	test ! -e "$$release_fixture_binary" && release_fixture_binary_owned=1 && \
	release_commit="$$(git rev-parse HEAD)" && \
	release_ldflags="-X 'main.buildVersion=$(RELEASE_VERSION)' -X 'main.buildRevision=$$release_commit'" && \
	GOBIN="$$release_gobin" $(GO) install -trimpath \
		-ldflags "$$release_ldflags" . && \
	MULGAE_RELEASE_BINARY="$$release_gobin/mulgae" \
		MULGAE_RELEASE_GOBIN="$$release_gobin" \
		MULGAE_RELEASE_VERSION="$(RELEASE_VERSION)" \
		MULGAE_RELEASE_REVISION="$$release_commit" \
		$(GO) test -tags=releasecheck -count=1 ./internal/releasecheck && \
	release_fixture_ldflags="$$release_ldflags -X 'github.com/irootkernel/mulgae/internal/adapters/environment.buildNativeHomeOverride=$$release_fixture_home'" && \
	$(GO) build -trimpath -ldflags "$$release_fixture_ldflags" -o "$$release_fixture_binary" . && \
	MULGAE_E2E_BINARY="$$release_fixture_binary" $(GO) test -count=1 \
		-run '^(TestIntegrationIsolatedReleaseFixtureComposesExactRecoveredReview|TestIntegrationIsolatedReleaseFixtureRecoversCancelledRunThroughExactReruns)$$' ./test/e2e
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
	zcode_app="$${MULGAE_E2E_ZCODE_APP_BUNDLE:-/Applications/ZCode.app}"; \
	test -d "$$zcode_app" || { echo "test-e2e requires the ZCode app bundle" >&2; exit 1; }; \
	case "$$zcode_app" in /*) ;; *) echo "test-e2e requires an absolute ZCode app bundle" >&2; exit 1;; esac; \
	zcode_executable="$$zcode_app/Contents/MacOS/ZCode"; \
	test -x "$$zcode_executable" || { echo "test-e2e requires the ZCode app runtime" >&2; exit 1; }; \
	zcode_launcher="$$zcode_app/Contents/Resources/glm/zcode.cjs"; \
	test -f "$$zcode_launcher" && test -r "$$zcode_launcher" || { echo "test-e2e requires the ZCode launcher" >&2; exit 1; }; \
	grok_candidate="$${MULGAE_E2E_GROK_EXECUTABLE:-$$(command -v grok)}"; \
	test -n "$$grok_candidate" && test -x "$$grok_candidate" || { echo "test-e2e requires the Grok executable" >&2; exit 1; }; \
	grok_bin="$$(realpath "$$grok_candidate")"; \
	case "$$grok_bin" in /*) ;; *) echo "test-e2e requires an absolute Grok executable" >&2; exit 1;; esac; \
	if MULGAE_E2E_BINARY="$$MULGAE_E2E_BINARY" MULGAE_E2E_PROJECT_ROOT="$$e2e_project" \
		MULGAE_E2E_ZCODE_APP_BUNDLE="$$zcode_app" \
		MULGAE_E2E_GROK_EXECUTABLE="$$grok_bin" \
		$(GO) test -v -tags=live_e2e -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^Test(E2E|Live)' ./test/e2e; then \
		:; \
	else \
		status=$$?; \
		printf '%s\n' "[test-e2e] failed; preserved private project: $$e2e_project" >&2; \
		exit $$status; \
	fi; \
	MULGAE_LIVE_ZCODE_APP_BUNDLE="$$zcode_app" \
		MULGAE_LIVE_GROK_BIN="$$grok_bin" \
		$(GO) test -v -tags=liveprovider -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^TestLive(ZCode|Grok)Capability$$|^TestLiveCapability(FailureEvidenceIsPrivateAndScreened|MismatchGuidanceDoesNotInventRootCause)$$' ./internal/adapters/providercli || { \
		status=$$?; \
		printf '%s\n' "[test-e2e] failed; preserved private project: $$e2e_project" >&2; \
		exit $$status; \
	}; \
	rm -rf "$$e2e_project"
	@printf '%s\n' '[test-e2e] completed'

test-e2e-opt-in:
	@if test "$${MULGAE_E2E_OPT_IN:-}" != "1"; then \
		printf '%s\n' '[test-e2e-opt-in] skipped: set MULGAE_E2E_OPT_IN=1'; \
		exit 0; \
	fi; \
	test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-e2e-opt-in requires darwin/arm64" >&2; exit 1; }; \
	opt_in_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$opt_in_tmp"' EXIT; \
	opt_in_base="$${TMPDIR:-/tmp}"; \
	opt_in_project="$$(mktemp -d "$${opt_in_base%/}/mulgae-e2e-opt-in-project.XXXXXX")"; \
	chmod 700 "$$opt_in_project"; \
	opt_in_binary="$$opt_in_tmp/mulgae"; \
	opt_in_commit="$$(git rev-parse HEAD)"; \
	$(GO) build -trimpath -ldflags "-X main.buildVersion=$(RELEASE_VERSION) -X main.buildRevision=$$opt_in_commit" -o "$$opt_in_binary" .; \
	codex_candidate="$${MULGAE_E2E_CODEX_EXECUTABLE:-$$(command -v codex)}"; \
	test -n "$$codex_candidate" && test -x "$$codex_candidate" || { echo "test-e2e-opt-in requires the Codex executable" >&2; exit 1; }; \
	codex_bin="$$(realpath "$$codex_candidate")"; \
	test -n "$$codex_bin" && test -x "$$codex_bin" || { echo "test-e2e-opt-in cannot resolve the Codex executable" >&2; exit 1; }; \
	case "$$codex_bin" in /*) ;; *) echo "test-e2e-opt-in requires an absolute Codex executable" >&2; exit 1;; esac; \
	codex_primary_home="$${MULGAE_E2E_CODEX_PRIMARY_HOME:-}"; \
	test -n "$$codex_primary_home" && test -d "$$codex_primary_home" || { echo "test-e2e-opt-in requires MULGAE_E2E_CODEX_PRIMARY_HOME" >&2; exit 1; }; \
	case "$$codex_primary_home" in /*) ;; *) echo "test-e2e-opt-in requires an absolute MULGAE_E2E_CODEX_PRIMARY_HOME" >&2; exit 1;; esac; \
	codex_secondary_home="$${MULGAE_E2E_CODEX_SECONDARY_HOME:-}"; \
	test -n "$$codex_secondary_home" && test -d "$$codex_secondary_home" || { echo "test-e2e-opt-in requires MULGAE_E2E_CODEX_SECONDARY_HOME" >&2; exit 1; }; \
	case "$$codex_secondary_home" in /*) ;; *) echo "test-e2e-opt-in requires an absolute MULGAE_E2E_CODEX_SECONDARY_HOME" >&2; exit 1;; esac; \
	if MULGAE_E2E_BINARY="$$opt_in_binary" MULGAE_E2E_PROJECT_ROOT="$$opt_in_project" \
		MULGAE_E2E_CODEX_EXECUTABLE="$$codex_bin" MULGAE_E2E_CODEX_PRIMARY_HOME="$$codex_primary_home" \
		MULGAE_E2E_CODEX_SECONDARY_HOME="$$codex_secondary_home" $(GO) test -v -tags='live_e2e live_e2e_opt_in' \
		-timeout $(TEST_TIMEOUT) -count=1 -run '^TestE2EOptInCodexCredentialProfiles$$' ./test/e2e; then \
		:; \
	else \
		status=$$?; \
		printf '%s\n' "[test-e2e-opt-in] failed; preserved private project: $$opt_in_project" >&2; \
		exit $$status; \
	fi; \
	rm -rf "$$opt_in_project"; \
	printf '%s\n' '[test-e2e-opt-in] completed'

test-grok:
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-grok requires darwin/arm64" >&2; exit 1; }
	@grok_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$grok_tmp"' EXIT; \
	grok_binary="$$grok_tmp/mulgae"; \
	grok_commit="$$(git rev-parse HEAD)"; \
	$(GO) build -trimpath -ldflags "-X main.buildVersion=$(RELEASE_VERSION) -X main.buildRevision=$$grok_commit" -o "$$grok_binary" .; \
	grok_candidate="$${MULGAE_E2E_GROK_EXECUTABLE:-$$(command -v grok)}"; \
	test -n "$$grok_candidate" && test -x "$$grok_candidate" || { echo "test-grok requires the Grok executable" >&2; exit 1; }; \
	grok_bin="$$(realpath "$$grok_candidate")"; \
	case "$$grok_bin" in /*) ;; *) echo "test-grok requires an absolute Grok executable" >&2; exit 1;; esac; \
	MULGAE_LIVE_GROK_BIN="$$grok_bin" \
		$(GO) test -v -tags=liveprovider -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^TestLiveGrokCapability$$' ./internal/adapters/providercli && \
	MULGAE_E2E_BINARY="$$grok_binary" MULGAE_E2E_GROK_EXECUTABLE="$$grok_bin" \
		$(GO) test -v -tags='live_e2e live_grok' -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^TestE2EGrokReleaseBinaryReview$$' ./test/e2e
	@printf '%s\n' '[test-grok] completed'

test-mcp-clients:
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-mcp-clients requires darwin/arm64" >&2; exit 1; }
	@mcp_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$mcp_tmp"' EXIT; \
	mcp_binary="$$mcp_tmp/mulgae"; \
	mcp_commit="$$(git rev-parse HEAD)"; \
	$(GO) build -trimpath -ldflags "-X main.buildVersion=$(RELEASE_VERSION) -X main.buildRevision=$$mcp_commit" -o "$$mcp_binary" .; \
	codex_bin="$${MULGAE_MCP_CODEX_BINARY:-$$(command -v codex)}"; \
	claude_bin="$${MULGAE_MCP_CLAUDE_BINARY:-$$(command -v claude)}"; \
	for client in "$$codex_bin" "$$claude_bin"; do \
		test -n "$$client" && test -x "$$client" || { echo "test-mcp-clients requires executable Codex and Claude clients" >&2; exit 1; }; \
		case "$$client" in /*) ;; *) echo "test-mcp-clients requires absolute client paths" >&2; exit 1;; esac; \
	done; \
	MULGAE_MCP_CLIENT_BINARY="$$mcp_binary" \
		MULGAE_MCP_CODEX_BINARY="$$codex_bin" \
		MULGAE_MCP_CLAUDE_BINARY="$$claude_bin" \
		$(GO) test -v -tags=mcpclientcheck -count=1 ./internal/mcpclientcheck
	@printf '%s\n' '[test-mcp-clients] completed'
