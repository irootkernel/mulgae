# Explicit legacy GO/PYTHON paths still pass through the exact-version guard.
ifdef GO
export MULGAE_GO_EXECUTABLE := $(GO)
endif
ifdef PYTHON
export MULGAE_PYTHON_EXECUTABLE := $(PYTHON)
endif
override GO := "$(CURDIR)/dev" go
override PYTHON := "$(CURDIR)/dev" python
# Children inherit the validated executable inputs, never these command strings.
unexport GO PYTHON
TEST_TIMEOUT ?= 90m
RELEASE_VERSION := v0.1.28
MCP_CLIENT_TAGS := mcpclientcheck
HAEPARI ?= haepari
RESOURCE ?=
SUITE ?= guest-qualification
MODE ?= auto
RUN_DIR ?=
REQUEST ?=

.DEFAULT_GOAL := test

.PHONY: help toolchain-install toolchain-check generate fmt fmt-check vuln-check test-toolchain test test-offline test-prepare test-unit test-int test-release test-e2e test-herdr test-grok test-mcp-clients test-mcp-requirements-clients test-vm test-vm-guest test-vm-contract test-vm-driver-compile

# These inputs are only for the separately admitted, sealed guest owning targets.
define validate_installed_test_inputs
if test -n "$${MULGAE_TEST_INSTALLED_BINARY:-}"; then \
	test -x "$$MULGAE_TEST_INSTALLED_BINARY" && test -n "$${MULGAE_TEST_SOURCE_COMMIT:-}" && test -f "$${MULGAE_TEST_PREPARED_MANIFEST:-}" || { echo "invalid installed-test inputs" >&2; exit 1; }; \
	case "$$MULGAE_TEST_SOURCE_COMMIT" in *[!0-9a-f]*) echo "invalid installed-test inputs" >&2; exit 1;; esac; \
	test "$${#MULGAE_TEST_SOURCE_COMMIT}" -eq 40 || { echo "invalid installed-test inputs" >&2; exit 1; }; \
	printf '%s\n' "[installed-test] supplied_source_commit=$$MULGAE_TEST_SOURCE_COMMIT"; \
	shasum -a 256 -- "$$MULGAE_TEST_INSTALLED_BINARY" "$$MULGAE_TEST_PREPARED_MANIFEST" || exit $$?; \
elif test -n "$${MULGAE_TEST_SOURCE_COMMIT:-}$${MULGAE_TEST_PREPARED_MANIFEST:-}"; then \
	echo "invalid installed-test inputs" >&2; exit 1; \
fi
endef

test:
	@test -z "$${MULGAE_TEST_INSTALLED_BINARY:-}$${MULGAE_TEST_SOURCE_COMMIT:-}$${MULGAE_TEST_PREPARED_MANIFEST:-}" || { echo "make test refuses installed-binary overrides" >&2; exit 1; }
	@$(MAKE) test-offline
	@$(MAKE) test-release
	@$(MAKE) test-e2e
	@printf '%s\n' '[test] completed'

test-offline:
	@$(MAKE) test-prepare
	@$(MAKE) test-unit
	@$(MAKE) test-int
	@printf '%s\n' '[test-offline] completed'

test-prepare:
	@$(MAKE) test-toolchain
	@$(MAKE) generate
	@$(MAKE) fmt
	$(GO) mod verify
	$(GO) tool golangci-lint run ./...
	$(GO) vet ./...
	$(GO) test -race -count=1 ./internal/architecture
	@printf '%s\n' '[test-prepare] completed'

test-unit:
	@packages="$$($(GO) list ./...)" || exit $$?; \
		packages="$$(printf '%s\n' "$$packages" | grep -v '/internal/architecture$$')" || exit $$?; \
		$(GO) test -p 1 -timeout $(TEST_TIMEOUT) -race -count=1 -skip '^TestIntegration' $$packages
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
		-run '^(TestIntegrationIsolatedReleaseFixtureLiveSelectors|TestIntegrationIsolatedReleaseFixtureCancelsLiveReviewWithoutReplay|TestIntegrationIsolatedReleaseFixtureProjectContext|TestIntegrationIsolatedReleaseFixtureGuardedAdmission|TestIntegrationIsolatedReleaseFixtureVerifiedContent|TestIntegrationIsolatedReleaseFixtureVerifiedWorkflow|TestIntegrationIsolatedReleaseFixtureRequirements)$$' ./test/e2e
	@printf '%s\n' '[test-release] completed'

test-e2e:
	@$(validate_installed_test_inputs)
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-e2e requires darwin/arm64" >&2; exit 1; }
	@e2e_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$e2e_tmp"' EXIT; \
	e2e_base="$${TMPDIR:-/tmp}"; \
	e2e_project="$$(mktemp -d "$${e2e_base%/}/mulgae-e2e-project.XXXXXX")"; \
	chmod 700 "$$e2e_project"; \
	MULGAE_E2E_BINARY="$$e2e_tmp/mulgae"; \
	MULGAE_E2E_COMMIT="$${MULGAE_TEST_SOURCE_COMMIT:-$$(git rev-parse HEAD)}"; \
	if test -n "$${MULGAE_TEST_INSTALLED_BINARY:-}"; then \
		test -x "$$MULGAE_TEST_INSTALLED_BINARY" && cp "$$MULGAE_TEST_INSTALLED_BINARY" "$$MULGAE_E2E_BINARY"; \
	else \
		$(GO) build -trimpath -ldflags "-X main.buildVersion=$(RELEASE_VERSION) -X main.buildRevision=$$MULGAE_E2E_COMMIT" -o "$$MULGAE_E2E_BINARY" .; \
	fi || exit $$?; \
	zcode_app="$${MULGAE_E2E_ZCODE_APP_BUNDLE:-/Applications/ZCode.app}"; \
	test -d "$$zcode_app" || { echo "test-e2e requires the ZCode app bundle" >&2; exit 1; }; \
	case "$$zcode_app" in /*) ;; *) echo "test-e2e requires an absolute ZCode app bundle" >&2; exit 1;; esac; \
	if MULGAE_E2E_BINARY="$$MULGAE_E2E_BINARY" MULGAE_E2E_PROJECT_ROOT="$$e2e_project" \
		MULGAE_E2E_ZCODE_APP_BUNDLE="$$zcode_app" \
		$(GO) test -v -tags=live_e2e -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^Test(E2E|Live)' ./test/e2e; then \
		:; \
	else \
		status=$$?; \
		printf '%s\n' "[test-e2e] failed; preserved private project: $$e2e_project" >&2; \
		exit $$status; \
	fi; \
	MULGAE_LIVE_ZCODE_APP_BUNDLE="$$zcode_app" \
		$(GO) test -v -tags=liveprovider -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^TestLiveZCodeCapability$$|^TestLiveCapability(FailureEvidenceIsPrivateAndScreened|MismatchGuidanceDoesNotInventRootCause)$$' ./internal/adapters/providercli || { \
		status=$$?; \
		printf '%s\n' "[test-e2e] failed; preserved private project: $$e2e_project" >&2; \
		exit $$status; \
	}; \
	rm -rf "$$e2e_project"
	@printf '%s\n' '[test-e2e] completed'

test-grok:
	@$(validate_installed_test_inputs)
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-grok requires darwin/arm64" >&2; exit 1; }
	@set -e; grok_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$grok_tmp"' EXIT; \
	grok_binary="$$grok_tmp/mulgae"; \
	grok_commit="$${MULGAE_TEST_SOURCE_COMMIT:-$$(git rev-parse HEAD)}"; \
	if test -n "$${MULGAE_TEST_INSTALLED_BINARY:-}"; then \
		test -x "$$MULGAE_TEST_INSTALLED_BINARY" && cp "$$MULGAE_TEST_INSTALLED_BINARY" "$$grok_binary"; \
	else \
		$(GO) build -trimpath -ldflags "-X main.buildVersion=$(RELEASE_VERSION) -X main.buildRevision=$$grok_commit" -o "$$grok_binary" .; \
	fi || exit $$?; \
	grok_candidate="$${MULGAE_E2E_GROK_EXECUTABLE:-$$(command -v grok)}"; \
	test -n "$$grok_candidate" && test -x "$$grok_candidate" || { echo "test-grok requires the Grok executable" >&2; exit 1; }; \
	grok_bin="$$(realpath "$$grok_candidate")"; \
	case "$$grok_bin" in /*) ;; *) echo "test-grok requires an absolute Grok executable" >&2; exit 1;; esac; \
	grok_runtime="$$(mktemp -d)"; \
	grok_runtime="$$(cd "$$grok_runtime" && pwd -P)"; \
	printf '%s\n' "[test-grok] retained private runtime: $$grok_runtime"; \
	$(MAKE) test-herdr && \
	TMPDIR="$$grok_runtime" MULGAE_LIVE_GROK_BIN="$$grok_bin" \
		$(GO) test -v -tags=liveprovider -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^TestLiveGrokCapability$$' ./internal/adapters/providercli && \
	TMPDIR="$$grok_runtime" MULGAE_E2E_BINARY="$$grok_binary" MULGAE_E2E_GROK_EXECUTABLE="$$grok_bin" \
		$(GO) test -v -tags='live_e2e live_grok' -timeout $(TEST_TIMEOUT) -count=1 \
		-run '^TestE2EGrokReleaseBinaryReview$$' ./test/e2e
	@printf '%s\n' '[test-grok] completed'

test-mcp-requirements-clients: MCP_CLIENT_TAGS := mcpclientcheck,requirementsclientcheck
test-mcp-requirements-clients: test-mcp-clients

test-mcp-clients:
	@$(validate_installed_test_inputs)
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-mcp-clients requires darwin/arm64" >&2; exit 1; }
	@mcp_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$mcp_tmp"' EXIT; \
	mcp_binary="$$mcp_tmp/mulgae"; \
	mcp_commit="$${MULGAE_TEST_SOURCE_COMMIT:-$$(git rev-parse HEAD)}"; \
	if test -n "$${MULGAE_TEST_INSTALLED_BINARY:-}"; then \
		test -x "$$MULGAE_TEST_INSTALLED_BINARY" && cp "$$MULGAE_TEST_INSTALLED_BINARY" "$$mcp_binary"; \
	else \
		$(GO) build -trimpath -ldflags "-X main.buildVersion=$(RELEASE_VERSION) -X main.buildRevision=$$mcp_commit" -o "$$mcp_binary" .; \
	fi || exit $$?; \
	codex_bin="$${MULGAE_MCP_CODEX_BINARY:-$$(command -v codex)}"; \
	claude_bin="$${MULGAE_MCP_CLAUDE_BINARY:-$$(command -v claude)}"; \
	for client in "$$codex_bin" "$$claude_bin"; do \
		test -n "$$client" && test -x "$$client" || { echo "test-mcp-clients requires executable Codex and Claude clients" >&2; exit 1; }; \
		case "$$client" in /*) ;; *) echo "test-mcp-clients requires absolute client paths" >&2; exit 1;; esac; \
	done; \
	MULGAE_MCP_CLIENT_BINARY="$$mcp_binary" \
		MULGAE_MCP_CODEX_BINARY="$$codex_bin" \
		MULGAE_MCP_CLAUDE_BINARY="$$claude_bin" \
		$(GO) test -v -tags=$(MCP_CLIENT_TAGS) -count=1 ./internal/mcpclientcheck
	@printf '%s\n' '[test-mcp-clients] completed'

test-herdr:
	@test "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" = "darwin/arm64" || { echo "test-herdr requires darwin/arm64" >&2; exit 1; }
	@if test -n "$${MULGAE_HERDR_CORE_BIN+x}"; then \
		herdr_candidate="$$MULGAE_HERDR_CORE_BIN"; \
	else \
		herdr_candidate="$$(command -v hc || command -v herdr-core || true)"; \
		if test -z "$$herdr_candidate"; then \
			for p in "$$HOME/.local/bin/hc" "$$HOME/.local/bin/herdr-core"; do \
				if test -f "$$p" && test -x "$$p"; then herdr_candidate="$$p"; break; fi; \
			done; \
		fi; \
	fi; \
	test -n "$$herdr_candidate" && test -f "$$herdr_candidate" && test -x "$$herdr_candidate" || { echo "test-herdr requires an executable hc/herdr-core binary" >&2; exit 1; }; \
	$(GO) test -v -race -tags=live_herdr -timeout $(TEST_TIMEOUT) -count=1 ./internal/adapters/herdr
	@printf '%s\n' '[test-herdr] completed'

test-vm:
	@test -n "$(PREPARED_DIR)" || { echo "test-vm requires PREPARED_DIR from test/vm/prepare.py" >&2; exit 1; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B ./test/vm/host.py \
		--haepari "$(HAEPARI)" \
		--resource "$(RESOURCE)" \
		--suite "$(SUITE)" \
		--mode "$(MODE)" \
		--run-dir "$(RUN_DIR)" \
		--request "$(REQUEST)" \
		--prepared-dir "$(PREPARED_DIR)"

test-vm-guest:
	@PYTHONDONTWRITEBYTECODE=1 PYTHON="$$("$(CURDIR)/dev" path python)" /bin/sh ./test/vm/run.sh "$(SUITE)"

test-vm-contract:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B -m unittest discover -s ./test/vm -p 'contract_test.py' -v
	@printf '%s\n' '[test-vm-contract] completed'

test-vm-driver-compile:
	@set -eu; \
	vm_compile="$$(mktemp -d /tmp/mulgae-vm-compile.XXXXXX)"; \
	trap 'rm -rf "$$vm_compile"' EXIT; \
	$(GO) test -c -tags=vm_qualification -o "$$vm_compile/qualification.test" ./test/e2e
	@printf '%s\n' '[test-vm-driver-compile] completed'

help:
	@printf '%s\n' 'make toolchain-install   Install only the exact declared language versions (requires mise)' \
	    'make toolchain-check     Show declared/observed versions and executable paths' \
	    './dev go|python ...      Run a pinned interpreter/compiler' \
	    './dev exec -- command    Run a command with both pinned runtimes' \
	    'make generate | fmt | fmt-check | vuln-check' \
	    'make test-toolchain | test-offline | test-herdr | test-vm-contract | test-vm-driver-compile | test-release' \
	    'make test                Complete release gate, including live providers'

toolchain-install:
	@"$(CURDIR)/dev" install

toolchain-check:
	@"$(CURDIR)/dev" check

generate:
	$(GO) generate ./internal/app/init
	$(GO) generate ./internal/builtin

fmt:
	@raw="$$(/usr/bin/mktemp /tmp/mulgae-fmt-raw.XXXXXX)" || exit $$?; \
		files="$$(/usr/bin/mktemp /tmp/mulgae-fmt.XXXXXX)" || { status=$$?; /bin/rm -f "$$raw"; exit $$status; }; \
		trap '/bin/rm -f "$$raw" "$$files"' EXIT; \
		git ls-files -z --cached --others --exclude-standard -- '*.go' ':!vendor/**' > "$$raw" || exit $$?; \
		if test -s "$$raw"; then xargs -0 /bin/sh -c 'for f do if test -e "$$f" || test -L "$$f"; then printf "%s\0" "$$f"; fi; done' _ < "$$raw" > "$$files" || exit $$?; fi; \
		test ! -s "$$files" || xargs -0 "$(CURDIR)/dev" gofmt -w < "$$files"

fmt-check:
	@raw="$$(/usr/bin/mktemp /tmp/mulgae-fmt-raw.XXXXXX)" || exit $$?; \
		files="$$(/usr/bin/mktemp /tmp/mulgae-fmt.XXXXXX)" || { status=$$?; /bin/rm -f "$$raw"; exit $$status; }; \
		trap '/bin/rm -f "$$raw" "$$files"' EXIT; \
		git ls-files -z --cached --others --exclude-standard -- '*.go' ':!vendor/**' > "$$raw" || exit $$?; \
		if test -s "$$raw"; then xargs -0 /bin/sh -c 'for f do if test -e "$$f" || test -L "$$f"; then printf "%s\0" "$$f"; fi; done' _ < "$$raw" > "$$files" || exit $$?; fi; \
		unformatted=""; \
		if test -s "$$files"; then unformatted="$$(xargs -0 "$(CURDIR)/dev" gofmt -l < "$$files")" || exit $$?; fi; \
		test -z "$$unformatted" || { printf '%s\n' "$$unformatted" >&2; exit 1; }

vuln-check:
	$(GO) tool govulncheck ./...

test-toolchain:
	$(PYTHON) -B ./test/toolchain_contract_test.py
