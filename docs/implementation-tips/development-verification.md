# Development verification policy

This page defines the canonical development verification policy delivered by
[EPIC-015](../roadmap/README.md#epic-015-development-verification-simplification)
across the [Makefile](../../Makefile), optional
[Gaori configuration](../../.gaori/tester.yaml), [AGENTS.md](../../AGENTS.md),
and [contributor verification guidance](README.md#local-checks).

The [roadmap](../roadmap/README.md#epic-015-development-verification-simplification)
owns Task order, delivery status, and Epic acceptance.

## Purpose and scope

Reduce the time spent preparing and repeating development checks while
preserving product behavior, trust boundaries and supported historical reads.
Keep unit, integration and E2E as the existing test categories. Execution scope
depends on the change and the claim being made.

This work changes test fixtures, build preparation, selected assertions and
repository guidance. It does not change provider policy, public commands or
schemas, production validation, publication authority, accounts or installed
tools. A production behavior change needs its own explicit scope and evidence.

## Command contract

| Entry point | Claim and execution |
|---|---|
| Focused Go test or existing individual Make target | Verifies the affected behavior during a Task. Use an explicit package and anchored test selection when selecting tests. |
| `make test-offline` | Runs `test-prepare`, `test-unit` and `test-int` once each, in that order, and stops on the first failure. It provides complete deterministic development verification. |
| `make test-release` | Preserves exact installed-binary checks and the separately identified isolated fixture checks. It uses no live provider. |
| `make test` | Runs the offline stages once, followed by `test-release`, mandatory `test-e2e` and conditional `test-e2e-opt-in`. It retains the existing full-gate meaning. |
| Standalone provider and client targets | Remain explicit checks for the provider or client contract being changed and for release obligations. |

The `gaori run offline` alias invokes `make test-offline` through the
[Gaori configuration](../../.gaori/tester.yaml). Gaori remains an optional
execution adapter for the same check and adds no acceptance step.

A complete offline claim applies to the supported native Apple Silicon macOS
platform. Other platforms may omit platform-constrained tests and must report
that limitation instead of claiming complete native coverage.

Use a thin Make aggregation for `test-offline`. The individual targets retain
their current flags, including `-race`, `-count=1` and package serialization
where currently present. The full gate must not execute the offline aggregate
and its member stages a second time.

Ordinary focused development checks may use the existing narrower commands.
A focused pass does not establish complete offline verification or release
readiness. The new aggregate is not a gate after every Task: EPIC-015 reserves
one complete offline backstop for its final integrated candidate in TASK-074.

### Release obligations

Keep the mandatory ZCode live checks and the conditional Codex target behavior.
The separately adopted `v0.1.26` release requirement still requires all five
providers, including the standalone Grok, Cursor and AGY campaigns and enabled
Codex profile checks, on the release candidate. The normal `make test` default
alone does not discharge that additional obligation.

EPIC-015 activated this development completion policy in TASK-070. Its
harness-only scope does not require a routine live-provider rerun after each
Task or at Epic closeout. Report live checks as unexecuted for this Epic and
make no new native-provider compatibility claim. Existing release obligations,
explicitly requested live checks and checks justified by an actual provider
boundary change still apply.

## Select checks from the change

| Change | Iteration and Task evidence | Wider verification |
|---|---|---|
| Ordinary prose, links or agent wording with no changed executable or normative meaning | Read back the text, check references and run `git diff --check`. | Broaden only if command claims or an affected contract changed. |
| CLI parsing, result mapping or a test fixture used by those tests | Relevant parser, application and fixture tests. | Include the affected public-schema and integration checks when their behavior changes. |
| Shared compiled test assets | Existing constructor and corruption negatives plus affected consumers and concurrent consumers under `-race`. | Complete offline suite on the final Epic candidate. |
| Test compilation cache or binary-build helper | Representative consumers, output/home isolation and affected release-harness checks. | Complete offline suite and the affected exact-release checks on the final candidate. |
| Provider protocol, permissions, credential or process authority | Affected adapter/process regressions and deterministic integration checks. | Relevant native-provider certification under its existing authority; this is outside EPIC-015's intended code scope. |
| Publication, recovery or historical compatibility | Relevant application/filesystem/read/recovery tests, including failure cases. | Complete candidate verification and any affected exact-binary checks. |

A text edit that changes a public option, exit code, identifier, schema,
permission or normative behavior is a contract change. Its formatting does not
qualify it for the ordinary-prose row.

Preserve a successful check when its tested inputs and assumptions still apply.
After a correction, identify the affected behavior and rerun the checks whose
evidence changed. Refresh the entire suite when shared changes or unresolved
failures invalidate the broader result. Neither a punctuation correction nor
a new review round automatically invalidates every previous check.

Record the selection and reason in the existing plan or handoff. Keep required
independent reviews and their authority. Reviewers can inspect unchanged
evidence and focus on the correction; the policy adds no review round or
mandatory live Mulgae review. Repository guidance must tell the selected
Aquarium workflow which checks are Task-owned and which belong to the final
candidate. A separately required broader check should be named as such, with
its reason, rather than silently counted as another routine Task gate.

## Test fixture ownership

In [application_test.go](../../internal/entrypoint/mulgae/application_test.go),
`sharedFoundationAssets` initializes one package-shared default
`*builtin.Catalog` (`builtin.NewCatalog()`) and compiled
`*jsonschema.Validator` (`jsonschema.New(context.Background(), catalog)`) once
via `sync.Once`. Both objects are safe for concurrent read reuse across tests:
`builtin.Catalog` accessors return defensive copies, and `jsonschema.Validator`
holds an unmutated map of compiled `*jschema.Schema` instances backed by
concurrency-safe `ecmaRegexp` (`*regexp2.Regexp`) engines with no mutable
validation state on the shared schema graph. The same package-scoped
`sync.Once` fixture reuse applies across `internal/app/publication`,
`internal/composition`, `internal/app/recovery`, `internal/app/query`,
`internal/app/reviewrun`, and `internal/adapters/jsonschema` (`pairs_test.go`).

A shared initializer must use `context.Background()` and return its value or
error without retaining a caller's `*testing.T`, cancelled context, temporary
path, or cleanup callback. Each caller handles initialization failure on its own
test goroutine.

Wrapper fixtures (`newFoundationFixtureWithWriter`,
`newFoundationFixtureWithEvidence`, `newG006FixtureWithWriter`,
`newG008Fixture`, `newG008Composition`, `newG008RealE2EFixture`,
`historicalValidator`, `retainedResolverFixture`, `retainedSchema`,
`newMCPTestApplicationWithReviewRuns`, `requirementsExecutionApplication`,
`recoveryReadFixture`, `mustSharedQueryTestValidator`,
`mustSharedReviewRunTestAssets`, and `newBuiltinValidator`) obtain shared
immutable assets directly and construct their `Application` and `gittarget`
reader once, retaining their own mutable dependencies without intermediate
discarded constructions.

Keep writers, request IDs, repositories, native homes, provider state, clocks
with mutable state, and other mutable dependencies independent per test.
Constructor-failure, cancellation, altered-catalog, and corrupt-schema tests
continue to construct fresh `Catalog` and `Validator` instances. Preserve
defensive copies, output bytes, and failure classification. Do not move this
optimization into a production singleton.

## Compiler cache and binary isolation

In [cli_integration_test.go](../../test/e2e/cli_integration_test.go),
`buildMulgaeBinary` and `buildFakeZCodeWithReport` build through `goBuildEnv`,
which reuses the inherited or caller-supplied `GOCACHE` when set and falls back
to one suite-scoped temporary directory (`sharedFallbackGoCache`, initialized
once via `sync.Once`) only when `GOCACHE` is empty, while preserving
`GOPROXY=off` and `GOSUMDB=off`. Each fixture build retains a separate output
binary path, per-fixture `<binary>.native-home` linker override
(`buildNativeHomeOverride`), Git repository, and provider state. Cleanup
removes only test-owned temporary directories and never deletes a shared
`GOCACHE` or developer provider home.

A native-home linker override requires a separate final binary without
requiring an empty compiler cache for every dependency build. Per-fixture
linker inputs and generated fake-provider code still require linking or
compilation; account for that work when interpreting timings. Sharing output
binaries or native homes is not required for this optimization and needs its own
lifetime justification.

Keep the distinction between the Go compiler cache (`GOCACHE`) and cached test
results (`-count=1`). Also retain the existing instrumentation claim: `-race` on
the Go test process does not automatically instrument a child binary built
without that flag. Do not describe that child as race-instrumented.

The disposable caches specified by [release design gates](../gating-rules.md)
have their own confinement requirements. This policy does not remove those
requirements merely because ordinary integration builds reuse a compiler cache.

## Assertions and repeated scenarios

Keep behavior-based checks for package boundaries, trust boundaries, failure
propagation, mandatory live-check no-skip behavior, release isolation and
historical compatibility. Preserve public grammar and legacy-path rejection.
Remove assertions
that only pin ordinary prose, line wrapping, a helper's name, source placement
or a duplicated literal count.

For an affected requirement, identify existing coverage or state why the
assertion concerns presentation rather than a runtime contract. A deleted
assertion does not automatically require a new test. Add a small behavioral
check only when a real requirement would otherwise lose coverage. Do not build
a general Makefile parser, source analyzer or validation framework for this
cleanup.

Keep release instructions consistent with the surviving version checks when
removing duplicated version literals. Preserve patch-only waiver conditions
and exact installed-binary version verification.

Review integration/release scenario overlap by the claim each execution
establishes. Distinguish repeated executions of isolated fixture binaries from
the separate production installed-binary checks. Compare build flags,
version/revision inputs, test instrumentation, fixture lifetimes and isolation.
Keep repetitions that prove distinct required claims and record the rationale;
deleting scenarios is not a completion quota.

### Assertion coverage basis (`TASK-073`)

- **`RELEASE_VERSION` and linker stamping (`TestMakefileContract`)**: `Makefile`
  owns the release version literal. `TestMakefileContract` verifies that
  `Makefile` declares a valid `RELEASE_VERSION := v<major>.<minor>.<patch>`
  line, passes `MULGAE_RELEASE_VERSION` to `./internal/releasecheck` in
  `test-release`, and stamps `main.buildVersion=$(RELEASE_VERSION)` in each of
  the seven exact-binary target slices (`test-release`, `test-e2e`,
  `test-e2e-opt-in`, `test-grok`, `test-cursor`, `test-agy`, and
  `test-mcp-clients`). `internal/releasecheck` (`TestInstalledRootModuleContract`)
  and the manual/waiver temporary-`GOBIN` checks verify `mulgae --version`,
  `mulgae version`, and `mulgae version --json` on the installed binary.
- **Live E2E and MCP projection ownership (`TestE2ELiveFamilyCapabilityAndNoSkipContract`, `TestMCPContractProjectionOwnership`)**:
  `TestE2ELiveFamilyCapabilityAndNoSkipContract` retains the exported test
  entrypoints (`TestLiveZCodeCapability`, `TestLiveGrokCapability`,
  `TestE2EZCodeGrokReviewAggregation`, `TestE2EOptInCodexCredentialProfiles`),
  `QualifyCurrent`, role/profile routing (`zcode-logic`, `zcode-security`,
  `codex-primary-logic`, `codex-primary-security`,
  `codex-primary-documentation`), required and forbidden environment
  variables (`MULGAE_E2E_CODEX_PRIMARY_HOME`), and the no-`.Skip(`/`.Skipf(` invariant across
  all three live test files without pinning unexported helper names in
  `test/e2e/live_test.go`.
  `TestMCPContractProjectionOwnership` retains the forbidden composition tokens
  and exported MCP entrypoints (`ParseResourceURI`, `ProjectRunStatus`,
  `ProjectInspection`) alongside the AST ownership guards in
  `internal/architecture/ownership_boundaries_test.go`, without pinning
  unexported helper names (`projectResource`, `resourceChunkEnd`).
- **Embedded help and catalog contracts (`TestCatalogHelpCoversProjectLocalInitContract`, `TestCatalogDocumentationContract`)**:
  `TestCatalogHelpCoversProjectLocalInitContract` retains the configuration
  authority paths (`<canonical-project-root>/.mulgae/config.yaml`,
  `<canonical-project-root>/.mulgae/local.yaml`), `--providers auto|FAMILY[,FAMILY...]`
  grammar, the `FAMILY := zcode | grok | codex | cursor | agy` set,
  `execution.workspace_access` and `Config v2` rejection tokens, and forbidden
  legacy paths (`~/.config/mulgae`, `$XDG_CONFIG_HOME/mulgae`,
  `--providers kimi`) without pinning multi-line paragraph prose or `\n` line
  wrapping. `TestCatalogDocumentationContract` remains unchanged because it
  exercises `Catalog.List` client-side kind filtering and `Catalog.Read`
  context-cancellation behavior.

### Integration and release scenario overlap assessment (`TASK-073`)

The seven `TestIntegrationIsolatedReleaseFixture*` scenarios in
`test/e2e/cli_integration_test.go` (`LiveSelectors`,
`CancelsLiveReviewWithoutReplay`, `ProjectContext`, `GuardedAdmission`,
`VerifiedContent`, `VerifiedWorkflow`, and `Requirements`) execute in both
`make test-int` and `make test-release` under distinct build and artifact
conditions:

1. **`make test-int` (per-test unstripped development binaries)**: runs the Go
   test binary under `-race -p 1` with `MULGAE_E2E_BINARY` unset. Each scenario
   invokes `buildMulgaeBinary`, which builds a separate unstripped binary
   (without `-trimpath`), stamps synthetic linker metadata
   (`main.buildVersion=v1.4.2`,
   `main.buildRevision=0123456789abcdef0123456789abcdef01234567`), and binds a
   per-test `<binary>.native-home` via `buildNativeHomeOverride`.
2. **`make test-release` Step 1 (`./internal/releasecheck` on installed `GOBIN/mulgae`)**:
   installs the unmodified production binary with `$(GO) install -trimpath` and
   real `RELEASE_VERSION` / `HEAD` revision linker flags (without
   `buildNativeHomeOverride`) into an isolated mode-`0700` `GOBIN`, then verifies
   `debug/buildinfo` (`-trimpath=true`, `vcs.revision=HEAD`),
   `mulgae --version`, `mulgae version`, `mulgae version --json`, and help output.
3. **`make test-release` Step 2 (shared `-trimpath` release-stamped isolated-fixture binary)**:
   builds one shared binary **with** `-trimpath`, real
   `main.buildVersion=$(RELEASE_VERSION)`, real
   `main.buildRevision=$$(git rev-parse HEAD)`, and `buildNativeHomeOverride`
   inside the guarded mode-`0700` `mulgae-release.*` temporary root, then runs
   all seven scenarios against that single prebuilt binary via
   `MULGAE_E2E_BINARY`.

All seven scenarios are retained in `make test-release`: Step 2 proves that a
single `-trimpath` binary stamped with the real `RELEASE_VERSION` and `HEAD`
commit revision (and injected via `MULGAE_E2E_BINARY`) satisfies
`buildIdentityFrom` and every end-to-end CLI/MCP live-selector, cancellation,
project-context, guarded-admission, verified-content, verified-workflow, and
requirements contract without reading the operator's real `HOME`. Neither
`make test-int` (no `-trimpath`, synthetic version/revision, per-test builds)
nor `internal/releasecheck` (version/help/buildinfo only) establishes that
claim alone. Reusing the single `release_fixture_binary` in `make test-release`
and the shared compiler cache from `TASK-072` in `make test-int` already
eliminates redundant cold-compilation overhead without reducing scenario
coverage.

## Measured outcomes (`EPIC-015`)

Matched focused measurements and final candidate gates were recorded on
`go1.27.1 darwin/arm64` with a warm host `GOCACHE` and `MULGAE_E2E_BINARY`
unset:

| Check | Command | Baseline (`4beb843`, `TASK-070`) | Task milestone (`eebc6d9` / `3f1ef2a`) | Final candidate (with 6-package fixture reuse) | Removed work |
|---|---|---:|---:|---:|---|
| Focused CLI fixture selection | `go test -p 1 -race -count=1 ./internal/entrypoint/mulgae -run '^(TestApplicationHelpAndUsageOutput\|TestApplicationG006FailureParityAcrossCommands)$'` | `62.333s` (`62.759s` initial) | `5.170s` (`5.567s` initial, `375ae33` in `TASK-071`) | `5.852s` | Repeated `builtin.NewCatalog` and 82-pair `jsonschema.New` compilation plus discarded intermediate `Application` and `gittarget` constructions per helper call |
| Focused integration build selection | `go test -p 1 -race -count=1 ./test/e2e -run '^(TestIntegrationIsolatedReleaseFixtureProjectContext\|TestIntegrationIsolatedReleaseFixtureVerifiedWorkflow)$'` | `35.318s` (`29.389s` initial) | `16.948s` (`229ecc8` in `TASK-072`; `2315` cache entries populated on first build and reused with `10` added on second in `TestBuildHelpersReuseCompilerCacheAndIsolateMutableOutputs`) | `19.541s` | Per-build empty `GOCACHE` directories that forced cold compilation for every `buildMulgaeBinary` and `buildFakeZCodeWithReport` call |
| Repository unit test stage (`test-unit` package execution sum) | `make test-unit` (`go test -p 1 -timeout 90m -race -count=1 -skip '^TestIntegration' ...`) | — | `1636.0s` (`3f1ef2a`) | `516.6s` (`-68.4%`) | Package-scoped `sync.Once` reuse of immutable `builtin.Catalog` and `jsonschema.Validator` across `publication` (`521.6s` → `32.0s`), `composition` (`477.8s` → `52.3s`), `recovery` (`111.4s` → `4.6s`), `query` (`106.9s` → `14.0s`), `jsonschema` (`91.6s` → `15.7s`), and `reviewrun` (`18.4s` → `14.2s`) |
| Repository integration test stage (`test-int` package execution sum) | `make test-int` (`go test -p 1 -timeout 90m -race -count=1 -run '^TestIntegration' ./...`) | — | `520.0s` (`3f1ef2a`) | `338.1s` (`-35.0%`) | Package-scoped `sync.Once` fixture reuse across `reviewrun` (`176.5s` → `60.1s`), `publication` (`89.2s` → `47.9s`), and `composition` (`14.1s` → `6.8s`) |
| Complete deterministic offline gate | `make test-offline` (via `gaori run offline`) | — | `2357.1s` (`3f1ef2a`, `exit 0`) | `909.0s` (`-61.4%`, `exit 0`) | Runs `test-prepare`, `test-unit`, and `test-int` once in order with package-scoped immutable `Catalog` and `Validator` reuse across all bottleneck test packages |
| Exact-binary release harness gate | `make test-release` (via `gaori run release`) | — | `166.0s` (`exit 0`) | `166.0s` (`exit 0`) | Verifies `internal/releasecheck` on the installed `-trimpath` `GOBIN/mulgae` binary and all seven isolated-fixture scenarios on one shared release-stamped fixture binary |

Live-provider gates (`make test-e2e`, `make test-grok`, `make test-cursor`,
`make test-agy`, and `MULGAE_E2E_OPT_IN=1 make test-e2e-opt-in`) were
unexecuted under the activated harness-only `EPIC-015` policy; the mandatory
`make test` release gate and the `v0.1.26` five-provider release-candidate
obligations remain unchanged.

## Known limits

- **Per-subtest Git repository creation**: the focused CLI selection still runs
  `git init` and `git commit` subprocesses per subtest to establish real Git
  repositories.
- **Per-fixture linking and generated fake providers**: shared compiler caches
  (`GOCACHE`) reuse compiled packages, but each isolated integration fixture
  still links its own binary with a per-fixture `buildNativeHomeOverride` path
  and compiles generated fake-provider source.
- **Open deferred feedback (`DF-028` and `DF-029`)**:
  [DF-028](../deferred-feedback/README.md#deferred-feedback) records an
  unresolved protected-directory failure under load, including a later
  serialized observation; preserve the rejection, report any occurrence, and do
  not assume that global parallelism is safe.
  [DF-029](../deferred-feedback/README.md#deferred-feedback) remains open with
  its standing rule that shared initialization and worker goroutines must never
  retain or invoke a caller's `*testing.T` fatal handler.
- **Separate `go vet ./...` coverage**: `golangci-lint` enables `govet` but
  excludes test files. A separate `go vet ./...` in `make test-prepare`
  therefore provides additional test-file coverage and is retained.
- **No timing or percentage gates**: comparable before/after observations
  document the removed repeated setup without introducing a percentage target,
  percentile threshold, or benchmark service.
