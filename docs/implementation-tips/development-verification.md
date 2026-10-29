# Development verification policy

This page defines the active development verification policy for
[EPIC-015](../roadmap/README.md#epic-015-development-verification-simplification),
activated in `TASK-070` across the [Makefile](../../Makefile), optional
[Gaori configuration](../../.gaori/tester.yaml), [AGENTS.md](../../AGENTS.md)
and [contributor verification guidance](README.md#local-checks).

The [execution dossier](../todo/development-verification-simplification.md) owns
the temporary implementation plan and measurement procedure for `TASK-071`
through `TASK-074`. The [roadmap](../roadmap/README.md) owns Task order and
status.

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

The default Catalog and compiled Validator are candidates for reuse inside
the test package. Confirm the entire shared object graph, including compiled
schemas, the regexp engine, lazy state and accessors, permits the intended
concurrent use. If that cannot be established, share a smaller proven-immutable
part or retain independent instances and report the remaining cost.

A shared initializer must return its value or error without retaining a
caller's `*testing.T`, cancelled context, temporary path or cleanup callback.
Each caller handles initialization failure on its own test goroutine.

Wrapper fixtures should obtain shared immutable assets directly and construct
their `Application` and Git reader once, retaining their own mutable
dependencies. Keep this cleanup local to the existing helpers.

Keep writers, request IDs, repositories, native homes, provider state, clocks
with mutable state and other mutable dependencies independent. Constructor
failure, cancellation, altered-catalog and corrupt-schema tests continue to
construct fresh objects. Preserve defensive copies, output bytes and failure
classification. Do not move this optimization into a production singleton.

## Compiler cache and binary isolation

Reuse compilation artifacts across related test builds while retaining separate
output binaries and mutable fixture roots. A private cache shared by the test
suite is sufficient if the harness needs a controlled cache location. Keep the
existing offline module settings.

A native-home linker override can require a separate final binary without
requiring an empty cache for every dependency build. Per-fixture linker inputs
and generated fake-provider code can still require linking or compilation;
account for that work when interpreting timings. Sharing output binaries or
native homes is not required for this optimization and needs its own lifetime
justification.

Keep the distinction between the Go compiler cache and cached test results.
Also retain the existing instrumentation claim: `-race` on the Go test
process does not automatically instrument a child binary built without that
flag. Do not describe that child as race-instrumented.

The disposable caches specified by [release design gates](../gating-rules.md)
have their own confinement requirements. This Epic does not remove those
requirements merely because ordinary integration builds can reuse a cache.

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
  `codex-secondary-documentation`), required and forbidden environment
  variables, and the no-`.Skip(`/`.Skipf(` invariant across all three live test
  files without pinning unexported helper names in `test/e2e/live_test.go`.
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
requirements contract without reading the operator's real `HOME`—a claim that
neither `make test-int` (no `-trimpath`, synthetic version/revision, per-test
builds) nor `internal/releasecheck` (version/help/buildinfo only) establishes
alone. Reusing the single `release_fixture_binary` in `make test-release` and
the shared compiler cache from `TASK-072` in `make test-int` already eliminates
redundant cold-compilation overhead without reducing scenario coverage.

## Known limits

[DF-028](../deferred-feedback/README.md#deferred-feedback) records an unresolved
protected-directory failure under load, including a later serialized
observation. Preserve the rejection and report any occurrence. This Epic
neither closes DF-028 nor assumes that global parallelism is safe.

The existing linter enables `govet` but excludes test files. A separate
`go vet ./...` therefore has additional coverage. Removing it is not an
accepted shortcut in this scope.

The historical timing observations in the dossier identify where to start.
They do not predict savings. Record comparable before/after observations and
the removed repeated work without introducing a percentage target or a
benchmark service.
