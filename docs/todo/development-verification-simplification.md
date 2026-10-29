# Development verification simplification dossier

Epic: [EPIC-015](../roadmap/README.md#epic-015-development-verification-simplification)

Adopted work definition: 2026-10-29.

Planning baseline: `edd969cbe199c4b166ea703e2c819fb8e583d6cd`.

The roadmap owns Task identities, order, dependencies and status. This dossier
owns the temporary execution detail. [Development verification policy](../implementation-tips/development-verification.md)
defines the planned operating rules. Registering this plan does not start
implementation or activate its new commands.

## Goal

Shorten development feedback by removing repeated setup and unnecessary
assertion maintenance while preserving Mulgae's behavior and safety coverage.
Deliver the changes through the existing Makefile, Go tests and repository
guidance. Keep the work small enough that it does not become another validation
or orchestration project.

The starting tree was clean during the review. Reconcile relevant source and
instructions against the actual implementation starting point; the planning
baseline is a source reference, not an assertion that future input is unchanged.

## Findings that define the scope

| Finding | Source at the planning baseline | Intended treatment |
|---|---|---|
| CLI fixtures construct a Catalog and compile the complete Schema portfolio on each invocation, including simple command tests and table cases. | [application fixture](../../internal/entrypoint/mulgae/application_test.go), `newFoundationFixtureWithWriter`; [Schema adapter](../../internal/adapters/jsonschema/validator.go), `New` and its 82-pair inventory | Reuse proven immutable default test assets; retain independent mutable dependencies and constructor-negative cases. |
| Integration helpers create an empty compiler cache for each Mulgae and fake-ZCode build. | [CLI integration helpers](../../test/e2e/cli_integration_test.go), `buildMulgaeBinary` and `buildFakeZCodeWithReport` | Reuse compilation artifacts while keeping outputs and homes isolated. |
| The full gate combines deterministic checks, exact binaries and live providers; agent wording groups development and release readiness. | [Makefile](../../Makefile), `test`; [agent verification rules](../../AGENTS.md) | Add one offline aggregate and define the claim and timing of each gate. |
| Meta-tests pin version text, an exact linker-flag occurrence count, source order and helper names. | [architecture tests](../../internal/architecture/architecture_test.go), `TestMakefileContract` and `TestE2ELiveFamilyCapabilityAndNoSkipContract` | Retain required behavior with fewer implementation-spelling assertions. |
| Some help tests pin complete prose and line wrapping. | [Catalog tests](../../internal/builtin/catalog_test.go), `TestCatalogHelpCoversProjectLocalInitContract` | Keep executable/public-contract checks and remove ordinary-prose pinning. |
| Seven isolated-fixture scenarios run in both integration and release selections. | [Makefile](../../Makefile), `test-int` and `test-release`; [binary helper](../../test/e2e/cli_integration_test.go) | Determine which executions prove different build/artifact claims before changing membership. Retaining justified overlap is acceptable. |

### Review observations

The 2026-10-29 review queried Gaori's `gaori-command-stats.v1` for the newest
20 retained completed standalone observations per command, without a revision
filter. The full command had 15 observations. Each query reported two skipped
records. The following distributions contain successful executions only.

| Command | Successful observations | Returned median, milliseconds |
|---|---:|---:|
| prepare | 20 | 14711 |
| unit | 17 | 2331908 |
| integration | 17 | 401156 |
| release | 20 | 82659 |
| e2e | 18 | 130735 |
| full | 9 | 2600692 |

The command samples span different revisions and dates. Their medians must not
be added or used as the before/after performance baseline. These are review
observations for prioritization, not retained acceptance evidence or a
statement about the current candidate's reliability.

At the planning baseline, one selected
`TestApplicationHelpAndUsageOutput` run passed in 4.949 seconds with `-race`
and 0.972 seconds without it, both with `-count=1` and a two-minute test
timeout. These single observations are not a fixture-reuse comparison and do
not identify the complete cause of the difference.

## Scope boundaries

Preserve public CLI/MCP contracts, schemas, exit codes, provider routing and
permissions, production validation, publication integrity, cancellation,
credential and filesystem isolation, supported historical consumers and
release obligations.

Keep the existing unit/integration/E2E categories. Existing complete
unit/integration targets retain race instrumentation, package serialization
and fresh test execution. Focused commands remain available during iteration.

Do not introduce a generic fixture framework, benchmark service, automatic
test-selection engine, new evidence format, new review loop or new
architecture checker. Do not change global Aquarium skills or Podway
procedures, provider settings, installed binaries, accounts, release versions
or historical fixture bytes for this cleanup. Do not rename tests solely to
move cost out of a reported category.

The ordinary integration build-cache change does not weaken the isolated
cache roots required by [release design gates](../gating-rules.md). Product
validation under `internal/app/validation` is not a development-harness
removal target.

## Task delivery

Execute TASK-070 through TASK-074 in the roadmap's sequence. Each Task after
TASK-070 depends on its predecessor. Keep Task evidence scoped to its changes;
TASK-074 owns the final complete offline backstop.

### TASK-070: Establish proportional verification entry points

Implement `make test-offline` as a thin sequential aggregate of
`test-prepare`, `test-unit` and `test-int`. Preserve existing individual
target semantics. Keep `make test` as the full gate, executing those offline
stages once and then release, mandatory live and conditional opt-in stages.

Update `AGENTS.md`, implementation guidance and the planned policy page in
the same change. Their completion language must distinguish focused Task
evidence, integrated offline evidence and release certification. Remove the
planned-command notice only when the target, command mapping and guidance
agree. The accepted `v0.1.26` five-provider release obligation remains explicit.

Add an optional `offline` command to the [Gaori configuration](../../.gaori/tester.yaml)
with `command: ["make", "test-offline"]`, and document `gaori run offline`
alongside the existing configured commands. It invokes the same gate; Gaori
remains optional and adds no second execution or acceptance step.

Adjust only the existing meta-assertions needed for this command change;
TASK-073 owns broader assertion cleanup. Use the existing harness to verify
stage membership, order, single execution and failure short-circuiting.
A failing offline stage must prevent later stages, and the offline target
must not enter release or provider execution. A dry-run alone does not prove
failure propagation.

Capture the focused performance baseline described below before changing
fixtures or cache policy. Record the selected checks and reuse policy in the
existing Task plan/handoff so a handler does not invoke the full offline suite
after every Task. Activation requires the Makefile and instructions together;
the planning registration does not waive the currently active gate.

Verification: affected architecture/harness tests, bounded command inspection,
failure-path controls, Gaori command-mapping and guidance consistency,
document/link checks and `git diff --check`. Validate
the new orchestration with stubs where appropriate; reserve a complete real
offline execution for TASK-074.

### TASK-071: Reuse immutable compiled test assets

Start with `newFoundationFixtureWithWriter` and its G006/doctor/CLI consumers.
Confirm Catalog defensive-copy behavior and shared-use safety of the compiled
Schema and regexp object graph, including lazy state. Choose the smallest
package-local reusable fixture. If a component cannot safely be shared, keep
it fresh and report the remaining cost.

Have `newG006FixtureWithWriter` and `newFoundationFixtureWithEvidence` obtain
the shared assets directly so each wrapper constructs its `Application` and
Git reader once. A small package-local asset accessor is sufficient; preserve
the helpers' separate mutable dependencies.

Return initialization errors normally and let each test handle them. Do not
retain a caller's `*testing.T`, context or cleanup-owned resource in shared
initialization. Preserve separate writers, IDs, clocks with mutable state,
repositories, native homes and other mutable state.

Constructor cancellation, corrupted or altered Catalogs and Schema failures
still use fresh construction. Preserve result bytes, error classes and
independent returned data. Do not replace a real-schema assertion with an
unconditional-success fake to reduce runtime.

Verification: the selected CLI baseline cases with identical flags, affected
fixture consumers, existing Catalog/Schema constructor and defensive-copy
tests, and relevant concurrent consumers under `-race`. Extend the approach
to another package only when an observed repeated setup has the same clear
lifetime and safety properties.

### TASK-072: Reuse test compiler caches

Remove the per-build empty-cache policy from ordinary Mulgae and fake-provider
integration builds. Use the existing compiler cache or one controlled cache
shared for the appropriate suite lifetime. Keep offline module settings and
per-test output binaries, native-home linker overrides, repositories and
provider state.

Compiler-cache reuse is the required optimization. Sharing binaries or native
homes is optional and should be omitted if its lifetime proof expands the
Task. Keep cleanup restricted to owned temporary artifacts; never remove a
developer's shared cache or provider state.

Verify at least two independent fixture builds can reuse compilation
artifacts while their mutable outputs remain distinct. Preserve the
instrumentation distinction between a race-instrumented test process and a
child executable built without `-race`.

Verification: matched representative integration commands, affected CLI/MCP
fixture consumers, failed-build and cleanup controls, and affected
release-harness checks. Preserve the production installed binary versus
isolated native-home fixture distinction.

### TASK-073: Simplify brittle assertions and assess repeated scenarios

Remove ordinary-sentence/newline matching, unnecessary helper-name tokens,
hardcoded release-version repetition and exact textual occurrence counts.
Retain public grammar, legacy-path rejection, identifiers, schema inventory,
dependency direction, security, failure propagation and cleanup behavior.
Preserve mandatory live checks' failure and no-skip behavior without requiring
the current source-token assertions.

For each affected requirement, identify existing behavior coverage or explain
why the removed assertion only constrained presentation. This can be a short
review note in the existing handoff. It is not a new registry or a demand for
one replacement test per removed assertion.

When removing the duplicated `RELEASE_VERSION` assertion, update the patch-only
release guidance in `AGENTS.md` and the manual release steps in
[implementation guidance](../implementation-tips/README.md) in the same change.
Describe the surviving version checks; preserve waiver eligibility and exact
installed-binary version verification.

Inspect a test's behavior before changing it. For example,
`TestCatalogDocumentationContract` exercises Catalog behavior despite its
name. Keep the behavior. Keep architecture checks that enforce the intended
dependency direction and the release tests that protect destructive cleanup.

At the planning baseline, both `test-int` and the seven isolated-fixture
checks in `test-release` use binaries with `buildNativeHomeOverride`.
Compare `-trimpath`, version/revision linker inputs, test-process
instrumentation, fixture lifetimes and isolation. The production installed
`GOBIN` binary has separate checks. Assess whether the differences justify
all seven repeated scenarios or a smaller selection.

Remove execution only when the same applicable claim already has current
evidence in the selected gate. A conclusion to retain distinct checks
satisfies this assessment. Do not require a scenario deletion count or change
installed-binary assertions to accept the isolated fixture.

Verification: affected assertion owners and the behavior checks they protect.
If target membership changes, exercise that target and its failure
propagation. A real unresolved coverage gap blocks removal of that assertion,
not unrelated cleanup.

### TASK-074: Verify the integrated improvement and promote guidance

Run the matched focused measurements against the final candidate. Show which
repeated construction or compilation was removed, observed times and any
remaining cost. Do not infer an improvement from different flags, reduced
coverage or unrelated historical samples.

Run `make test-offline` once on the final integrated candidate on native
Apple Silicon macOS and `make test-release` for the affected build/release harness. Reuse Task evidence
only for the claim and inputs it still covers. A correction requires the
invalidated checks to run again; it does not automatically restart every
check. Broaden if a shared change or unresolved failure invalidates the whole
result.

After TASK-070 activates the policy, this harness-only Epic does not need a
routine live-provider campaign. Report live checks as unexecuted and retain
the mandatory release and `v0.1.26` five-provider requirements. Unexpected
production/provider changes require a reconciled scope and the relevant
existing checks, without expanding this Epic into provider development.

Promote implemented policy, fixture/cache lifetime rules and concise measured
outcomes to their canonical owners. Reconcile indices and the roadmap, retire
this dossier at closeout, and prepare the explicit Epic acceptance handoff.
Child completion does not complete the Epic automatically.

## Measurement procedure

Use existing commands and their output. Record the exact source revision and
dirty delta when applicable, Go version, native platform, flags, selected
tests and cache condition in the existing Task notes. Keep full logs local.
Promote an evidence package only if a downstream consumer requires retention.

The initial focused selection is:

```sh
go test -p 1 -race -count=1 ./internal/entrypoint/mulgae -run '^(TestApplicationHelpAndUsageOutput|TestApplicationG006FailureParityAcrossCommands)$'
go test -p 1 -race -count=1 ./test/e2e -run '^(TestIntegrationIsolatedReleaseFixtureProjectContext|TestIntegrationIsolatedReleaseFixtureVerifiedWorkflow)$'
```

Use native Apple Silicon macOS for these existing fixture tests. Confirm the
named tests execute. Keep the selected commands, flags and relevant
environment comparable before and after each optimization. Account for
`MULGAE_E2E_BINARY`: an inherited override can bypass the build helper being
measured. Do not change or use a user's active provider home as a fixture.

For compiler-cache work, state whether the comparison uses the existing
warm cache or a controlled cache shared by the selected builds. Observe the
first build and reuse across subsequent builds; a warm/cold change alone is
not evidence about test-result caching or production speed.

The focused CLI selection still creates Git roots with `git init` and
`git commit`. Shared compiler caches still leave per-fixture native-home
linker inputs and generated fake-provider code. Account for that work when
interpreting timings; it does not require a separate profiling step or broader
optimization. Do not rank these remaining costs without measurement.

One matched before/after observation plus evidence that repeated setup was
removed is the initial measurement budget. Repeat only to resolve ambiguous
results or interference from a failure. No percentile target, arbitrary
percentage reduction or repeated full-suite benchmark campaign is required.
Investigate a regression before claiming an improvement; if noise prevents a
timing conclusion, report that limit alongside the confirmed work removed.

The historical medians above justify priority. They are not acceptance
thresholds. The final complete offline run establishes broad correctness; its
runtime may be reported without claiming a matched full-suite speedup.

## Evidence reuse and known failures

Keep related successful evidence through a correction when its source,
inputs and assumptions remain applicable. Describe invalidation in the
existing review or Task notes. Use the selected workflow's existing review
authority and records; add no mandatory reviewer rounds or telemetry.

DF-028 remains open. If its protected-directory failure occurs, preserve the
failure and use its existing diagnosis guidance. Do not relabel it as a pass,
loosen `unsafe_source`, or rerun repeatedly until a green result erases the
failure. Resolve or explicitly disposition it under the applicable authority.
DF-029 remains with its current owner; a fixture touched by this Epic must
avoid retaining or calling a particular test's fatal handler from shared
initialization or worker goroutines.

## Completion and canonical owners

Epic acceptance in the roadmap requires:

- Removed repeated setup with comparable observations and preserved behavior.
- The offline/full-gate distinction implemented consistently, with one final
  complete offline backstop and affected release-harness evidence.
- Mutable fixture isolation, constructor-negative controls, historical
  compatibility, dependency direction and trust boundaries preserved.
- Brittle assertions reduced for a stated reason; retained scenario overlap
  explained without inventing a deletion quota.
- Release obligations and unexecuted live checks reported accurately.
- Durable guidance promoted and explicit Epic acceptance recorded.

| Durable outcome | Owner |
|---|---|
| Entry points, optional Gaori aliases, scope selection and evidence reuse | [Development verification policy](../implementation-tips/development-verification.md), [implementation guidance](../implementation-tips/README.md), [AGENTS.md](../../AGENTS.md), [Makefile](../../Makefile) and [Gaori configuration](../../.gaori/tester.yaml) |
| Test asset and compiler-cache lifetime rules; concise measurements | [Development verification policy](../implementation-tips/development-verification.md) and nearby test helper comments |
| Unresolved independent work | Existing [deferred-feedback index](../deferred-feedback/README.md), without moving required acceptance work there |
| Delivery and acceptance | [Roadmap](../roadmap/README.md#epic-015-development-verification-simplification) |
