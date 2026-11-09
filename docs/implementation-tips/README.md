# Implementation and release guidance

## Requirements

- macOS on Apple silicon for the complete release gate
- Go 1.27.1 or newer
- Git
- a ZCode app bundle with a current Z.AI Individual Coding Plan connection for
  the mandatory live tests, plus an authenticated Grok installation for
  `make test-grok`
- an authenticated primary Codex home only for the opt-in profile E2E

Codex provider execution requires CLI 0.154.0 or newer for the app-server
route. The separate Codex MCP-client compatibility check retains its own
minimum version.

Grok provider execution requires CLI 1.0.34 or newer. Version 1.0.40 is the
latest release verified for the exact ACP model and reasoning-effort selection
contract; later versions remain eligible but require current qualification.

ZCode app 3.12.3 is the minimum and currently verified app release for the app-owned
Electron plus bundled `zcode.cjs app-server --stdio` route. That bundle's
launcher reports protocol version 0.16.5; provider qualification observes that
launcher value, so its minimum and verified-latest guidance remain 0.16.5.
App releases above 3.12.3 and launcher protocol releases above 0.16.5 remain
eligible as `newer_than_verified`; the two version axes are never substituted.

## Verification simplification

[EPIC-015](../roadmap/README.md#epic-015-development-verification-simplification)
delivered the [development verification policy](development-verification.md),
including `make test-offline`, `gaori run offline`, proportional verification
guidance, shared immutable CLI test assets, reused integration compiler caches,
and assertion simplification.

## Local checks

The complete release gate is:

```bash
make test
```

It runs `make test-offline` once (generators and static checks, serialized
race-instrumented unit tests, and serialized race-instrumented integration
tests), followed by `make test-release`, one exact-binary two-role live
review, and independent live capability certification for ZCode. The
live review routes `logic` and `security` to ZCode concurrently, accepts
one Markdown report from each role without repair or structured extraction,
and requires Mulgae to publish one complete reports-only review. Each role must
reproduce a fresh marker stored only in its original source file, never the
objective, so a report that merely claims it could not read the target does not
certify original-source access. The complete gate then invokes the opt-in Codex
profile target, which reports a stable skip unless `MULGAE_E2E_OPT_IN=1` is
present.

`make test` rejects `MULGAE_TEST_INSTALLED_BINARY`,
`MULGAE_TEST_SOURCE_COMMIT` and `MULGAE_TEST_PREPARED_MANIFEST` overrides.
Separately authorized [sealed guest owning targets](../../test/vm/README.md)
require all three together and record the supplied source label plus executable
and manifest SHA-256. A source label alone cannot relabel a worktree build;
the sealed request remains responsible for candidate provenance.

The complete deterministic offline development gate is:

```bash
make test-offline
```

It runs `test-prepare`, `test-unit`, and `test-int` once each in order and
stops on the first failure without invoking release or live-provider targets.

The mandatory live gate uses its existing bounded whole-review retry helper.
The separately authorized EPIC-008 requirements demonstration must use one
start outside that helper and outside Make's `^Test(E2E|Live)` selection. Persist
its exact request, binary/source/input identity and admitted budget before the
native effect; an uncertain result permits only reconciliation of that operation.

For task-owned verification, `MULGAE_E2E_FUNCTIONAL_EVIDENCE_DIR` may name an
existing canonical mode-`0700` directory. The mandatory helper writes exclusive
per-attempt start, terminal and, when P2 exists, publication metadata there,
preserving failed attempts, actual exits, typed reasons, source/binary digests
and invocation counts.
It exports no objective, provider transcript or diagnostic prose. With the
variable unset, the helper's execution and retry policy is unchanged.

Vulnerability scanning is separate from `make test` and `make test-prepare`.
Run it manually with the module's declared tool:

```bash
go tool govulncheck ./...
```

The scan reports findings independently of the test gate. Passing `make test`
does not establish that the vulnerability scan passes.

Independent live capability certification failures preserve the exact request,
nonempty version/capability stdout and stderr, and process exit metadata in a
private `mulgae-capability-failure-<family>-*` temporary directory. The failure
log prints that directory; the secure writer drops credential-bearing streams.
These diagnostics survive fixture cleanup and are local evidence, not published
review artifacts. `launches=2` means version plus capability, not two retries.
Inspect this evidence before attributing a binding mismatch to provider load or
to a Mulgae decoder defect; successful reruns alone do not establish stability.
The mandatory `make test-e2e` capability filter also runs the offline checks for
private evidence permissions, credential screening, and failure guidance.

Smaller targets are available while iterating:

```bash
make test-offline
make test-prepare
make test-unit
make test-int
make test-release
make test-e2e
make test-e2e-opt-in
make test-grok
make test-cursor
make test-agy
make test-mcp-clients
```

`make test-release` first installs the production binary with only the public
version and revision link flags and checks that exact installed artifact through
`internal/releasecheck`. It separately builds an isolated live-source
fixture with the test-only native-home override. The fixture exercises original-source admission, lifecycle and verified reads
with read-only CLI/MCP project-context parity without reading the operator's real
home; it is not the installed release
artifact and does not replace the releasecheck evidence.

For guarded-admission changes, run
`TestIntegrationIsolatedReleaseFixtureGuardedAdmission` in `./test/e2e` against
the isolated release fixture. It checks independent CLI/MCP project binding,
provider-free preflight and no-change, guarded foreground and start/await
execution, distinct repeated starts, rejection of retired selectors/guards
before providers, and integrity failures after a process restart.
`make test-release` includes this fixture. It uses a fake provider and does not
replace mandatory live gates.

`make test-grok` builds the exact current release binary, runs independent live
Grok capability certification, and runs one authorized Grok review through
ACP v1. The isolated review fixture enables structured extraction and disables
repair. It requires exactly one initial review and one successful extraction
on the same attempt and provider, with successful extraction diagnostics and
a structured public result. A source-only marker, original source/Git,
authentication and executable hashes, and removed runtime roots check the
surrounding boundary. The target retains a private physical temporary directory
so a failure cannot erase an uncertain process's protection files.
It uses `MULGAE_E2E_GROK_EXECUTABLE` when set and otherwise discovers
`grok` on `PATH`. The target requires an already authenticated installation,
does not modify native Grok configuration, and is the standalone Grok live
provider gate outside `make test-e2e`.

Grok may report zero-tool MCP initialization before its `session/new` response.
The adapter retains that notification's session identity after authentication and
requires it to match the response before prompting. Missing or nonzero tool
counts, conflicting identities and initialization before authentication fail
closed; native MCP servers and tools remain disabled.

`make test-cursor` builds the exact current release binary and runs one Cursor
review. It requires `darwin/arm64`, `CURSOR_AUTH_TOKEN`, and an absolute
executable in `MULGAE_E2E_CURSOR_EXECUTABLE`. The executable's version line
must match `YYYY.MM.DD` followed by a hyphen and
lowercase hexadecimal, with a padded month and day. The target is not part of
`make test`. A missing or unsafe prerequisite fails the target.

`make test-agy` builds the exact current candidate release binary with the
release version and HEAD revision linker values. It requires `darwin/arm64`,
the installed `agy` (or `MULGAE_E2E_AGY_EXECUTABLE`) and the OS user's existing
default Gemini token. It first runs the installed CLI's six native command
controls: the default-agent MCP baseline, the paired isolated-agent read,
the guarded read without disclosing the guard in its prompt, and appended,
fallback and bare-command denial. The controls bind the observed version and
executable digest for that run, accept the supported minimum `1.2.9` and newer,
and stop at the first failed or inconclusive control. The target then performs
one documentation review, with model and effort omitted, and no automatic
whole-review retry. A source-only nonce in a
parenthesized path proves a real source read. The gate checks one initial
invocation, native protocol closure, public status/inspection/report/export,
unchanged original source/Git/token, and removed invocation runtime roots.
Qualification is part of that review; the command controls issue no production
qualification authority. The gate neither requires nor validates a second account.

AGY 1.5.3 reports native file reads as `read_file` with a `Path` operand in
canonical tool events. The adapter also accepts the earlier
`view_file`/`AbsolutePath` format. Both use the same workspace-only source
admission, credential protection and start/completion checks. Qualification and
extraction remain prompt-bound and admit no file-read operation.

The Make target retains its private fixture, exact binary hashes and candidate
diff/untracked-file hashes under the selected temporary directory on success
or failure. Inspect those local artifacts before cleanup, especially after
uncertain drain. Runtime data is not durable tracked evidence. A dirty candidate
build is an exact tested candidate, not an exact committed release claim.
This target is separate from `make test`. The mandatory live E2E
gate explicitly selects ZCode, so optional AGY discovery cannot add a
second provider or change that gate's two-role assertions.

`make test-e2e-opt-in` is called after `make test-e2e`, but performs no provider
discovery or execution unless `MULGAE_E2E_OPT_IN=1`. When enabled it runs one
three-role exact-binary review in which Codex profile `primary` owns `logic`,
`security`, and `documentation`. Supply the primary credential root
explicitly; the profile name is a test alias and does not prescribe the
directory name:

```bash
MULGAE_E2E_OPT_IN=1 \
MULGAE_E2E_CODEX_PRIMARY_HOME=/absolute/path/to/primary-codex-home \
make test-e2e-opt-in
```

Override executable discovery with `MULGAE_E2E_CODEX_EXECUTABLE`. Once enabled,
missing credentials, qualification
failure, invalid provider output, wrong role routing, publication failure, or
credential mutation fails the target; the Go test never converts these states
to a skip. This optional result does not replace mandatory ZCode
certification.

`make test-mcp-clients` is a registration-only local compatibility check and is
not part of `make test`. It builds the exact current Mulgae binary, isolates client
configuration in temporary directories, verifies that installed Codex can
initialize Mulgae as a required MCP server, validates the observable Codex
`mcp get mulgae --json` fields, and verifies that installed Claude Code reports
the server as connected. The Codex check preserves an absent `required` field
as unobserved rather than interpreting it as `false`. Override client paths with
`MULGAE_MCP_CODEX_BINARY` and `MULGAE_MCP_CLAUDE_BINARY`. The installed-client
check does not expose or assert either client's discovered tool catalog. It also
does not invoke a model or provider, mutate user client configuration, or prove
a live review; deterministic MCP tests cover tool discovery, calls, resources,
progress, and cancellation.

`make test-mcp-requirements-clients` is the separate opt-in public-read check.
It reuses that build recipe with both `mcpclientcheck` and
`requirementsclientcheck` tags. Codex uses its native app-server MCP tool/resource
APIs on an ephemeral thread without starting a model turn. Claude uses existing
authentication and its configured default model to call only the allowed public
context/inspection/page tools; the invocation supplies no model or effort
override and permits no Mulgae review/start/cancel/preflight call. It therefore
has model/client effects even though its Mulgae reads call no provider.

The check compares every requirement page and its receipt/counts/origins with
independent CLI reads. Codex resource bodies must also match each CLI-verified
item's declared content digest and byte length. Claude's native event stream
must correlate each permitted tool use with its real public result; final model
text alone is insufficient. The selected Claude route certifies metadata pages,
not native resource reads. Neither route certifies a long await or a release
lifecycle. The preliminary paths were exercised with Codex 0.164.0 and Claude
Code 2.1.312; connection minimums do not promise these client-specific APIs.

By default the new check creates isolated provider-free no-change publications.
For the authorized same-result certification, `MULGAE_MCP_REQUIREMENTS_FIXTURE`
may name a private JSON pointer containing `project_root`, `run_id`,
`project_binding` and `publication_receipt` for the existing publication.
With that pointer, the check only reads the existing publication.
`MULGAE_MCP_CLIENT_EVIDENCE_DIR` retains compact native
call/page metadata when requested; it contains no client transcript. Keep all
fixtures and outputs task-owned and remove unused builds after their last reader.

Release evidence for the lifecycle workflow additionally requires separately
authorized, exact-client model runs against an isolated or read-only project
target. Each supported client must discover all three lifecycle tools, call one
`start_review`, keep one `await_review` pending through a meaningfully long live
review, and inspect the exact terminal run. The client event stream must show no
assistant/model message or second tool call between the await start and its
terminal result. Host-rendered progress events are permitted observation and do
not count as model turns. Record client versions, target SHA-256, invocation and
run identities, elapsed await behavior, publication/coverage state, and finding
count without committing client transcripts or `.mulgae/` artifacts.

The integrated review fixture uses independently maintained consumer
decoders and frozen response projections under `test/e2e/testdata/verified-consumer/`.
Keep these fixtures outside the producer generators: changing a public envelope
must require a deliberate consumer compatibility decision. The release fixture
connects project lookup, original-source admission, one start/await pair,
coherent inspection and complete report/evidence reads. It checks no-change
provenance, source selection identity and absence of source archives. Frozen
historical projections preserve their original envelopes; the owning query
tests establish historical artifact integrity. Current envelopes pass through
an independently updated consumer, including command-result v23, preflight v11
and live-source/source-evidence capabilities.

For actual client checks, use invocation-only MCP configuration and existing
authentication with a disposable project. A transparent stdio recorder may
capture discovery and request/response boundaries without changing messages.
Combine that protocol evidence with the client's own timestamped event stream;
protocol logs alone cannot prove that the model remained idle during await.
Record resource access separately when a client exposes tools but no resource
reader. The native CLI fallback does not certify that client's resource support.

### Optional Gaori evidence compression

Gaori can wrap long or noisy local test commands so coding agents and developers
can inspect bounded summaries before opening complete logs. It does not replace
the Make targets above or change their pass/fail result.

Use the locally installed Gaori without enforcing a specific version. Portable
configuration lives in the tracked `.gaori/tester.yaml`; evidence and
machine-local state remain ignored below `.gaori/`. The repository configuration
defines these commands:

| Command ID | Wrapped command | Parser | Tags | Timeout |
|---|---|---|---|---:|
| `prepare` | `make test-prepare` | `generic` | `go`, `static` | 3,600s |
| `unit` | `make test-unit` | `go-test` | `go`, `unit` | 6,000s |
| `integration` | `make test-int` | `go-test` | `go`, `integration` | 6,000s |
| `offline` | `make test-offline` | `generic` | `go`, `offline` | 15,600s |
| `release` | `make test-release` | `generic` | `go`, `release` | 1,800s |
| `e2e` | `make test-e2e` | `go-test` | `go`, `e2e`, `live` | 11,400s |
| `e2e-opt-in` | `make test-e2e-opt-in` | `go-test` | `go`, `e2e`, `live`, `codex`, `multi-profile` | 7,200s |
| `grok` | `make test-grok` | `go-test` | `go`, `e2e`, `live`, `grok` | 6,000s |
| `full` | `make test` | `generic` | `go`, `full`, `live` | 28,800s |

Use argv arrays for the wrapped commands and configure these RE2 redaction
patterns for derived evidence:

```yaml
redaction:
  patterns:
    - name: credential-assignment
      regex: '(?i)\b(authorization|api[_-]?key|token|secret|password)=\S+'
      replace: '$1=<redacted>'
    - name: bearer-token
      regex: '(?i)(Bearer)\s+\S+'
      replace: '$1 <redacted>'
```

Run a configured command from the repository root, for example:

```bash
gaori run unit
```

For a focused Go test that is not configured, select the parser explicitly:

```bash
gaori run --parser go-test --tag go --tag unit -- \
  go test -count=1 ./internal/app/reviewrun -run '^TestQualifiedPlanner'
```

Gaori emits no running heartbeat. A long period without console output can be
normal for the serialized race and live-provider targets. After a pass, use the
compact status and do not open logs by default. After a failure, inspect the
Markdown summary, structured summary, and bounded excerpts in that order. Open
only the necessary portion of the raw log when extraction is insufficient or
degraded: raw logs are preserved without redaction and may contain secrets.

If Gaori is unavailable, run the corresponding Make target directly and report
that evidence compression was unavailable. Never skip a required check because
its optional wrapper is unavailable.

## Review request compatibility controls

The request characterization tests keep literal expectations for CLI and MCP
behavior. They cover objective byte boundaries (12000 for CLI, 4096 for public
MCP), multibyte input, omitted and explicit roles, and competing invalid inputs.
Malformed binding combined with newline or leading-`--` objectives exercises
the different validation order at the public MCP handler and backend mapping.
Call counts distinguish entrypoint rejection from a dispatched backend request
that fails before review execution. Keep those boundaries when changing a
transport; moving every rejection to the first validator changes behavior.

`reviewrun.TestReviewRequestAdmissionCompatibility` checks configured selection,
artist defaults and overrides, repeated automatic selection, and ownership of
mutable input slices. Existing live-service no-change tests retain admission
and publication checks with zero provider qualification or review calls.
The startup and rejected-init controls cover incomplete tool configuration and
unambiguous JSON intent, including duplicate and mixed output flags. MCP identity
and lifecycle controls check the actual SDK-facing errors; result controls
measure encoded envelopes at, below and above both output limits.

The frozen verified-consumer fixtures remain independent decoder compatibility
samples. They do not freeze complete producer failure envelopes. Preserve those
fixtures and run the request/output controls alongside them. Characterization
establishes current behavior before movement; an intentionally changed behavior
needs a separately identified regression and its intended-behavior source.

Run each focused command on one physical line:

```sh
go test -count=1 ./internal/entrypoint/mulgae -run '^TestReviewRequestTransportCharacterization$'
go test -count=1 ./internal/entrypoint/mulgae -run '^TestReviewPolicyRepeatedResolutionCharacterization$'
go test -count=1 ./internal/entrypoint/mulgae -run '^TestRejectedInitOutputModes$'
go test -count=1 ./internal/entrypoint/mcp -run '^TestReviewToolTransportCharacterization$'
go test -count=1 ./internal/entrypoint/mcp -run '^TestServePartialToolConfiguration$'
go test -count=1 ./internal/entrypoint/mcp -run '^TestMCPRequestIdentityAdmission$'
go test -count=1 ./internal/entrypoint/mcp -run '^TestMCPLifecycleAndResultBounds$'
go test -count=1 ./internal/entrypoint/mcp -run '^TestReviewMappingDirectCompatibility$'
go test -count=1 ./internal/composition -run '^TestMCPReviewRequestMappingCompatibility$'
go test -count=1 ./internal/app/reviewrun -run '^TestReviewRequestAdmissionCompatibility$'
go test -count=1 ./test/e2e -run '^TestVerifiedWorkflowFrozenConsumers$'
go test -count=1 ./internal/entrypoint/mulgae -run '^TestIntegrationHistoricalCorpusConsumers$'
```

## Status acquisition and failure selection controls

`runstatus.Service` acquires publication status before diagnostics. Test exact
root/run scope, original error identity, diagnostic-only fallback, unavailable
status, best-effort same-run coordination enrichment of committed reads, and
session-bound summary merging. Missing, corrupt, unsupported, unreadable or
mismatched supplementary diagnostics must not fail a valid committed P2 read.
Diagnostic projection eligibility remains a transport decision: CLI
accepts pending/running diagnostic-only status; MCP requires a completed failed
or cancelled record. A shared use case must not narrow CLI or widen MCP.

The literal operational precedence oracle is:

| Rank | Classes |
|---|---|
| 7 | internal |
| 6 | security policy |
| 5 | artifact |
| 4 | cancellation |
| 3 | configuration |
| 2 | provider unavailable, timeout, authentication, quota, rate limit |
| 1 | invalid provider output |
| 0 | unknown/default |

Use this literal ordering for all unequal-class pairs in both orders and retain
the first observation for equal-ranked ties. Do not calculate expected ranks
through the reducer being tested. Include parent-before-cause ties, nested
joins, ordinary/typed wrappers, raw leaves, empty multi-unwrap and nil
single-unwrap. CLI raw fallback is suppressed beneath a typed single cause;
each joined child is independent. MCP ignores raw leaves. Preparation,
diagnostic-persistence and invocation lifecycle controls must still exercise
their specialized public projections.

CLI status uses missing-only semantics at all three branches: publication
absence before diagnostic fallback, diagnostic absence after sole publication
absence, and session diagnostic absence during noncommitted status enrichment.
Ordinary and typed artifact wrappers around a sole missing cause, single-child
joins and missing-only joins remain eligible. For each branch, test both join
orders with artifact/security/internal, raw, cancellation and deadline siblings.
Assert the complete JSON output and reasons, human stdout/stderr, exit, and
both diagnostic lookup counts. Preserve original causes in application tests.

The authorized correction intentionally changes these public outcomes:

- Every mixed publication error now preserves the original publication error
  without any diagnostic lookup. This replaces the earlier diagnostic success,
  diagnostic failure or diagnostic projection failure. Error-to-error changes
  can alter human output and public JSON failure fields: publication absence
  joined with security, followed by diagnostic artifact failure, changes from
  artifact/exit 7 to security/exit 8; publication absence joined with artifact,
  followed by diagnostic security failure, changes from security/exit 8 to
  artifact/exit 7.
- After sole publication absence, mixed diagnostic failure now reports that
  diagnostic error instead of the earlier publication error. Reasons and exits
  may change, including artifact 7 to security 8 or internal 10.
- Mixed session diagnostic enrichment failure now returns status_failed or
  human failure instead of successful status_read/exit 0.
- Some mixed cases keep identical sanitized output and exit despite corrected
  causal handling. A cancellation sibling does not universally mean exit 9:
  raw missing leaves, typed artifact wrappers and protected siblings still
  participate in the existing precedence reducer.

`TestStatusMissingErrorCharacterization` recorded the previous three CLI
branches before extraction. Its mixed-security expectations changed under the
approved correction; the pre-change execution remains separate evidence.
`TestStatusStrictMissingOnlyRegression` was written and failed before repair,
then passed with the shared missing-only policy. Keep its pure-wrapper and
single-join controls. `TestStatusMixedPublicationFailureRegression` separately
covers both join orders when bypassed diagnostics would fail or return a valid
record for the wrong run ID. It checks the complete JSON/human output, exit and
zero diagnostic lookups against the predecessor's observed error-to-error
transitions. The correction preserves legitimate success, committed reads, MCP
behavior and the frozen verified-consumer fixtures.

DF-024 controls exercise malformed await/cancel IDs while a real session-local
invocation remains active, followed by a valid cancellation control. Generated
request-ID failures remain JSON-RPC internal errors before backend activity.
Encoded tool results exercise limit-1, limit and limit+1 directly and through
the actual SDK: 1 MiB normally, 32 MiB for inspect_review/list_findings. Every
SDK size invokes the backend once; oversized output fails after production.
Argument and incoming-frame limits remain separate.

Run each focused command on one physical line:

```sh
go test -count=1 ./internal/entrypoint/mulgae -run '^TestStatusMissingErrorCharacterization$'
go test -count=1 ./internal/entrypoint/mulgae -run '^TestStatusStrictMissingOnlyRegression$'
go test -count=1 ./internal/entrypoint/mulgae -run '^TestStatusMixedPublicationFailureRegression$'
go test -count=1 ./internal/entrypoint/mulgae -run '^TestG006OperationalFailureExitPrecedence$'
go test -count=1 ./internal/app -run '^TestFailurePrecedenceIsExactAndClosed$'
go test -count=1 ./internal/app -run '^TestFailureSelectionCompatibility$'
go test -count=1 ./internal/app/runstatus -run '^TestStatusAcquisitionCompatibility$'
go test -count=1 ./internal/app/reviewrun -run '^TestReviewPreparationClassificationDefersToDiagnosticPersistenceFailure$'
go test -count=1 ./internal/composition -run '^TestMCPBackendGetRunFallsBackOnlyToSafeDiagnosticStatus$'
go test -count=1 ./internal/composition -run '^TestMCPBackendGetRunMergesSessionBoundDiagnosticSummary$'
go test -count=1 ./internal/composition -run '^TestMCPBackendGetRunReportsUnavailableDiagnosticIdentity$'
go test -count=1 ./internal/composition -run '^TestMCPBackendGetRunPreservesSoleDiagnosticCancellation$'
go test -count=1 ./internal/entrypoint/mulgae -run '^TestStatusDiagnosticEligibilityCompatibility$'
go test -count=1 ./internal/entrypoint/mcp -run '^TestMCPLifecycleAndResultBounds$'
go test -count=1 ./internal/entrypoint/mcp -run '^TestPublicToolErrorUsesFailurePrecedenceBeforeCancellation$'
go test -count=1 ./internal/entrypoint/mcp -run '^TestMCPStatusFailureCharacterization$'
go test -count=1 ./internal/composition -run '^TestMCPStatusAcquisitionCharacterization$'
go test -race -count=1 ./internal/architecture -run '^TestProductionDependencyDirection$'
go test -race -count=1 ./internal/architecture -run '^TestMCPContractProjectionOwnership$'
go test -race -count=1 ./internal/architecture -run '^TestWireLeafDependencyDirection$'
```

Inspect new application imports directly for forbidden entrypoint, adapter and
OS dependencies. Current architecture tests complement this inspection; they
do not replace it. Keep both shared-leaf import allowlists and the historical
corpus unchanged.

## Ownership guard and relocation checks

Run the ownership roots to check dependency direction, the canonical request
alias and the MCP route. The controls cover allowed and rejected syntax,
lexical shadowing, expression boundaries and inspection failures.

Use bounded relocation comparisons for the three
[internal file boundaries](../architecture/README.md#internal-file-responsibilities). Inventory every Go file in the affected
packages, including tests and inactive or ignore-tagged files. Compare exact
declaration and comment bytes, reconstruct each original file's remainder, and
verify untouched files. Account for detached and trailing comments, directives,
package names, build headers and filename constraints. Preserve import
qualifier-to-path bindings and the import union for each activation class.
Keep package variables and init declarations in their original files and order,
including lexical initialization-file order. Stop on any unaccounted change.

Establish the relevant focused baseline before moving declarations. After each
move, run its package selection below and the whole architecture package before
continuing. Run commands from the repository root, one physical line each, and
confirm every named root executes. Exact source comparison and native checks
complement each other; these focused checks supplement the standard local gates.

Ownership guards and their controls:

```sh
go test -p 1 -race -count=1 ./internal/architecture -run '^(TestEstablishedOwnershipDependencyDirection|TestTypedReviewRequestOwnership|TestMCPParserRouteOwnership|TestEstablishedOwnershipDependencyControls|TestTypedReviewRequestOwnershipControls|TestMCPParserRouteControls|TestOwnershipInspectionFailures|TestTestSupportDependencyControls|TestTestSupportDependencyDirection)$'
```

After the query excerpt move:

```sh
go test -p 1 -race -count=1 ./internal/app/query -run '^(TestReadCommittedListFindingsAndRenderExcerpt|TestRenderExcerptUsesPersistedArtifactAfterRestart|TestRenderExcerptFailsClosedWhenPersistedArtifactIsMissing|TestRenderExcerptRejectsPersistedArtifactCorruption|TestSyntheticExcerptLayoutCapsAggregateAllocation|TestCommittedFindingAndRuntimeSourcesBindEveryAuxiliaryDigest|TestCommittedFindingAndRuntimeSourcesRejectMissingTamperedOrReboundArtifacts|TestHistoricalCorpusRead)$'
```

After the filesystem document move:

```sh
go test -p 1 -race -count=1 ./internal/adapters/filesystem -run '^(TestPublicationJournalWireRejectsDuplicateUnknownAndTrailingJSON|TestPublicationSchemaSelectionPreservesArtifactFamily|TestSupportIndexDecoderDiagnostics|TestPublicationStorePreparesCommitsAndRecoversFromDisk|TestPublicationStoreResumesExactPersistedCompositeMembers|TestPublicationStoreRejectsRecoveryAmbiguityAndDestinationCollision)$'
```

After the CLI doctor move:

```sh
go test -p 1 -race -count=1 ./internal/entrypoint/mulgae -run '^(TestDoctorV7Characterization|TestDoctorProvidersConformanceCompatibility|TestProvidersCharacterization|TestDoctorProvidersNativeHomeReplacementRegression|TestDoctorProvidersNativeHomeCancellationProjection|TestLocalDoctorHumanOutputIsANSIFreeAndUsesFixedInventory)$'
```

After each move:

```sh
go test -p 1 -race -count=1 ./internal/architecture
```

## Changing embedded assets

Runtime assets live in `internal/builtin/assets` and are embedded directly.
There is no `assets.zip` build product. The role document is the one exception
to the location: `assets/roles.yaml` sits at the repository root so the tunable
role defaults are discoverable, and is embedded by the root `assets` package
because a `go:embed` pattern cannot escape its own package directory.

The checksum generator follows the `go:embed assets` directory rule: files and
directories whose names start with `.` or `_` are excluded at every depth.
Excluded directories are not traversed, so local tool state inside them cannot
enter the checksum inventory. Included assets must remain regular files; symbolic
links and other non-regular entries are rejected.

```bash
go generate ./internal/app/init
go generate ./internal/builtin
```

The first generator maintains init schema sections and golden data. The second
validates the role document and regenerates `CHECKSUMS.sha256`, which covers the
embedded tree *and* the root role document. The order matters: the first writes
into the tree the second checksums. Running both twice must leave the worktree
unchanged. Every schema needs exactly one paired valid example, plus semantic
tests in the owning application package.

## Contribution checklist

- Keep dependency direction intact; external behavior belongs behind a port.
- Preserve project-local and provider isolation boundaries.
- For provider-concurrency changes, prove overlap with separate coordinators
  and registries and with two release-binary processes sharing the applicable
  runtime environment. Cover both legacy runtime-root discovery branches when
  proving that the removed global filesystem namespace is not recreated.
- Keep publication tests separate from provider-execution concurrency: prove
  different project roots publish independently and a same-root filesystem-lock
  waiter honors cancellation or deadline without mutating committed artifacts.
- Preserve canonical failure precedence in cancellation tests; test pure
  cancellation independently from cancellation joined with artifact, security,
  or internal failures.
- Add negative fail-closed tests, not only success tests.
- Update affected versioned contracts and docs with user-visible behavior.
- Keep unrelated changes out of the commit.
- Run the complete gate before release.

## Verification for the adopted review Epics

Native boundary fixtures require canonical directory paths. Resolve owned
`t.TempDir` and `os.MkdirTemp` roots with `filepath.EvalSymlinks` before passing
them into descriptor admission; the default macOS `TMPDIR` commonly traverses
the `/var` alias. After changing these fixtures, check the affected tests with
the inherited `TMPDIR` and a custom symlinked temporary parent, then run the
complete gate. A pass using only a short canonical `TMPDIR` does not verify the
default environment.

For TASK-064's provider-mechanics extraction, keep the class controls
`TestProtocolStringResponseMatches`, `TestProtocolDiagnosticIdentifierGrammar`,
`TestLiveReadPlanMechanics` and `TestProviderToolDiagnosticOrder` alongside the
existing family tests. Characterize the original methods before extracting
them. Diagnostic grammar checks include byte and Unicode boundaries; command
and path checks preserve family normalization, original errors and admission
counts. Native admission must read no file bodies, while evidence reads retain
content validation.

The diagnostic-order regression admits completed reads before synchronously
invalidating their targets, then invokes the final protocol response handler.
It compares literal raw-ID admission order and the selected diagnostic across
both insertion directions and a fixed 64-trial corpus. Only a wrong-order
observation with unchanged typed refusal establishes the pre-repair failure;
setup, EOF or unrelated failures do not. An all-green pre-repair corpus is
inconclusive. Preserve Grok's late close-time updates, Cursor permission and
ask-phase controls, AGY permission codecs and natural exit, and ZCode's
post-turn stream-end acceptance. Run focused checks and completion gates
serially in the native default environment; scripted and compile-only checks
do not certify deferred non-ZCode live behavior.

EPIC-013 proves its reuse rules with deterministic counts and call traces,
never timing. Count digest, defensive-copy, construction and whole-support
traversal work through the disabled-by-default in-package seams
(`beginVerificationCounting` in `internal/ports`, `beginPublicationCounting`
in `internal/app/publication`) or through a package's own port fakes and
counting helpers, such as `supportIndexReads`, `liveCommandCount`,
`executionConfigParses` and `countingLiveSource`. Do not export test-only API
to read another package's seam, and recheck count-armed tests whenever a
change alters a count they assert. Resolve each task-owned temporary root
once, at creation, through one helper such as `canonicalTestRoot`. A
concurrency control first proves that the code under test ran, for example
with synchronized rounds before a racing `Close`; it proves overlap with
barriers that have bounded escapes, and mutual exclusion with a deliberately
unsynchronized cell inside the guarded section, which `-race` reports if two
guarded sections overlap. Benchmarks, percentiles, speedup estimates and
memory-peak gates are not acceptance evidence. Cross-version certification
runs the baseline and the candidate binary against the same frozen harness
and fixtures and compares normalized public outputs, stored members and
recovery outcomes.

EPIC-009's internal neutral execution fixtures live in
`internal/adapters/providercli` under the `liveprovider` build tag. The focused
groups `TestLiveNeutralReviewReports`, `TestLiveNeutralExtractionReports`,
`TestLiveNeutralReviewConcurrentCancellation`,
`TestLiveNeutralCredentialBoundary`, `TestLiveZCodeNeutralKernelProtection`
and `TestLiveGrokNeutralKernelProtection` exercise actual native providers in
disposable source and reviewer-home fixtures. Supply the explicit supported
Codex executable and home through `MULGAE_LIVE_CODEX_BIN` and
`MULGAE_LIVE_CODEX_HOME`; the EPIC-009 baseline is CLI 0.156.0. Select an exact
group with an anchored `-run` expression and an explicit package. Never use the
operator's project or provider state as the disposable target.

Run the complete focused set explicitly after supplying those Codex variables:

```bash
go test -count=1 -tags=liveprovider ./internal/adapters/providercli \
  -run '^TestLive(Neutral(ReviewReports|ExtractionReports|ReviewConcurrentCancellation|CredentialBoundary)|(ZCode|Grok)NeutralKernelProtection)$' -v
```

Credential fixtures contain generated test text. ZCode requires actual Bash
failure receipts. Its separate kernel probe runs the actual ZCode executable
in Electron-as-Node mode under the exact boundary, environment and neutral
directory from production admission. Native child-process receipts verify the
five write denials and positive source/Git/guide reads and owned scratch writes;
the normal plan-mode app-server report remains a separate conversation.
Grok requires a correlated read-plan rejection through its permission handler
or completed native operation, plus the separate kernel-boundary test. A native
operation outside the plan must fail report admission even when the kernel
denies its file access. Codex's kernel probe sends sandboxed
`command/exec` through the same native server and its unchanged default
`mulgae` profile before the independently correlated assistant turn. It checks
real exit codes and direct/alias denials. Model refusal or reported denial alone
does not prove kernel enforcement. The process-adapter tests separately cover
hard links, protected ancestors, writable-root overlap and rejected root aliases.
Credential and writable-root admission tests reject existing regular-file
hardlink aliases before spawn; source hardlinks remain supported. Runner tests
cover descriptor cleanup on early returns and cancellation during admission.
Unix socket fixtures check direct and symlink-alias denial at protected source
and credential paths while an owned invocation socket remains reachable.
These focused fixtures do not replace the complete integrated `make test`
gate or the opt-in Codex certification. TASK-080 supersedes TASK-039's earlier
secondary-home requirement; the live gate now certifies the primary account.

The [verified review contracts](../specs/verified-review-contracts.md) and their
[roadmap outcomes](../roadmap/README.md#epic-007-verified-review-contracts)
retain EPIC-007's historical requirements and verification. The
[requirements assessment specification](../specs/review-completeness-and-iteration.md)
defines the implemented reduced scope. All five member Tasks are complete.
The [roadmap](../roadmap/README.md#adopted-execution-order) owns their order:
TASK-026, TASK-027, TASK-028, TASK-029, TASK-033.

Read current code and the nearest contract before each implementation Task.
Add focused behavior and negative checks using explicit Go packages and
anchored test names, then run the applicable Make targets. Contract foundations
need paired schema examples and semantic tests before production wiring.
TASK-027 exposes admission/preflight only. TASK-028 tests internal execution and
publication. TASK-029 enables public requirements-bearing execution and its
existing capability advertisement together with verified CLI/MCP reads.
Requirements-bearing execution remains unavailable before that point;
objective-only execution stays available throughout. Add no general feature flags.

Use provider/writer spies and exact-binary fixtures for the provider-free
guarantees. Preserve original-source sides, native project binding, current
provider-call ceilings and historical consumer fixtures independent of producer
generation. Embedded asset changes retain the two-pass generator requirement.

| Group | Required EPIC-008 checks |
|---|---|
| Input and assignment | Optional requirements with/without the objective; strict JSON/Unicode/IDs/owners; safe paths; safe untracked local requirements with staged/committed code differing from the working tree; admitted input bytes reused by prompts/publication; invalid input fails before qualification or no-change publication. |
| Extraction availability | Valid initial structured assessments with extraction disabled; reports preserved with explicit unverified reasons when extraction is disabled, its allowance is consumed or content is missing/invalid; no extra call/config/provider change. Preflight describes known policy, not future allowance consumption. |
| Assessment independence | Valid findings/invalid assessment and valid assessment/invalid findings retain their valid sections and primary report; omitted/duplicate/unknown/wrong-owner IDs; whole-response invalid JSON supplies no independently validated section; protected failures deny publication. |
| Counts and origin | One met, one valid provider unverified and one missing answer yield selected_count = 3 and evaluated_count = 2. Keep placeholders distinct, unknown historical counts unavailable and requirements visible through finding severity filters. |
| No-change evaluation | Every existing admitted no-change case, including empty-tree HEAD, with/without requirements; zero provider calls/attempts/reports/evaluated count; persistent unverified/no_change_target rows; invalid input still fails and an explicit new target remains separate. |
| Verified results and compatibility | No public requirements-bearing execution before TASK-029; execution/read/capability activation together; restart, receipt-bound paging, support tamper, CLI/MCP count/origin/availability parity, no current-source reconstruction, export/cleanup privacy and unchanged exits. |

TASK-026 freezes the contracts, TASK-027 admits input and preflight,
TASK-028 validates/publishes internally, TASK-029 activates execution with
verified reads and TASK-033 certifies the integrated feature. Use existing
no-change publication and historical read fixtures as compatibility anchors.
Do not restore retired
dirty/patch/stdin selectors, full capture identity, batch execution or comparison.

Run the current complete `make test` gate before EPIC-008 integrated acceptance.
Its mandatory live checks use ZCode; `make test-e2e-opt-in` retains its existing
Codex opt-in/skip policy. Other provider campaigns need their applicable
authority. Registration inspection alone is not supported-client execution
proof. Distinguish deterministic, exact-binary, actual-client and live-provider
evidence.

EPIC-008 additionally needs one explicitly authorized bounded live
requirements-bearing review through existing routes. Reuse that result for
provider-free assessment inspection. Mulgae-derived unverified placeholders alone
do not establish structured coverage. Missing structured coverage is an evidence
gap, not a successful demonstration or permission for unlimited retries.
No batch recheck, comparison demonstration, provider migration or installation
is required.

For a documentation-only scope revision, read back changed files, validate
links, IDs, membership, dependencies and requirement ownership, apply the
required final prose pass, and run `git diff --check`. No runtime gate or
provider call is needed. Planning approval establishes Planned work without
marking implementation requirements or Tasks complete.

At eventual Epic closeout, promote durable outcomes, replace Detailed SOT with
Canonical Outcomes, remove the temporary dossier and its TODO entry, repair
links and obtain explicit Epic acceptance.

Under Master's quota-preservation decision for `EPIC-012` through `EPIC-014`,
development and Epic certification run the deterministic Make gates
(`make test-prepare`, `make test-unit`, `make test-int`, and
`make test-release`), `make test-mcp-clients` when MCP consumer paths change,
and ZCode-only live verification (`make test-e2e`, which runs
`TestLiveZCodeCapability` and the two-role ZCode live review), while live
provider gates for Grok (`make test-grok`), Cursor
(`make test-cursor`), AGY (`make test-agy`), and Codex
(`MULGAE_E2E_OPT_IN=1 make test-e2e-opt-in`) are explicitly deferred to the
`v0.1.26` five-provider release gate.

### Tagged compilation and native execution

Default test selections omit files behind additional build tags. Check the
supported tagged sets from the repository root:

```sh
go vet -tags=liveprovider ./...
go vet -tags=live_e2e ./test/e2e
go vet -tags="live_e2e live_grok" ./test/e2e
go vet -tags="live_e2e live_cursor" ./test/e2e
go vet -tags="live_e2e live_agy" ./test/e2e
go vet -tags="live_e2e live_e2e_opt_in" ./test/e2e
go vet -tags=releasecheck ./internal/releasecheck
go vet -tags=mcpclientcheck ./internal/mcpclientcheck
go vet -tags="mcpclientcheck requirementsclientcheck" ./internal/mcpclientcheck
```

These commands compile and type-check the tagged source without running live
providers. They supplement the Make gates and confer no live certification.
Run native boundary checks outside nested agent sandboxes with the inherited
macOS `TMPDIR` and default build environment. Serialize gate members and all
`go test` processes (DF-028). Run each member separately, retain every exit and
continue with later members after a failure. If a recipe stops internally,
complete its remaining mandatory cases on the same frozen candidate before
correcting it.

`TestIntegrationPublicationAcceptsTenMiBRoleReport` in
`internal/app/publication/integration_darwin_test.go` publishes and reads exact
10 MiB role-report bytes with publication and query services configured at
8 MiB, then rejects same-length tampering without exposing a verified report
URI. Preserve this integrity control and the provider-content policy without a
product byte ceiling.

## Shared configuration admission controls

`internal/app/config/admission.go` owns the shared source, attestor, source
confirmation and account comparisons. Tests assert early-stop order and exact
error identity, including cancellation, and preserve the existing account
acceptance and rejection messages. Composition supplies the source, codec,
account and locality capabilities; OS lookup and `.git` inspection stay in
adapters. Application production files, including files behind build tags,
must not import OS account, filesystem or process implementations. Inspect their
imports directly as well as running the architecture guard.

Run the focused controls on one physical line per command. Keep the doctor
compatibility commands below alongside these checks: they pin the unchanged
outputs and effects while admission ownership moves. The separate Q1/Q3 controls
below cover the approved conformance corrections; no control certifies live
providers.

```sh
go test -count=1 -v ./internal/app/config -run '^(TestLocalityAdmissionSequence|TestNativeAccountAdmissionCompatibility|TestServiceResolvesCanonicalConfigV2Pair|TestBundleSHA256BindsAuthorityOrderAndBoundaries)$'
go test -count=1 -v ./internal/app/init -run '^(TestInitializeProjectRejectsExistingConfigBeforeDiscovery|TestInitializeProjectPrevalidationFailureDoesNotMutateFilesystem|TestInitializeProjectRejectsSameByteConfigIdentitySubstitution|TestInitializeProjectRequiresTerminalLocalityRevalidation|TestInitializeProjectRejectsConfigMutationAfterTerminalAttestation)$'
go test -count=1 -v ./internal/entrypoint/mulgae -run '^(TestAdmissionSequenceCharacterization|TestDoctorProvidersConformanceCompatibility|TestApplicationConfigRejectsNativeAccountAndIdentityMismatch|TestApplicationNativeHomeCancellationUsesExitNine|TestRejectedInitOutputModes)$'
go test -count=1 -v ./internal/composition -run '^(TestProductionLivePreflightPreservesIndependentBindingAndConfigIdentity|TestProductionConfigCredentialFailuresRemainSecurityFailures|TestProviderSpawnRejectsConfigMutationAfterLocalityAttestation)$'
go test -count=1 -v ./internal/architecture -run '^TestProductionDependencyDirection$'
```

## Doctor admission compatibility controls

`internal/entrypoint/mulgae/doctor_characterization_test.go` and its fixed
`testdata/task063-doctor-before.json` capture the production behavior at
`41ad32adae32bca48b898b25478368e2ea5d33c8` before TASK-063 moves admission
policy. The snapshots preserve complete command JSON, human stdout/stderr,
process exits and ordered capability callbacks. They include provider listing
with and without unverified profiles and recorded evidence.

The fixture fixes the clock, request ID, provider identities and locality
observations. Only the request's temporary project root and the doctor
configuration digest are normalized. The test checks that digest against the
admitted local file bytes before replacing it. Schema validation still receives
the original output. Expected outputs are fixed files with no update mode.

The trace records injected locality, native-home, executable, version and
recorded-diagnosis observations. Same-byte replacement around locality callbacks
checks the surrounding source confirmations through real configuration files.
These traces do not claim to instrument the concrete source's internal reads or
OS account lookup. Keep the existing native-account comparison tests alongside
the snapshots. Review composition separately checks static, preflight, target
and spawn locality order using the real configuration source.

Two groups of immutable predecessor snapshots record the defects corrected in
TASK-063. Final native-home replacement originally requested an internal exit
10, projected by doctor and providers to exit 7. Doctor JSON lost the inline
diagnosis. Cursor originally failed before launch, and the generic normalizer
rejected its complete calendar/hash tuple. `task063-doctor-before.json` retains
those bytes. Other characterization cases continue to compare with that file.

`task063-doctor-corrected.json` contains separate fixed expectations for the
12 Q1/Q3 cases, constructed from the predecessor controls and the approved
corrections. `TestDoctorProvidersConformanceCompatibility` compares the corrected
public outputs and effects.
`TestProviderVersionObserverCursorTupleAndGenericNormalization` checks one Cursor
launch, the full tuple and unchanged generic normalization. These controls now
require a complete unsafe diagnosis after final native-home mismatch and an
observed Cursor calendar/hash tuple, replacing the predecessor defect assertions.
Model and v7 schema validation are unchanged. The Q1 regression checks the complete unsafe
projection, both providers filtering modes and the earlier version observation
plus independent later evidence reads. Cursor controls use synthetic executables,
physical temporary roots, exact argv, empty cwd/home, launch markers, identity
replacement, failure/timeout precedence and complete tuple policy cases. They
make no live model request or use an operator provider home.

`doctor.LocalService` owns local diagnosis and reduction. Its focused tests
trace source, locality, codec, account, native-home and version calls, including
both source confirmations around every locality confirmation. No final config
confirmation is added after provider observation. Record red regressions before
repair, green corrections before the policy move, and the same green controls
afterward. Keep the original predecessor JSON immutable. DF-027 remains open;
unsupported configuration versions retain `config_yaml_invalid`.

Native-home cancellation preserves its original cause in LocalService. Doctor
projects it to public exit 9. Providers retains its existing command envelope
restriction: requested cancellation projects to public exit 7. The exit-9 CLI
controls cover init, config and doctor, and do not include providers.

Run each command on one physical line, and confirm that every named test runs:

```sh
go test -count=1 -v ./internal/entrypoint/mulgae -run '^(TestDoctorV7Characterization|TestAdmissionSequenceCharacterization|TestDoctorProvidersConformanceCompatibility|TestProvidersCharacterization|TestAdmitConfiguredNativeAccount|TestApplicationNativeHomeCancellationUsesExitNine|TestApplicationNativeHomeCancellationHumanOutput)$'
go test -count=1 -v ./internal/adapters/environment -run '^(TestProviderVersionObserverCursorTupleAndGenericNormalization|TestProviderVersionObserverFailureDriftPrecedence|TestProviderVersionObserverRejectsIdentityMismatchBeforeExecution|TestObserveNativeHomeIdentityCapturesDescriptorAndDetectsReplacement|TestProviderVersionObserverClassifiesLocalVersionCommandOutcomes)$'
go test -count=1 -v ./internal/composition -run '^TestReviewAdmissionSequenceCharacterization$'
```

Use the standard checks after focused verification. Tagged compilation does
not certify live provider behavior. Grok, Cursor, AGY and opt-in Codex live
certification remain deferred to the v0.1.26 release gate.

## Local doctor correction and extraction controls

Run every command on one physical line. These controls cover Q1/Q3 and the
shared LocalService used by doctor and providers; keep the earlier M1/M2
commands alongside them.

```sh
go test -count=1 -v ./internal/entrypoint/mulgae -run '^(TestDoctorProvidersNativeHomeReplacementRegression|TestDoctorProvidersNativeHomeCancellationProjection)$'
go test -count=1 -v ./internal/adapters/environment -run '^TestProviderVersionObserverCursorCompatibility$'
go test -count=1 -v ./internal/entrypoint/mulgae -run '^TestDoctorProvidersProductionCursorCompatibility$'
go test -count=1 -v ./internal/app/doctor -run '^(TestLocalDoctorAdmissionSequence|TestLocalDoctorReadinessCompatibility|TestLocalDoctorRejectsNativeHomeReplacement|TestLocalDoctorCancellationAndEffects)$'
go test -count=1 -v ./internal/entrypoint/mulgae -run '^(TestDoctorV7Characterization|TestDoctorProvidersConformanceCompatibility|TestApplicationDoctorReportsStableBinaryAvailabilityReasons|TestApplicationDoctorClassifiesProviderCLIVersionOutcomes|TestApplicationDoctorNeverInvokesLiveHeartbeatService|TestApplicationProvidersKeepsOfflineReadinessWhenStaticEvidenceRejectsEveryProfile|TestApplicationNativeHomeCancellationUsesExitNine|TestApplicationNativeHomeCancellationHumanOutput)$'
go test -count=1 -v ./internal/adapters/environment -run '^(TestProviderVersionObserverFailureDriftPrecedence|TestProviderVersionObserverAcceptsReadableNonExecutableZCodeLauncher|TestProviderVersionObserverClassifiesLocalVersionCommandOutcomes|TestProviderVersionObserverAdmitsAgyOfflineVersion|TestProviderVersionObserverRejectsIdentityMismatchBeforeExecution|TestSpawnVerifierRejectsZCodeProviderConfigDrift|TestApplicationMetadataObservationBindsShortVersionAndDigest)$'
go test -count=1 -v ./internal/app/reviewrun -run '^(TestClassifyVersion|TestCursorDateHashGuidanceIgnoresHashOrder)$'
go test -count=1 -v ./internal/architecture -run '^TestProductionDependencyDirection$'
go test -count=1 -v ./internal/entrypoint/mulgae -run '^TestDoctorCursorProductionVersionPolicy$'
```

## Runtime wire compatibility controls

`internal/app/{query,report}/strict_object_compatibility_test.go` compares fixed
pre-move outcomes for synthetic destinations. Query also covers the actual M1
runtime/support DTOs and containing final and manifest destinations; report
covers its final projection.
The owner-local `testdata/m1-strict-before.json` files preserve accepted values,
concrete error types, complete messages, offsets and JSON field paths.

The snapshots were captured once from production sources at `58bbc89` before
the M1 DTO moves, using temporary overlay tests. No capture tool or update mode
is retained. `testdata/m1-strict-diagnostic-moves.json` records the exact allowed
Go struct/type-name changes caused by the moves. Its assertions permit only
those mechanical names and the corresponding raw message substitutions;
failure classes, reasons, repair authority and other decoder details retain
their existing contracts.

Publication and filesystem `TestSupportIndexDecoderDiagnostics` cases also
freeze their support-index decoder names in owner-local
`testdata/m1-support-diagnostics.json` files. The publication baseline uses
`58bbc89`'s serializer types; the cleanup baseline uses its original anonymous
destination. Both retain exact before/after messages and require every
non-name diagnostic field to match. Cleanup reduces these errors to a corrupt
observation, and publication retains its typed artifact-failure envelope.

`internal/app/publication/testdata/m1-runtime-wire.json` freezes literal writer
bytes from the same pre-move source. It covers field order, optional presence,
null/empty collections, Unicode, HTML escaping, CRLF and terminal LF, plus historical
runtime artifact outputs and support-index v1/v2/v3 selection. Expected
bytes are loaded from the fixed file. `TestRetainedRuntimeWireBytes` exercises
the retained DTO encoders and support-index construction. Retired runtime-writer
rows keep their original expectations and explicit historical-consumer owners in
`TestRetainedGoldenInventory`. DF-013 cases in the owning review and
followup parsers reject lone surrogates and accept a valid pair as the exact
Unicode scalar, while preserving validation and repair outcomes.

The M2 `publication_object_compatibility_test.go` controls in query, report,
publication and filesystem exercise the actual shared components and containing
roots. Query also covers receipt and cursor destinations; their existing caller
checks retain canonical encoding, identity and sentinel behavior. The fixed
`testdata/m2-object-before.json` inputs and outcomes come from M1C1's unchanged
production implementation. `m2-object-diagnostic-moves.json` lists each exact
allowed name change. Assertions allow only declared Go name relocations and
preserve every other error detail and caller prefix.

`TestRetainedPublicationDTOBytes` and `TestRetainedLiveGoldenBytes` load
`testdata/m2-publication-wire.json`, captured before the DTO moves. They compare
retained DTO and historical live v3 wire bytes, including live omission/order,
lifecycle journal/status variants, corruption diagnostics and composite DTO
serialization. At the TASK-029 cutover, legacy version-bound records round-trip
through their retained DTO encoders while unchanged support bytes remain exact.
Current Build checks require v4, explicit-null requirements support without input
and index v4; no legacy production emitter is retained.
Historical captured/followup/composite creation rows remain fixed and explicitly
classified; actual reader/recovery tests carry their retained properties.
`TestCompositeRecoveryReencodesFrozenCanonicalManifest` invokes the real canonical
recovery encoder against fixed v1/v2 expectations. Binary support bytes use a literal hex
representation so JSON cannot replace invalid UTF-8. The fixtures have no update
mode. The path controls compare fixed pre-move owner vectors and direct leaf
spellings; ports and recovery tests retain rejection and precedence checks.
`TestCorruptionDiagnosticWireTypeIdentity` preserves the raw diagnostic decoder
name at the ports boundary.

`internal/strictjson/TestDecodeObjectCompatibility` uses the same 42 fixed
synthetic inputs and outcomes previously verified through both query/report
helpers. The full owner matrices still exercise their actual destinations and
caller wrappers through `strictjson.DecodeObject`. Extraction preserves error
text, concrete types, offsets, JSON field paths and ordering; it introduces no
new diagnostic-name allowance. Keep the M1/M2 snapshots and name maps fixed.
The shared helper does not replace provider or schema-adapter parsing. DF-013's
owning review/followup parser cases retain exact scalar and repair assertions.

Run each command on one physical line:

```sh
go test -race -count=1 ./internal/app/validation -run '^TestProviderJSONSurrogateCompatibility$'
go test -race -count=1 ./internal/app/query -run '^TestStrictObjectCompatibility$'
go test -race -count=1 ./internal/app/report -run '^TestStrictObjectCompatibility$'
go test -race -count=1 ./internal/app/publication -run '^(TestRetainedGoldenInventory|TestRetainedRuntimeWireBytes)$'
go test -race -count=1 ./internal/app/publication -run '^TestSupportIndexDecoderDiagnostics$'
go test -race -count=1 ./internal/adapters/filesystem -run '^TestSupportIndexDecoderDiagnostics$'
go test -race -count=1 ./internal/app/query -run '^(TestRuntimeTargetRetainsArtistPresenceAndConfiguredLargeBriefBytes|TestReadRuntimeTargetLegacyArchiveControls)$'
go test -race -count=1 ./internal/app/publication -run '^(TestRetainedPublicationDTOBytes|TestRetainedLiveGoldenBytes|TestM2PublicationObjectCompatibility|TestM2DiagnosticMoveRejectsNonNameChanges)$'
go test -race -count=1 ./internal/adapters/filesystem -run '^(TestM2PublicationObjectCompatibility|TestM2DiagnosticMoveRejectsNonNameChanges|TestPublicationJournalWireRejectsDuplicateUnknownAndTrailingJSON)$'
go test -race -count=1 ./internal/artifactwire -run '^TestArtifactPathGrammarCompatibility$'
go test -race -count=1 ./internal/ports -run '^(TestPublicationPathContractCompatibility|TestCorruptionDiagnosticWireTypeIdentity|TestClassifyRunSupportArtifactPathRequiresCanonicalRecoveryArtifacts|TestClassifyLiveSupportArtifactPaths)$'
go test -race -count=1 ./internal/app/publication -run '^(TestPreparedCandidateBuildDeterministicPublicationBundle|TestRetainedLiveManifestRoleReportRecordsTransport|TestRetainedLiveRecoverCorruptionDiagnosticIsIdempotentByEpochAndBytes)$'
go test -race -count=1 ./internal/app/publication -run '^(TestLivePublicationConstructsSharedSupportOnce|TestBuildAbsentLiveRefusalPreservesProloguePrecedence|TestLiveFirstBindingProloguePrecedenceMatchesBuild|TestLiveBindingMemberPrecedenceMatchesBuild)$'
go test -race -count=1 ./internal/app/publication -run '^(TestRunSupportContractAcceptsOnlyCanonicalRuntimeInventoryPaths|TestPublicationVariableSizedSupportPathsUseCanonicalKindPolicy)$'
go test -race -count=1 ./internal/strictjson -run '^TestDecodeObjectCompatibility$'
go test -race -count=1 ./internal/app/query -run '^(TestDecodeFinalDTORejectsDuplicateUnknownAndTrailingJSON|TestPublicationReceiptBindsOneCompleteObservation|TestFindingCursorRejectsCrossSnapshotQueryAndNoncanonicalValues)$'
go test -race -count=1 ./internal/app/report -run '^(TestDecodeReportFinalAcceptsRerunSourceAttempt|TestReportFailureReductionUsesOperationalPrecedenceInBothJoinOrders)$'
go test -race -count=1 ./internal/adapters/jsonschema -run '^(TestValidatorAcceptsExactAuthoritativePairs|TestValidatorStrictJSONDecodeRejectsAmbiguity|TestStrictJSONDecoderDepthUnicodeAndEquivalentKeys)$'
go test -race -count=1 ./internal/architecture -run '^(TestWireLeafDependencyDirection|TestProductionDependencyDirection|TestTestSupportDependencyDirection)$'
```

Run the historical corpus consumers below after each migrated writer/reader
pair and after shared strict-object changes. Keep the corpus, its tests and
provenance unchanged. The extracted query/report mechanics preserve their
acceptance sets; other parsers and provider protocol tolerance are unchanged.

## Historical compatibility corpus

`internal/testsupport/historical/testdata/corpus.json` records synthetic, fixed
artifact bytes under `testdata/bytes/`. Each case maps logical store paths to
content-addressed files and records format versions, operation results and
integrity bindings. The loader checks every file's length and SHA-256 before a
consumer sees it. No committed directory is a runtime store or has a `.mulgae`
path segment. Inputs contain no copied source archive, transcript, credential
or real review.

| Cases | Preserved behavior |
|---|---|
| Ordinary archive v1/v2 | Real-schema reads, reports, exports, exact non-minified v1 bytes and v2 transport reconstruction |
| No-change and artist | Empty findings/skipped roles; exact Unicode, CRLF brief and binary visual identities |
| Committed attempts in ordinary and child runs | Fixed IDs, role/provider selectors, prompt/template/stdin identities and exact stdin bytes; missing, tampered, prompt-binding and complete-stdin negatives |
| Exact/recomposed rerun, delta and four followup resolutions | Historical lineage, outcomes and source/current evidence identities |
| Ordinary review/manifest v2 | Failed-recovery source identity without an invented source review ID |
| Legacy composite v1 | Support-index v1 and explicit evidence unavailability |
| Copied composite v1/v2 | Published and failed-root source receipts, copied evidence, local reads after permitted source cleanup and private-copy export exclusion |
| Failed recovery and exact failed-rerun lineage | Verified retry inventories, ancestor binding and cleanup protection without P2 report/export authority |
| Retired Kimi and integrity controls | Retained rejection, missing/tampered support, hash-consistent rebound/cross-run paths and wrong lineage |

Archive v1/v2, ordinary review/manifest v1/v2 and composite v1/v2 are separate
version axes. A legacy composite without copied support uses support-index v1;
support-index v2 requires `support/composite.json`. Explicitly unavailable
evidence remains distinct from a missing bound copy.

The one-time provenance is in
[`testdata/provenance.md`](../../internal/testsupport/historical/testdata/provenance.md).
Expected report/export digests and reconstructed-archive digests come from
baseline consumer reads. Tests load these fixed expectations; they have no
update mode and invoke no historical producer to reconstruct their inputs.
TASK-061 uses the same bytes for wire/parser changes. TASK-065 replaced the
producer-backed setup before removing the retired writer halves. Their retained
properties now run through live owners, fixed historical readers and actual
recovery. Keep `ports.MarshalCapturedReviewMaterial`: runtime-target reads use it to reconstruct
v2 archives, so it is a retained reader dependency.

Keep the capture manifest tests in `internal/app/capture`; the former
`reviewrun` facade is gone. Fresh prompt compilation and its reservation maps
remain active, while replay issuance methods and the v1 production fixture
encoder are removed. Legacy query-only synthetic input stays in `_test.go`;
the corpus supplies independent fixed v1 expectations. Do not regenerate corpus,
golden files or inline vectors to accommodate a changed implementation.

Run the focused checks with explicit packages:

```sh
go test -race -count=1 ./internal/testsupport/historical -run '^TestHistoricalCorpus(Records|RejectsChecksumMutation)$'
go test -race -count=1 ./internal/app/query -run '^TestHistoricalCorpus(Read|Recovery|Attempts)$'
go test -race -count=1 ./internal/entrypoint/mulgae -run '^TestIntegrationHistoricalCorpus(Consumers|Recovery|Cleanup)$'
go test -race -count=1 ./internal/architecture -run '^TestTestSupportDependencyDirection$'
```

The loader and in-memory checks belong to the unit tier. The filesystem,
publication reconciliation, report/export and cleanup consumers belong to the
integration tier. They materialize only frozen files beneath owned temporary
roots and exercise the retained application services with real schema and
filesystem adapters. Run them with inherited `TMPDIR` and a symlinked temporary
parent; resolve each owned root with `filepath.EvalSymlinks` before admission.
After any consumer run, verify the complete corpus is byte-unchanged. Changing
shared corpus bytes requires the applicable complete candidate gate in addition
to these focused checks.

## Composite support verification

For changes to self-contained composite support, cover published P2 sources and
retained failed-run recovery sources separately. Verify original finding copies,
ID remapping, every evidence index, copied retirement provenance and per-source
capture reconstruction. A common capture requires all selected roles to agree,
including roles without findings; missing historical capture remains unavailable.

Exercise missing, corrupt and unlisted support artifacts, interrupted stored-state
recovery, and reads of a legacy P2 composite without rewriting it. Keep all six
interrupted-copy read refusals, the 19 historical provenance mutations, the three
effect boundaries crossed with four unreadable-support cases, and repaired/failed
attempt initial-prompt selection. Verify
receipt-bound detail, report and evidence reads using only composite-local copies
after source cleanup permitted by native policy. Keep failed-recovery roots
protected and check that the export allowlist omits the additional private copies.

Use the focused application tests while iterating, then the applicable Make
integration and release-binary gates. TASK-025 separately owns the exact supported
client workflow and complete `make test` gate; TASK-024 support fixtures do not
establish that integrated acceptance.

## Manual release

The repository intentionally has no GitHub Actions release workflow:

1. start from a clean commit on `main`;
2. replace the current changelog section's `Unreleased` marker with the release
   date;
3. commit the release metadata and require a clean candidate on `main`;
4. run `make test` against that exact candidate;
5. verify module installation in a temporary `GOBIN`;
6. verify `mulgae version`, `mulgae --help`, and project initialization;
7. tag the exact verified commit;
8. push the commit and tag as a separate explicit operation;
9. create and publish the GitHub Release for that exact tag as a separate
   explicit operation, using the settled changelog entries;
10. after verifying the hosted Release, immediately open the next planned
    release cycle in a separate change by advancing `RELEASE_VERSION` in
    `Makefile` and prepending an empty `Unreleased` changelog section
    (`TestMakefileContract` checks the `RELEASE_VERSION` declaration format and
    `MULGAE_RELEASE_VERSION` wiring, while `make test-release` verifies the
    installed binary version).

During development, record concise user-visible outcomes under `Added`,
`Changed`, or `Fixed` in the current `Unreleased` section.

Never tag a dirty tree or a different commit from the one exercised by the
release gate.

## Requirements-assessment contract foundations

Use the [frozen contract](../specs/review-completeness-and-iteration.md#frozen-requirements-assessment-contracts)
when wiring the later Tasks. Requirement input and per-item content use their
strict prose-bearing decoders without the structured-envelope byte ceiling.
Keep support/read metadata bounded and use existing publication/digest-bound
content chunks for large prose. Foundation checks do not establish filesystem
admission, provider execution, publication or public read availability.

TASK-027 admission checks use ordinary project files and the existing live root
lease, not private artifact-directory permission rules. Exercise untracked local
input with staged/committed code, malformed input on every no-change selector,
independent project binding, and zero provider/private-writer calls. Verify both
the original preflight v10 and command-result v22, including failed preflight. Keep prose out
of the bounded metadata projection and preserve the original v9/v21 assets.

TASK-028 exercises the internal requirements producer through isolated live-source
readers and the production runtime/publication owners. Cover complete and partial
sections, available-section reason priority, shared retry/repair/extraction slots,
protected joined failures, honest parse states and one normalized row per selected
item. Verify distinct local/index/commit bytes at the same input path, exact input
retention and unbounded rationale/limitations through v4 publication. Restart and
corruption checks must work from retained support with the source unavailable.
The trusted normalized provider-v3 composition needs both a small serialized-shape
assertion and a production serialization beyond the generic envelope bound.

Settle paired assets and exact catalog inventory before package-wide checks.
Run focused owning tests, `make test-prepare`, scoped owning-package race units and
`make test-int` for this internal execution/publication boundary. The complete
`make test`, exact release binary, actual-client and live provider evidence remain
TASK-033 obligations. No synthetic provider fixture establishes live certification.

TASK-029 verifies the public cutover with command-result v23/preflight v11 and
v4 final/manifest/support-index producers, including explicit-null no-input
records. Preserve substantive old schemas/examples and extend only generated
aggregate inventory. Requirements execution needs the existing verified Git
binding; test non-Git CLI/MCP rejection before writer/qualification effects,
honest unavailable preflight and objective-only non-Git compatibility.

Verify whole selected-set count/order/owner/origin/input/content integrity before
paging and final publication confirmation after reads. Exercise old unknown/null
counts, new no-input zero counts, no-change zero evaluated rows, provider
unverified versus derived placeholders, reports-only/missing answers, large prose,
receipt changes, tamper and concurrent cleanup. Reuse the existing 16 KiB content
chunk owner; never feed full requirement prose through the 8 MiB schema adapter.
Keep the existing 8 MiB bound on legacy `report --output-path` file export; it
does not limit retained prose, rendering or read-only report continuation.
Keep finding filters, extraction, role coverage, assessment availability and exits
independent. Export excludes private requirement bodies; cleanup preserves the
original invocation file.

`make test-release` explicitly selects
`TestIntegrationIsolatedReleaseFixtureRequirements` alongside the established
exact-binary fixtures. It exercises public execution, CLI and stdio MCP tools and
resources, receipt-bound pages/content, rendered reports, export privacy and
cleanup. Run the applicable owning-package race units, `make test-prepare`,
`make test-int` and `make test-release` for this cutover. These fixture gates
use isolated fake providers; complete `make test`, mandatory live ZCode,
supported-client certification and a bounded live requirements demo remain
TASK-033 obligations. Do not present fixture success as live-provider evidence.

## Planned Haepari integration verification

EPIC-016's [dossier](../todo/TODO-HAEPARI-REVIEW-COORDINATION.md) maps the full
scenario and producer-return requirements to member Tasks. The
[coordination specification](../specs/haepari-review-coordination.md) owns the
owner and borrower behavior and the remaining migration/qualification obligations.
The commands below define checks; their presence records no passing result.

Start with focused Go behavior checks for affected native adapter, application
lifecycle and CLI/MCP paths. Run each `TASK-076` foundation check on one
physical line:

```sh
go test -race -count=1 ./internal/artifactwire -run '^TestArtifactPathGrammarCompatibility$'
go test -race -count=1 ./internal/ports -run '^TestReview(Lock|Coordination)'
go test -race -count=1 ./internal/adapters/filesystem -run '^TestCoordinationIntentStore'
go test -race -count=1 ./internal/adapters/haepari -run '^Test(ResolveStateRoot|Client)'
go test -race -count=1 ./internal/app/reviewrun -run '^TestReviewCoordinator'
go test -race -count=1 ./internal/architecture -run '^(TestWireLeafDependencyDirection|TestProductionDependencyDirection|TestEstablishedOwnershipDependencyDirection|TestTestTierNaming)$'
```

Owner and borrower lifecycle tests use an isolated Unix controller under a short
physical 0700 temporary root and never the host Installation. Shared Installation
tests serialize CLI, foreground MCP and async start/await/cancel across project
roots and verify read-only child execution under `HAEPARI_LOCK_GRANT` without
mutating parent lock state; the existing provider barrier test uses separate
Installations to retain overlap. Controlled timers cover stalled renewal and
stalled borrowed `locks.list` polls independently from their deadline guards,
multi-page borrowed lookup beyond 64 pages using same-page `now`, and partial-role
preservation without cross-run coverage. Private intent v2 and v3 tests cover
legacy unknown proof, owned and borrowed local-state transitions and
linked/unlinked cleanup drift. Committed-status tests cover best-effort
supplement failure without weakening independent P2 verification.

Paired-skill and prior-state candidate checks use the released v0.1.26
configuration examples pinned at `c422590155f62380709c8f6fd08c9ad423badaaa`
under `internal/entrypoint/mulgae/testdata/coordination-upgrade/`. Their source
hashes cover the original example bytes after the provenance comments. These
Config v5 inputs need preservation rather than an invented schema conversion.
The historical corpus retains its separate producer provenance.

```sh
go test -race -count=1 ./internal/entrypoint/mulgae -run '^TestIntegrationPreExistingProjectMigrationAndHistoryCoexistence$'
go test -race -count=1 ./test/e2e -run '^TestIntegrationPriorStateCLIAndMCP$'
go test -tags=releasecheck -race -count=1 ./internal/releasecheck -run '^TestTrackedReleaseSurface$'
```

The first case compares historical publication and failed-recovery identities,
bytes and modes while preserving custom routing, timeouts and credential
bindings. Actual cleanup retains legacy unknown proof, unsupported records and
unverified owned/borrowed intent, while deleting an eligible diagnostic. The
second seeds the prior configuration without init and retains a real
provider-free requirements publication across a controller-admission failure
and one nonempty CLI, foreground MCP and asynchronous MCP review each. It checks
native requirements results, receipt-bound CLI/MCP content, distinct run IDs,
unchanged inputs and settled grants using isolated stub providers. The initial
requirements publication is current fixture output, not v0.1.26 execution.
The tracked-surface check is packaging policy, not skill behavior or discovery.

Read the full six-file `skills/use-mulgae/` tree against the supported
CLI/MCP contracts and bind every path, byte count and SHA256 to the tested
candidate and eventual committed Git tree/blobs. For candidate discovery, copy
that exact tree into an isolated Git project's supported skill scope and start
a fresh native agent session. Installed AGY documents `.agents/skills/` as
project scope. Observe native discovery/loading and its source path; explicit
file reading, an older global skill, or a synthetic loader is insufficient.
Keep the probe read-only and exclude review execution, host installation and
configuration changes. Record the observed harness and any unsupported route;
candidate AGY discovery does not qualify installed Codex/Claude consumers.
Requalify the actual released full tree under the release/guest requirements.

Use `make test-prepare` once on the frozen member candidate. Native
`make test-mcp-clients` checks client registration and server connectivity;
it does not load this skill or run the separate requirements-client checks. Reuse unchanged
runtime evidence and refresh only checks whose inputs or assumptions changed.
Use make test-offline on the integrated candidate,
make test-release for the installed-binary surface and make test-mcp-clients
for changed MCP consumers. Release readiness requires the applicable exact-commit
make test and provider-specific obligations under the repository's release
policy. A runtime feature cannot use the patch-only version-increment waiver.
Live-provider checks retain separate execution authority and cannot be replaced
with fixture success. `make test-e2e`, `make test-grok`, `make test-cursor`,
`make test-agy` and enabled `make test-e2e-opt-in` now also require an explicitly
selected usable Haepari Installation or an isolated controller. Missing
coordination prerequisites fail closed; no target automatically changes resource
policy. These live gates remain TASK-080 obligations.

Run installation and fault/contention scenarios in the dedicated utm-macos
guest, with approved shared VM occupancy once at the outer boundary. Synthetic
guest targets use an isolated controller/resource and stub providers; they must
not reacquire the parent's occupied VM or justify concurrent production-account
calls. Compare meaningful prior configuration/history/retry/active-work state
with the candidate, then requalify the actual released binary and full skill.

Freeze admitted source, binary/archive, complete skill tree and profile digests
before submission. Keep pre-submission inputs distinct from returned native Job
identity/revision and exported results. Automatic recipe cleanup and inventory
finish before workload exit. Manual operators stage evidence and complete
cleanup/inventory while awaiting_manual, before manual complete starts native
collection. Export follows consumer cleanup. Retain the tested combination when
the scenario requires it and verify the declared reusable guest inventory.

Record original per-case negatives, manual observations and unknowns separately
from Job success, evidence completeness, native and consumer cleanup, capacity,
review publication and assessment. Runtime evidence remains with its tool owner;
promote only a separately approved bounded package when downstream retention
requires it. No local runtime path or identity becomes canonical evidence.
