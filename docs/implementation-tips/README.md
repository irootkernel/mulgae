# Implementation and release guidance

## Requirements

- macOS on Apple silicon for the complete release gate
- Go 1.27.1 or newer
- Git
- a ZCode app bundle with a current Z.AI Individual Coding Plan connection for
  the mandatory live tests, plus an authenticated Grok installation for
  `make test-grok`
- two distinct authenticated Codex homes only for the opt-in profile E2E

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

## Local checks

The complete gate is:

```bash
make test
```

It runs generators and static checks, serialized race-instrumented unit tests,
serialized race-instrumented integration tests, one exact-binary two-role live
review, and independent live capability certification for ZCode. The
live review routes `logic` and `security` to ZCode concurrently, accepts
one Markdown report from each role without repair or structured extraction,
and requires Mulgae to publish one complete reports-only review. Each role must
reproduce a fresh marker stored only in its original source file, never the
objective, so a report that merely claims it could not read the target does not
certify original-source access. The complete gate then invokes the opt-in Codex
profile target, which reports a stable skip unless `MULGAE_E2E_OPT_IN=1` is
present.

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
ACP v1. It uses `MULGAE_E2E_GROK_EXECUTABLE` when set and otherwise discovers
`grok` on `PATH`. The target requires an already authenticated installation,
does not modify native Grok configuration, and is the standalone Grok live
provider gate outside `make test-e2e`.

`make test-cursor` builds the exact current release binary and runs one Cursor
review. It requires `darwin/arm64`, `CURSOR_AUTH_TOKEN`, and an absolute
executable in `MULGAE_E2E_CURSOR_EXECUTABLE`. The executable's version line
must match `YYYY.MM.DD` followed by a hyphen and
lowercase hexadecimal, with a padded month and day. The target is not part of
`make test`. A missing or unsafe prerequisite fails the target.

`make test-agy` builds the exact current candidate release binary with the
release version and HEAD revision linker values. It requires `darwin/arm64`,
the installed `agy` (or `MULGAE_E2E_AGY_EXECUTABLE`) and the OS user's existing
default Gemini token. It performs one documentation review, with model and
effort omitted, and no automatic whole-review retry. A source-only nonce in a
parenthesized path proves a real source read. The gate checks one initial
invocation, native protocol closure, public status/inspection/report/export,
unchanged original source/Git/token, and removed invocation runtime roots.
Qualification is part of that review; no redundant standalone capability
request is added. The gate neither requires nor validates a second account.

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
three-role exact-binary review: Codex profile `primary` owns `logic` and
`security`, while profile `secondary` owns `documentation`. Supply the two
distinct credential roots explicitly; profile names are test aliases and do
not prescribe directory names:

```bash
MULGAE_E2E_OPT_IN=1 \
MULGAE_E2E_CODEX_PRIMARY_HOME=/absolute/path/to/primary-codex-home \
MULGAE_E2E_CODEX_SECONDARY_HOME=/absolute/path/to/secondary-codex-home \
make test-e2e-opt-in
```

Override executable discovery with `MULGAE_E2E_CODEX_EXECUTABLE`. Once enabled,
missing credentials, qualification
failure, invalid provider output, wrong role routing, publication failure, or
credential mutation fails the target; the Go test never converts these states
to a skip. This optional result does not replace mandatory ZCode
certification.

`make test-mcp-clients` is an opt-in local compatibility check and is not part
of `make test`. It builds the exact current Mulgae binary, isolates client
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
an independently updated consumer, including command-result v21, preflight v9
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
status, committed reads with zero diagnostic calls, and session-bound summary
merging. Diagnostic projection eligibility remains a transport decision: CLI
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
gate or the explicit two-home Codex certification required by TASK-039.

The [verified review contracts](../specs/verified-review-contracts.md) and their
[roadmap outcomes](../roadmap/README.md#epic-007-verified-review-contracts)
retain EPIC-007 requirements and verification. The planned
[EPIC-008 dossier](../todo/EPIC-008-review-completeness-and-iteration.md) defines
its per-Task implementation, exclusions, checks, and completion conditions.
The [roadmap](../roadmap/README.md#adopted-execution-order) owns the strictly
sequential order. EPIC-008 remains deferred until explicit EPIC-009 acceptance and redesign of
its capture-dependent requirements. The regression matrix below records that
frozen design; it does not authorize retired child execution.

For each implementation Task, read current code and the nearest contract, add
focused behavioral/negative tests, and run the applicable existing Make targets.
Use explicit packages and anchored test names for narrow Go test selections.
Do not add prose-only tests as a substitute for native behavior. Contract-only
foundations need schema examples and semantic tests before production wiring;
new capabilities remain unadvertised until their runtime path exists.

Keep provider-free guarantees observable with writer/provider spies and exact
binary fixtures. Test root confusion and anchor replacement before qualification,
original-source selection, receipt/cursor consistency, historical capability gaps,
reports-only output, and immutable parent artifacts. Freeze old/new consumer
fixtures independently of producer generators so regeneration cannot erase a
compatibility failure. When embedded assets change, follow the two-pass generator
procedure above.

The plan review adds four required deterministic regression groups, owned by
existing Tasks rather than new Epics or live campaigns:

| Group | Required checks |
|---|---|
| No-change Brief evaluation | Empty stage/dirty/diff in both modes with/without requirements; invalid input/guard rejection first; zero qualification/review calls; exact Brief and unverified/no_change_target results retained and readable after restart; explicit workspace remains a separate request. |
| Complete capture identity | Keep patch bytes equal while changing unchanged support files, binary content, paths, sides, or context; identities must differ. Equal captures with different objectives/roles must remain comparable for resolution. Prove historical unavailability differs from corrupt support. |
| All-followup receipt paging | Keep before/after fixed while only a selected followup is deleted, replaced, or corrupted between pages; fail the page, including followups used on later pages. Reject changed selection and duplicate IDs; permutations preserve scope. |
| Conflicting claims | Test differing conclusive followup verdicts and conflicts with after observations; preserve all evidence and stable reasons. Separate unclear/missing answers from negative claims. Vary input order and timestamps without selecting a winner or increasing confidence. |

TASK-019/021/022/024 establish the capture foundation. TASK-026 freezes the
remaining semantics, TASK-027/028/029 cover no-change admission/publication/reads,
TASK-030/031 retain batch current-capture identity, TASK-032 covers comparison,
and TASK-033 verifies the integrated boundary matrix. Use existing no-change
service/publication fixtures as compatibility anchors, not tests that assume
all future no-change formats have an empty support index.

Run the complete `make test` gate before each Epic's integrated acceptance.
Retain the existing mandatory live ZCode/Grok and optional Codex policy; do not
multiply live runs to cover cases deterministic fixtures can prove. Registration
inspection alone cannot certify an actual client invocation or await behavior.
Record exact binary/client identities and distinguish mock, release-binary,
actual-client, and live-provider evidence.

EPIC-008 additionally calls for one bounded, explicitly authorized live initial
Brief review and one selected batch recheck through existing routes. Reuse that
campaign's outputs for provider-free inspection and comparison checks. Missing
structured coverage is not a successful feature demonstration. A failure is a
specific blocker/remediation item, not permission to repeat reviews until clean.
Neither dossier authorizes credential, provider, host-config, installation, or
release changes. Keep runtime evidence local unless a reviewed promoted-evidence
package is explicitly required.

For this documentation-only adoption, read back changed files, validate links,
IDs, dependencies, requirement ownership, and proposed-command labeling, and run
`git diff --check`. No runtime gate or provider call is necessary to verify that
planning change. Do not mark feature requirements or Tasks complete from these
document checks.

At Epic closeout, promote durable outcomes to canonical owners, remove its
temporary dossier and index entry, repair all dossier links (including this
section), and replace Detailed SOT with Canonical Outcomes before changing the
Epic status. Stop at the accepted scope; no additional feature or unlimited
review cycle is an acceptance condition.

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
null/empty collections, Unicode, HTML escaping, CRLF and terminal LF, plus real
runtime artifact construction and support-index v1/v2/v3 selection. Expected
bytes are loaded from the fixed file. DF-013 cases in the owning review and
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

`TestPublicationWireGoldenCompatibility` loads
`testdata/m2-publication-wire.json`, captured before M2's DTO moves. It compares
literal bytes from captured, followup, live v3 and composite builders, including
live omission/order, lifecycle journal/status variants, corruption diagnostics
and custom composite serialization. Binary support bytes use a literal hex
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
go test -race -count=1 ./internal/app/publication -run '^TestRuntimeWireGoldenCompatibility$'
go test -race -count=1 ./internal/app/publication -run '^TestSupportIndexDecoderDiagnostics$'
go test -race -count=1 ./internal/adapters/filesystem -run '^TestSupportIndexDecoderDiagnostics$'
go test -race -count=1 ./internal/app/publication -run '^(TestRuntimeArtifactsPersistAndBindArtistInputs|TestPublicationBundleBindsCanonicalSupportIndex)$'
go test -race -count=1 ./internal/app/publication -run '^(TestPublicationWireGoldenCompatibility|TestM2PublicationObjectCompatibility|TestM2DiagnosticMoveRejectsNonNameChanges)$'
go test -race -count=1 ./internal/adapters/filesystem -run '^(TestM2PublicationObjectCompatibility|TestM2DiagnosticMoveRejectsNonNameChanges|TestPublicationJournalWireRejectsDuplicateUnknownAndTrailingJSON)$'
go test -race -count=1 ./internal/artifactwire -run '^TestArtifactPathGrammarCompatibility$'
go test -race -count=1 ./internal/ports -run '^(TestPublicationPathContractCompatibility|TestCorruptionDiagnosticWireTypeIdentity|TestClassifyRunSupportArtifactPathRequiresCanonicalRecoveryArtifacts|TestClassifyLiveSupportArtifactPaths)$'
go test -race -count=1 ./internal/app/publication -run '^(TestPreparedCandidateBuildDeterministicPublicationBundle|TestManifestRoleReportRecordsTransport|TestRecoverCorruptionDiagnosticIsIdempotentByEpochAndBytes)$'
go test -race -count=1 ./internal/app/publication -run '^(TestLivePublicationConstructsSharedSupportOnce|TestBuildCapturedPrecedenceOnForceablePairs)$'
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
TASK-061 uses the same bytes for wire/parser changes. TASK-065 replaces the
remaining producer-backed tests before deleting writers. Keep
`ports.MarshalCapturedReviewMaterial`: runtime-target reads use it to reconstruct
v2 archives, so it is a retained reader dependency.

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

Exercise missing, corrupt and unlisted support artifacts, interrupted publication
and replay, and exact reuse of a legacy P2 composite without rewriting it. Verify
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
    release cycle in a separate change by advancing `RELEASE_VERSION` and its
    architecture assertion and prepending an empty `Unreleased` changelog
    section.

During development, record concise user-visible outcomes under `Added`,
`Changed`, or `Fixed` in the current `Unreleased` section.

Never tag a dirty tree or a different commit from the one exercised by the
release gate.
