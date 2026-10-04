# Implementation and release guidance

## Requirements

- macOS on Apple silicon for the complete release gate
- Go 1.27.1 or newer
- Git
- a ZCode app bundle with a current Z.AI Individual Coding Plan connection,
  plus an authenticated Grok installation, for the mandatory live tests
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
review, and independent live capability certification for ZCode and Grok. The
live review routes `logic` to ZCode and `security` to Grok concurrently, accepts
one Markdown report from each provider without repair or structured extraction,
and requires Mulgae to publish one complete reports-only review. Each role must
reproduce a fresh marker stored only in its original source file, never the
objective, so a report that merely claims it could not read the target does not
certify original-source access. The complete gate then invokes the opt-in Codex
profile target, which reports a stable skip unless `MULGAE_E2E_OPT_IN=1` is
present.
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

`make test-grok` builds the exact current release binary and runs one authorized
Grok review through ACP v1. It uses `MULGAE_E2E_GROK_EXECUTABLE` when set and
otherwise discovers `grok` on `PATH`. The target requires an already
authenticated installation, does not modify native Grok configuration, and is
an optional standalone provider diagnostic; the mandatory `make test-e2e` gate
already exercises Grok through the mixed-provider review.

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
to a skip. This optional result does not replace mandatory ZCode/Grok
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
an independently updated consumer, including command-result v19, preflight v8
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
Grok requires its correlated permission rejection plus the
separate kernel-boundary test. Codex's kernel probe sends sandboxed
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
