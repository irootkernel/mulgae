# EPIC-009 development dossier: live workspace and Git review

This temporary dossier develops the [planned requirements](../specs/live-workspace-and-git-review.md). The [roadmap](../roadmap/README.md#epic-009-live-workspace-and-git-review) owns identity, status, dependencies, and task order. Planning baseline: `31cc20a`. Re-read affected state before implementation; the baseline is not a reset instruction.

## Execution and ownership

Execute TASK-034 through TASK-039 sequentially. Each task depends on the preceding task. TASK-034 must pass before production changes proceed. Keep unfinished live execution unavailable until the integrated cutover in TASK-038. Preserve layer ownership: reviewrun owns admission and orchestration; source adapters implement inward ports; providercli owns native restrictions; validation and publication own trusted results; CLI/MCP project shared application behavior.

Update affected contracts, assets, tests, and contributor/operator guidance in the task that changes their behavior. Complete all remaining cutover-related updates in TASK-038 before enabling live execution. TASK-039 verifies those updates and the integrated model.

EPIC-007 is complete. EPIC-008 has an execution hold: its immutable Brief, replay, and comparison contracts must be redesigned before any of its tasks resume. Preserve historical IDs and completed evidence. No other repository changes, installation, credentials, profile selection, staging, or delivery are part of this design.

## TASK-034: Freeze contracts and prove provider feasibility

Define the source selector matrix, independent project binding, preflight limits, public schema/capability transition, evidence-side semantics, command removals, and historical compatibility fixtures. Record the concrete native protocol/configuration route for ZCode, Grok, and Codex using the supported existing providers.

In isolated fixtures, prove neutral process and session cwd, external workspace reads, exact partially staged/index and fixed-history reads, correlated complete protocol reports, conflicting project/ancestor AGENTS.md and CLAUDE.md handling, and rejected source/index/ref/config writes. Include native scratch, shared-guide integrity, concurrent sessions, and cancellation. Inspect actual permission behavior; model self-attestation is insufficient.

A failed prerequisite blocks the epic and leaves current production execution intact. Report the unsupported operation and required decision; do not add a fallback, provider substitution, or speculative tool framework. Verification requires actual providers and an exact compatibility matrix. Do not advertise a prototype as supported execution.

### Frozen source and evidence matrix

The following matrix refines the adopted requirements for implementation. It
does not enable live execution or change the existing public contracts.

| Selector | Candidate inventory | Before evidence | After and supporting evidence | Provider-free result |
|---|---|---|---|---|
| workspace | Eligible tracked paths plus non-ignored untracked paths in the current worktree | Not a transition | Current worktree bytes | Only when the eligible inventory is empty |
| stage | HEAD-to-index changed paths; reject unmerged entries | Resolved HEAD objects, or empty tree for an unborn HEAD | Index objects, including unchanged support | Empty HEAD-to-index transition |
| head | Whole tree at the admitted HEAD commit | Not a transition | Objects at the resolved commit | Only when the eligible tree is empty |
| commit REV | Changed paths from the first parent, or empty tree for a root commit | First-parent objects, or empty tree | Objects at the resolved commit | Empty first-parent-to-commit transition |
| diff A..B | Changed paths from resolved A to resolved B | Resolved A objects | Resolved B objects | Empty A-to-B transition |
| diff A...B | Changed paths from merge-base(A,B) to resolved B | Merge-base objects | Resolved B objects | Empty merge-base-to-B transition |

Resolve revisions to commit object IDs once at admission; retained source
metadata records those IDs and the range operator. Do not resolve them again
inside provider prompts. A deletion retains before-side evidence; a rename
preserves both declared paths. Stage never substitutes an unstaged support file.
An unavailable object, missing required live file, unsafe path, or conflicted
index fails with its typed source error before publication. Candidate ignores
remain selection policy, not a filesystem access boundary.
Unrelated histories in a triple-dot range fail with a typed source error when
no merge base exists; they never substitute an empty-tree base.

Source identity describes the declared selector and resolved Git operands. It
does not assert a content digest for a live tree or index. Verify provider claims
against that side at validation time and retain the verified excerpt or selected
binary evidence with its digest. Readers use retained evidence, never a later
workspace read presented as the original observation. Preserve absent historical
evidence as absent. Do not construct a replay archive from retained excerpts.

### Admission and public transition

| Surface | TASK-038 behavior | Compatibility check |
|---|---|---|
| Project binding | Keep the independently established canonical project binding and startup lease checks; accept the verified expected binding by itself | A different worktree, replaced root, or stale MCP startup lease fails before a provider call |
| Non-Git workspace | Preserve the existing unguarded workspace path; an unavailable binding is explicit | Never fabricate a Git binding or silently accept an expected binding |
| Preflight | Provider-free source inventory, resolved operands, routes, and live-consistency limits; no credential qualification or source capture | No request receipt, capture identity, or promise that mutable content is frozen |
| Capture guards | Reject expected request digest and capture-bound fields rather than ignore them | CLI and closed MCP input schemas reject old requests before provider execution |
| Capabilities | Advertise `live_source: "v1"` and `source_evidence: "v1"`; stop advertising new-execution capture identity and execution guard | Retain supported historical inspection capabilities independently of new execution |
| Result versions | New command-result v19, review-preflight v8, review-artifact v3, run-manifest v3, and run-support-index v3 | Do not reinterpret an existing version; retain each required historical decoder |
| Attached execution | Preserve start/await/cancel correlation, role identity, typed failures, bounded lifetimes, and zero-call no-change | No fallback provider or recovery replay after a failed or cancelled role |
| Removed execution | Reject dirty/patch/stdin, followup/delta/rerun, recovery-provider replay, and compose | Remove routes, recovery-only configuration, writers, prompts, schemas used only for admission, examples, and help together |

Historical schemas needed to inspect untouched artifacts remain available even
when their creation route is removed. The MCP v1 transport envelope, publication
receipt, finding cursor, export format, and provider wire finding format retain
their current versions when their structure and semantics remain unchanged.
Every changed embedded schema has one paired valid example and semantic tests.

### Historical compatibility fixtures

TASK-037 and TASK-038 preserve these existing behavior fixtures and extend them
to the new source model. Tests that create retired execution inputs may become
historical fixture builders; their read and integrity assertions remain required.

| Artifact or boundary | Existing fixture owner | Required retained behavior |
|---|---|---|
| Ordinary and old nonproduction results | `internal/app/query/service_test.go`, `TestValidateProductionProvenanceAllowsLegacyNonproductionRoot` | Read original schema and provenance without rewriting files |
| Child lineage and excerpts | `internal/app/export/service_test.go`, `TestBuildRedactedBundlePreservesSelectedFollowupAndHistoricalEvidenceIdentities` | Preserve parent/finding/evidence identity and redaction |
| Composite results | `internal/app/publication/composite_support_test.go`, `TestCompositeSupportLegacyMappingReturnsExistingArtifactUnchanged`; `internal/app/export/model_test.go`, `TestCompositeFindingsExportWithoutExcerptEvidence` | Retain unchanged historical bytes, portable support, and explicit absent evidence |
| Failed and cancelled runs | `internal/app/query/recovery_test.go`; `internal/app/publication/failed_run_recovery_darwin_test.go` | Inspect terminal state and retained reports after restart without enabling provider replay |
| No-change results | `internal/app/query/service_test.go`, `TestReadRunStatusAcceptsCanonicalEmptySupportIndexForNoChange` | Preserve zero attempts and historical support verification |
| Capture and selected evidence corruption | `internal/app/query/inspection_test.go`, `TestInspectionVerifiesCompleteCaptureAndRejectsLostBlob`, `TestReadFindingRejectsChangedBoundExcerpt` | Fail closed on bound historical corruption; do not use a live source as replacement |
| Publication reconciliation | `internal/app/publication/service_test.go`, `TestRecoverCommitsExactPreparedCompositeFromP1Installed` | Reconcile the exact prepared artifact without invoking a provider |
| Cleanup lineage | `internal/app/clean/planner_test.go`, `TestPlanProtectsFailedRecoveryAndTransitivePublishedAncestors` | Preserve protected lineage and secure project-local deletion scope |

### Native feasibility route

The three `TestLive{ZCode,Grok,Codex}LiveSourceFeasibility` probes in
`internal/adapters/providercli/live_source_feasibility_test.go` use the
`liveprovider` build tag on native Apple Silicon macOS. Each uses an isolated
original repository, separate neutral cwd, projected credentials, and an owned
namespace. No source materializer or capture archive participates.

| Provider and observed baseline | Native read and instruction route | Mutation denial and report route |
|---|---|---|
| ZCode app 3.14.4, launcher 0.16.9 | App-server session in plan mode; Read/Glob/Grep/Bash allowlist; absolute file reads and fixed-environment Git; memory disabled; the regular neutral AGENTS.md stops nearest-guide ancestor discovery, and the projected home contains no user guide | Reject every interactive permission request and forbid write/edit/web/plan-transition tools; require a native Bash error for the mutation probe; collect correlated assistant messages after turn completion |
| Grok CLI 1.0.46, ACP v1 | Plan mode with read_file/grep/list_dir/Bash only; sterile compatibility, hooks, rules, skills, plugins, and MCP configuration; custom workspace sandbox with explicit read_only source and neutral directories, and real operator-home denial; allow only declared file reads and the two exact raw-object Git commands in ACP permission responses | Reject all other permission requests, including the exact mutation probe; its cancelled terminal response is the expected negative result; a separate successful conversation supplies the complete correlated assistant report |
| Codex CLI 0.156.0, app-server | Strict configuration with the existing read-only permission profile and approvalPolicy=never; project_doc_max_bytes=0; require an empty instructionSources receipt; explicitly set the deterministic shell Git environment | Require the actual commandExecution completion, nonzero exit, and native permission error for the mutation command, including its native shell wrapper; collect the correlated final_answer report |

All probes bind Git through `GIT_DIR` and `GIT_WORK_TREE` while keeping both
process and session cwd neutral. Use `/usr/bin:/bin`, disable optional locks,
lazy fetch, replacement objects, global/system configuration and attributes,
fsmonitor, and hooks. The allowed `git --no-pager show :target.txt` and
fixed-commit blob reads do not request external diff or textconv. ZCode's native
plan classifier rejects `git -C`; changing cwd or broadening permission is not
the route. TASK-035 and TASK-036 must preserve safe Git execution when adding
the remaining selector operations.

Worktree, index, and fixed-commit contents are independent random values withheld
from the prompt. A successful complete assistant report must contain all three
observed values. Source guides contain conflicting instructions; ancestor guides
contain a distinct hostile marker. The source, complete Git directory, ancestor
guides, and regular shared guide must retain identical bytes and inventory.
The negative command attempts source, index, ref, Git configuration, and shared
guide mutations in one batch; its native denial is checked independently of
the assistant's explanation. This is bounded feasibility evidence, not a claim
that every possible hostile instruction or shell command has been certified.
Keep the ZCode-specific negative prompt distinct from the shared prompt: a
model non-attempt supplies no native denial receipt and fails the prerequisite.
Grok's base workspace profile also permits writes in native temp directories.
Its custom `read_only` source and neutral directories must preserve reads while denying
writes even when an original source lives beneath a temp directory. Preserve
these explicit paths in TASK-036 rather than relying on the source being outside
cwd. The probe verifies the ACP denial; TASK-036 must verify effective kernel
protection independently of that permission response. These are separate native
layers in the [Grok sandbox contract](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/18-sandbox.md).
The probes do not certify arbitrary out-of-source read denial for ZCode or
Codex; candidate ignores are not such a boundary. TASK-036 owns the applicable
credential-access checks without treating this feasibility result as proof.

Each provider also starts two sessions against the same source and neutral cwd
with independent namespaces. One returns its report while the other is cancelled
only after both turns are natively admitted and the peer read conversation is
still active. Cancellation must return the cancelled process
termination and a process-group-absent lifecycle receipt; every namespace and
transcript is drained through the existing owners. The probe checks owned
namespace environment paths and unchanged neutral-directory inventory. ZCode
uses its existing short, private shared runtime-temp directory for native socket
paths; its temp variables intentionally do not point inside one namespace.
These checks do not inventory all native filesystem writes or claim exclusive
scratch confinement. TASK-036 must verify the supported scratch lifecycle.

ZCode requires the observed `/Applications/ZCode.app` bundle layout and an
available account bridge. Grok requires the credentialed operator-home install
at `~/.grok/bin/grok`; it copies that executable into an owned temporary path.
The Codex probe requires explicit `MULGAE_LIVE_CODEX_BIN` and
`MULGAE_LIVE_CODEX_HOME`; it never discovers or changes the selected profile.
Supply those Codex inputs explicitly and run only the named prerequisites:

```bash
go test -count=1 -parallel=2 -tags=liveprovider \
  ./internal/adapters/providercli \
  -run '^TestLive(ZCode|Grok|Codex)LiveSourceFeasibility$' -v
```

A parallel budget below two fails before provider admission.
An exit-zero run that reports no matching tests is not prerequisite evidence.
This command does not certify the entire older `liveprovider` suite: its
pre-existing Grok executable-identity test still pins 1.0.40, outside this
candidate's observed 1.0.46 baseline and focused verification claim.
These observed versions establish feasibility rather than certification of
untested versions. Existing snapshot qualification tests do not satisfy this
prerequisite. Production constructors and entrypoints remain unchanged until
the subsequent owning tasks pass their checks.

## TASK-035: Implement live source readers

Add typed source access through existing domain/app/port boundaries and Git/workspace adapters. Workspace selection uses current eligible files. Stage reads index objects for candidates and support; head/commit/range read resolved Git objects. Preserve deletion, rename, root-commit, merge-parent, triple-dot, image, and no-change semantics. Avoid original-repository write-tree, temporary repos, checkout copies, source archives, and project-selected Git executables.

Verify partial staging with divergent worktree bytes, unchanged support with unstaged changes, root and merge commits, equal-content distinct roots, linked worktrees, ignored/untracked/tracked state, conflicts, missing revisions/objects, path safety, and binary signatures. Run focused Go checks followed by the applicable Make targets. Do not wire unfinished public execution.

The internal `LiveSourceOpener`/`LiveSourceReader` boundary selects sources
without a captured-tree identity. Whole-tree candidates use `included`;
transitions preserve added, modified, deleted, and renamed paths. Git revisions
are resolved once. Workspace and index reads remain live, including index
support; the caller keeps mutable state unchanged during review. Root leases
check directory identity and namespace without pinning directory content times.

The dark Git adapter uses the original admitted Git directory and `/usr/bin/git`
with fixed environment and read-only arguments. Executable-bearing Git policies
are disabled. Control responses retain their existing bounds; source-derived
inventories and file bodies have no product byte ceiling. Git and provider
runtime directories are excluded. The caller also supplies canonical
machine-owned credential/runtime roots, including arbitrarily named Codex
profile homes. The adapter resolves them to descriptor-derived filesystem paths
and excludes them from inventories and support reads, including case and
Unicode-normalization aliases. Admission rejects source, worktree Git, and
common Git directories inside those roots, including redirected Git pointers.
Repositories with alternate object databases fail admission; every Git read
rechecks that boundary so objects cannot come from an additional source store.
Rename comparison uses the fixed 50% threshold
without a repository-selected rename limit or copy-detection policy.
Git ignores select workspace candidates,
while safe support reads remain available. `.mulgaeignore`
is not interpreted in this path, and existing files are left untouched. The
non-Git workspace path retains local `.gitignore` selection. Raster reads verify
extension and signature and preserve binary bytes. Typed source errors keep
native paths and Git diagnostics in their private causes.

Production composition, capture contracts, CLI, and MCP remain unchanged. Native
provider restrictions belong to TASK-036, evidence retention to TASK-037, and the
public execution and compatibility cutover to TASK-038.

## TASK-036: Implement neutral reviewer execution

Separate source root from process/session cwd in provider invocation contracts. Initialize/read the shared guide safely without overwriting an existing file; inject it alongside existing role prompts. Preserve isolated credential projections and scratch lifetimes. Apply the proven native restrictions and exact source/Git access route from TASK-034.

Collect complete native assistant role reports for all three providers and remove source-tree report-write permission in the new path. Verify hostile instruction isolation, attempts to edit source/Git/guide, native scratch handling, concurrent session isolation, credential redaction, cancellation, and failed-provider identity without substitution. Reuse protocol correlation and qualification tests; certify effective behavior with bounded actual-provider fixtures.

### Native kernel protection amendment

The initial `TestLiveGrokNeutralKernelProtection` exposed Grok 1.0.46's
independent kernel gap. A test-only ACP client granted one exact Bash command
against disposable fixtures. Source, index, ref, Git configuration, and shared
guide writes succeeded despite custom `read_only` entries. A separate fixture
credential directory in `deny` remained unreadable, confirming that the custom
profile was active. TASK-034's ACP rejection evidence remains valid; it did not
prove this separate kernel protection.

Master approved a mandatory application-owned macOS Seatbelt launch boundary
for Grok's TASK-036 live path. The internal process adapter now consumes typed
protection roots without a shell or a changed provider identity. The outer policy denies writes
outside the owned invocation namespace, protects source/Git/neutral roots and
ancestor renames, denies protected credential reads and links, and restricts
Unix sockets at protected paths. Canonical descriptor admission rejects missing
or symlinked protection roots. Source binding and neutral guide authorities
retain separate directory identities; they do not freeze source contents.

Layering Seatbelt with Grok's own sandbox initialization fails with a native
`Operation not permitted` error before a session starts. The guarded new route
therefore uses `--sandbox off` inside the mandatory outer Seatbelt boundary,
while preserving plan mode, sterile configuration, closed protocol permissions,
and the fixed Git environment. This is an internal invocation choice under the
approved amendment, not a user-profile change or an unguarded fallback. The
actual guarded Grok fixture passed correlated command completion, original
file and fixed-object reads, shared-guide reads, owned scratch writes, all five
protected write denials, and fixture credential-read denial. These results
certify the outer policy, not Grok's inactive custom profile.

The shared reviewer-home adapter safely creates a complete default guide with
exclusive atomic rename, preserves an existing safe regular file, and rejects
unsafe guides or replaced directories. Concurrent creation and guide change
regressions pass. Internal invocation and
report composition now separate original source authority from neutral launch authority. Native stage
reports have returned the hidden committed and index tokens for each provider;
overlapping workspace sessions and cancellation have passed for each provider.
Grok's ACP partial tool-input notifications carry no permission authority and
must not be treated as complete read requests. Complete permission requests
still require exact admitted paths or Git commands. Terminal integrity checks
use an independent context so cancellation retains its typed outcome. Failed
protocol admission closes the unconsumed neutral descriptor.

A separate protected-root fixture exposed a ZCode read gap: native Bash read
the generated private token and the correlated report disclosed it while plan
mode and the isolated namespace were active. A test-only Seatbelt overlay
blocked the same native read with an observed tool error. That prototype keeps
ZCode's existing private short runtime directory writable for native sockets.
Master approved the ZCode guard amendment. Both live review and extraction now
require the app-owned outer boundary while preserving the native provider and
plan policy. The existing private short runtime directory is admitted by its
canonical path, current-user ownership, private mode and retained identity,
then checked before and after execution. It is the only additional writable
root; explicit protected-root denials still apply on overlap. Replacement,
symlink, unsafe-mode and missing-directory regressions pass.

Actual ZCode Bash receipts now prove that both direct and symlink-alias reads
of generated protected text fail without disclosing it. Grok rejects the same
unplanned command at its closed ACP permission gate. Codex's model probes did
not supply native command receipts, so its negative kernel probe uses the pinned
app-server's sandboxed `command/exec` operation with the production default
`mulgae` profile unchanged. Actual nonzero command results prove both direct and
alias denial. The assistant turn remains independently correlated. The
unsandboxed `thread/shellCommand` operation is excluded from this probe.

Native stage reports and overlapping review/cancellation pass under the ZCode
production guard. All three providers return complete extraction responses
without source-tree report writers. Platform tests prove writable invocation
and runtime scratch while overlapping source and credential roots stay protected.

ZCode's independent kernel fixture runs the actual executable in its existing
Electron-as-Node mode with the production boundary, environment and neutral
directory. Actual child-process results prove all five write denials, positive
source/Git/guide reads and owned scratch writes. The unchanged plan-mode
app-server conversation separately proves the correlated assistant report.

Read-only review identified neutral-descriptor leaks on early cancellation,
clock failure and missing conversation-driver returns. Regression tests
reproduced the leaks; consuming the descriptor immediately after valid request
admission fixes each return path. A separate kernel fixture reproduced access
through a preexisting credential hardlink outside its protected tree. Guard
admission now rejects multiply linked regular files in credential and writable
roots using descriptor-based metadata inspection. It follows no symlinks and
reads no file contents. Links outside writable roots are denied, while ordinary
source and Git hardlinks remain supported. Context cancellation and the request
timeout bound inspection. These controls do not contain unrelated same-user
processes.

Release-note decision: intentional no-note for TASK-036. This internal path has
no public composition or shipped command behavior until TASK-038.

The first selected review led to two corrections: reviewer-home revalidation
now checks the operator directory's ownership and permissions as well as its
children, and live ZCode extraction retains its tool-free policy without the
review-only allowlist. Focused regressions reproduced both omissions before
the fixes. A separate actual kernel probe rejected an outward-pointing
credential symlink while permitting direct access to the outside control
file; blanket rejection of internal symlinks was unnecessary. The shared
short native socket directory remains the approved exception, with its
cross-session residual recorded in
[DF-004](../deferred-feedback/README.md). This does not weaken the declared
source, Git, guide or credential denials.

The latest production candidate passes the relevant unit suite, preparation
checks and standard integration target. Actual native stage reports,
extraction, overlapping sessions and cancellation pass for all three providers.
Separate protected-read and kernel-write fixtures pass with real native
receipts. Unix socket fixtures verify direct and symlink-alias denials at
protected source and credential paths while owned invocation sockets remain
reachable. The selected Mulgae confirmation is complete, with no unresolved
in-scope findings. Public composition and
contracts remain snapshot-based until TASK-038.

The second review exposed a path-encoding mismatch in the launch policy.
Live execution now rejects non-printable or invalid UTF-8 policy roots before
Seatbelt or native provider configuration is produced. Printable Unicode and
quoted roots retain their literal meaning. Grok accepts partial tool-input
notifications without granting authority; only a complete, correlated
permission request can select an exact planned read with `allow_once`.
The common prompt qualifies fixed Git environment bindings for Git-backed
sources. Deadline and socket controls have focused regression coverage.
Canonical specification and architecture documents state that reads outside
credential roots and network destinations outside protected Unix sockets remain
outside the outer guard's containment claim.

The third review identified missing regression evidence for terminal integrity
checks. A deterministic registry test now replaces an isolated source or changes
its guide after a complete scripted native conversation. The terminal check
discards the report and returns a security failure, including when cancellation
coincides with the change. An unchanged binding retains its report after the
conversation completes. Removing only the deferred check through a temporary Go
overlay makes all three changed-binding cases fail. Focused tests also cover
Run-mode cancellation and invalid neutral launch descriptors. These tests add
evidence without changing production behavior. The frozen correction was
confirmed in the completed six-role assessment.

## TASK-037: Add live-result publication and historical readers

Publish the new source/evidence semantics without full-tree capture support. Keep trusted-field injection, finding validation, result/report integrity, single-final publication, typed failure coverage, and provider-free no-change behavior. Verify evidence against the correct source side and retain only selected excerpts or binary evidence needed by result readers.

Preserve untouched historical ordinary, child, composite, failed, and no-change artifacts and their verified reads/export. Add fixtures for historical absent capabilities, damaged receipts/evidence, stale pages, unsupported new source replay, and interrupted publication reconciliation without provider execution. Keep original-source consistency limits explicit. New execution remains unavailable until TASK-038.

## TASK-038: Cut over CLI/MCP and remove retired execution

Wire live orchestration and all five selectors through shared application admission. Preserve expected project binding; reject retired capture-bound guards and target/child requests before provider calls. Update capability/schema discovery, preflight, start/await/cancel, inspection, export, and cleanup projections together.

Remove snapshot materialization/archive writers and retired followup/delta/rerun/recovery/compose entrypoints, application wiring, recovery-only configuration, and obsolete assets/tests. Retain the narrow historical archive-reader boundary and atomic publication protections. Remove .mulgaeignore interpretation/generation while leaving existing user files untouched. Eliminate suggestions to invoke removed commands.

Update all affected runtime authorities, AGENTS.md invariants, public README/help/examples/schemas, architecture/security guidance, and source-distributed use-mulgae instructions in the same cutover change. Keep role defaults in their canonical asset. Run documented asset generators twice in the task that changes the assets; the second pass must leave the worktree unchanged.

Verify exact release-binary and CLI/MCP parity, wrong-root rejection, removed-command failures, empty-diff zero-provider calls, asynchronous cancellation/await identity, historical exports and cleanup protections, and absence of source snapshots. Exercise the updated documented preflight/start/await flow with the exact binary and supported clients; it must not request retired capture-bound guards. Existing runtime directories and temporary legacy workspaces are not disposable test inputs.

## TASK-039: Certify the integrated model and validate documentation

Verify that the runtime authorities, embedded contracts, help/examples, security guidance, and source-distributed use-mulgae instructions updated by the owning tasks match the implemented behavior. Finish the English prose review with humanizer once, preserving contract terms and commands. Cutover-required guidance must already be usable before this task begins.

Use isolated fixtures and the exact candidate binary for workspace/stage/head/commit/range, hostile instruction content, non-mutation, full reports, supported images, error paths, historical readers/export/cleanup, and concurrent reviewer-home sessions. Run the complete `make test` gate and the explicit two-home, three-role Codex opt-in certification. Missing provider prerequisites or skipped required live evidence block acceptance; do not change authentication or profile configuration without separate authorization.

Read back canonical docs and links, run `git diff --check`, and inspect status and complete diff. Promote durable outcomes and retire this dossier only at authorized epic closeout. Passing tests does not authorize installation, release, or epic acceptance.
