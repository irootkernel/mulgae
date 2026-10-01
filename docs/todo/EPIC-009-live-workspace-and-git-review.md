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

## TASK-035: Implement live source readers

Add typed source access through existing domain/app/port boundaries and Git/workspace adapters. Workspace selection uses current eligible files. Stage reads index objects for candidates and support; head/commit/range read resolved Git objects. Preserve deletion, rename, root-commit, merge-parent, triple-dot, image, and no-change semantics. Avoid original-repository write-tree, temporary repos, checkout copies, source archives, and project-selected Git executables.

Verify partial staging with divergent worktree bytes, unchanged support with unstaged changes, root and merge commits, equal-content distinct roots, linked worktrees, ignored/untracked/tracked state, conflicts, missing revisions/objects, path safety, and binary signatures. Run focused Go checks followed by the applicable Make targets. Do not wire unfinished public execution.

## TASK-036: Implement neutral reviewer execution

Separate source root from process/session cwd in provider invocation contracts. Initialize/read the shared guide safely without overwriting an existing file; inject it alongside existing role prompts. Preserve isolated credential projections and scratch lifetimes. Apply the proven native restrictions and exact source/Git access route from TASK-034.

Collect complete native assistant role reports for all three providers and remove source-tree report-write permission in the new path. Verify hostile instruction isolation, attempts to edit source/Git/guide, native scratch handling, concurrent session isolation, credential redaction, cancellation, and failed-provider identity without substitution. Reuse protocol correlation and qualification tests; certify effective behavior with bounded actual-provider fixtures.

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
