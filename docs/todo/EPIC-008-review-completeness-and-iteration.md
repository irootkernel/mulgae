# EPIC-008 development dossier: review completeness and iteration

This temporary dossier defines the reduced requirements-assessment work approved
on 2026-10-27. The [roadmap](../roadmap/README.md#epic-008-review-completeness-and-iteration)
owns identity, lifecycle, membership and order. The
[specification](../specs/review-completeness-and-iteration.md) owns required behavior.
TASK-026 contract foundations, TASK-027 admission/preflight, TASK-028 internal
assessment/publication and TASK-029 verified public reads with paired
execution/capability activation are complete. TASK-033 certification is complete;
whole-Epic validation and explicit Epic acceptance remain pending.

## Goal, dependencies and execution boundary

Add optional explicit requirements to one ordinary review and retain one
inspectable assessment per item. Preserve current objective input, source
selection, provider routing, ordinary findings, exits and attached lifecycle.

The completed EPIC-007 and EPIC-009 provide verified reads and original-source
execution. TASK-026, TASK-027, TASK-028, TASK-029 and TASK-033 run in that order;
each depends on its predecessor. No completed Epic is reopened. Re-read current
code and native contracts before implementation; the source layout in older
designs is not an instruction to restore retired packages.

The approved Epic execution envelope governs implementation, verification and
review. This dossier defines work and grants no separate installation, provider
configuration or release authority.

## Exclusions and reserved identities

Exclude batch rechecks, cross-run comparison, resolution transfer, conflict
reduction, automatic remediation/retry, requirements-driven CI exits, full
Review Briefs, change/completion modes and referenced-document capture.
Create no source snapshots, replay archives, copied worktrees, content guards
or new execution framework.

TASK-030, TASK-031 and TASK-032 remain Deferred records outside current Epic
membership and acceptance. Their former batch-admission, batch-execution and
comparison purposes are preserved only in the roadmap's separate deferred
table and historical design decision. RCI-004 and RCI-005 remain reserved and
excluded. Reconsideration requires demonstrated need and a separately approved
original-source design; these records do not delay the five active Tasks.

## Ownership

| Owner | Required responsibility |
|---|---|
| `internal/domain` and `internal/ports` | Immutable requirement/assessment values and inward interfaces where needed |
| `internal/app/reviewrun` and input adapters | Secure optional input admission, role assignment, preflight and original-source orchestration |
| `internal/app/prompt`, review templates and canonical role assets | Frame requirements as untrusted data without duplicating role/provider defaults |
| `internal/app/validation` | Assigned-ID, owner, verdict and source-evidence validation; separate assessment and finding results |
| `internal/app/publication` | Hash-bound input and assessment support for ordinary and no-change results |
| `internal/app/{query,report,clean,export}` | Verified reads, rendering and bounded artifact lifecycle |
| CLI/MCP entrypoints and `internal/composition` | Parse/project the common use case and wire the existing invocation lifecycle |

Reuse existing boundaries and live readers. No other repository, new provider,
configuration migration or platform is part of this Epic.

## TASK-026: Freeze the reduced contracts

- [x] Define optional CLI `--requirements PATH` and MCP `requirements_path`
      on existing review/preflight inputs, usable alongside the existing objective.
- [x] Freeze strict JSON input, assigned IDs/owner roles, four verdicts, reasons,
      selected/evaluated counts, provider versus Mulgae-derived origin and
      not-requested/unavailable/not-run/evaluated availability. Valid provider
      unverified answers count as evaluated; placeholders do not.
- [x] Freeze reasons for disabled extraction, consumed allowance, omitted answers
      and invalid assessment content, plus the specification's independent-section
      outcome matrix, whole-response parse failures and protected precedence.
- [x] Define separate versioned assessment/publication/read contracts and the
      old/new support matrix; preserve current objective limits and source policy.
- [x] Specify normal assessment results and provider-free no-change results.
      The latter retain zero calls, no fabricated attempts/reports and one
      `unverified/no_change_target` row per selected item for every existing
      no-change case, including empty-tree HEAD.
- [x] Separate admitted local requirements bytes/digest from implementation
      evidence selected from workspace, index or resolved Git objects. The
      requirements file need not exist in the reviewed commit.
- [x] Add needed schema/example and semantic foundations without advertising
      unimplemented execution. Do not implement batch or comparison foundations.

Verify invalid input/ownership, missing answers, trusted-field ownership, paired
examples, historical absence and integrity distinctions. Run focused foundation
checks and applicable generation/static checks. Finish with no unresolved
product-scope, invocation-ceiling or compatibility decision for later Tasks.

## TASK-027: Admit optional requirements

- [x] Read one safe project-relative regular UTF-8 JSON file from the admitted
      local project filesystem once per request, even for staged/committed reviews.
      Retain its exact bytes/digest; prompts and publication reuse those bytes.
- [x] Validate strict fields, IDs, criteria, bounds, selected-role ownership,
      Unicode, ignore/protected paths and project binding before qualification.
- [x] Add provider-free CLI/MCP preflight through shared application admission,
      showing selected items, owners, source limits, evaluation-not-run state and
      known disabled extraction policy. Do not predict allowance consumption that
      may occur during execution.
- [x] Preserve objective-only behavior and selected workspace/index/Git semantics.
      Requirements do not widen source access or add referenced-document capture.
- [x] Keep public requirements-bearing execution unavailable until TASK-029
      supplies verified reads and enables execution/capability together. Preserve
      objective-only execution; preflight does not lock the source or input file.

Cover invalid JSON/Unicode, duplicate keys/IDs, missing and unsafe files,
explicit untracked input, wrong/unselected roles, objective coexistence,
and a safe untracked requirements file with staged/committed code whose
working-tree version differs. Cover known disabled extraction, source-side
isolation and input errors on all no-change targets, including empty-tree HEAD.
Prove rejected requests and preflight invoke no provider and publish nothing.
Run focused admission/transport tests and applicable unit/integration checks.

## TASK-028: Validate and publish assessments

- [x] Frame requirements as untrusted data for exactly their assigned roles.
      Retain valid initial structured assessments even with extraction disabled.
      Reuse existing extraction policy and budget; never enable it from input or
      add a call after retry/repair consumed the allowance.
- [x] Validate four verdicts and supporting source evidence independently from
      ordinary findings; retain primary reports and protected failure precedence.
- [x] Normalize one row per selected ID. Missing answers become `unverified`;
      duplicate, foreign or wrong-owner IDs invalidate the owning role's section.
- [x] Implement the independent-section outcome matrix and explicit reasons for
      disabled extraction, consumed allowance, omission and invalid content.
      Whole-response parse failures cannot supply independently validated sections.
      Preserve role coverage, finding extraction status and assessment availability
      as separate axes, including when only an assessment is valid.
- [x] Persist exact input, assignments, limitations and normalized results in
      hash-bound support under the existing publication owner. Count only valid
      provider assessments as evaluated; retain each normalized row's origin.
- [x] Preserve no-change zero-call publication with zero attempts/reports and
      zero evaluated count for every existing no-change target, including empty-tree
      HEAD. Exercise ordinary/no-change internal execution with focused tests;
      keep public requirements-bearing execution unavailable until TASK-029.

Cover all verdicts, omitted/malformed sections, unsupported evidence, absence
claims, ordinary extraction failure in either section, protected failures,
disabled extraction, consumed allowance, whole-response invalid JSON, mixed
provider/placeholder counts, publication interruption, corruption and restart.
Assert provider-call ceilings, one final at most and unchanged severity/CI exits.
Run focused prompt, validation/publication and applicable integration checks.

## TASK-029: Expose verified assessment reads

- [x] Extend existing inspection/JSON/report paths with requirement rows,
      rationale, evidence, limitations, origin and selected/evaluated coverage.
      Keep unknown historical counts unavailable instead of filling them with zero.
- [x] Show unmet/unverified results independently of finding count, severity
      filters and exits. Distinguish not requested, historical unavailable,
      not run, valid provider unverified answers and Mulgae-derived placeholders.
- [x] Preserve receipt-bound paging and evidence reads without provider calls,
      current-source fallback or historical artifact rewrites.
- [x] Extend query/cleanup/export allowlists only for owned new support, retaining
      export privacy, integrity checks and lineage protection.
- [x] Enable public requirements-bearing execution and its existing capability
      advertisement only together with the necessary verified CLI/MCP reads.
      Keep objective-only execution available; add no general feature-flag system.

Cover CLI/MCP parity, empty and large pages, reports-only output, missing owner
answers, old artifacts, receipt changes, tamper, concurrent cleanup and no-change
reads after restart, including empty-tree HEAD. Check count/origin parity and
that finding severity filters do not hide requirements. Prove public execution
stays unavailable before this Task and becomes usable with verified reads.
Use exact-binary consumer fixtures and applicable query/report/integration checks.
Every selected item must be inspectable through
public reads without private artifact parsing.

## TASK-033: Certify the reduced feature

- [x] Build a deterministic integrated fixture for requirements input, ordinary
      findings, all assessment states, missing answers and verified reads.
- [x] Freeze independent historical consumer fixtures; preserve current selectors,
      source restrictions, role routing, exits and attached start/await/cancel.
- [x] Verify invalid input before no-change publication, zero provider calls on
      all existing no-change cases including empty-tree HEAD, extraction-disabled
      and consumed-allowance outcomes, section independence/whole-response failures,
      provider/placeholder counts, local-input/source-side separation, protected
      failures, restart, support corruption and receipt-consistent paging.
- [x] Update public usage/help/examples and source-distributed client guidance
      only after their runtime paths are verified; synchronize canonical owners.
- [x] Run exact-binary and actual supported-client checks plus the complete
      current `make test` gate. State opt-in skips and unavailable evidence.
- [x] Under an explicit implementation envelope, perform one bounded live
      requirements-bearing review through existing routes and inspect its result.
      Record actual admitted provider assessments; Mulgae-derived placeholders
      alone do not establish structured coverage. No batch recheck is required.

A failed live demonstration is an evidence gap or remediation item, not
permission for unlimited retries or provider substitution. Keep current
mandatory ZCode and opt-in Codex Make policy; other provider campaigns retain
their separate authority. Run documentation/link checks and `git diff --check`,
then inspect the complete diff and status.

## Integration acceptance and next-session handoff

Require all five Tasks and RCI-001/002/003/006/007, including production wiring,
source/evidence restrictions, old/new compatibility, exact-binary/client proof
and the bounded live assessment. Zero findings or a model's `met` verdict
cannot substitute for verification. Keep all requirement checkboxes unchecked
until their behavior is verified.

TASK-026 supplies the frozen contracts and tested foundations. TASK-027 delivers
local-file admission and provider-free preflight under the approved
`aquarium:epic-handler` envelope. TASK-028 delivers internal assessment validation
and publication under the same envelope. TASK-029 delivers verified public
assessment reads and paired execution/capability activation. TASK-033 has completed
integrated full/live/client certification; whole-Epic validation and explicit
Epic acceptance remain pending.

Before eventual Epic closeout, promote durable outcomes to their canonical
owners, replace this Epic's Detailed SOT with Canonical Outcomes, remove this
dossier and its TODO index entry, repair links and obtain explicit Epic
acceptance. Retain the independent deferred Task records in the roadmap;
they are not dossier consumers or current completion blockers.
