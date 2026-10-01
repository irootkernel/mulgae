# EPIC-008 development dossier: review completeness and iteration

This is an adopted temporary development dossier, not implementation evidence.
[Roadmap](../roadmap/README.md#epic-008-review-completeness-and-iteration) owns
status and dependencies. Durable requirements are in
[review completeness and iteration](../specs/review-completeness-and-iteration.md).

## Goal, dependency, and scope

Combine explicit requirements assessment with selected-finding rechecks and
provider-free result comparison. Keep these features independently usable:
ordinary reviews and batch followups need no requirements list.

The roadmap places this Epic and TASK-026 through TASK-033 under an execution
hold until EPIC-009 is accepted and this design is revised and reapproved.
Preserve the task detail below for redesign; its capture/replay assumptions and
legacy-execution promises do not override the live-review transition.
No Task in completed EPIC-007 or planned EPIC-009 waits for this Epic.

Planning baseline: `d21e77a`. Re-read current code before implementation; the
baseline is not a reset instruction. Existing single `followup`, `delta`,
`rerun`, and `compose` behavior remains available. New batch and assessment
formats do not retrospectively reinterpret their artifacts.

| Existing owner | Intended responsibility |
|---|---|
| `internal/app/reviewrun`, `internal/ports/review_archive*.go` | Capture Brief and selected content, extend native preflight identity |
| `internal/app/prompt`, `assets/roles.yaml` | Trusted framing of untrusted requirements, without duplicated role defaults |
| `internal/app/validation` | Assigned-ID admission and separately verified assessment sections |
| `internal/app/publication` | Immutable normalized assessments and batch artifacts |
| `internal/app/{followup,childrun,review}` | Source admission, one captured target, existing bounded group execution |
| `internal/app/{query,report}` | Snapshot-bound assessment/result inspection |
| `internal/domain/finding.go` | Existing fingerprint and run-scoped finding identity |
| `internal/entrypoint/{mulgae,mcp}`, `internal/composition` | Transport projection and shared use-case wiring |

New use-case packages are justified only for a distinct owner such as batch
admission or comparison. Do not create a general workflow engine or duplicate
provider execution. No Seongge/Gamchi/Zamchi/Camchi, Aquarium, Gaori, or Gul
repository changes are part of this Epic.

## TASK-026: Freeze Brief, assessment, batch, and comparison contracts

**Implement**

- [ ] Record exact CLI/MCP grammar, capability discovery, schema versions,
      structured bounds, and failure/coverage semantics from the specification.
- [ ] Define typed Brief and assigned-requirement values, normalized assessments,
      source-finding selections, batch outcome records, and comparison categories.
- [ ] Define a distinct batch run/publication contract and its required-group
      failure behavior; keep old single-followup schemas unchanged.
- [ ] Add schema/example/semantic foundations without advertising unimplemented
      paths. Record support by historical run type and evidence capability.
- [ ] Specify how the EPIC-007 request digest includes new input dimensions and
      how old guards fail rather than silently ignoring them. Keep complete
      capture identity separate from request and source-finding identity.
- [ ] Freeze the no-change result (`unverified`, `no_change_target`, evaluation
      not run), full comparison receipt-set/cursor binding, and deterministic
      followup conflict table from the specification. Map page-level read
      failures separately from semantic unavailable or conflicting assessments.

**Do not**

- [ ] Add a global issue ID, approval state, suppression database, new scheduler,
      arbitrary provider remapping, or fuzzy semantic correspondence.

**Verify and complete**

- [ ] Test schema boundaries, source/target identity separation, assigned IDs,
      omitted assessments, legacy artifact reads, and nullable resolution.
- [ ] Include no-change publication examples without attempts/reports, complete
      receipt-set permutations, conflicting conclusive verdicts, and inconclusive
      claims that are not negative verdicts. Keep the existing Task count/order.
- [ ] Run focused foundation checks and generator/static checks when applicable.
- [ ] Finish with an exact old/new compatibility matrix and no unresolved input,
      invocation-ceiling, publication, or comparison-state decision.

## TASK-027: Capture and admit structured Review Briefs

**Implement**

- [ ] Admit strict UTF-8 JSON through an explicit safe project-relative file
      selector, with duplicate-key, Unicode, reserved-path, and exclusion checks.
- [ ] Capture exact Brief bytes once, retain source-sized prose without a new
      content ceiling, and bind references to the selected target's captured sides.
- [ ] Enforce role ownership, cardinality limits, valid ID uniqueness, and
      mutual exclusion with legacy objective input.
- [ ] Extend CLI/MCP preflight and internal guarded admission with Brief identity
      and the complete transmission plan; use common application admission.
- [ ] Validate Brief/reference/owner and guard inputs before no-change dispatch.
      For empty Git diffs in either mode, disclose zero qualification/assessment
      calls and `no_change_target`; keep exact captured `current/` references.
      Do not advertise Brief-aware execution until TASK-028 preserves its results.

**Do not**

- [ ] Read references from the live tree after capture, discover remote/recursive
      material, execute Brief content, or bypass `.mulgaeignore` for explicit input.
- [ ] Convert an empty diff to a workspace review, rewrite reference prefixes,
      invoke a provider for no-change completion, or let no-change hide bad input.

**Verify and complete**

- [ ] Cover tracked and explicitly selected untracked Briefs, missing/excluded
      references, staged-versus-worktree differences, drift, symlink swaps,
      invalid UTF-8/Unicode, duplicate IDs, wrong roles, and legacy objective use.
- [ ] Prove rejected/changed requests invoke no provider; prove later Brief edits
      cannot alter admitted prompts. Include content beyond old incidental caps.
- [ ] Cover empty stage/dirty/diff with both Brief modes, with/without requirements,
      invalid references/owners, and mismatched guards. Assert zero provider calls
      and no implicit target substitution; contrast an explicit workspace request.
- [ ] Run focused capture/parser tests and applicable unit/integration gates.
      Complete with production CLI/MCP preflight and internal admission parity;
      Brief-aware execution remains unavailable until TASK-028, not silently empty.

## TASK-028: Validate and publish requirements assessments

**Implement**

- [ ] Frame mode, requirements, ownership, and references as untrusted review
      data while preserving trusted role and provider security instructions.
- [ ] Extend the optional structured path with a separately validated assessment
      section; reuse the current same-role/provider secondary invocation slot.
- [ ] Normalize exactly one result per selected requirement. Missing claims are
      unverified; wrong-owner/duplicate/unknown IDs invalidate the affected set.
- [ ] Verify typed captured-support and requirement references without relaxing
      finding evidence. Store assessments and Brief provenance in hash-bound
      publication support; keep primary reports and ordinary findings independent.
- [ ] Extend Brief-aware no-change publication with exact Brief, selected IDs and
      owners, complete capture identity, and one `unverified`/`no_change_target`
      result per requirement. Preserve zero attempts/reports and no evaluated
      requirements; with no requirements, retain explicit evaluation-not-run state.
- [ ] Enable Brief-aware execution only with this no-change path and its normal
      assessment path covered; do not relabel skipped assessment as reports-only.

**Do not**

- [ ] Derive met from zero findings, create findings from unmet verdicts, add a
      third model call, or turn textual agreement into test-execution proof.

**Verify and complete**

- [ ] Cover all four assessment states, missing and malformed sections, unsupported
      source references, absence claims, and contradictory self-attestation.
- [ ] Preserve valid ordinary findings on assessment-only failure and valid prose
      on ordinary extraction failure; retain protected failure precedence.
- [ ] Assert unchanged CI/severity exits and bounded invocation counts. Keep
      legacy no-change fixtures readable and new Brief-aware support versioned.
      Cover skipped assessment with zero calls, no fabricated provider fields,
      valid workspace evaluation, and ordinary/protected failure behavior.
- [ ] Run validation/publication/prompt regressions plus applicable integration
      tests, including the existing no-change service and publication tests.
- [ ] Complete when immutable assessment artifacts and provenance survive
      restart, corruption checks, and source-file changes.

## TASK-029: Expose assessment inspection and reports

**Implement**

- [ ] Extend EPIC-007 inspection and content resources with bounded requirements
      pages, owner/verdict/rationale, coverage, limitations, and evidence reads.
- [ ] Show unmet and unverified obligations prominently in rendered reports,
      independently of finding severity and command exit. Expose no-change
      evaluation-not-run state, selected/evaluated counts, and `no_change_target`
      without interpreting `structured`/`no_findings` as evaluated requirements.
      Give an explicit workspace/preflight hint, never automatic execution.
- [ ] Extend artifact query, cleanup, and export allowlists intentionally; keep
      local bindings and unrequested private source out of portable exports.
- [ ] Report historical unsupported assessments explicitly, not as empty success.

**Do not**

- [ ] Reassess with a provider during a read, rewrite old artifacts, or interpret
      a requirements verdict as organizational approval.

**Verify and complete**

- [ ] Cover complete, partial, reports-only, missing-owner, old-artifact, large-page,
      and changed-receipt cases through both transports and exact-binary fixtures.
      Verify Brief-aware no-change results after restart and reference-file edits,
      with/without requirements; contrast legacy assessment-capability absence.
- [ ] Reassemble supported content losslessly and fail closed on evidence tamper.
- [ ] Complete when a user can inspect every requirement and its limitations
      using public reads without parsing private runtime artifacts.

## TASK-030: Admit and plan a single-capture finding batch

**Implement**

- [ ] Admit one exact source run and 1 to 32 unique explicit finding IDs, checking
      supported source type, immutable receipt, and evidence capability.
- [ ] Capture the selected new target once and create deterministic role/route
      groups from that same capture, using current admitted model/effort policy.
- [ ] Require source role/provider/profile consistency; expose route differences
      as admission errors rather than silently selecting replacement providers.
- [ ] Add provider-free CLI/MCP batch preflight with selection, source receipts,
      complete evaluated-current-capture identity, request guard, role groups,
      invocation ceilings, and deadline. Do not substitute the batch request
      digest for current-capture identity.

**Do not**

- [ ] Execute providers, select latest, reconstruct missing legacy composite
      evidence, or require a Review Brief for this workflow.

**Verify and complete**

- [ ] Cover unique/duplicate/unknown IDs, size bounds, all admitted run types,
      historical missing evidence, source corruption/change, route/profile drift,
      target drift, and correct grouping with at most seven role groups.
- [ ] Use spies to prove one capture and zero invocations in preflight. Prove
      selection and source receipts are bound into the native request identity.
      Hold patch bytes fixed while changing a support file or context; require
      different current-capture identity and native rejection of the stale guard.
- [ ] Complete the source/planning tests and applicable unit/integration gates;
      leave batch start unadvertised until TASK-031 implements it.

## TASK-031: Execute and publish bounded batch followups

**Implement**

- [ ] Reuse coordinator lanes and child execution for the planned groups; each
      group gets at most its existing initial-plus-one-secondary budget.
- [ ] Validate per-finding source mapping, resolution, current evidence, and new
      findings; normalize unanswered items without inventing provider verdicts.
- [ ] Persist evaluated-current-capture identity and canonical verification
      support, distinct from source identity, request digest, and model policy.
      Verify its equality to the admitted capture when publishing and reading.
- [ ] Publish one batch run and final only after every required group supplies
      an accepted primary report. Keep reports-only item results explicit.
- [ ] Preserve exact failed-run identity and diagnostics on a required-group or
      protected failure; do not publish partial success as authoritative completion.
- [ ] Wire guarded CLI execution and MCP `start_followup_batch` to the existing
      invocation registry, `await_review`, and `cancel_review`.

**Do not**

- [ ] Retry per finding, create an automatic batch-recovery scheduler, mutate the
      parent review, or let observer cancellation kill server-owned execution.

**Verify and complete**

- [ ] Cover single/multiple items, mixed roles, one shared target, malformed group
      output, omitted results, group failure, reports-only success, cancellation,
      lost start response, disconnect, and publication interruption.
- [ ] Assert maximum calls, exact route/provenance, unmodified parent artifacts,
      one final at most, safe read/cleanup/export behavior, and old followup parity.
      Prove current-capture support survives restart and live-tree changes;
      missing historical identity is unavailable, corrupted bound support is an error.
- [ ] Run focused plus applicable unit/integration/release checks. Complete with
      terminal run reconciliation, never blind restart after uncertain delivery.

## TASK-032: Add provider-free run and requirements comparison

**Implement**

- [ ] Add one application use case reading exact before/after receipts and up to
      32 unique explicit followup receipts, without working-tree content or provider
      dependencies. Canonically order the selected set and reject duplicates.
- [ ] Bind the initial page and every continuation to the project, before/after,
      complete followup set and each publication/support receipt, filters, and
      contract versions. Revalidate every selected receipt on every page, including
      evidence for other pages or semantically ineligible claims.
- [ ] Implement conservative unique observation matching and scope/coverage
      checks. Preserve newly observed versus newly introduced distinctions.
- [ ] Require exact source-finding binding and equal complete evaluated-current
      and after capture identities for resolution. Compare different before/after
      captures normally; never require equal request digests across workflows.
- [ ] Implement the specification's order-independent conflict table. Conflicting
      conclusive followups yield `unverified`/`followup_resolution_conflict`;
      conflict with an after observation yields `followup_observation_conflict`.
      Preserve all claims, observation evidence, and both reasons when applicable.
- [ ] Keep `unclear`/missing answers distinct from negative verdicts. Surface
      ineligible-target and historical-identity reasons; unreadable or corrupted
      selected publications fail the whole page rather than shrinking the set.
- [ ] Compare requirements only under matching Brief identity and requirement
      IDs. Expose changed-contract and unavailable states explicitly.
- [ ] Wire paginated CLI `compare` and MCP `compare_reviews` using shared query
      and cursor contracts, without persisting a second review authority.

**Do not**

- [ ] Treat not-observed as resolved, match by run-local F-number or patch hash
      alone, use model consensus/latest time/input order, merge fuzzy duplicates,
      drop a selected followup during paging, or carry met across changed Briefs.

**Verify and complete**

- [ ] Cover one-to-one/duplicate/changed-title matches, differing roles and scope,
      narrow delta, reports-only after results, missing evidence, foreign roots,
      wrong-target followups, conflicts, changed Briefs, and corrupted receipts.
- [ ] Hold patch bytes fixed and vary support file content/path, binary content,
      logical side, or context between followup and after; reject resolution
      transfer. Identical captures with different objectives/roles remain eligible.
- [ ] Keep before/after fixed and delete, replace, corrupt, or change only a
      selected followup between pages, including one used on a later page.
      Require a typed page failure; changed selection fails and permutations agree.
- [ ] Cover resolved/still-open, resolved/partial, partial/still-open, identical
      conclusive claims, resolved/unclear, reports-only items, simultaneous conflict
      types, and different-target ineligibility. Permute inputs and timestamps;
      preserve all provenance without confidence inflation or winner selection.
- [ ] Prove no provider, mutation, or hidden live-tree content read, and no mixed
      receipt pages under concurrent cleanup. Run query and transport regressions.
- [ ] Complete with every result attributable to the two exact selected reviews
      and optional explicitly selected resolution evidence.

## TASK-033: Certify the complete bounded review iteration

**Implement**

- [ ] Build an isolated end-to-end fixture: Brief and initial review, missing
      requirement plus findings, a code change, selected batch followup, and
      provider-free comparison with explicit residual uncertainty.
- [ ] Add immutable consumer fixtures independent from producer regeneration;
      cover old ordinary/single-followup/composite artifacts and new contracts.
- [ ] Update public README, embedded help/examples, `skills/use-mulgae`, canonical
      specifications, architecture, security, and operator guidance.
- [ ] Verify requirement checkboxes from behavior, not model self-report or
      completed code scaffolding. Add deterministic integrated regressions for
      no-change unverified publication/reads, equal-patch unequal-capture rejection,
      followup-only continuation drift, and order-independent conflicting claims.

**Do not**

- [ ] Add automatic remediation, force unrelated repositories to adopt the APIs,
      require zero findings for acceptance, or repeat reviews until a clean result.

**Verify and complete**

- [ ] Run the complete `make test` gate. Preserve mandatory ZCode/Grok and opt-in
      Codex rules; use deterministic fixtures for exhaustive failure scenarios.
- [ ] Perform one explicitly authorized isolated exact-binary live Brief/recheck
      workflow through already configured routes, where deterministic tests cannot
      establish provider handling. Record exact requested and actually observed
      structured coverage; a missing assessment is not a passing demonstration.
- [ ] Limit that added live workflow to its initial review and one batch recheck,
      under existing per-group invocation bounds. A failed check is a reported
      blocker/remediation item, not permission for an unbounded retry campaign.
- [ ] Verify actual supported-client batch start/await behavior, distinguish
      registration checks from execution, and record unavailable evidence.
- [ ] Run `git diff --check`, inspect the complete diff and status, and report
      candidate identity, passes, skips, and blockers without unauthorized release.

## Epic acceptance and dossier retirement

Require RCI-001 through RCI-007, TASK-026 through TASK-033, legacy compatibility,
negative matrices, exact-binary/client evidence, bounded live evidence, and the
complete repository gate. The four feedback boundaries must pass through real
application/transport fixtures, not prose checks: no-change assessment, full
capture equality, all-followup receipt paging, and conflicting claims. Exhaustive
cases remain deterministic and do not add live retries. This is explicit
integrated acceptance, not automatic acceptance when all child statuses change.

Before closeout, promote implementation outcomes to canonical owners and update
cross-references. Remove this dossier and its TODO entry, replace Detailed SOT
with Canonical Outcomes in the roadmap, remove the specification's dossier link,
and then record Epic acceptance. Keep unresolved independent future ideas out
of acceptance. Stop when the agreed criteria are satisfied.
