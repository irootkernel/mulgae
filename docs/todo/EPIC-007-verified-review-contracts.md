# EPIC-007 development dossier: verified review contracts

This is an adopted temporary development dossier, not implementation evidence.
[Roadmap](../roadmap/README.md#epic-007-verified-review-contracts) owns all Task
and Epic status. The durable requirements are in
[verified review contracts](../specs/verified-review-contracts.md).

## Goal and starting point

Finish a native chain from independently identified project and admitted input
to one verified result. This work combines result inspection and native
project/preflight verification. It must finish before EPIC-008 starts and must
remain useful without any EPIC-008 feature.

Planning baseline: `d21e77a`. Re-read the worktree before each Task; this revision
is navigation context, not a required reset or implementation pin. Existing
completed Epics and TASK-018 stay completed. Do not reopen them retroactively.

| Existing owner | Reuse or extend |
|---|---|
| `internal/app/reviewrun/{model,preflight,service}.go` | Capture, planning, qualification, execution admission |
| `internal/ports/{foundation,review_input,publication}.go` | Anchored identity, captured values, publication boundaries |
| `internal/app/query/{model,service,composite}.go` | Verified reads and historical capability checks |
| `internal/app/report/{service,render}.go` | Rendering under committed source identity |
| `internal/app/{reviewcompose,publication}` | Composite source provenance and atomic support publication |
| `internal/entrypoint/mulgae/{parser,handlers,review_preflight}.go` | CLI grammar and projection only |
| `internal/entrypoint/mcp/{tools,resources,projection,invocations}.go` | MCP projection and existing lifecycle |
| `internal/composition/mcp_backend.go` | Shared application wiring |

At baseline, CLI findings JSON has a count but no finding array, CLI report
rendering requires a destination write, composite excerpts are unavailable, and
root/preflight checking relies partly on agent guidance. Preserve existing
fail-closed behavior while closing these explicit product gaps.

## Execution order and scope control

Execute TASK-019 through TASK-025 sequentially. Each Task is one implementation
goal with its own focused tests and one task-owned commit when separately
authorized. Do not include unrelated cleanup or change another repository.
The completed previous Task is the next Task's prerequisite. TASK-019 may add
tested contract foundations without production callers; later Tasks expose only
capabilities they actually implement.

Do not wait for Review Briefs, batch followup, new providers, a standard Tasks
extension, or a new service. Do not add provider calls to a read or preflight.
Do not weaken TASK-018 guidance before the native replacement is accepted.

## TASK-019: Freeze identity, guard, and verified-read contracts

**Implement**

- [x] Inventory existing machine schemas, historical readers, relevant command
      grammar, P2 receipts, and composite support formats.
- [x] Define typed project binding, complete capture identity, request identity,
      guard, publication receipt, cursor, and capabilities in the existing
      domain/app/port owners. Freeze canonical encoding and mismatch precedence.
- [x] Separate target kind/sides, complete file inventory, capture policy, and
      support context from request-only objective, roles, provider policy, and
      workflow source inputs. Preserve the existing patch-only target SHA-256.
- [x] Define retained canonical capture support and historical availability,
      including ordinary, no-change, existing child, and composite publications.
      Reuse file-set computation under an application owner, not CLI-only policy.
- [x] Freeze every planned CLI/MCP surface in the specification, including
      finding detail access, role reports, evidence index, and diagnostic-only
      behavior. Allocate only the next versions actually needed by this Task.
- [x] Add affected new contract schemas, paired examples, and semantic tests;
      record an old/new writer-reader matrix and inactive-feature boundaries.

**Do not**

- [x] Advertise unimplemented tools, persist a global project ID, introduce a
      capability-token service, or break legacy result meanings silently.

**Verify and complete**

- [x] Test encoding separation, omitted versus explicit input, cursor binding,
      unsupported capability, old fixture reads, and malformed new examples.
- [x] Prove identical patches with different unchanged support files, logical
      sides, or context have different capture identities. Prove request-only
      changes can preserve capture identity while changing request identity.
- [x] Complete the documented generator checks when assets change, plus focused
      tests and `make test-prepare`. Read back the contracts and diff.
- [x] Finish only when later Tasks have no unresolved wire identity, read-size,
      compatibility, or public surface decision. A concrete blocker stops here.

TASK-019 release-note decision: intentional no-note. These inactive contract
foundations add no user-facing command or runtime capability. The later owning
Tasks record release notes when those capabilities become available.

## TASK-020: Implement independently comparable project binding

**Implement**

- [x] Add descriptor-backed local worktree identity and revalidation through an
      application port; keep filesystem details in the adapter.
- [x] Wire read-only CLI `context` and MCP `get_context` to that shared service.
      Publish only implemented binding capabilities and redacted identity.
- [x] Test independently obtaining the expected identity from the requested root
      rather than trusting the server's self-reported identity as its own proof.

**Do not**

- [x] Retarget an attached server, initialize configuration, read credentials,
      invoke a provider, or expose absolute paths through the new response.

**Verify and complete**

- [x] Cover same root, canonical aliases, equal-content distinct checkouts,
      linked worktrees, directory replacement, unavailable roots, and unsafe
      path/metadata failures with zero provider and persistent-write calls.
- [x] Add CLI/MCP parity and release-binary fixture coverage. Run focused tests,
      `make test-unit`, and `make test-int` for affected ownership boundaries.
- [x] Complete when identity is independently comparable and root drift fails
      before subsequent guarded operations can use a foreign root.

## TASK-021: Bind preflight to execution admission

**Implement**

- [x] Produce the complete capture and component/request receipts from existing
      capture/planning, covering target, context, policy, routes, assets, and
      budgets without hashing temporary paths or run-specific metadata.
- [x] Bind the capture identity and canonical verification manifest into new
      ordinary/no-change and existing child publications. Preserve no-change
      zero-provider behavior and version new support without rewriting old files.
- [x] Accept paired expected-binding/request-digest guards through CLI review
      and MCP foreground/start paths. Validate before qualification or review.
- [x] Execute the exact capture and plan checked by the guard; preserve existing
      spawn revalidation, legacy unguarded behavior, and lifecycle ownership.
- [x] Add native result fields distinguishing guarded and unguarded execution;
      document why a guard does not make start idempotent.

**Do not**

- [x] Compare one capture and execute another, transmit a qualification packet
      before rejecting drift, or create runs/diagnostics during preflight.

**Verify and complete**

- [x] Mutate target files, binary content, objective, context, exclusions, role
      selection, model/effort policy, route/profile, and assets between preflight
      and execution; reject changed requests with zero provider invocations.
- [x] Prove post-admission live-tree edits do not change the execution snapshot,
      guards cannot cross roots, and observer cancellation remains isolated.
- [x] Cover equal-patch/different-support captures and request-only changes over
      identical captures. Verify published capture support after restart and
      corruption; keep the legacy no-change outcome and exit behavior.
- [x] Add release-binary/transport regressions and run focused plus applicable
      unit/integration checks. Complete without relying on EPIC-008 inputs.

## TASK-022: Provide coherent inspection and finding pages

**Implement**

- [x] Extend the verified query owner to return one reobserved publication
      receipt with status, capture identity/availability, coverage, extraction
      state, and finding page. Verify capture support, not just a stored digest.
- [x] Wire CLI `inspect`, MCP `inspect_review`, and versioned finding-list
      projections, preserving total-count semantics and canonical ordering.
- [x] Provide bounded verified finding details and cursor-bound continuation;
      keep report/source bodies out of unbounded summary arrays.

**Do not**

- [x] Stitch public status and findings queries together, read raw final JSON
      after an unrelated check, or equate reports-only zero findings with clean.

**Verify and complete**

- [x] Cover empty, multi-page, exact-boundary, final-page, mixed, reports-only,
      diagnostic-only, and historical-capability cases. Missing historical
      capture support is unavailable; corrupted bound support fails the read.
- [x] Inject corruption, cleanup, epoch replacement, filter changes, and foreign
      cursors; prove failure without mixing snapshots or choosing another run.
- [x] Run query/projection tests and applicable unit/integration gates. Complete
      when an agent can obtain IDs and verified details without private IO.

## TASK-023: Add lossless read-only report and evidence access

**Implement**

- [x] Reuse committed report rendering for CLI read-only report chunks and
      equivalent MCP resources, including original per-role reports.
- [x] Bind all report/detail/evidence continuations to their receipt and complete
      content digest; expose every supported evidence index, not only the first.
- [x] Preserve legacy report-to-file as a separate explicit mutation.

**Do not**

- [x] Create report files during reads, cap total provider report size, truncate
      content silently, or fall back to current working-tree evidence.

**Verify and complete**

- [x] Cover empty valid files where supported, large reports, UTF-8 boundaries,
      exact binary bytes, out-of-range offsets/indices, missing support, and
      mid-pagination tamper. Reassemble all chunks to the exact original bytes.
- [x] Prove no writer or provider invocation through new reads, and ordinary
      CLI/MCP evidence parity. Run focused and release-binary fixture tests.
- [x] Complete when every supported normal-run content item is fully retrievable
      through its public verified read path.

## TASK-024: Publish self-contained composite evidence

**Implement**

- [x] Extend new composite support with verified source finding/evidence copies,
      source receipts, remapped IDs, per-source capture identity/support, and
      per-item capability metadata. Expose a common capture only when every
      contributing role capture is proved equal; preserve composition admission.
- [x] Support published and retained failed-run recovery sources without
      changing exact same-target composition or replacing accepted roles.
- [x] Integrate atomic publication/recovery, query, cleanup, and export policy.
      Keep legacy composites readable with explicit evidence unavailability.
- [x] Preserve idempotent existing mappings: finding an already published legacy
      composite returns it unchanged, not a retrofitted artifact at the same ID.

**Do not**

- [x] Repair old evidence implicitly, read source runs lazily after publication,
      include additional private source in exports by default, or weaken replay.

**Verify and complete**

- [x] Exercise ordinary/recovery sources, missing legacy evidence, ID remapping,
      interrupted support writes, journal replay, corruption, and exact reuse.
- [x] Verify newly self-contained evidence and capture identities after source
      cleanup permitted by the native cleanup contract and working-tree changes.
      Equal patches with unequal or unavailable source captures must not yield
      a falsely verified common capture identity.
- [x] Run composition/publication/query/export/cleanup tests and applicable
      integration/release gates. Complete with old/new artifact fixture coverage.

## TASK-025: Certify integrated contracts and simplify operating guidance

**Implement**

- [x] Exercise requested-root lookup, guarded preflight/start, event-driven wait,
      coherent inspection, full report reads, and composite evidence as one
      isolated workflow using the exact release binary.
- [x] Update public README, affected embedded help/examples, and
      `skills/use-mulgae` to use proven native checks. Retain safe CLI/legacy
      fallback for clients that cannot expose the new capabilities.
- [x] Freeze consumer fixtures/decoders independently of producer generation and
      test both CLI and attached MCP consumption. Include complete capture versus
      request identity, no-change provenance, and historical unavailability.
      Update canonical docs and requirement checkboxes only from verified outcomes.

**Do not**

- [x] Rewrite host configuration, migrate providers, claim unsupported client
      behavior, begin EPIC-008, or claim Epic acceptance from unit tests alone.

**Verify and complete**

- [x] Run the complete `make test` gate under repository authorization and
      credential rules. Its mandatory live ZCode/Grok checks remain mandatory;
      do not create an unrelated live matrix or require opt-in Codex by default.
- [x] Exercise the new tool schemas and waiting behavior with supported attached
      client versions; distinguish registration-only checks from actual client
      calls. Record blocked/unavailable client evidence honestly.
- [x] Review the whole diff and `git status`; require `git diff --check`.
      Report exact candidate, gates, and limitations without committing or
      publishing unless separately authorized.

## Epic acceptance and dossier retirement

Explicit acceptance requires VRC-001 through VRC-007, TASK-019 through TASK-025,
negative and compatibility matrices, exact-binary evidence, and the complete
repository gate. Passing every child is necessary but not sufficient; the
roadmap Epic changes only after integrated acceptance. Capture identity must be
verified from retained support independently of request identity, with the same
patch/different-support regression and historical unavailability established
before EPIC-008 consumes it.

Before closeout, promote enduring implementation details to specifications,
architecture, security, operations guidance, and the accepted design record.
Remove this dossier and its TODO index entry, replace the roadmap Detailed SOT
with Canonical Outcomes, and then record Epic acceptance. Update the specification
so it no longer links to a deleted dossier. Stop at the accepted scope; neither
an extra feature nor repeated clean reviews are a completion requirement.
