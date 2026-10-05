# Native review contracts before review completeness and iteration

Decision: accepted for planned implementation on 2026-09-26.
Implementation status is owned only by the
[roadmap](../roadmap/README.md). Acceptance of this design is not evidence that
any new command, schema, or runtime behavior exists.

## Later execution-order decision

The 2026-10-01 live-review design places EPIC-009 after completed EPIC-007 and
holds EPIC-008 and TASK-026 through TASK-033 for redesign after EPIC-009 acceptance.
The [roadmap](../roadmap/README.md#adopted-execution-order) owns that order and status.
This supersedes the future execution order and capture-dependent EPIC-008
assumptions below. It preserves the accepted EPIC-007 implementation and historical
rationale. See [live workspace and Git review](../specs/live-workspace-and-git-review.md).

### Live provider protection decision

EPIC-009's native boundary probes showed that planning modes and permission
responses alone did not establish the required filesystem denials. Grok's
custom `read_only` entries permitted source, Git and shared-guide writes in a
kernel fixture while its credential denial remained active. ZCode's plan-mode
Bash tool also read protected credential text. These observations ruled out
native-only enforcement for those two providers.

ZCode and Grok therefore require Mulgae's outer Seatbelt launch guard for live
review and extraction. Grok uses `--sandbox off` inside that guard because
nested sandbox initialization fails before a session starts. ZCode retains its
private short socket directory as a bounded writable exception. Codex keeps
its native read-only policy and explicit credential-root denials. The guard's
containment claim covers the declared protected roots; ordinary network access,
reads outside credential roots and unrelated same-user processes remain outside
that claim. Current behavior and limits are owned by the
[security specification](../specs/security.md) and
[live execution specification](../specs/live-workspace-and-git-review.md).

## Context

The adopted work combines four improvements: verified public inspection,
structured Review Briefs and requirements assessment, selected-finding batch
followup and run comparison, and native project/preflight binding.

At adoption, the product had immutable capture, optional structured findings,
free-form role reports, single-finding followup, delta, rerun, exact composition,
and attached start/await/cancel. The remaining work was richer verified
consumption, native request checks, and explicit assessment/iteration semantics
within the existing provider transport and orchestration system.

## Decision

Deliver two sequential Epics:

1. **EPIC-007: Verified review contracts** owns project binding, preflight guards,
   coherent inspection, lossless public reads, and new self-contained composite
   evidence. It is useful with current objectives and finishes independently.
2. **EPIC-008: Review completeness and iteration** builds on the accepted first
   Epic to add immutable Briefs, requirement assessments, bounded batch followup,
   and provider-free exact-run comparison.

Execute every Task in roadmap order. Start the second Epic only after explicit
acceptance of the first, not merely after its last implementation Task. A future
Brief extends an established request identity; EPIC-007 cannot depend on a
not-yet-built Brief engine.

## Ownership and trust boundaries

Project binding is independently established local identity, not content-only
identity, a bearer credential, or a promise against a malicious host. Native
admission checks guard the exact immutable input that will execute before any
qualification or provider transmission.

Verified reads derive from publication authority and receipt-bound continuations,
not independent path comparisons or private artifact parsing. New composites
retain their own copied evidence; historical absence remains explicit. Reads do
not create runs, rewrite artifacts, or invoke providers.

Briefs are untrusted requirements data. Providers propose assessments, while
Mulgae owns assigned IDs, evidence binding, coverage, and publication. Keep
requirements verdicts distinct from findings, extraction, CI exits, and approval.
Missing support is unverified, not satisfied.

Batch followup reuses the current execution coordinator, one captured new target,
and bounded role groups. It owns one immutable run, not a persistent campaign.
Original artifacts never change. Comparison is a read-only projection of exact
selected runs and optional exact resolution evidence; fingerprints are
conservative observation keys, not semantic issue identities.

Aquarium and the operator retain remediation, issue disposition, waiver, and
Epic acceptance. Mulgae does not become a second scheduler or issue tracker.

## Plan-review refinements

The 2026-09-27 review retains the two Epics and existing Task identities while
closing four implementation-contract gaps:

| Decision | Reason and ownership |
|---|---|
| Preserve provider-free empty Git diffs, including completion Briefs; retain every selected requirement as unverified/no_change_target with explicit evaluation-not-run state. | Avoid implicit scope expansion and a false assessment-success signal. A workspace assessment is a separately selected request. TASK-026 through TASK-029 cover admission, new publication support, and reads. |
| Define complete capture identity separately from patch digest, request identity, and publication receipt. | Equal patches may have unequal supporting files. EPIC-007 defines and retains the canonical identity; EPIC-008 transfers a resolution only to an equal evaluated-current/after capture. Different before/after captures remain comparable. |
| Bind comparison pages to before/after and the complete selected followup ID/receipt set, including filters and versions. | Every selected publication contributes to the query's fixed evidence scope. A missing or corrupt followup fails the page rather than changing the inputs mid-query. |
| Preserve conflicting conclusive followup assessments as unverified with stable reasons; retain inconclusive claims separately. | Ordering, timestamps, provider preference, and majority counts are not resolution authority. TASK-026 defines the table and TASK-032 applies it with full provenance. |

Capture identity excludes workflow-only objective, routing, and selected-source
inputs but includes the full captured target, logical sides, file inventory,
policy, and supporting context. Historical missing identity remains unavailable;
corruption is a read failure. No change to the existing patch-hash meaning or
retroactive artifact rewrite is authorized. Composite provenance must not claim
a common capture unless all contributing role captures prove it.

No-change Brief publication is a deliberate versioned extension of the existing
zero-attempt/zero-report path, not an attempt to fit assessment records into a
legacy empty support index. Brief-aware execution stays unadvertised until that
publication path is ready. Deterministic regressions cover all four decisions;
they do not enlarge the bounded live campaign or introduce a new review loop.

## Alternatives not adopted

| Alternative | Reason |
|---|---|
| Four independent Epics | Splits shared request/result contracts and fragments the initial-review-to-recheck flow without a separate delivery requirement. |
| One large Epic | Couples foundational safety/inspection delivery to much broader assessment semantics and delays an independently useful result. |
| Three Epics separating assessment and iteration | Reasonable for a later expanded issue-tracking scope, but unnecessary for the bounded selected-finding workflow adopted here. |
| Bind by target hash alone | Equal-content worktrees can still be different local review projects. |
| Fix all ambiguity in agent instructions | Leaves native invariants dependent on repeated client-side checks. |
| Infer resolved from a missing finding | Confuses changed scope, extraction gaps, or model variation with a verified followup claim. |
| Run completion providers automatically on an empty diff | Changes the existing no-change execution contract and can expand the requested scope; use explicit workspace selection instead. |
| Treat equal patch hashes or request hashes as equal evaluated targets | Patch hashes omit support context, while request hashes also include workflow-only inputs that need not match. |
| Bind paging only to before/after or choose the newest conflicting followup | Lets relevant evidence change mid-query or substitutes timing for resolution evidence. |
| Persistently track, suppress, or merge semantic issues | Adds cross-run authority and policy beyond this scope. |
| Add a new execution framework for batch review | Duplicates existing lifecycle, cancellation, concurrency, and publication ownership. |

## Consequences and verification

Public result and artifact changes require explicit schema/capability versioning
and historical reader fixtures. Old output stays immutable; unsupported new
capabilities are typed absence rather than silent fallback. Per-response bounds
must not become provider-content ceilings.

Both Epics need targeted negative tests, exact-binary and supported-client
verification, and the existing complete repository gate. EPIC-008 additionally
needs a bounded authorized live initial-review/recheck demonstration, not a
quality benchmark or an unbounded clean-review campaign. Delivery does not
include provider migration, host configuration changes, installation, release,
or changes in other repositories.

The durable details live in [verified review contracts](../specs/verified-review-contracts.md)
and [review completeness and iteration](../specs/review-completeness-and-iteration.md).
Temporary dossiers are retired at Epic closeout after their durable outcomes
have been promoted to the canonical owners.
