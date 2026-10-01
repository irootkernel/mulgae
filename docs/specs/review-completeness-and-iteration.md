# Review completeness and iteration

Execution hold: the [roadmap](../roadmap/README.md#epic-008-review-completeness-and-iteration)
requires EPIC-009 acceptance and a separately approved redesign before this work
resumes. The immutable-capture assumptions and legacy-execution retention below,
including RCI-006, do not override the [live-review transition](live-workspace-and-git-review.md).
Retain the earlier requirements for redesign; do not treat them as currently
executable work or implemented runtime claims.

This specification preserves the earlier, not-yet-implemented design for
[EPIC-008](../roadmap/README.md#epic-008-review-completeness-and-iteration).
It depends on explicit acceptance of
[verified review contracts](verified-review-contracts.md), not an unfinished
cross-Epic branch. Current runtime contracts remain in [contracts.md](contracts.md).
The [development dossier](../todo/EPIC-008-review-completeness-and-iteration.md)
owns temporary task detail; the roadmap alone owns delivery status.

## Purpose and non-goals

Support an explicit requirements review, selected-finding recheck after code
changes, and comparison of exact review results. These capabilities share
immutable inputs and provenance, but remain independently usable. A normal code
review and a batch followup do not require a requirements document.

Mulgae reports reviewer assessments; it does not prove program correctness,
execute project tests, approve an Epic, waive a finding, or decide whether to
merge. Aquarium and the operator retain workflow and acceptance ownership.
No permanent issue tracker, suppression database, automatic code modification,
semantic finding merger, cross-project comparison, provider substitution,
provider migration, autonomous remediation loop, or new job framework is added.

## Required behavior

- [ ] RCI-001: admit a structured, immutable Review Brief with explicit scope,
      requirements, criteria, role ownership, non-goals, and captured references.
- [ ] RCI-002: report every selected requirement as `met`, `partially_met`,
      `unmet`, or `unverified`, including explicit provider-free no-change
      results, with provenance and assessment limitations.
- [ ] RCI-003: keep requirements, finding severity, role coverage, extraction,
      publication, and operational exit semantics distinct.
- [ ] RCI-004: recheck an explicit bounded set of findings against one newly
      captured target, with per-finding results and bounded role-group execution.
- [ ] RCI-005: compare exact runs without a provider call, separating matches,
      new observations, non-observation, full-capture-bound followup claims,
      conflicts, and unavailable cases; bind every page to the selected receipt set.
- [ ] RCI-006: preserve original artifacts and legacy single-finding workflows,
      including explicit unavailable states for historical missing capabilities.
- [ ] RCI-007: expose guarded execution and verified reads through CLI and MCP,
      reuse event-driven waiting, and finish without an automatic review loop.

These are requirement verification checkboxes, not another lifecycle ledger.

## Review Brief input

The first format is strict UTF-8 JSON, `mulgae-review-brief.v1`, selected by a
project-relative `--brief` path or MCP `brief_path`. This is a planned interface.
Reject duplicate keys, unknown fields, invalid Unicode, NUL, traversal, symlinks,
and reserved/control paths. Do not add YAML, inline MCP document bodies,
remote URLs, executable directives, templates, or recursive document discovery.

The Brief is an explicitly selected invocation input. Read it once through the
secure capture boundary and retain its exact bytes and digest; do not read it
again while composing prompts. It may be an explicitly selected untracked file,
but that is not permission to admit other untracked files or bypass capture
exclusions. Apply `.mulgaeignore` and reserved-path policy to the Brief itself.
Preflight shows the Brief and all referenced content in the transmission plan.

The Brief's file bytes are captured from that admitted local file; code and
reference documents retain the chosen review target's Git-side semantics. A
staged review does not substitute working-tree versions for staged code or
reference files. References name exact captured workspace paths, such as
`after/docs/specs/contracts.md` or `current/README.md`. Require them to exist in
the admitted capture and bind their side and digest. Missing, excluded, or
unsupported references fail preflight, rather than silently reading the live
tree. A requirement describing a missing implementation is not an input-file
reference and must not be rejected just because the implementation is absent.

### Shape and limits

The Brief requires `schema_version`, `mode`, and `objective`. Optional
`non_goals`, `context_references`, and `requirements` default to empty arrays;
explicit null is invalid. Mode is `change` or `completion`.
Change mode focuses on the selected change; completion mode asks about the
stated criteria using the available capture. Completion mode does not enlarge
capture implicitly or bypass the selected target. Unavailable scope produces
`unverified`, not a claim of full-repository coverage.

Each requirement has an operator-assigned `id`, `text`, one or more
`acceptance_criteria`, exactly one `owner_role`, and optional `references`.
IDs are case-sensitive ASCII identifiers matching `[A-Za-z][A-Za-z0-9_-]{0,63}`.
Duplicates are invalid. Require the owner to be a selected, enabled role with
an admitted route. Supporting roles may report findings but cannot overwrite
another role's requirements assessment. Omission of the requirements list
means ordinary review with a structured Brief, not inferred requirements.

Bound metadata to 100 requirements, 32 criteria per requirement, 32 non-goals,
and 32 distinct referenced files across the Brief. Keep the existing 12,000-byte
objective rule, but do not introduce a product byte ceiling for captured Brief
prose, source, prompts, or provider reports. Keep control values bounded and
handle source-sized text through existing content storage. The file selector
uses existing safe-path bounds. The Brief objective retains valid UTF-8,
nonempty single-line, no-NUL/CR/LF admission; requirement and criterion prose may
contain JSON-escaped line breaks. A supplied Brief and legacy `--objective` are
mutually exclusive; do not concatenate or silently override them. Legacy
objective-only CLI/MCP limits and behavior remain unchanged.

Example of planned input, assuming the referenced file is in the capture:

```json
{
  "schema_version": "mulgae-review-brief.v1",
  "mode": "completion",
  "objective": "Assess cancellation and recovery against the stated criteria.",
  "non_goals": ["Do not redesign provider routing."],
  "context_references": ["after/docs/specs/contracts.md"],
  "requirements": [
    {
      "id": "REQ-CANCEL",
      "text": "Cancelling a wait must not cancel the underlying review.",
      "acceptance_criteria": [
        "The observer returns without transferring cancellation to execution.",
        "The same invocation can be awaited again."
      ],
      "owner_role": "logic",
      "references": ["after/docs/specs/contracts.md"]
    }
  ]
}
```

Brief text, criteria, and references are untrusted review data, not instructions
that can weaken provider permissions or Mulgae publication rules. Frame them as
such in trusted prompts. Extend the EPIC-007 preflight request identity with
Brief presence, exact bytes, requirement ownership, and reference identities.
Never treat an old guard as covering a new input dimension.

### No-change Git targets

The first version preserves the provider-free empty-Git-diff path. A Brief's
`completion` mode does not bypass `publishNoChange`, trigger qualification, or
convert `--stage`, `--dirty`, or `--diff` to `--workspace`. Empty patch/stdin
admission remains unchanged and is not this special case.

| Admitted request | Required behavior |
|---|---|
| Legacy objective-only review with an empty Git diff | Preserve existing no-change outcome, exits, and zero provider calls. |
| Brief in either mode with requirements and an empty Git diff | Return every selected requirement as Mulgae-derived `unverified`, reason `no_change_target`; do not infer an assessment from no findings. |
| Brief without requirements and an empty Git diff | Report evaluation not run with `no_change_target`, retain the Brief, and report zero selected requirements without claiming criteria were satisfied. |
| Completion with explicitly selected `--workspace` or a nonempty admitted target | Use the ordinary bounded assessment path for that capture; retain unavailable-scope limitations. |
| Invalid Brief, owner, reference, or guard, even with an empty diff | Fail normal admission before publication; do not replace an error with unverified success. |

No-change preflight must disclose that qualification and assessment will not run,
while still validating the Brief, references, roles, and guard components.
Reference paths must match the actual captured layout. The current no-change
Git layout uses `current/`, not `before/` and `after/`; no implicit prefix
rewriting or live-tree fallback is permitted. Preflight is not a publication.

On execution, persist the exact Brief, selected IDs/owners, capture identity,
and every unverified requirement in versioned, hash-bound publication support.
Expose zero evaluated requirements, the selected total, and evaluation-not-run
state independently from existing no-change content/extraction axes. Preserve
zero attempts and zero role reports; do not invent provider verdicts,
role-report URIs, or verification claims. This deliberately extends the new Brief-aware
no-change support format, not historical artifacts or their empty support
index. Reads and reports must preserve this distinction after restart.

Offer a next-action hint to explicitly select a workspace review and obtain a
new preflight, adjusting reference paths to that capture. Never start it
automatically. TASK-027 owns admission/preflight, TASK-028 owns no-change
publication, and TASK-029 owns inspection/reporting. Keep the Brief-aware
execution capability unadvertised until TASK-028 can publish these results;
TASK-027 may expose its provider-free preflight first.

## Requirements assessment

Mulgae owns the selected ID set, owner role, Brief digest, result identity, and
coverage. A provider proposes a verdict and rationale for its assigned IDs;
validate every echoed ID against that assignment. Keep the free-form role report
as the primary record and reuse the existing same-role, same-provider optional
structured extraction slot. No dedicated third assessment invocation is allowed.

| Verdict | Meaning and minimum support |
|---|---|
| `met` | The reviewer considers all stated criteria satisfied in the available scope, with captured implementation/support references and explicit limitations. It is not execution proof. |
| `partially_met` | Some criteria have support and other criteria are missing or contradicted; identify both sets. |
| `unmet` | The reviewer identifies a missing or contradictory obligation, citing the requirement and available implementation or captured search scope. |
| `unverified` | No admissible assessment is available, the owner did not answer, or required evidence/scope is unavailable. Include a stable reason; do not imply success. |

Every selected requirement appears once in normalized output. An omitted claim
becomes a Mulgae-derived `unverified` with no invented provider verdict. Duplicate,
unknown, or wrong-owner IDs invalidate that role's structured assessment set;
retain a valid primary role report under existing reports-only rules. An invalid
assessment extension must not discard independently valid ordinary findings,
unless a protected failure triggers existing fail-closed precedence. Use a
separately validated structured assessment section to make that boundary explicit.

Assessment evidence is a separate typed reference to captured material, not a
relaxation of finding evidence. It can cite an unchanged captured support file,
an exact requirement, or a declared captured search scope. Mulgae verifies bytes,
side, digest, and scope membership, not whether the model's interpretation is
true. `met` requires captured implementation/support evidence, not only the
requirement quoting itself. An absence claim names the examined capture and
limitations; a text search is not proof that no implementation can exist.

Store normalized assessments and input references in hash-bound publication
support, with independently versioned contracts. Report requirement coverage and
extraction availability separately from finding count and role execution coverage.
A legacy artifact without assessments reports capability unavailable, not an
empty successful assessment. Preserve original reports even if extraction fails.

Do not synthesize findings from `unmet`, promote `met` into approval, or infer
`met` from zero findings. Requirements verdicts do not change existing severity
thresholds or CI exit policy in this first version. Reports must prominently
show unmet and unverified obligations despite an otherwise successful command.
Any later requirements-based CI policy requires a separate explicit design.

## Selected-finding batch followup

Introduce a distinct `followup_batch` child-run contract, not a reinterpretation
of existing `followup` artifacts. Select one exact committed source run, 1 to 32
unique source finding IDs, and one current target. Reject `latest` and ambiguous
selectors on this new mutation. No Brief is required. A single-item batch is
valid, but the legacy single-finding command retains its existing contract.

Admit ordinary review, delta, rerun, and new composite sources only when each
selected finding has the required verified source/evidence capability. Historical
composites without it fail explicitly. Use the selected composite's copied
provenance rather than guessing an old source run. Preserve source final,
manifest, finding, evidence, and target receipts for the entire batch. Retain
the newly evaluated current capture's complete EPIC-007 identity and canonical
verification support in each batch publication, independently from source
finding identity, the batch request digest, and its model/effort provenance.

Capture the new target exactly once. Group work by source role and admitted
provider/profile route, using the existing coordinator and process-local lane
budget. A group may examine several findings in one review invocation, while
each finding retains an independent outcome. Require the currently configured
route to match that role's source provider/profile; a changed route requires a
separately authorized existing recovery/review path, not silent substitution.
Current model/effort policy is explicit in the new preflight and provenance;
never claim a new evaluation used the original model unless its identity matches.

Each selected role group is required for this batch. Preserve at most the
existing initial-plus-one-secondary invocation per group, with repair, retry,
and extraction sharing the existing second slot. Never retry separately per
finding or keep rechecking until all results are resolved. Preflight includes
group membership, selected source identities, invocation ceilings, and the full
run deadline before any provider request. These are review-path invocation
ceilings; existing qualification probes retain their separate current bounds
and must not be mistaken for a per-finding review allowance. No user-global
queue or provider lock is introduced.

Per-finding structured resolutions reuse `resolved`, `partially_resolved`,
`still_open`, and `unclear`. Each includes captured-current-target evidence and
rationale. If the item lacks an admissible structured answer, expose
`assessment_state: unverified`, `resolution: null`, and a stable reason; do not
fabricate `unclear` or `resolved`. Missing items affect those items; duplicate,
foreign, or unknown IDs invalidate that group's structured resolution set. A
valid primary report survives ordinary extraction failure. New findings, when
present, enter the ordinary finding validation path with fresh run-scoped IDs.

One batch owns one immutable run and at most one final artifact, containing all
selected items and one primary report per accepted role group. An execution
failure in a required group prevents an authoritative batch final. Preserve the
exact allocated run ID and non-authoritative diagnostics; accepted reports do
not become a partial approval. Ordinary missing/invalid structured answers can
still publish accepted reports with unverified item results. Protected failures
continue to deny publication. Automatic batch replay or partial-batch recovery
is out of scope; no uncertain mutation is retried blindly.

Reuse the attached invocation registry and existing `await_review` and
`cancel_review` semantics for batch starts. A cancelled observer never cancels
the batch. Disconnect does not authorize a replacement start, and there is no
restart-resumable scheduler. CLI execution retains its existing process ownership.

## Provider-free comparison

Comparison selects exact before and after run IDs in the same requested project,
plus optional exact committed followup run IDs as explicit resolution evidence.
No provider, persistent comparison artifact, source mutation, or working-tree
content read is permitted.

### Complete receipt-set pagination

Read every selected run under an EPIC-007 publication receipt. The comparison
scope binds the project, before receipt, after receipt, the complete selected
followup ID set and each corresponding receipt, filters, and comparison/identity
contract versions. Canonically sort the followup IDs, including an explicit
empty set, and reject duplicate selections. Input permutations must produce the
same scope and comparison content; neither ordering nor time selects a verdict.

Each receipt binds publication epoch, final/manifest digests, and the support
identities used for the comparison. Reobserve all selected publications and
verify required support before returning the first page and every continuation.
Bind the cursor to this entire scope, including followups not contributing to
the current page or excluded from resolution by target mismatch. Recheck the
original selection; do not rediscover runs or silently shrink the set.

Changing only a followup selection or receipt invalidates a continuation even
when before/after and filters are unchanged. Missing, replaced, corrupted, or
changed selected publications cause a typed page-level unavailable/integrity
failure, not a successful page with that evidence omitted or a row marked merely
unverified. Historical capability absence in an intact artifact is instead an
explicit semantic limitation. Native root anchoring remains allowed; comparison
must not read current source files. No persistent cursor session is required.

### Observation comparison

Use existing fingerprints only as conservative observation keys. The current
fingerprint can depend on title and evidence-region text; it is not a permanent
semantic issue ID. Match only unique one-to-one same-role observations with
compatible exact fingerprint and normalized evidence identities. Run IDs,
run-local finding IDs, and whole-target digests are provenance, not cross-run
match keys; verify each target independently rather than requiring equal target
bytes to compare changed code. Preserve every original finding. Ambiguous
duplicates stay ambiguous; do not merge votes, promote confidence, or assign a
project-global issue identity.

| Comparison category | Meaning |
|---|---|
| `observed_again` | A unique conservative observation match exists in both runs. |
| `newly_observed` | An after-run observation has no admissible exact match; it is not proof of a newly introduced bug. |
| `not_observed` | The comparable after-run scope/role has usable structured coverage but did not repeat the earlier observation. It is not resolved. |
| `resolved_by_followup` | An explicitly selected committed followup binds the exact source finding and the after capture's complete identity, with an admissible `resolved` claim and no contradictory eligible claim or after observation. It remains a reviewer assessment. |
| `unverified` | Coverage, evidence, correspondence, or compatible scope is unavailable or ambiguous. |

Determine scope comparability from captured target kind/sides/file set and role
coverage, not run timestamps. A narrow delta, missing role, reports-only result,
or absent current evidence cannot prove non-observation over a broader baseline.
A no-change after result has no evaluated role coverage and cannot prove
non-observation or completed requirements merely through `no_findings`.

### Resolution eligibility requires identical complete captures

Before and after may have different captures: that is the purpose of comparison.
Only transferring a followup resolution to the after state requires full equality
between the followup's evaluated current capture and the after capture. Use the
versioned [EPIC-007 capture identity](verified-review-contracts.md#capture-identity-and-request-identity),
not `target_sha256`, a request digest, a timestamp, or a Git patch alone. The
identity includes target kinds, Git mode/sides, all captured file paths and
content digests, capture policy, and supporting context. Matching code hunks or
finding excerpts cannot substitute for a matching complete inventory.

Bind the claim to the exact source publication and finding, including verified
composite remapping when applicable. Different objectives, selected roles, or
provider/model policy do not by themselves prevent capture equality; preserve
those differences as provenance, not a same-request requirement. If the Brief
is independently part of the target's ordinary file inventory, its change still
changes the capture. No field is omitted just to admit a resolution.

An intact historical artifact without enough bound material reports
`capture_identity_unavailable`; a proved different capture reports
`followup_target_mismatch`. Such claims are ineligible for resolving this after
state and remain visible with their reason, rather than being silently dropped.
Never weaken to patch-only comparison or reconstruct evidence from the live
tree. Support new batch and existing single-followup results only to the extent
that their verified identities prove this contract. A composite with no proved
common capture cannot supply one by choosing a convenient source role.

### Conflicting followup assessments

Group eligible claims by exact source publication/finding and evaluated current
capture identity. For each group, consider every explicitly selected, admissible
claim, preserving run/receipt, provider, resolution, rationale, and evidence
references. Different-target claims are ineligible, not votes for or against a
resolution at this target. These rules are deterministic and order-independent:

| Eligible claims or observation | Required result |
|---|---|
| `resolved` plus `still_open` or `partially_resolved` | Overall `unverified`, reason `followup_resolution_conflict`; preserve both sides. |
| `still_open` plus `partially_resolved` | The same conflict reason because the asserted resolution states differ; do not select either. |
| Multiple identical conclusive resolutions | Preserve every claim without increasing confidence or treating count as consensus. Only `resolved` can establish the resolved-by-followup category. |
| `resolved` plus `unclear` or an item with no admissible structured answer | The latter is inconclusive, not a contradictory verdict. A supported resolved claim remains eligible, with the inconclusive claims and their limitations visible. |
| Only inconclusive or unavailable resolution evidence | Resolution remains unverified; retain any independently established observation category and its evidence. |
| An eligible resolved claim plus a matching after observation | Overall `unverified`, reason `followup_observation_conflict`; preserve the after observation and the claim. |

Conclusive resolutions are `resolved`, `partially_resolved`, and `still_open`.
If more than one distinct conclusive value appears, record the resolution
conflict even when one value has more votes or is newer. `unclear` is not a
negative verdict. When both conflict types apply, emit both stable reasons in
canonical order. A conflict controlling the overall category must not erase
the separate observation result or any candidate claim. Timestamps, selection
order, provider preference, and majority voting never settle these conflicts.
Malformed or damaged publication data still fails the page-level read; it is
not an inconclusive model assessment. Freeze bounded/paginated claim detail
and exact reason projection in TASK-026, then implement it in TASK-032.

### Requirements comparison

Requirements comparison uses `(Brief digest, requirement ID)` as its first
version key. A changed Brief is not comparable merely because IDs were reused.
Show changed-contract/unavailable state rather than transferring an old `met`.
Do not add historical requirement editing or fuzzy criterion equivalence.

## Planned public surfaces and compatibility

| Planned surface | Responsibility |
|---|---|
| Existing CLI review/preflight with `--brief PATH`, MCP review/preflight with `brief_path` | Structured input using the guarded EPIC-007 admission path |
| Existing planned `inspect`, report reads, and MCP inspection/resources | Bounded requirements assessment pages and supporting evidence under the same publication receipt |
| `mulgae followup-batch --run ID --finding ID ... TARGET --preflight --output json` | Provider-free source selection, capture, grouping, and budget receipt |
| Same CLI command without `--preflight`, with native guards | One authorized batch execution |
| `preflight_followup_batch`, `start_followup_batch` | MCP batch admission; reuse `await_review`/`cancel_review` |
| `mulgae compare --before-run ID --after-run ID [--followup-run ID ...] --output json`, MCP `compare_reviews` | Provider-free, snapshot-bound comparison pages |

`TARGET` above denotes exactly one existing target selector, not a literal
argument. Preserve transport-specific support: CLI can use stdin as a target;
MCP cannot. Batch sources, guards, Brief references, and selected IDs are part
of the request identity. Read pages reuse EPIC-007 limits, continuations, and
content chunking. Comparison accepts at most 32 unique explicit resolution runs;
their complete receipt set remains bound to all comparison continuations.

TASK-026 freezes exact grammar, capability versions, reason codes, metadata
bounds, and old/new artifact support before wiring production. Supported
historical finals remain readable without rewriting. New schemas need paired
examples and semantic tests; do not advertise new capabilities before their
runtime path and tests exist. No Config rewrite, provider installation, release,
or Aquarium repository mutation is authorized by adopting this specification.
