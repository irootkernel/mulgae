# Review completeness and iteration

EPIC-008 implements explicit requirements assessment within one ordinary review.
Batch rechecks and cross-run comparison are outside the revised scope approved
on 2026-10-27.

The [roadmap](../roadmap/README.md#epic-008-review-completeness-and-iteration)
owns lifecycle and the five completed implementation Tasks. The
[verification guide](../implementation-tips/README.md) retains acceptance and
regression checks. Local input admission and provider-free preflight, assessment
execution/publication and verified CLI/MCP reads are implemented. Task and Epic
acceptance remain separate.
Current behavior remains defined by [contracts](contracts.md) and
[live workspace and Git review](live-workspace-and-git-review.md).

## Purpose and boundaries

Let an operator supply explicit requirements and receive one assessment for
every selected item. Keep requirements assessment optional: ordinary reviews
continue to use the existing objective, roles, source selectors and lifecycle.

Mulgae reports reviewer judgments and evidence limitations. Aquarium and the
operator retain test execution, remediation, issue disposition and final
acceptance. A satisfied requirement is not proof of correctness or approval.

This Epic excludes selected-finding batch rechecks, cross-run comparison,
resolution transfer, conflict reduction, automatic retries or remediation,
requirements-based CI exits, and a new scheduler or issue tracker. It adds no
change/completion modes, full Review Brief format, referenced-document capture,
source snapshot, copied checkout, source archive or capture-bound request guard.

## Required behavior

- [x] RCI-001: admit an optional requirements file containing explicit IDs,
      descriptions, acceptance criteria and one owner role per item, alongside
      the existing objective and original-source target.
- [x] RCI-002: retain every selected requirement with a verdict, rationale,
      evidence and limitations or an explicit unverified reason, including
      provider-free no-change results.
- [x] RCI-003: keep requirements assessment, ordinary findings, role coverage,
      extraction, publication and operational exits separate.
- [x] RCI-006: preserve existing execution and historical artifact readers;
      distinguish unsupported historical assessments from an empty successful
      assessment without rewriting stored results.
- [x] RCI-007: expose optional input and verified results through existing CLI
      and MCP review/preflight/read paths, preserving start/await/cancel.

Master retired the former batch-recheck and cross-run comparison plan on
2026-10-29. RCI-004, RCI-005 and TASK-030 through TASK-032 belong to that retired
plan. They are outside current Epic acceptance and planned or deferred work;
their IDs remain reserved and are not reassigned.

Unchecked requirements are planned obligations, not implementation evidence.

## Optional requirements input

CLI `--requirements PATH` and MCP `requirements_path` accept a project-relative
file for review or provider-free preflight. Requirements execution requires the
existing verified Git/common-directory project binding, with or without an
explicit expected-binding guard. Objective-only non-Git workspace execution
remains supported. Non-Git requirements preflight may validate input but discloses
unavailable execution and an empty requirements capability; execution fails with
`contract_unsupported` before private writer effects, allocation or qualification.

Use a strict UTF-8 JSON object with `schema_version` and a `requirements` array.
Each item contains `id`, `text`, `acceptance_criteria` and `owner_role`.
Retain the original metadata bounds of 100 requirements and 32 criteria per
item. IDs are case-sensitive ASCII identifiers matching
`[A-Za-z][A-Za-z0-9_-]{0,63}`; duplicates are invalid. Require nonempty
descriptions and criteria and an owner among the selected, enabled review roles.
Do not infer requirements or assign additional roles automatically.

Reject duplicate keys, unknown fields, invalid Unicode, NUL, invalid ownership,
unsafe paths and non-regular files before qualification or publication.
Use the existing secure project-relative file admission and applicable ignore
and protected-path policies. Explicit selection may admit an untracked input
file but grants no access to other excluded or protected material. There is no
YAML, inline document body, remote fetch, recursive reference discovery or
executable content.

Read the requirements file from the admitted local project filesystem once per
admitted request. It need not exist in the reviewed index or commit. Retain its
exact bytes and digest as invocation input; prompt construction and publication
reuse those bytes without reopening the file. A provider-free preflight validates
the file and discloses its presence, selected IDs and owners without creating a run.
A later execution admits its own input; preflight is not a content lock or a
promise that the file remained unchanged. Preserve the existing independent
expected-project-binding guard.

The requirements file and objective can be supplied together. Preserve existing
transport-specific objective limits and semantics. With no requirements file,
preserve ordinary review behavior. Do not add a product byte ceiling for
requirement prose, source observations, prompts or role reports.

### Current admission summary

Preflight v13 exposes bounded metadata under `requirements`: the exact input
SHA-256, selected count, ordered IDs and owners, `evaluation_status: not_run`,
known extraction policy, `source_limit: selected_target_only`, and
conditional `execution_available` matching actual Git binding availability. No text, criteria, assessment rows or verdicts
enter that summary. Input absence is explicit null. CLI includes the native
source read plan; MCP retains its existing bounded read-count projection.

The local-file port uses the admitted project descriptor and no-follow regular
file reads, independently of index or commit membership. It checks canonical
paths, protected roots, local `.gitignore` rules and the admitted common Git
directory's `info/exclude`, including linked worktrees.
Ordinary project directory and file permissions remain supported. A file that
also supplies ignore configuration must satisfy that control input's existing
bounds; the requirements prose contract adds no body ceiling. Same-request
control bytes are reused when the selected input itself is an ignore file.

Public execution admits the optional input through the shared application path
before run allocation, qualification or publication-directory creation. Requests
without the required Git/common-directory binding fail before those effects.
Preflight and execution each admit their own input before every no-change branch,
including empty-tree HEAD. Execution retains its admitted bytes for prompts and
publication; an earlier preflight neither supplies those bytes nor locks the file.

## Original-source evidence

Requirements describe the selected workspace, index or resolved Git target.
They do not enlarge that target or authorize reading another source side.
Use existing live source readers and evidence verification; staged evidence
must use index bytes and committed evidence must use the resolved Git objects.

Retain selected verified evidence needed to inspect an assessment. Do not
capture referenced documents or build a complete source inventory or content
fingerprint. Workspace/index consistency remains the caller's responsibility;
source identity records selection metadata rather than immutable contents.
Keep existing binary-evidence validation and private-content protections.

Treat requirement text as untrusted data in trusted prompt framing. It grants
no tool, test, build, network, filesystem or provider permission.

| Review target | Requirements input | Implementation evidence |
|---|---|---|
| Workspace | The admitted local requirements file | Eligible workspace content |
| Stage | The admitted local requirements file | Index content |
| Head, commit or diff | The admitted local requirements file | Selected resolved Git objects and source sides |

Requirement prose, quoted code and file references cannot establish implementation
evidence or authorize a different source side. A safe untracked requirements file
can accompany staged or committed code even when the working-tree code differs;
the requirements digest identifies invocation input only.

## Assessment and normalization

Mulgae owns the selected IDs, owner roles, input digest, result identity,
coverage and publication state. Providers propose assessments only for their
assigned IDs. Supporting roles may report ordinary findings but cannot replace
another role's assessment.

| Verdict | Meaning and support |
|---|---|
| `met` | The reviewer considers all criteria satisfied in the available scope, with verified implementation/support evidence and stated limitations. |
| `partially_met` | Some criteria have support and others are missing or contradicted; identify both. |
| `unmet` | The reviewer identifies a missing or contradictory obligation with evidence or a stated examined scope and its limitations. |
| `unverified` | No admissible answer or sufficient evidence is available; retain an explicit reason. |

A requirement quoting itself cannot establish `met`. Mulgae verifies evidence
binding and bytes, not the truth of the interpretation. An absence claim must
state its examined scope and limitations; a search is not proof that no
implementation exists.

Keep free-form role reports as the primary provider record. Reuse the existing
same-role, same-provider structured extraction allowance. Add no dedicated
assessment call or per-requirement retry; keep current invocation ceilings.

For roles with assigned requirements, append the trusted requirements output
contract after the initial, extraction or repair contracts. It selects full
provider-output v3 JSON, including the requirements section, instead of the
finding-only v1 form. A repair plan selecting a patch keeps its existing form
and allowed paths. Primary Markdown reports assess the assigned original IDs
and include exact verbatim target excerpts (source side, project-relative path,
inclusive line range, and exact line bytes preserving tabs, CRLF, trailing
whitespace, and each selected line's terminating LF when present) for every
reported defect and every `met` or `partially_met` requirement. Structured
extraction prompts carry compact target metadata (`review:live-extract-target`
v1, omitting repository-wide `reads`) and instruct pure transcription from
verbatim excerpts already in `prior_report` without re-reading workspace files
or Git objects. When an assigned requirement whose claimed verdict requires
source evidence (such as `met`, `partially_met`, or an evidence-backed `unmet`
claim) lacks a verbatim excerpt, extraction emits `verdict: "unverified"`
(`reason: "insufficient_evidence"`) or omits it so Mulgae derives `unverified`,
while keeping valid sibling answers; an `unmet` absence claim supported by
explicit `examined_scope` and `limitations` may still be transcribed with
`evidence: []`.
When any claimed defect lacks a verbatim excerpt in `--requirements` mode,
extraction omits the top-level `findings` key while keeping `requirements`
intact rather than emitting `findings: []` or prose-only refusal, so verified
assessments survive while findings remain `reports_only`. Extraction's
top-level coverage fields do not erase assessment-specific limitations. Roles
without assigned requirements retain the ordinary v1 contract (and refuse
findings transcription in plain text with no JSON object when any claimed
defect lacks a verbatim excerpt).

### Extraction availability

Requirements input never enables extraction, rewrites configuration, changes a
provider or increases the invocation budget. Preserve the existing policy that
an omitted extraction setting in an existing configuration leaves it disabled.

| Situation | Required behavior |
|---|---|
| The initial response contains a valid structured assessment | Admit it under normal validation, including when optional extraction is disabled. |
| Extraction is disabled and no valid assessment is available | Retain the accepted primary report and normalize missing items to Mulgae-derived unverified results with the disabled-policy reason. |
| Retry/repair already consumed the additional invocation | Retain the call ceiling and normalize unanswered items with the unavailable-allowance reason; make no extra call. |
| Extraction yields omitted or invalid assessment content | Apply the independent-section rules below and retain the accepted primary report. |
| A protected failure occurs | Apply existing publication-denial rules. |

Provider-free preflight discloses a known disabled extraction policy and its
effect on structured availability. It cannot predict that retry/repair will
consume the allowance later; record that fact in the result when it occurs.
TASK-026 freezes a small reason vocabulary distinguishing disabled extraction,
unavailable allowance, omitted answers and invalid assessment content.

### Independent section outcomes

Normalize exactly one result per selected requirement. An omitted answer becomes
Mulgae-derived `unverified`, without an invented provider verdict. A whole-array
structural and ID pre-pass rejects that role's whole assessment section when any
row is not a JSON object, lacks a string `requirement_id`, or contains a
duplicate, unknown, foreign, or wrong-owner ID. Within a structurally valid
section, ordinary per-item content, inner unknown-key, evidence-claim,
quote-mismatch, self-prose, visual, or pure bounded citation faults isolate to
the offending `requirement_id` (`invalid_assessment`) while preserving valid
sibling answers and cleanly omitted IDs (`answer_omitted`). Findings validation
remains strictly all-or-nothing. Keep validation of assessments and ordinary
findings independent: an ordinary failure in one section must not discard valid
content in the other or the accepted primary report. Protected failures retain
fail-closed precedence.

| Validated outcome | Required result |
|---|---|
| Findings and assessment sections are valid | Retain both. |
| Findings are valid; one or more assessment rows fail ordinary per-item validation | Retain findings, valid sibling assessments, and the accepted primary report; normalize only the failed requirement IDs to `invalid_assessment` and omitted IDs to `answer_omitted`. |
| Findings are valid; assessment section fails ordinary section-wide validation | Retain findings and the accepted primary report; normalize affected requirements to `invalid_assessment` (preserving any earlier valid or partial initial section across extraction). |
| Assessment is valid; findings have an ordinary validation failure (including omitted top-level `findings` key) | Retain verified assessments and accepted primary report (or prior verified findings); preserve existing finding-availability semantics (`reports_only`) without persisting an incomplete structured findings candidate when `findings` was omitted. |
| A selected assessment is omitted | Supply a Mulgae-derived unverified row (`answer_omitted`) without inventing a provider verdict. |
| Non-object row or missing, duplicate, unknown, foreign, or wrong-owner requirement IDs occur | Reject the emitting role's whole assessment section before per-item verification without replacing another role's assessment. |
| The entire structured response is syntactically invalid | Apply existing bounded handling and preserve an accepted primary report where permitted; claim no independently validated section from unparseable content. |
| Security, integrity, real live-source drift, non-pure/joined source or validator failure, cancellation, or another protected failure occurs | Immediately abort fail-closed and preserve publication-denial precedence over otherwise valid sections or sibling rows. |

Role execution coverage, finding extraction status and assessment availability
remain separate. An assessment-only success does not turn unavailable findings
into zero findings. These distinctions need no generic validation framework,
new retry policy or additional provider invocation.

Do not infer `met` from zero findings, turn `unmet` into a finding, or change
severity thresholds or CI exits based on requirement verdicts.

### Counts, origin and availability

- `selected_count` is the number of admitted requirements.
- `evaluated_count` counts valid, admitted provider assessments, including an
  explicit provider `unverified` answer. Mulgae-derived placeholders contribute
  zero to this count.
- Counts measure accepted assessment responses, not satisfied requirements,
  exhaustive examination or proof of correctness.

For three selected items, a valid met answer, a valid provider unverified answer
and one omitted answer produce selected_count = 3 and evaluated_count = 2.
All three rows remain visible; the omitted answer is Mulgae-derived unverified.

| Case | Availability and origin |
|---|---|
| No requirements input | Assessment was not requested. |
| An intact historical artifact lacks support | Assessment capability is unavailable; keep unknown historical counts unavailable instead of filling them with zero. |
| Requirements on a no-change target | Evaluation did not run; evaluated_count is zero and all selected items are Mulgae-derived unverified/no_change_target. |
| An owner returns a valid unverified answer | A provider assessment was admitted, but its limitations prevent a conclusive verdict. |
| An owner omits an answer or its section is rejected | Mulgae supplies the normalized row and reason, with no fabricated provider verdict. |

Keep these meanings identical in CLI, MCP and rendered output. Finding severity
filters and successful operational exits must not hide requirement results.
TASK-026 freezes the exact availability/origin fields and reason representation;
add no scores, per-criterion metrics or separate metrics subsystem.

## No-change targets

Validate requirements, ownership and project binding before the existing
no-change branch. Preserve the admission result for every supported selector,
including an empty-tree HEAD; selector names do not override that result.

| Request | Planned result |
|---|---|
| No requirements file and any admitted no-change target | Existing no-change behavior and exits, with zero provider calls. |
| Requirements supplied and any admitted no-change target | Evaluation not run; every selected item is `unverified` with `no_change_target`; zero qualification or review calls. |
| Workspace/head whole-tree or another target not classified as no-change | Ordinary bounded review and assessment within that target. |
| Invalid requirements, ownership or project binding, including a no-change target | Admission fails before provider calls or publication. |

No-change publication retains the exact input, selected IDs and owners, source
selection and normalized results in versioned hash-bound support. It has zero
evaluated requirements, zero attempts and zero role reports. Do not fabricate
provider provenance or interpret `no_findings` as requirement satisfaction.

Expose selected/evaluated counts and evaluation-not-run state after restart.
A workspace assessment requires an explicit new request and preflight; never
substitute a target automatically. No obsolete dirty/patch/stdin selector or
captured-side reference is restored.

## Publication, inspection and compatibility

Extend existing ordinary and no-change publication with separately versioned,
hash-bound assessment support. Keep the exact admitted requirements and their
ownership attributable to that result. Add no batch or comparison run type.

Expose assessments, rationale, limitations and verified evidence through existing
inspection, JSON and rendered reports. Prominently display unmet and unverified
items independently of finding severity and successful operational completion.
Keep result pages and evidence reads bounded and bound to the same publication
receipt. Reads invoke no provider and never consult current source to recreate
missing historical evidence.

Distinguish input not supplied, historical assessment capability unavailable,
evaluation not run and evaluated results. Missing capability in an intact old
artifact is not corruption or successful evaluation; missing or altered
hash-bound new support is an integrity failure. Preserve historical ordinary,
child, composite, failed and no-change artifacts and their original contracts.

Update query, cleanup and export allowlists only for the new owned support.
Keep raw requirements and private evidence out of portable exports unless an
explicit supported export contract admits them. Preserve existing privacy and
lineage protection.

TASK-026 freezes schema versions and compatibility cases. Every new embedded
schema needs its paired example and owning semantic tests. Advertise execution
capability only when admission, validation, publication and verified reads work
together; provider-free preflight can precede execution.

| Task | Public activation boundary |
|---|---|
| TASK-027 | Expose requirements admission and provider-free preflight; public requirements-bearing execution remains unavailable. |
| TASK-028 | Implement internal execution, validation and publication with focused tests; public requirements-bearing execution remains unavailable. |
| TASK-029 | Enable public requirements-bearing execution and its capability advertisement together with the necessary verified CLI/MCP reads. |
| TASK-033 | Certify the integrated feature under the existing acceptance criteria. |

Objective-only execution stays available throughout. Use the existing capability
mechanism; add no general feature-flag system.

## Frozen requirements-assessment contracts

TASK-026 supplies contract values, strict byte decoders and schema/semantic
foundations. TASK-027 implements local input admission and provider-free
preflight. TASK-028 implements internal provider integration and publication.
TASK-029 supplies verified assessment reads and the paired public activation.
The original criteria remain governing; implementation is not final acceptance.

### Versions and ownership

| Contract | Version and contents | Owner |
|---|---|---|
| Invocation input | `mulgae-requirements-input.v1`: `schema_version`, `requirements`; each item has `id`, `text`, `acceptance_criteria`, `owner_role` | `validation` decodes bytes; `reviewrun` admits the local file and selected roles |
| Provider assessment section | `mulgae-provider-requirements.v1`: `schema_version`, `assessments`; each answer has `requirement_id`, `verdict`, `rationale`, `evidence`, `examined_scope`, `limitations`, `reason` | `validation`; providers supply only assigned content |
| Publication metadata | `mulgae-requirements-support.v1`: exact input path/digest/byte length, availability, selected/evaluated counts and normalized item metadata | `publication` |
| Per-item content | `mulgae-requirement-content.v1`: requirement ID, rationale, evidence, examined scope and limitations | `validation` checks content; `publication` retains exact bytes |
| Verified metadata read | `mulgae-requirements-read.v1`: publication receipt, availability, input digest, nullable counts, item metadata and continuation cursor | `query`; CLI/MCP project the same result |

A supplied input contains 1 through 100 requirements, each with 1 through 32
criteria. Text must be nonblank UTF-8 without NUL. IDs retain their exact ASCII
spelling and case. No requirement prose byte limit applies. Secure local-file
admission must run independently of selected-source/artist admission: an untracked
local file can accompany an index or committed target without changing the
implementation evidence side.

`origin` is `provider` or `mulgae_derived`. A provider's accepted unverified answer
uses `reason=insufficient_evidence` and counts as evaluated. Other valid provider
verdicts use an empty reason. Mulgae-derived rows always have verdict `unverified`
and one of these reasons:

| Reason | Condition |
|---|---|
| `extraction_disabled` | No assessment section is available and optional extraction is disabled. |
| `extraction_allowance_consumed` | No assessment section is available and retry/repair already consumed the shared additional invocation. |
| `answer_omitted` | A valid section omits an assigned ID, or an eligible extraction finishes without its answer. |
| `invalid_assessment` | The available assessment section fails ordinary section-wide validation, or that requirement item fails ordinary per-item validation or pure bounded citation verification. |
| `no_change_target` | Admission classified the selected original-source target as no-change. |

A valid available section determines its own answers and omissions even when
extraction is disabled. An invalid available section determines
`invalid_assessment`; disabled-policy and consumed-allowance reasons describe
absence of a usable section, not an otherwise valid provider answer. No-change
classification takes the provider-free branch before any qualification or review
call. Protected failures retain precedence over every assessment result and deny
publication under the existing failure policy.

### Unbounded content and bounded metadata

The exact input is retained at `requirements/input.json`. Bounded support metadata
is retained at `requirements/support.json`. Its `input_sha256` and
`input_byte_length` describe the exact admitted bytes, including whitespace.
Each metadata row contains only `requirement_id`, `owner_role`, `verdict`, `origin`,
`reason`, `content_path`, `content_sha256` and `content_byte_length`.

Content paths are `requirements/items/000.json` through
`requirements/items/099.json` in input order. Ordinal paths keep case-sensitive IDs
from colliding on case-insensitive filesystems. Reject duplicate or misbound paths,
IDs or owners, missing rows, false counts, changed input bytes, and missing or
altered referenced content. A metadata decoder needs the admitted immutable item
set, exact input bytes and trusted selected-source no-change state.

Per-item content holds unbounded rationale, examined-scope prose and limitations.
Its dedicated strict JSON decoder does not apply the generic structured-envelope
8 MiB limit. Source evidence retains the existing current/visual evidence fields,
source-side rules, verification and quote bounds; binary bodies remain binary.
A `met` or `partially_met` answer needs verified implementation evidence. An
`unmet` answer may instead state its examined scope and at least one limitation.
Derived rows cannot invent examined scope or evidence.

Support/read envelopes contain no raw input, rationale, limitation bodies or
quoted source. TASK-029 extends the existing verified content/chunk read owner
for these exact support paths. Every chunk retains the publication receipt and
complete-content digest, with the existing 16 KiB chunk bound. Metadata pages
contain at most 100 rows and use cursors of at most 4096 bytes. A result's counts
refer to the complete selected set, independently of page size or finding filters.
The read path never reconstructs missing content from current source.
Historical `unavailable` reads retain their original publication receipt v1 for
captured ordinary/child/composite results or v2 for live results. Other availability
states require the live v2 receipt. Never manufacture live identity for a v1
historical publication.

### Section validation and invocation policy

The provider assessment section belongs to its one scheduled role and provider.
Providers cannot set Mulgae-owned fields in the closed protected key sets for
`requirements`, `assessment`, `evidence`, `current`, and `visual` (owner,
origin, counts, input/source/excerpt digests, verification, publication, or
execution identity; `visual.sha256` remains an allowed provider digest and
`schema_version` is outside the protected set). A complete tree pre-pass scans
all keys before any outer envelope, structural, or per-item check so any
protected key deterministically fails closed with `security_violation`
(`provider_ownership_violation`) ahead of ordinary unknown keys or invalid
rows. Outer envelope failures (invalid JSON, outer unknown key, wrong
`schema_version`, missing or non-array `assessments`, or >100 rows) and a
whole-array structural/ID pre-pass (non-object rows, missing or non-string
`requirement_id`, or duplicate, foreign, or wrong-owner IDs) reject that role's
whole assessment section before per-item verification. Within a structurally
valid section, ordinary per-item content errors, inner unknown keys, evidence
claim or quote mismatches, self-prose citations, unverified visuals, and pure
bounded provider citation faults (`LiveSourceError` citation/invalid/unsupported
errors whose wrapped chain contains no forbidden context, ownership, drift, or
infrastructure node) isolate to only that `requirement_id`
(`invalid_assessment`), preserving valid sibling requirements and cleanly
omitted IDs (`answer_omitted`). Any non-pure or protected source failure or
cancelled context aborts the entire section fail-closed immediately even after
an earlier row was isolated. Findings validation remains strictly
all-or-nothing. A structural, unknown-key, or citation failure confined to one
ordinary section does not discard a valid other section or its accepted primary
role report. A syntactically invalid complete response supplies no independently
validated section. A protected failure in either section (such as a Mulgae-owned
key violation or real live-source drift on an admitted path) still denies
publication.

The provider section is prose-bearing input. Its strict production decoder must
preserve unbounded rationale and limitations without passing the complete body
through the bounded structured-envelope validator. Schema fixtures check the
wire shape; TASK-028 supplies the production section decoder and source verifier.

The initial response may supply assessments with extraction disabled. Otherwise
assessment extraction shares the existing same-role/same-provider additional
invocation with retry/repair. There is no assessment-specific call, per-item
retry, provider substitution, or configuration override. Assessment success changes
neither finding availability nor role coverage. Verdicts and missing assessments
change neither severity policy nor operational exits.

### Internal assessment execution

`reviewrun.LiveService` admits requirements after independent project binding
and before identity allocation, qualification or the no-change branch. It keeps
the exact admitted bytes for publication. Each owning role receives only its
assigned text and criteria in the existing untrusted task-requirements frame.
The trusted requirements prompt leaves the source plan and provider policy intact.

Provider wire v2 carries `schema_version: mulgae-provider-review-output.v3`
and an optional `requirements` section using `mulgae-provider-requirements.v1`.
The strict whole-document parser separates that prose-bearing section and
records whether the top-level `findings` key was present before the existing
bounded findings validator runs unconditionally on the findings projection.
Assessment decoding verifies selected-side evidence while the original source
lease remains open. At the input path, a verifier-owned digest of the
already-read cited file rejects the exact invocation prose as proof. Different
index or committed implementation bytes at the same path remain eligible. This
digest is an ephemeral file observation; it adds no source inventory, persisted
fingerprint or extra read.

When findings are accepted and the role's assessment section is present with no
section-wide error and no unresolved per-item invalid IDs, the runtime retains a
trusted `NormalizedRequirementsOutput` value for provider output v3 with answers
projected in deterministic admitted input order (shared with
`RequirementsResult`). Its optional serialization composes the validated live
findings component with verified assessment content without applying the generic
envelope limit to the full body. Partial section results stay separate and never
fabricate a complete findings envelope. Publication retains normalized item
content instead of adding another provider-output artifact.

The coordinator may use its existing second invocation when extraction is
enabled for an accepted reports-only result or for an initial invocation whose
assessment section is absent, section-invalid, or has per-item invalid IDs. A
structurally valid initial section with zero invalid IDs owns its clean
omissions and does not schedule extraction solely for omissions. Across
`initial -> extract`, requirement state merges monotonically: a later
structurally valid section inserts missing accepted answers, clears resolved IDs
from invalid state, and may upgrade an earlier provider `unverified` answer to a
decisive verdict (`met`, `partially_met`, or `unmet`), while never overwriting
or downgrading an already-accepted decisive answer and never letting a later
ordinary section-wide or per-item failure erase earlier accepted answers or flip
clean omissions to `invalid_assessment`. Retry or malformed-document repair
still consumes that same slot. The extraction prompt carries compact target
metadata (`review:live-extract-target` v1 without repository-wide `reads`) and
remains pure transcription from verbatim excerpts in `prior_report`. When a
provider signals findings-only extraction refusal by omitting the top-level
`findings` key, `ReviewValidator.Validate` still runs unconditionally so context
cancellation, scope errors, and non-document-violation schema or infrastructure
errors fail closed; an ordinary missing-`findings` document violation falls back
with `nil` structured candidate capture (preserving complete `stdout.raw` and
verified requirements while keeping the role `reports_only` or retaining prior
verified findings). Ordinary peer failure retains accepted findings, assessments
and the primary report independently while still emitting single-pass
parse/validation diagnostics (emitting `validation_failed` and recording
`invalid`/`repair_exhausted` on either section-wide or per-item failures),
updating invocation status states, cleaning up extraction/repair state, and
capturing raw stdout/stderr streams (retaining the findings projection in
`candidate.*.json` only when `findings` was present and fits within the 8 MiB
structured member bound, omitting `candidate.*.json` when absent or oversized,
and always preserving the full unbounded response in `stdout.raw` and normalized
`requirements/items/*.json`). Original free-form, parsed-invalid and
exhausted-repair states remain distinct in attempt metadata. Trusted source and
validator failures use the existing canonical failure selector, including every
joined cause; internal, artifact, security and cancellation observations cannot
become ordinary section success, while typed admission-based pure provider
citation faults stay bounded to the offending requirement instead of aborting
the run. Bare cancellation/deadline leaves retain the selector's cancelled
classification; an explicit typed timeout retains its own class.

### Publication and historical compatibility

| Publication | Assessment availability and counts | Required handling |
|---|---|---|
| Existing intact artifact without assessment support | `unavailable`; selected/evaluated counts and input digest are null | Preserve old bytes and readers; never manufacture zero coverage. |
| New ordinary request without requirements | `not_requested`; selected/evaluated counts are zero, input digest is null | Preserve objective-only review and omit assessment support. |
| Requirements on a no-change target | `not_run`; selected count is known and evaluated count is zero | Retain input and one derived `unverified/no_change_target` row per selected item; zero qualification/review calls, attempts and role reports. |
| Ordinary requirements-bearing review | `evaluated`; selected count equals admitted items; evaluated count counts valid provider rows | Retain exactly one normalized row per selected item in input order, including placeholders. |
| New artifact declares bound support that is missing or damaged | Integrity failure | Do not relabel corruption as historical absence or consult current source. |

The no-change row applies to every existing admitted selector case, including
empty-tree HEAD. No automatic workspace substitution is permitted. Counts measure
admitted responses, not satisfaction; a valid provider unverified answer contributes
one while a derived placeholder contributes zero.

TASK-027 introduces preflight v10 and command-result v22 together for the
optional admission summary, including the preflight-failure version projection.
Command-result v21 retains its embedded preflight v9 contract. TASK-028 supplies
the internal requirements-bearing provider wire v2 and normalized provider
output v3, plus review artifact v4, run manifest v4 and support index v4. Public
objective-only execution used v3 until the TASK-029 cutover. New
ordinary/no-change producers use v4 with verified readers.

At TASK-029 activation, every new ordinary/no-change artifact and manifest uses v4
and contains `requirements_support`: null for a request without requirements, or
an object with `path=requirements/support.json` and the support file `sha256`.
Final and manifest bindings must agree and the v4 support index must cover the
metadata, exact input and every content body. Explicit null establishes
`not_requested`; a v3 or older artifact lacks this capability and remains
`unavailable`. This distinction cannot be inferred from current binary version.
TASK-029 also introduces preflight v11 with command-result v23 and advertises
`requirements_assessment=v1` with execution and verified reads on roots with
the existing Git/common-directory binding. Non-Git roots retain empty capability
and `execution_available: false`; their requirements execution is unsupported.
Preflight v10
retains `requirements.execution_available: false`; v11 owns the later enabled
execution contract with binding-dependent availability. Preflight v10 and
command-result v22 stay frozen, and the MCP
lifecycle remains unchanged. The internal TASK-028 contracts confer no public
requirements execution or verified-read capability.

### Verified public read projection

CLI `inspect`/`findings` and MCP `inspect_review`/`list_findings` return the frozen
requirements-read v1 metadata under `requirements`, plus a sibling
`requirement_content_uris` map keyed by each returned ID. Requirement pagination
uses its own limit (1 through 100, default 100) and sealed receipt/binding/run/limit/offset
cursor. Finding severity and finding cursors do not change requirement selection.
Whole-set counts, ordered IDs/owners/origins and every input/content binding are
verified before any page; final receipt confirmation rejects concurrent cleanup.

`read-report --requirement ID` and the corresponding
`mulgae://runs/RUN/requirements/ID` resource reuse 16 KiB UTF-8 chunks and existing
receipt/content-digest continuation guards. Full item JSON retains rationale,
source evidence, scope and limitations without the bounded-envelope prose limit.
Reports render all selected assessments independently of extraction availability.
Reads use retained support only, with no providers or current-source fallback.
Portable export admits no raw requirement input or assessment body. Cleanup may
remove run-owned copies while preserving the original project input.

## Acceptance evidence

TASK-033 integrates the five Tasks against RCI-001/002/003/006/007. Cover valid
and invalid input, all verdicts, missing or malformed answers, wrong ownership,
extraction independence, disabled/consumed extraction allowance, provider versus
Mulgae-derived counts, protected failure precedence, all existing no-change
cases including empty-tree HEAD, local-input versus selected-source evidence,
restart, tamper, paging, historical absence, CLI/MCP parity and unchanged exits.

Use focused deterministic tests, exact-binary and supported-client checks,
the current complete `make test` gate, and one explicitly authorized bounded
live requirements-bearing review through existing routes. Inspect that same
result without another provider call. No batch recheck or cross-run comparison
demonstration is required. A result containing only Mulgae-derived placeholders
does not establish successful structured assessment. Missing structured
assessment is an evidence gap, not permission for an unbounded retry campaign.

Implementation, verification, review, commits, installation, configuration and
release retain their separate authorization boundaries. TASK-029 implements
public execution with verified reads; TASK-033 has completed integrated certification.
