# Review completeness and iteration

EPIC-008 plans explicit requirements assessment within one ordinary review.
Batch rechecks and cross-run comparison are outside the revised scope approved
on 2026-10-27.

The [roadmap](../roadmap/README.md#epic-008-review-completeness-and-iteration)
owns lifecycle and the five implementation Tasks. The
[development dossier](../todo/EPIC-008-review-completeness-and-iteration.md)
owns their temporary execution detail. This feature is unimplemented.
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

- [ ] RCI-001: admit an optional requirements file containing explicit IDs,
      descriptions, acceptance criteria and one owner role per item, alongside
      the existing objective and original-source target.
- [ ] RCI-002: retain every selected requirement with a verdict, rationale,
      evidence and limitations or an explicit unverified reason, including
      provider-free no-change results.
- [ ] RCI-003: keep requirements assessment, ordinary findings, role coverage,
      extraction, publication and operational exits separate.
- [ ] RCI-006: preserve existing execution and historical artifact readers;
      distinguish unsupported historical assessments from an empty successful
      assessment without rewriting stored results.
- [ ] RCI-007: expose optional input and verified results through existing CLI
      and MCP review/preflight/read paths, preserving start/await/cancel.

RCI-004 (batch rechecks) and RCI-005 (cross-run comparison) are excluded from
current Epic acceptance. Their IDs remain reserved for the original requirements
and are not reassigned. TASK-030 through TASK-032 remain separate Deferred
records in the roadmap; any future adoption needs a new scope decision and
a design compatible with original-source review.

Unchecked requirements are planned obligations, not implementation evidence.

## Optional requirements input

Plan a project-relative `--requirements PATH` option on existing CLI review and
preflight, with `requirements_path` on the equivalent MCP inputs. These interfaces
are not available in the current binary. TASK-026 freezes their exact versioned
input, result and capability contracts before production wiring.

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
Mulgae-derived `unverified`, without an invented provider verdict. Duplicate,
unknown or wrong-owner IDs invalidate that role's assessment section.
Keep validation of assessments and ordinary findings independent: an ordinary
failure in one section must not discard valid content in the other or the
accepted primary report. Protected failures retain fail-closed precedence.

| Validated outcome | Required result |
|---|---|
| Findings and assessment sections are valid | Retain both. |
| Findings are valid; assessment has an ordinary validation failure | Retain findings and the accepted primary report; normalize affected requirements to unverified with an explicit reason. |
| Assessment is valid; findings have an ordinary validation failure | Retain the assessment and accepted primary report; preserve existing finding-availability semantics. |
| A selected assessment is omitted | Supply a Mulgae-derived unverified row without inventing a provider verdict. |
| Duplicate, unknown or wrong-owner requirement IDs occur | Reject the emitting role's assessment section without replacing another role's assessment. |
| The entire structured response is syntactically invalid | Apply existing bounded handling and preserve an accepted primary report where permitted; claim no independently validated section from unparseable content. |
| Security, integrity or another protected failure occurs | Preserve publication-denial precedence over otherwise valid sections. |

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
release retain their separate authorization boundaries. This planning revision
implements no runtime capability.
