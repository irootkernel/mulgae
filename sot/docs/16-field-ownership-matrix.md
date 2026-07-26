# Mandatory Field and Ownership Matrix

This document is the implementation checklist for mandatory values, field ownership, repair eligibility, and validation responsibility. JSON Schema files remain the machine-readable source for structural requirements.

The v1 tables below remain frozen compatibility contracts. Since SOT 1.3.0, the v2 and G0 ownership rules in Sections 2 through 4 have remained authoritative; those rules do not permit a provider to create system-owned fields.


## 1. Ownership Rules

| Owner | Meaning | AI repair allowed |
|---|---|---:|
| KAR | Deterministic execution, identity, policy, validation, or artifact metadata | No |
| Provider | Review content generated for a selected role | Yes, only for explicit missing or invalid paths |
| Validator | Derived result of deterministic checks | No |
| Publisher | Final path, review identity, serialization, and integrity result | No |

A field being mandatory does not imply that the provider should generate it.

## 2. Four Outcome Axes and Publication State

The four outcome axes are independent. A content or CI result never overwrites coverage or publication state.

| Field | Owner | Source and validation | AI repairable |
|---|---|---|---:|
| `/content_verdict` | KAR assessment aggregator | Deterministic aggregation of normalized findings: `no_findings`, `findings_present`, or `request_changes` | No |
| `/coverage_status` | Coordinator | Terminal role results and required-role policy: `complete`, `degraded`, or `incomplete` | No |
| `/publication_status` | Publisher recovery classifier | Serialized only from `derived_publication_status`: `not_published`, `staged`, `installed`, `committed`, or `corrupt` | No |
| `/ci_decision` | KAR CI policy projector | `pass` or `fail`, projected from valid content, coverage, and configured policy | No |
| `/ci_reason_codes` | KAR CI policy projector | Deterministic, bounded reasons for the CI projection | No |
| `/persisted_journal_state` | Artifact store | Last fsynced journal hint: `collecting`, `content_validated`, `final_staged`, `final_file_installed`, `manifest_committed`, or `completed` | No |
| `/derived_publication_status` | Recovery classifier | Recomputed from durable observations; never copied from the journal hint | No |

`persisted_journal_state` is a recovery hint, not publication authority. The classifier applies `ambiguity/mismatch > P2 committed > P1 installed > P0 staged > P0 none hint recovery > corrupt default`. Only valid P2 durable observations authorize `publication_status=committed`; ambiguity or mismatch derives `corrupt` and artifact exit `7`.

## 3. Source and Current Evidence

The normalized v2 review artifact separates immutable source identity from independently verified current evidence. Source evidence cannot be represented as current verified evidence.

| Field group | Required fields | Owner | Validation and repair |
|---|---|---|---|
| Source identity | `session_id`, `run_id`, `review_id`, `finding_id`, `source_target_sha256`, `source_excerpt_sha256` | KAR source artifact and evidence reducer | `source_excerpt_sha256` identifies only the immutable original source excerpt; provider repair is prohibited and it cannot substitute for current evidence |
| Current evidence | `target_sha256`, `current_excerpt_sha256`, `path`, `line_start`, `line_end`, `side`, `quote`, `verification` | KAR injects target identity; provider claims path/range/quote; KAR evidence reducer computes and owns `current_excerpt_sha256`, acceptance, and final serialization | `current_excerpt_sha256` identifies the newly verified current excerpt and controls indexed excerpt verification and order; it must not be conflated with or fall back to `source.source_excerpt_sha256`. `side` is `base`, `head`, or `worktree`; provider output is `claimed`, while final state is `verified`, `stale`, `invalid`, or `unverifiable` |
| Current verified projection | All current-evidence fields plus `verification=verified` | KAR evidence reducer | Requires exact current target, range, quote, `current_excerpt_sha256`, and indexed excerpt order match; source identity alone can never satisfy it |

The v2 provider schemas serialize a KAR-normalized result envelope. KAR injects the current target digest for every review and injects immutable source identity only for source-bearing followup, delta, rerun, or equivalent modes; root review omits `source`. The provider owns finding text and the current path/range/quote claim only; its wire value is always `verification=claimed`. The evidence reducer owns every transition to `verified`, `stale`, `invalid`, or `unverifiable` and serializes that state only in validation/final artifacts.

## 4. Role, Provider, and Requirement Assignment

| Field group | Owner | Source and validation | Provider authority |
|---|---|---|---|
| `/assignments/<role>/primary` | Project-local policy plus coordinator | Config v2 selects a configured family; coordinator resolves its qualified provider instance | None |
| `/assignments/<role>/fallback` | Project-local policy plus coordinator | Config v2 selects a distinct configured family or singleton omission; coordinator resolves its qualified route | None |
| `/required_floor` | Code-fixed safety floor | Fixed to `logic` | None |
| `/effective_required` | Project-local policy reducer | `required_floor` plus enabled additions from the admitted `.kar/config.yaml` | None |
| Provider and platform contract evidence | Probe validator | Required tuple and native-cell probe assertions, secure-writer receipt, and evidence index | Provider may supply untrusted probe output only |

The role order is `logic`, `security`, `maintainability`, `product`, `documentation`, `testing`, `artist`. Artist is available only to UI projects. A provider does not assign a role, select a fallback, choose a concurrency lane, or weaken required coverage. CLI selection is run-local and cannot weaken policy.

## 5. Provider Review Output (v1 Compatibility)

Schema: [kar-provider-review-output.v1.schema.json](../schemas/kar-provider-review-output.v1.schema.json)

| JSON path | Mandatory | Meaningful non-empty value | Owner | Repairable | Additional validation |
|---|---:|---:|---|---:|---|
| `/schema_version` | Yes | Yes | Provider, fixed constant | Yes if missing | Must equal `kar-provider-review-output.v1` |
| `/summary` | Yes | Yes | Provider | Yes | Must agree with findings and completeness |
| `/completeness` | Yes | Yes | Provider | Yes if missing | Enum and limitation consistency |
| `/limitations` | Yes | Array may be empty | Provider | Yes if missing | Placeholder strings rejected |
| `/findings` | Yes | Array may be empty | Provider | Yes only if field missing, not to alter existing count | Summary and completeness consistency |
| `/findings/*/severity` | For each finding | Yes | Provider | Yes if missing | Enum and evidence policy |
| `/findings/*/title` | For each finding | Yes | Provider | Yes if missing | Trimmed, no placeholder |
| `/findings/*/description` | For each finding | Yes | Provider | Yes if missing | Must describe a concrete issue |
| `/findings/*/evidence` | For each finding | At least one item | Provider | Yes if missing and relevant target context is supplied | KAR verifies path, lines, side, and quote |
| `/findings/*/recommendation` | For each finding | Yes | Provider | Yes if missing | Must not claim approval authority |
| `/findings/*/confidence` | For each finding | Yes | Provider | Yes if missing | Enum only |

The provider does not generate final finding IDs, fingerprints, lifecycle states, final evidence status, session IDs, run IDs, attempt IDs, review IDs, `content_verdict`, `coverage_status`, `publication_status`, `ci_decision`, or artifact hashes.

## 6. Provider Followup Output (v1 Compatibility)

Schema: [kar-provider-followup-output.v1.schema.json](../schemas/kar-provider-followup-output.v1.schema.json)

| JSON path | Mandatory | Meaningful non-empty value | Owner | Repairable | Additional validation |
|---|---:|---:|---|---:|---|
| `/schema_version` | Yes | Yes | Provider, fixed constant | Yes if missing | Exact version constant |
| `/summary` | Yes | Yes | Provider | Yes | Must agree with resolution |
| `/resolution` | Yes | Yes | Provider | Yes if missing | Enum and rationale consistency |
| `/rationale` | Yes | Yes | Provider | Yes | Must address the source finding |
| `/evidence` | Yes | At least one item | Provider | Yes if missing with source context | Verified against current captured target |
| `/new_findings` | Yes | Array may be empty | Provider | Yes only if field missing | Existing finding count cannot change during repair |
| `/limitations` | Yes | Array may be empty | Provider | Yes if missing | Placeholder strings rejected |

KAR supplies the source finding reference in the prompt and records it in the final artifact. The provider does not invent or rewrite that reference.

## 7. Final Review Artifact (v1 Compatibility)

Schema: [kar-review-artifact.v1.schema.json](../schemas/kar-review-artifact.v1.schema.json)

All mandatory fields in the final artifact are KAR-owned or deterministically normalized. None are AI-repairable at this stage.

| JSON path | Owner | Source |
|---|---|---|
| `/schema_version` | KAR publisher | Configured final schema |
| `/session_id` | KAR ID generator | Session creation |
| `/run_id` | KAR ID generator | Run creation |
| `/review_id` | KAR ID generator | Generated after final validation |
| `/run_type` | KAR application request | CLI workflow |
| `/created_at` | KAR clock | Publication time |
| `/kar` | KAR build metadata | Running binary |
| `/lineage` | KAR coordinator | Source and parent run references |
| `/target` | Target capture adapter | Immutable target manifest |
| `/validation` | Validation pipeline | Final validation result |
| `/coverage` | Coordinator | Role task terminal states |
| `/assessment` | KAR policy and aggregation | Findings, coverage, and threshold policy |
| `/role_results` | Normalizer | Selected valid attempt outputs |
| `/findings` | Normalizer | Verified and deterministically ordered findings |
| `/followup` | Followup application service | Normalized provider result plus source reference |
| `/limitations` | Aggregator | Role limitations and degradation |
| `/provenance` | Artifact and aggregation services | Target and validation references |

If any of these values cannot be produced, publication fails. KAR must not ask a provider to fill the gap.

## 8. Run Manifest (v1 Compatibility)

Schema: [kar-run-manifest.v1.schema.json](../schemas/kar-run-manifest.v1.schema.json)

| Field group | Owner | Mutable before sealing | AI repairable |
|---|---|---:|---:|
| Session, run, type, timestamps | KAR | Limited atomic replacement | No |
| State and sealed flag | Coordinator and artifact store | Yes | No |
| Lineage | Application service | No after run creation | No |
| Target reference | Target capture | No after capture | No |
| Role selection | Config and application service | No after execution starts | No |
| Attempt index and invocation count | Coordinator and artifact store | Append through atomic manifest replacement | No |
| Final review reference and SHA-256 | Publisher | Written once | No |
| Failures and warnings | Coordinator | Until sealing | No |

## 9. Meaningful Value Rules

A mandatory value fails meaningful-value validation when it is:

- `null` where not explicitly allowed;
- an empty or whitespace-only string;
- a rejected placeholder such as `N/A`, `TBD`, `TODO`, `unknown`, `none`, or `-`;
- an empty array where the field requires at least one item;
- an enum value outside the contract;
- structurally present but semantically contradictory;
- evidence that cannot be matched to the captured target.

Placeholder rejection is field-specific. For example, an evidence side may legitimately use the enum `unknown`, while a free-text recommendation may not use `unknown` as its entire value.

## 10. Repair Decision Table

| Condition | Repair mode | Same provider | Fallback after failure |
|---|---|---:|---:|
| JSON syntax or Markdown fence | `reformat_only` | Yes | Yes |
| Missing AI-owned mandatory field | `fill_missing_fields` | Yes | Yes |
| Empty AI-owned mandatory value | `fill_missing_fields` | Yes | Yes |
| Wrong primitive type in an isolated AI-owned path | `fill_missing_fields` when replacement is unambiguous | Yes | Yes |
| Existing finding must be deleted or rewritten | None | No | Yes or exact rerun |
| Severity downgrade requested | None | No | Yes or exact rerun |
| Summary and findings contradict | None by default | No | Yes or exact rerun |
| Missing system-owned metadata | None | No | No, KAR failure |
| Evidence cannot be verified | Limited evidence repair only with exact target excerpt, otherwise none | Yes when policy allows | Yes |
| Secret exposure or mutation violation | None | No | No |
| User cancellation | None | No | No |

## 11. Publication Assertion

The publisher must be able to assert all of the following before the final rename:

```text
final schema passes
all system-owned fields were generated by KAR
all selected role results have terminal policy states
all included provider content passed schema and semantic validation
all included evidence satisfies configured verification policy
repair budget was not exceeded
review_id is a valid UUIDv7
no final review already exists for the run
serialized bytes match the object that was validated
```
