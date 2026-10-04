# Verified review contracts

This specification preserves the frozen pre-cutover requirements for
[EPIC-007](../roadmap/README.md#epic-007-verified-review-contracts), including
capture-bound guards and composite creation. TASK-038 retires those execution
surfaces. Current execution is owned by [live workspace and Git review](live-workspace-and-git-review.md)
and the [contracts](contracts.md). Project binding, coherent verified reads,
retained historical support and integrity remain implemented. Historical text
below confers no current source replay or child/compose creation authority.
The roadmap owns delivery status and Epic acceptance.

## Purpose and boundary

Connect the requested project, captured review input, admitted execution, and
verified result through native contracts. CLI and MCP must use the same
application policy rather than asking an agent to reconstruct it from private
files or independently queried status and finding results.

This Epic is independently useful with today's objective and project context.
It does not depend on structured Review Briefs, requirements assessment, batch
followup, provider changes, a new daemon, or MCP Tasks migration.

## Required behavior

- [x] VRC-001: expose a read-only, independently comparable local project binding.
- [x] VRC-002: distinguish complete capture identity from request identity, bind
      preflight to the effective request, and reject mismatched execution
      preconditions before any provider request.
- [x] VRC-003: return status and a bounded finding page under one verified
      publication receipt, including capture identity availability, extraction,
      and coverage state.
- [x] VRC-004: expose actual structured findings and read-only report content
      through the CLI, with equivalent MCP semantics and lossless pagination.
- [x] VRC-005: provide verified, self-contained finding evidence for newly
      published composites without inventing evidence for historical artifacts.
- [x] VRC-006: preserve legacy command behavior where unchanged, declare new
      capabilities explicitly, and keep all new reads provider-free.
- [x] VRC-007: replace agent-side verification steps only after native checks and
      supported-client acceptance demonstrate equivalent or stronger guarantees.

These checkboxes track requirement verification, not Epic or Task lifecycle.
Do not check them merely because a design or schema exists.

## Native project binding

A project binding identifies a particular local Git worktree, not just its
content. Compute it from the canonical, descriptor-observed root identity and
Git worktree identity using a versioned, domain-separated encoding. Freeze the
exact identity fields and replacement detection tests in TASK-019. Two distinct
roots with identical content must differ; canonical aliases of the same root
must agree. Moving or replacing a root may invalidate a binding. It is not a
portable repository ID or a credential.

A CLI lookup executed from the independently established requested root is the
comparison authority. An MCP lookup reports the identity of its fixed startup
root. Copying the MCP response into a request without comparing it to an
independently obtained expectation proves nothing. A native mismatch must fail
before target capture or provider construction. Revalidate descriptor identity
when entering a guarded operation; a server cannot retarget itself.

Do not expose absolute paths, credential homes, device details, or provider
credentials in public bindings. A digest is an identity aid, not a claim of
anonymity or authentication against a malicious host. Retain the existing trust
assumption that the locally launched Mulgae binary and host are trusted. Keep
local bindings out of portable exports; copied artifacts retain their immutable
content provenance without pretending to retain the original local identity.

Context lookup performs no initialization, configuration rewrite, credential
read, provider discovery process, heartbeat, run allocation, or persistent write.
It reports supported native contract versions. Unknown capabilities are not
success and must not be inferred from version text alone.

## Capture identity and request identity

Keep four separate identities; do not substitute one for another:

| Identity | Question answered |
|---|---|
| Project binding | Is this the independently selected local worktree? |
| Capture identity | Are the complete captured target and its support material identical? |
| Request identity | Are the capture, objective/context inputs, roles, policy, and execution plan the ones requested? |
| Publication receipt | Is this the exact verified result and support set being read? |

For a Git target, the existing `target_sha256` hashes patch bytes. Preserve that
meaning. Equal patch hashes do not establish equal captured context. Define a
versioned, domain-separated capture identity over canonical target kind, Git
mode and logical sides, target byte digest/length and applicable captured Git
object/tree identities, capture/exclusion policy, and the complete admitted file
inventory. Each file entry binds logical side, project-relative path, media type,
disposition, byte length, and exact content digest. Include added, removed,
unchanged, empty, and binary support files and separately framed project context
with its presence and digest. Canonically sort entries; reject duplicate or
incomplete entries. Reuse the current file-set machinery under an application
owner instead of defining separate CLI and MCP hash algorithms.

The capture identity excludes objective text, role/provider/model policy,
execution budgets, selected prior findings, and workflow-generated source
excerpts; these belong to request or source provenance. Invocation-specific
temporary paths, timestamps, and IDs are not stable capture inputs. Credentials
must never enter capture/request receipts or retained review material. A future
Brief is a separate request input; its referenced captured material still
participates in capture identity. If that file also belongs to the ordinary target snapshot, keep its
snapshot entry: never hide a captured file merely to make identities equal.
Generated manifests contribute through their canonical content inventory, not
through ephemeral workspace serialization. Distinct local roots still require
separate project bindings even when capture identities agree.

TASK-019 freezes the complete encoding and writer/reader matrix. TASK-021 binds
capture identity into preflight and new ordinary/child publication support;
TASK-022 verifies and exposes it; TASK-024 preserves its per-source provenance in
new composites. Retain a hash-bound canonical capture manifest sufficient to
verify the identity after process restart without reading the working tree.
Preserve an existing no-change run's provider-free outcome while versioning any
new capture support; do not reinterpret its patch digest or old empty support
index. Capture identity is distinct from provider execution evidence.

Historical artifacts may expose an identity only when verified retained material
proves every required component under the same encoding. Otherwise expose
`capture_identity_unavailable`, not an identity reconstructed from the patch or
live tree. Keep absence distinct from corrupt retained material, which remains
an integrity failure. A composite cannot assert one common capture identity
unless all contributing role captures have verified equal identities; preserve
per-source identity and report unavailability when that cannot be established.
Do not change existing composition eligibility or retrofit published artifacts.

## Preflight and guarded execution

A preflight receipt binds all behavior-relevant admitted input: project binding,
complete capture identity, requested and captured target kinds, Git sides and
revision selection, target bytes, complete file-set identities including binary
files, objective presence
and exact bytes, project context, exclusion decisions, selected roles and their
explicit/default selection, effective project policy, role prompts, configured
provider/profile routes, and execution budgets. Record the Mulgae contract and
asset versions used to compute it. Keep credentials out of the receipt.

Define separate typed component digests and one request digest so a mismatch
has a bounded reason without echoing content. The request digest includes the
capture identity and all request-only dimensions; it is not a cross-workflow
capture-equality key. A local route identity can bind private configuration
without disclosing it. Preflight remains execution-free:
no qualification, provider process, session/run, diagnostic, or publication.
Readiness is not authentication or live provider qualification.

A guarded execution request carries the expected project binding and expected
preflight request digest. Validate them together; do not accept a half-specified
execution guard. Preflight itself can accept an expected project binding without
a request digest because it is computing that digest. Verified reads use their
expected project/publication receipt, not an execution preflight requirement.
Recapture and plan once, compare against the expectation, and execute from that
same immutable capture and admitted plan. Do not compare one capture and then
execute another. Changes after execution capture do not invalidate that already
captured target; changes detected before admission require a new explicit
preflight and a deliberate decision to review the changed input.

Check the guard before qualification as well as review invocation, because
qualification can authenticate, use the network, and incur cost. Preserve the
existing spawn-time executable, credential, permission, and configuration
checks. Preflight cannot replace those checks or promise provider availability.

Existing unguarded commands retain their documented behavior and must never be
labeled guarded. All new guarded entrypoints fail closed if a requested guard
is unsupported, malformed, or mismatched. A receipt is not authorization to
start twice: preserve the existing start/await/cancel ownership, no-blind-retry
rules, and process-local invocation lifetime. Do not add a durable request queue
or transparent retry under this feature.

## One verified inspection receipt

The inspection application service resolves an exact run ID and returns one
coherent publication observation: project binding, session/run/review identity,
run type, target digest, verified capture identity or explicit unavailability,
final and manifest digests, publication epoch, coverage, structured extraction
state, verified role-report references, filtered finding count, and the first
requested finding page. Reobserve the publication before
returning. Never assemble a successful result by calling public status and
findings independently and comparing only path strings.

A receipt does not freeze mutable storage indefinitely. Every continuation and
content read must reverify the same immutable identities. Concurrent cleanup,
replacement, corruption, or epoch change returns a typed unavailable/integrity
result; never switch to another run or silently restart at a newer snapshot.
Diagnostic-only runs retain their existing non-authoritative projection with no
findings, report, or approval claims. Corruption must not trigger diagnostic
fallback. Historical finals still expose explicit capability availability.

`reports_only`, `mixed`, and `structured` remain distinct. Zero extracted
findings is not proof that the primary reports contain no concerns. The new
inspection exposes these existing axes rather than synthesizing a clean verdict.
Review outcome, coverage, publication, and execution failure remain separate.

## Public surfaces

The writer and reader matrix below records the implemented transport and storage
contracts. TASK-019 established their grammar, encodings and compatibility
boundaries before the runtime owners wired the public surfaces.

| CLI target | MCP target | Contract |
|---|---|---|
| `mulgae context --output json` | `get_context` | Independently comparable local binding and capability versions |
| Existing `review --preflight` and guarded `review` | Existing `preflight_review`, `run_review`, `start_review` with optional guards | Same native admission and receipt; legacy requests stay distinguishable |
| `mulgae inspect --run ID --output json` | `inspect_review` | One verified snapshot and first finding page |
| Existing `findings --run ID --output json`, with optional page selectors | Existing `list_findings`, with versioned page support | Real finding summaries, not only a count or an internal file path |
| `mulgae read-finding --run ID --finding ID --output json`, with optional offset | New verified finding-detail resource | Complete structured finding detail bound to the selected receipt |
| `mulgae read-report --run ID --output json`, with optional role and offset | Existing verified report resources plus role-report selection | Read-only rendered or original role-report bytes |
| Existing `excerpt` with an optional evidence index and bound snapshot | Existing verified evidence resources with an evidence index | Every supported evidence item, including new composites |

Finding pages use canonical committed ordering, default limit 100, maximum
1,000, an explicit total filtered count, returned count, and opaque continuation.
Keep the existing CLI `finding_count` meaning as the total matching count;
introduce a separate returned count rather than reinterpreting it per page.
Bind cursors to the project, publication receipt, query kind, and filters.
Reject cross-run, cross-project, altered, stale, or incompatible cursors. Expose
IDs, fingerprints, role/provider, severity, title, confidence, lifecycle, and
verified detail/evidence references; do not embed unbounded report bodies.
Finding details must be available through bounded content reads, not raw file IO.

Report and evidence content chunks reuse the existing 16 KiB maximum, exact
byte offsets, total size, full-content digest, and continuation semantics.
UTF-8 report chunks cannot split a code point; evidence preserves exact bytes.
A complete report remains retrievable regardless of length. Per-response bounds
must not become capture, prompt, raw-stream, or report-size ceilings.

Legacy report-to-file remains an explicit mutation. New reads never generate
files, repair publications, invoke providers, or promote findings. Preserve
existing severity semantics and expose any legacy info-severity limitation
rather than silently relabeling findings.

## Composite evidence and historical compatibility

New composite publication copies the selected verified source finding,
evidence bytes, source receipt, and evidence index into its own hash-bound
support set before committing its final authority. Include both ordinary
published sources and supported failed-run recovery sources. Preserve original
run/attempt/finding identity, per-source complete capture identity and its
verification support, and any composite finding remapping. A patch-only source
must not be presented as proving full-capture equality.

TASK-024 implements these copies as `mulgae-composite-support.v1` under
support-index v2, with unchanged composite final and manifest versions.
Published source receipts retain P2 identities and epoch. Failed recovery
receipts carry the recovery manifest digest and attempt with an empty review ID
and no P2 claim. Local finding details include `source_finding` and
`source_receipt`; copied provider identities retain retirement provenance.

After publication, evidence reads require neither a surviving source run
nor the current working tree. Reuse atomic publication and recovery; interrupted
copies cannot leave a readable final. Integrate cleanup dependency and export
rules so a permitted source cleanup does not break the new composite. Failed
recovery roots remain protected by the existing cleanup policy. Exports
retain their existing opt-in content/redaction boundaries; evidence support is
not permission to include extra private source in an export. The existing export
allowlist excludes the added copied source findings, receipts, capture support
and evidence bodies.

Old composite versions without evidence stay readable for their existing
surfaces and explicitly report evidence unavailable. Do not mutate them, infer
quotes from live files, or silently fetch a potentially different source. New
composites can also contain unavailable legacy source evidence; capability is
per finding/evidence, not an invented all-or-nothing historical upgrade. An
operation requiring absent evidence must stop with a typed reason. An exact
mapping that already resolves to a published legacy composite returns that
artifact unchanged. Do not retrofit new support or rewrite bytes at its existing
identity merely because a newer writer can publish evidence.

Do not conflate this evidence extension with composition of different targets,
replacement of accepted roles, or automatic selection of recovery runs. Existing
exact mapping, deterministic replay, and at-most-one-final guarantees remain.

## Compatibility and acceptance

TASK-019 records the old/new writer and reader matrix for command/MCP results,
preflight receipts, manifests, composite finals, support indexes, and resources.
Version changed meanings; preserve supported historical reads and immutable
fixtures. Old binaries may reject new contracts explicitly; never claim that
new output can be read by an old strict decoder without proving it. No automatic
Config migration, public provider changes, or rewrite of installed host settings
is part of this Epic.

Acceptance must exercise wrong-root equal-content worktrees, alias/replacement
identity, preflight drift, zero provider calls on rejection, post-capture tree
changes, coherent pagination under corruption/cleanup, reports-only visibility,
all evidence indices, old/new composites, and CLI/MCP parity. Include equal
patches with different unchanged support files, side/policy/context differences,
request-only differences over an identical capture, and historical incomplete
capture metadata. The [roadmap](../roadmap/README.md#epic-007-verified-review-contracts)
records task-owned verification and Epic acceptance; the
[verification guidance](../implementation-tips/README.md#verification-for-the-adopted-review-epics)
defines the ongoing checks.

## Frozen TASK-019 contracts

TASK-019 established value types, validation, canonical encodings, schemas, and
examples. TASK-020 through TASK-025 connected them to commands, MCP tools and
resources, retained capture support, and capability declarations. The following
transport and storage rules remain the compatibility authority.

### Encoding and ownership

All four identities are `sha256:` followed by 64 lowercase hexadecimal digits;
the all-zero digest is invalid. Hash `version + NUL + canonical JSON bytes`.
JSON uses the declared Go DTO field order, no insignificant whitespace, decimal
integers, UTF-8 strings with Go `encoding/json` escaping, and no omitted fields.
Empty strings, empty arrays, and explicit presence booleans remain distinct.
There is no Unicode normalization. Readers reject duplicate, unknown, missing,
reordered, or alternatively encoded fields; whitespace in stored JSON is allowed.
The paired embedded examples pin the canonical hash inputs independently of the
producer. Cursor payloads require the compact encoding exactly.

| Value and owner | Canonical fields, in order |
|---|---|
| Project binding, `reviewrun.NewProjectBinding` | Version `mulgae-project-binding.v1`; `root`, `git_directory`, `common_directory`, `root_identity`, `git_identity`, `common_identity`. Each private directory identity contains `device`, `inode`, `birth_seconds`, `birth_nanoseconds`. |
| Capture, `reviewrun.CaptureManifest` | Version `mulgae-capture-manifest.v1`; `schema_version`, `target`, `policy_identity`, `sides`, `files`, `context`. |
| Request, `reviewrun.RequestReceipt` | Version `mulgae-request-receipt.v1`; `schema_version`, `project_binding`, `capture_identity`, `components`. The serialized `request_digest` is excluded from its own hash. |
| Publication, `query.InspectionReceipt` | Version `mulgae-publication-receipt.v1`; `schema_version`, `project_binding`, `session_id`, `run_id`, `review_id`, `run_type`, `target_sha256`, `final_sha256`, `manifest_sha256`, `support_sha256`, `lineage_sha256`, `epoch`, `capture_identity`, `capture_availability`. |

`ports.ProjectBindingObserver` returns a descriptor lease and private observation;
the application computes the binding. The filesystem adapter resolves canonical
aliases, observes the worktree root, Git directory and common Git directory, and
rejects path or descriptor drift on revalidation. A linked worktree has its own
root and Git directory even when the common directory is shared. No descriptor
metadata is serialized in a public result or persisted as a project ID.

The capture target fields are `kind`, `git_mode`, `sha256`, `size`,
`base_object_id`, `head_object_id`, `head_tree_object_id`, `index_tree_object_id`.
They preserve the existing target identity, excluding its local repository ID.
Git object IDs are canonical nonzero 40- or 64-digit hex values. Stage mode
requires its index-tree ID; missing historical identity is unavailable. Non-Git captures
carry empty Git fields. The target digest and length refer to exact target bytes,
including an empty Git patch. `policy_identity` is the admitted snapshot policy.

Logical sides are sorted lexically. Every capture includes `snapshot`; Git also
requires `base` and its selected after-side (`head`, `index`, or `worktree`),
workspace requires `worktree`, and patch/stdin requires `head`. An admitted empty
side has an entry in `sides` and no files; an absent side cannot stand in for it.
Each file has `side`, `path`, `media_type`, `disposition`, `size`, `sha256`, sorted
by side then path. Reject unsafe paths, duplicates, case-fold collisions and
file/directory collisions within a side. Text uses `text/plain` and `text`;
binary uses `binary_preserved` with its admitted raster or octet-stream type.
Context has `present`, `size`, `sha256`; absence is `false`, zero, empty string,
while present empty context hashes empty bytes. Verification rebuilds this entire
inventory from the retained immutable archive, including target and context,
and compares both the manifest and expected identity. A digest alone is not
verification. The existing preflight file-set encoding remains byte-for-byte
unchanged under `reviewrun.PreflightFileSetID`.

Request component fields are `target_selection`, `objective`, `roles`, `policy`,
`routes`, `assets`, `budget`, `workflow`. Each hashes
`mulgae-request-receipt.v1/NAME + NUL + canonical component bytes`. Objective is
`{"present":boolean,"text":string}` with exact admitted text. Roles are
`{"explicit":boolean,"roles":[...]}` with unique role names sorted lexically.
The other six components use the following exact shapes. Object keys are sorted
recursively; all shown fields are required. Empty lists use `[]`. `S` means a
UTF-8 string, `D` a digest, `N` an integer, and `B` a boolean. A selected string
is always `{"explicit":B,"value":S}`; absent selectors use false and an empty
value, while resolved defaults are recorded in the corresponding effective field.

| Component | Complete JSON shape |
|---|---|
| `target_selection` | `{"requested_kind":S,"captured_kind":S,"git_mode":S,"base":{"explicit":B,"value":S},"head":{"explicit":B,"value":S},"resolved":{"base_object_id":S,"head_object_id":S,"head_tree_object_id":S,"index_tree_object_id":S}}` |
| `policy` | `{"configuration_sha256":D,"snapshot_policy":S,"exclusions":[{"path":S,"reason":S}]}` |
| `routes` | `{"roles":[{"role":S,"provider_instance":S,"provider_family":S,"model":{"explicit":B,"value":S},"effort":{"explicit":B,"value":S},"profile":{"explicit":B,"value":S},"effective_model":S,"effective_effort":S,"effective_profile":S,"launcher_path":S,"profile_path":S,"permission_mode":S,"target_channel":S,"configured_timeout_ns":N}]}` |
| `assets` | `{"contracts":[{"name":S,"version":S}],"contents":[{"name":S,"sha256":D}]}` |
| `budget` | `{"eligible":B,"reason_code":S,"max_active_lanes":N,"total_invocations":N,"critical_path_deadline_ns":N,"run_deadline_ns":N,"ceilings":{"provider_timeout_ns":N,"role_path_deadline_ns":N,"run_deadline_ns":N,"max_invocations_per_role":N,"max_invocations_per_run":N},"role_paths":[{"role":S,"provider_instance":S,"invocation_count":N,"transition_count":N,"invocation_timeouts_ns":N,"deadline_ns":N}]}` |
| `workflow` | `{"kind":S,"sources":[{"run_id":S,"attempt_id":S,"finding_ids":[S],"content_sha256":D}],"prompt_inputs":[{"name":S,"sha256":D}],"artist":{"present":B,"automatic":B,"brief_path":S,"design_spec_globs":[S]}}` |

`configuration_sha256` is the existing `config.Resolution.SHA256()` over the
exact admitted project and local Config v4 source bytes. `BundleSHA256` hashes
`Mulgae-CONFIG-v4 + NUL + project + NUL`, the project byte length as an unsigned
64-bit big-endian integer, the project bytes, `NUL + local + NUL`, the local
byte length in the same encoding, and the local bytes, in that order. Here
`project` and `local` in the framing strings are literal labels. The result uses
the `sha256:` prefix and lowercase hexadecimal. Admission canonicalizes the
merged configuration for resolution; it does not replace either source byte
sequence in this hash. Accepted comment or formatting changes therefore alter
the configuration hash and request identity even when effective policy is
unchanged. Effective route values and budget operands bind resolved defaults
separately. Credentials and provider-home contents never enter any preimage.

Exclusion rows use admitted project-relative paths and capture decision codes
`gitignore`, `mulgaeignore`, `ignore_control`, or `reserved_path`, sorted by path
then reason. Decisions are collected within one capture and never reused by a
subsequent capture.
An empty exclusion list means no admitted exclusion decisions, not unknown data.

Route and budget rows are sorted by role, asset rows by name, source rows by
run/attempt ID, and source finding IDs lexically; reject duplicates. Preserve
prompt-input order and artist glob order. A missing provider model, effort or
profile remains an empty effective string when that provider exposes no such
setting. Configured selectors preserve their explicit/default distinction.
The route permission and channel fields retain preflight meanings:
`not_applicable` and `prompt`. Provider-native permission policy remains in the
protocol adapters. Private resolved launcher/profile paths enter only the route
preimage. Runtime temporary paths, invocation IDs and wall-clock timestamps are excluded.

Asset rows include every selected prompt, role and schema content digest and
contract version; unrelated catalog entries are excluded. Budget fields project
the existing admitted `review.RunBudgetReceipt` and role paths, with durations
as integer nanoseconds. Ordinary workflow has kind `review`, empty sources and
prompt inputs, and its actual artist selectors (or false, false, empty string,
empty globs when absent). Child workflows bind their selected immutable source
provenance and exact workflow-only prompt inputs. Artist files that are captured
normally remain in the capture inventory. Workflow-only inputs do not alter
complete-capture equality.

Production construction must derive every component from the admitted plan;
the foundation's component-hash helper alone makes no completeness claim.
The request receipt contains only the component digests. Capture support stays
portable; a local project binding or request receipt is not exported by default.

### Admission and read failures

Transport syntax and version validation precede application work. A paired
execution guard is either absent or complete; half guards return
`guard_incomplete`, malformed digests `guard_invalid`, and unsupported versions
`contract_unsupported`. After checking descriptor safety, compare project binding
before capture (`project_binding_mismatch`). Capture and plan once, then compare
request identity (`request_digest_mismatch`) before qualification or any provider
construction. Execution consumes those same captured values. Revalidate the
lease at admission and preserve the existing spawn-time checks. Neither guard
comparison nor a preflight creates a run. Repeated accepted starts remain
separate executions; guards are not idempotency keys.

Reads validate selectors, revalidate project identity, and verify the selected
publication, support and epoch before comparing an expected receipt. They then
validate cursor scope or content identity and reobserve the same publication
before returning. Integrity and security failures retain their existing typed
failure class; they never become receipt mismatches, historical unavailability,
or diagnostic fallback. Use `publication_receipt_mismatch`, `cursor_invalid`,
`cursor_mismatch`, `content_digest_mismatch`, and
`read_continuation_incomplete` for validly observed contract failures. Missing
historical support uses `capture_identity_unavailable` or
`evidence_unavailable`; missing bound support is an artifact-integrity failure.
Invalid offsets/indices use the existing invalid-input projection. Existing CLI
exit-class and MCP error-envelope mappings remain authoritative.

Publication receipts bind the P2-observed final, manifest, support-index and
optional lineage digests with the nonzero epoch and current local binding.
Absent lineage is an empty string. Capture availability is either `verified`
with an identity or `capture_identity_unavailable` with an empty identity.
Construction validates a value; only the query service can establish its P2
provenance. Diagnostic-only inspection returns its existing non-authoritative
status with an empty receipt and no page or content references.

### Transport grammar and result fields

All CLI surfaces below accept the existing `--output json` convention. IDs must
name an exact run; continuations never fall back to the latest run. Optional
`--expected-project-binding DIGEST` applies to preflight and new reads. Execution
uses both that flag and `--expected-request-digest DIGEST`, or neither. MCP uses
`expected_project_binding` and `expected_request_digest` with the same rules.
Existing review selectors, objective, roles and provider restrictions remain.

| Surface | Additional selectors | Result |
|---|---|---|
| CLI `context`, MCP `get_context` | None | `project_binding`, `capabilities` |
| CLI `review --preflight`, MCP `preflight_review` | Expected binding only | Existing preflight fields plus `project_binding`, `capture_identity`, `request_receipt`, `capabilities` |
| CLI `review`, MCP `run_review` / `start_review` | Paired execution guard | Existing lifecycle envelope plus `guarded`, admitted `project_binding`, `capture_identity`, `request_digest` |
| CLI `inspect --run ID`, MCP `inspect_review` | `--severity LEVEL` (default low), `--limit N`, `--cursor TOKEN`, `--expected-publication-receipt DIGEST` | Coherent existing status/coverage/extraction axes, `publication_receipt`, capture identity/availability, capabilities, finding page |
| CLI `findings --run ID --severity LEVEL`, MCP `list_findings` | Same page/receipt selectors; MCP retains its default low severity | Existing total `finding_count`, `returned_count`, `findings`, `next_cursor`, `publication_receipt`, capture identity/availability |
| CLI `read-finding --run ID --finding ID` | Content selectors below | Canonical complete committed finding JSON bytes |
| CLI `read-report --run ID` | Optional `--role ROLE`, content selectors | Rendered Markdown, or exact original selected role report |
| CLI `excerpt --run ID --finding ID` | Existing target digest selector plus `--evidence-index N` (zero-based, default zero), content selectors | Exact selected committed evidence bytes and metadata |

MCP page selectors are `run_id`, `minimum_severity`, `limit`, `cursor`,
`expected_publication_receipt`. Page responses preserve canonical committed
finding order after filtering. A summary contains finding ID, fingerprint, role,
provider, severity, title, confidence, lifecycle, detail URI and indexed evidence
references; it omits description, rationale, suggested fix and report bodies.
The total count is the count after filtering, independent of page size. Empty
pages use `[]`, zero returned count and an empty `next_cursor`. Page size defaults
to 100 and accepts 1 through 1,000. CLI severity remains required on `findings`;
the historical low floor excludes info findings and is not relabeled.

A cursor is unpadded base64url of compact `mulgae-finding-cursor.v1` JSON, a dot,
and the lowercase SHA-256 of its domain-separated payload. Its fields are
`schema_version`, `scope`, `offset`; scope fields are `project_binding`,
`publication_receipt`, `run_id`, `query_kind`, `minimum_severity`, `limit`.
Query kind is `inspect` or `findings`. The offset is a positive multiple of the
bound limit and must identify a nonempty next page in the verified result.
Reject a changed limit, filter, run, project or receipt and tokens above 4,096
bytes. The checksum detects malformed tokens; it grants no authority.

Content selectors are `--offset N` (default zero),
`--expected-publication-receipt DIGEST`, and `--expected-content-sha256 DIGEST`.
Both expected digests are mandatory for any nonzero offset. The response fields
are `publication_receipt`, `content_sha256`, `media_type`, `encoding`, `offset`,
`total_bytes`, `returned_bytes`, `next_offset`, `content`, and the selected
run/finding/role/evidence identities. `encoding` is `utf8` for finding JSON and
reports, `base64` for binary evidence; text evidence uses `utf8`. Hash exact
complete bytes before encoding. `next_offset` is null at EOF. Empty content at
offset zero returns zero bytes and null continuation. Reject out-of-range or
non-issued chunk boundaries; returned offsets always advance. Chunks contain at
most 16,384 source bytes and never split UTF-8. Integer offsets cover signed
64-bit nonnegative byte positions; there is no product total-content ceiling.

MCP content resources retain `mulgae://runs/R/report` and
`mulgae://runs/R/findings/F/evidence`, and add
`mulgae://runs/R/findings/F/detail`. Optional query parameters, in canonical
order, are `target_sha256` (evidence only), `role` (report only), `evidence_index`
(evidence only), `project_binding`, `publication_receipt`, `content_sha256`,
`offset`. Values use canonical URL encoding; path IDs must be literal canonical
IDs. Unknown, duplicate, wrongly ordered or encoded-alias parameters fail.
Omit default offset/index zero; nonzero values use decimal without leading zeros.
Continuations carry both receipt and content digest. Existing report/evidence
URIs without new parameters retain their historical meaning and verification.
New response metadata and returned continuation URIs bind the selected content.
Legacy report/evidence continuations preserve their old URI mode and evidence
byte boundaries; they do not gain receipt binding implicitly. CLI `excerpt`
uses the new chunk projection when any new content/index selector is supplied,
otherwise preserving its legacy projection.
Transport projections call shared query/report policy; they never read a final
file independently or write a rendered report file.

`capabilities` contains the closed fields defined by
`query.VerifiedReadCapabilities`. Each value is empty (unavailable) or `v1`.
Advertise a field only after its owning implementation and verification land.
Per-artifact evidence availability is separate from binary support; a supported
reader can still return `evidence_unavailable` for a legacy item.

### Writer and reader matrix

| Contract | Current writer / reader | Owning Task and next change |
|---|---|---|
| CLI command envelope | v18 emission with self-contained composite evidence; v5-v17 schemas retained unchanged | TASK-024 advertises composite evidence. Strict old readers may reject v18. |
| Preflight | v7 emission with request/capture receipt and composite evidence capability; v3-v6 fixtures retained | TASK-024. Historical v5 does not assert guard support. |
| MCP tool envelope | v1 unchanged | Keep the outer v1 envelope; data contracts and advertised capabilities distinguish new projections. |
| Capture/request/publication/cursor | Four v1 schema/example pairs; capture and request are emitted; inspection emits receipts and cursors | Unknown versions fail closed. |
| Ordinary/child final and manifest | Current v1 plus existing recovery v2, unchanged | TASK-021 retains complete capture support through support-index v2. |
| Composite final and manifest | Current v1/v2, unchanged | TASK-024 uses support-index v2 for self-contained evidence and per-source capture support. Existing exact mappings stay unchanged. |
| Run support index | v2 for complete ordinary/child/no-change captures and new composite support; historical v1 remains readable | TASK-021 requires the indexed capture manifest and retained material. Historical child replays without complete sides retain unavailable identity. TASK-024 retains composite per-source support. Old strict binaries may reject v2. |
| Content resources | Finding detail, report and indexed evidence are receipt-bound; legacy report/evidence URI semantics remain supported | TASK-023/024 implemented; copied composite evidence uses the same verified reads. |

Support-index v2 must hash-bind every added capture manifest and archive/blob,
and composite provenance/evidence item before publication commits. Its strict
v2 reader verifies complete inventory and never upgrades v1 in place. Existing
v1 archives can establish capture identity only if they independently satisfy
the complete v1 capture encoding; an old no-change empty index cannot. New
composites carry each selected source's capture manifest/material or explicit
unavailability, plus exact copied evidence identities. A common capture exists
only when all selected role sources verify the same complete identity. Recovery
source receipts retain their existing attempt provenance rather than claiming
an uncommitted source has a publication receipt. These rules preserve cleanup,
recovery, replay and export boundaries while versioning the new support meaning.
