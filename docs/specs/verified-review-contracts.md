# Verified review contracts

This specification defines adopted, not-yet-implemented requirements for
[EPIC-007](../roadmap/README.md#epic-007-verified-review-contracts).
It does not change what an installed binary supports. The existing
[contracts](contracts.md) remain the implemented baseline until each owning
Task updates source, tests, embedded contracts, and user guidance together.
The [development dossier](../todo/EPIC-007-verified-review-contracts.md) owns
temporary implementation sequencing; the roadmap alone owns delivery status.

## Purpose and boundary

Connect the requested project, captured review input, admitted execution, and
verified result through native contracts. CLI and MCP must use the same
application policy rather than asking an agent to reconstruct it from private
files or independently queried status and finding results.

This Epic is independently useful with today's objective and project context.
It does not depend on structured Review Briefs, requirements assessment, batch
followup, provider changes, a new daemon, or MCP Tasks migration.

## Required behavior

- [ ] VRC-001: expose a read-only, independently comparable local project binding.
- [ ] VRC-002: distinguish complete capture identity from request identity, bind
      preflight to the effective request, and reject mismatched execution
      preconditions before any provider request.
- [ ] VRC-003: return status and a bounded finding page under one verified
      publication receipt, including capture identity availability, extraction,
      and coverage state.
- [ ] VRC-004: expose actual structured findings and read-only report content
      through the CLI, with equivalent MCP semantics and lossless pagination.
- [ ] VRC-005: provide verified, self-contained finding evidence for newly
      published composites without inventing evidence for historical artifacts.
- [ ] VRC-006: preserve legacy command behavior where unchanged, declare new
      capabilities explicitly, and keep all new reads provider-free.
- [ ] VRC-007: replace agent-side verification steps only after native checks and
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

## Planned public surfaces

The following names are implementation targets, not commands available today.
TASK-019 freezes their complete grammar, result versions, errors, and paired
examples before production wiring. Do not allocate speculative future versions
in existing runtime schemas during documentation planning.

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

After publication, evidence reads must require neither a surviving source run
nor the current working tree. Reuse atomic publication and recovery; interrupted
copies cannot leave a readable final. Integrate cleanup dependency and export
rules so a permitted source cleanup does not break the new composite. Exports
retain their existing opt-in content/redaction boundaries; evidence support is
not permission to include extra private source in an export.

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
capture metadata. See the dossier for task-owned tests and the explicit Epic
closeout gate.
