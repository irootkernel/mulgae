# EPIC-012 execution dossier: correctness and historical compatibility

[EPIC-012](../roadmap/README.md#epic-012-correctness-and-historical-compatibility)
repairs bounded correctness and conformance defects before optimization.

## Authority and execution boundary

The [roadmap](../roadmap/README.md) alone owns IDs, order, dependencies and
status. This dossier defines future work; it does not describe delivered
capability. The planning baseline is `c4d717e282a426be0095533b94460c0cf40ae2db`.
Re-observe source, tests and contracts before each implementation task.

This documentation-only design records no implementation or acceptance.
Starting implementation requires a separate explicit request. This design does
not authorize staging, commits, installation, configuration changes, provider
credential changes, pushes, tags, publication or release. Provider calls and
managed workflow effects belong to the later disclosed execution envelope.

Canonical owners remain [goals](../specs/goals.md),
[contracts](../specs/contracts.md), [security](../specs/security.md),
[architecture](../architecture/README.md), and
[verification guidance](../implementation-tips/README.md). Update each affected
owner with its implementing task; do not advertise future behavior as current.

## Shared constraints

- Preserve source-before-provider admission, original source reads, neutral cwd,
  native restrictions, exact provider assignment and fail-closed publication.
- Preserve public JSON, command grammar, typed failures and exits, stored bytes,
  historical readers and cleanup requirements. Correct an explicit documented
  inconsistency only in its named task, with compatibility tests.
- Keep provider content without a new product byte ceiling. Preserve existing
  metadata, structured-member, process and concurrency bounds.
- No timing measurements, benchmarks, latency targets, percentiles, speedup
  estimates or memory-peak gates. Prove behavior, ownership, traversal complexity
  and repeated-operation elimination with deterministic tests and call traces.
- Keep initial-wave progression, process-wide worker capacity and per-namespace
  ZCode/AGY qualification identities. Retain credential/locality revalidation,
  read-path durability adoption and sync ordering, and transcript spooling.
- No generic provider plugin framework, stat-only security cache, process-wide
  content cache, objective-limit change, or lazy schema compilation that moves
  constructor failures to first use.

## Goal and evidence basis

Make repair address the provider's actual claim, make conversation teardown and
framing progress correctly, remove an accidental lifetime epoch failure, and
restore strict historical artist reads. Keep the current trust and publication
model. Severity labels and occurrence frequencies in the two external analysis
reports are not accepted incident evidence.

| Finding | Current owner | Planned resolution |
|---|---|---|
| Canonical finding/evidence order supplies JSON pointers for unsorted original bytes; valid `index` side is omitted from repair admission | `app/validation`, `app/review/provider_runtime.go` | TASK-046 |
| Teardown continues selecting an already closed context channel | `adapters/process/conversation_darwin.go` | TASK-047 |
| Each stdout chunk searches the complete unfinished line again | Same conversation feed | TASK-048 |
| Accumulating epoch files exceed the generic 4096-entry directory helper | `adapters/filesystem/publicationstore_darwin.go` | TASK-049 |
| Historical artist manifest writer fields are missing from strict reader DTO | `app/publication/serialization.go`, `app/query/model.go` | TASK-050 |
| Cursor diagnostic IDs bypass the shared admission grammar; embedded schema index omits current versions | Cursor driver and embedded schema README | TASK-051 |

The epoch defect is a scan of more than 4096 existing entries; do not claim a
specific publication ordinal without tracing the complete transaction.
TASK-051 owns correction of the qualification contract to the implemented
sequential behavior. TASK-058 owns both the later cross-family scheduler change
and its matching concurrent contract wording; no concurrency is implied here.

## Task execution contracts

### TASK-046: Preserve provider coordinates through normalization

Record original finding/evidence coordinates before either sort. Carry them
through validation and evidence verification as internal correlation metadata.
Evidence coordinates refer to the complete original wire evidence array,
including entries with visual references; do not index a filtered claim list;
construct exact-evidence repair pointers from those coordinates and the exact
original candidate. Preserve the repair plan's existing sorted/unique pointer
contract after mapping back to wire positions. Reuse
`CurrentEvidenceSide.Valid()` for side repair.
Do not alter finding IDs, normalized sort order, provider wire shape or repair
authority. Do not add wire coordinates to public receipts or persisted records.

Verify finding-only permutations, evidence-only permutations, both together,
several mismatches, duplicate-looking claims and an already canonical input.
Apply the generated repair to original bytes and re-verify: only authorized
quotes change, cardinality/severity remain fixed, and outside-path patches
fail. Cover all four sides including `index` and rejection of unknown sides.

### TASK-047: Consume cancellation once during teardown

Disable the local done-channel receive after its first observation in
`Converse` and the retained `runBoundedPostOutput` teardown loop. The latter
remains a legacy path; this fix does not reactivate it. Preserve
context/timeout precedence, full stream drain, driver completion, bounded
signal escalation, final wait and process-group absence requirements.

Use deterministic cancellation and delayed child/driver completion fixtures.
Assert cancellation is consumed once and other teardown events make progress;
verify cancellation classification, signal receipts and no orphaned child.
Test simultaneous cancellation/EOF/exit without CPU or duration measurements.

### TASK-048: Assemble protocol lines incrementally

Search only incoming bytes for newlines, retaining an unfinished tail with
amortized append. Completed lines must own their bytes. Keep complete stdout
capture, line order, blank lines and partial-line EOF rejection. Do not impose
a line-size ceiling or remove the transcript spool.

Verify chunking equivalence across boundaries, a large single line, several
lines per chunk, input-buffer mutation, later append, teardown drain and EOF.
Establish linear scanning by construction and deterministic work counters where
needed; do not benchmark.

### TASK-049: Stream the epoch directory safely

Use an epoch-specific bounded-batch directory scan, retaining only the current
batch and maximum epoch. Validate every entry with the existing private-file,
owner/mode, no-follow and namespace checks. Keep overflow, next-name collision
and directory revalidation. Retain the current layout and monotonic numbering;
do not add a latest pointer, shard files, or lift unrelated directory caps.

Verify 4096 and 4097 existing entries, unsafe entries after the first batch,
malformed/zero/overflow names, symlinks, non-regular files, bad owner/mode,
namespace replacement and cancellation at the established transaction boundary.
Cleanup must not remove epoch evidence to make the test pass.

### TASK-050: Read retained artist manifests strictly

Admit optional `artist_brief` and `artist_visual_assets` fields in the historical
runtime target reader. Correlate their canonical per-run paths, artifact kinds,
digests, support-index membership and exact retained bytes. Keep strict unknown-
field rejection and live-source replay refusal. Share the runtime-target wire
shape if needed to prevent this specific writer/reader drift; broad format
consolidation remains TASK-061.

Cover a frozen synthetic artist manifest, a historical publish/read round trip,
old manifests without artist fields, independent optional-field presence,
missing/tampered/rebound artifacts and cross-run paths. Keep DF-022 v1 archive
negative controls and v2 controls. Do not restore captured execution.

### TASK-051: Align existing diagnostic and metadata contracts

Sanitize Cursor's optional provider session ID using the existing port grammar;
invalid diagnostic IDs must not invalidate an otherwise valid observation.
Share only identical sanitization mechanics. Preserve native session correlation.
Correct ZCode/Grok `providers` result-transport metadata from `staged_file` to
`stdout` to describe the current protocol result path. Keep the existing public
field, command envelope and schema version, whose value contract already
permits the actual transport; preserve historical stored transport values.
Add the six missing schema-index entries and correct its current command and
preflight versions; regenerate the embedded checksum through its generator.
Correct the qualification contract sentence to the implemented sequential
family-probe behavior without changing scheduling; TASK-058 later changes both
code and documentation together. Add a composition-level assertion that the
existing JSON validation and publication structured-member limits stay equal.

Verify valid and invalid Cursor IDs against port admission, unchanged native
correlation/outcomes, the exact `providers --json` envelope and factual transport
values, both structured-limit constants, every indexed schema/example pair and
generator stability. Preserve the four current-evidence sides separately from
workspace admission-failure side vocabularies. Do not change protocol trailing-
data tolerance, final-review size failure policy, diagnostic failure precedence
or schema versions in this task.

### TASK-052: Certify the correctness candidate

Run the deterministic gates (`make test-prepare`, `make test-unit`,
`make test-int`, and `make test-release`) and ZCode-only live verification,
confirm each earlier regression is meaningful, and update canonical
documentation in the owning changes. Recheck the preserved wave barrier,
process worker pool, durability adoption, source boundary and historical
support matrix. Record non-ZCode live provider gates (`grok`, `cursor`, `agy`,
and `codex`) as explicitly deferred to the `v0.1.26` release gate under
Master's quota-preservation decision. Hand the accepted exact candidate to
EPIC-013; do not claim release or implementation of later Epics.

## Excluded behavioral changes

Oversized final-review handling is outside this sequence: keep current
structured-member bounds and protected publication failure behavior. Matching
two constants does not authorize reclassifying publication failure as ordinary
extraction failure. Stricter ZCode/Grok protocol-line trailing-data rejection
also needs a separate behavior-change proposal and live certification; parser
consolidation must preserve existing tolerance. Cursor cancellation wrapping
is characterized in TASK-064; runner precedence is not changed on an
unverified hypothesis. Shared provider-family type unification is not required.

## Verification and handoff

Each implementation task adds a failing-first regression or establishes its
existing behavior before changing it. Use an explicit package and anchored
`-run` for focused Go tests. Then run the applicable Makefile unit, integration
and static targets. Changing embedded assets requires both documented
generators twice and an unchanged second output.

Under Master's quota-preservation decision for EPIC-012 through EPIC-014,
development and Epic acceptance run the deterministic gates (`make test-prepare`,
`make test-unit`, `make test-int`, and `make test-release`),
`make test-mcp-clients` when MCP consumer paths change, and ZCode-only live
verification (`TestLiveZCodeCapability` and ZCode-only live review checks).
Live provider checks for Grok (`make test` / `make test-e2e` Grok leg and
`make test-grok`), Cursor (`make test-cursor`), AGY (`make test-agy`), and
Codex (`MULGAE_E2E_OPT_IN=1 make test-e2e-opt-in` with the two explicit homes)
are explicitly deferred to the `v0.1.26` release gate (`release-handler`),
where all five providers (`zcode`, `grok`, `cursor`, `agy`, and `codex`) must
be certified on the release candidate. Record those deferred non-ZCode live
checks explicitly at handoff; never substitute ZCode as proof of another
provider's live wire behavior, modify credentials/configuration, or claim
unexercised providers were live-certified. These are future implementation
checks, not commands run by this design task.

Hand off the exact candidate identity, changed owners, regression results,
compatibility matrix, integrity/cancellation evidence and all unperformed
checks. Keep local runtime evidence local. Do not cite local run identities as
retained product evidence. Use a reviewed promoted package only if a downstream
consumer requires retention.

Before closeout, promote behavior, structure, rationale and verification to
their canonical owners, verify links, and replace the Epic's Detailed SOT with
Canonical Outcomes. Remove this dossier and its TODO entry only when its last
consumer is closed and that removal is authorized. Master accepts the Epic;
passing tests or technical design agreement does not provide that acceptance.
