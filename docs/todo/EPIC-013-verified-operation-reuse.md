# EPIC-013 execution dossier: verified operation reuse

[EPIC-013](../roadmap/README.md#epic-013-verified-operation-reuse)
removes repeated computation inside existing trusted operations.

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

## Goal and design decisions

Keep verification at real input, filesystem, process and provider boundaries;
reuse an already proved immutable value only inside its declared lifetime.
Support-artifact count and evidence count must not multiply whole-publication
reads within one request. A new request, including an MCP continuation, performs
fresh verification. No measured performance or allocation target is required.

EPIC-012 provides the accepted correctness baseline. TASK-055 includes DF-010
negative/interleaving controls before altering query observation. TASK-056 and
TASK-057 include DF-011 controls before altering source admission. TASK-058
includes DF-020 guards and preserves DF-002/DF-004/DF-008 boundaries.

## Task execution contracts

### TASK-053: Prove immutable values at construction

Inventory all constructors, zero values, internal literals, clone paths and
getters for provider packets and immutable publication artifacts. Keep exact-
byte digest verification at construction, private storage and defensive copies
at mutable byte boundaries. Make repeated validity checks use a constructor-
owned proof only after that inventory shows the representation cannot change.
Expose byte length and exact equality without copying content where needed.

Preserve getter ownership promises, including nested invocation observations;
a shallow copy must not expose mutable storage. Do not replace disk/provider
revalidation with the proof. If immutable storage cannot be established for a
type, retain its full validity check and remove only demonstrably redundant
copies. Do not extend proof bits to process-success classification without a
separate proof of every receipt and termination path.

Verify zero/forged input rejection, source/getter mutation, clone independence,
exact digests and unchanged publication/protocol bytes. Count repeated hashes
only on constructor-proven values; never treat a flag as external evidence.

### TASK-054: Reuse publication's review-independent build

Limit production construction changes to the live and no-change candidate
paths. Keep historical fixture-producing writer paths unchanged until the
TASK-060 corpus is frozen. Split support construction from binding the issued
review ID. Construct and
hash review-independent members once per candidate, then reuse them for dummy-
ID preflight and real-ID binding. Keep every ID-dependent excerpt, support-index
entry, final, manifest, journal, lineage and epoch identity correctly bound.

Keep schema/size rejection before ID issuance, candidate binding, resumed-
candidate equality and P0/P1/P2 ordering. Retain durable write/read-back and
sync behavior. Verify byte equality with the old builder over live, no-change
and retained historical fixtures; count shared-member builds and verify issue-
ID calls are zero on preflight failure. Test interrupted/resumed publication.

### TASK-055: Share a verified view within one query

Create a query-owned per-call read context containing the initial P2 binding,
verified index and already-verified artifacts. Thread it explicitly through
inspection, status, excerpts and report rendering. Return immutable data only
after fresh final P2 confirmation for every consumed publication, in a
deterministic dependency order. Do not attach the cache to a reusable public
review or the long-lived service. Preserve historical no-index reads.

Each artifact retains path/kind/digest checks. Verify all support required by
the current public contract; do not narrow verification to returned artifacts.
MCP continuations start a fresh context. Avoid retaining unnecessary large
bodies; lifetime reuse does not authorize a new content cap or source snapshot.

Before optimizing, cover DF-010 cleanup/epoch/snapshot interleavings, missing or
rebound support, corrupted unserved support and failure precedence. Preserve
safe corrupt-status identity, unavailable-recovery metadata and typed errors;
a generic wrapper must not erase a meaningful partial error result. Verify
separate requests detect later corruption and report chunks retain their exact
receipt/full-content identity. Assert whole-support traversal is not repeated
per excerpt; do not prescribe a universal observation count for historical
multi-publication lineages.

### TASK-056: Separate source access admission from body reads

Add a source-owned typed path-admission operation for native read-plan checks.
Use descriptor-based path, protected-root, file-kind and namespace checks;
do not read/hash a file body merely to authorize its path. Keep actual evidence
reads and their byte/stability verification separate. Update Grok, Cursor and
AGY through the shared port; no driver owns filesystem policy.

Retain per-event source/config revalidation and completed-tool correlation.
Do not skip later checks using a bare admitted boolean: provider operations can
change kind/path/command under the same native ID. Test late mutations, failed
operations and missing permission handshakes, protected/ignored symlinks,
non-regular files, root swaps, post-open unlink/rename versus in-place mutation,
and synchronized Close. Assert no body read during admission.

### TASK-057: Reuse immutable Git inventory and identical config parsing

Retain fixed commit-side path-to-OID inventories already admitted for the
selector. Read blobs by the bound OID while preserving source/root/Git
revalidation. Do not treat index or worktree contents as immutable inventories.
Keep credential and locality attestation unchanged.

For each execution Git config file (`<common-git-dir>/config` and
`<git-dir>/config.worktree`), retain at most its last successful
content digest and parsing verdict inside one reader. Read and verify current
file descriptors every time; only skip the identical-byte Git key-parsing subprocess
(`git config --file - --no-includes --null --name-only --list`). This is not
a cache of `.mulgae/config.yaml` or `.mulgae/local.yaml` admission. Cache no
failure and keep policy/parser identity fixed for that reader. No process-wide
cache or stat-only shortcut is permitted.

Cover DF-011 non-branch/empty HEAD, unsafe per-worktree config, post-open swaps,
protected-name case variants and no-change zero-provider controls. Test config
appearance/disappearance, changed unsafe bytes, restored valid bytes, parser
failure, Close and a second reader. Assert fixed-object lookup reuse and bounded
config-cache cardinality without suppressing fresh byte/identity checks.

### TASK-058: Qualify different families concurrently with complete cleanup

Schedule groups in original-order batches containing at most one group per
family. Stop a batch at the first repeated family rather than moving groups
past an earlier unresolved group. Distinct families in a batch may overlap;
same-family probes and namespace qualification remain independent. Replace
TASK-051's sequential contract description with the exact implemented batch
concurrency guarantee in the same change, including its same-family restriction.

Reduce public routes/evidence/failures in original order through the first
failed group. Always retain cleanup ownership from every started group,
including groups after that failure. In particular, replace the current
`runFamilyQualificationBatches` early return during parts merging so later
acquisitions remain visible to `closeAdmitted`. Drain or explicitly retain undrained
namespaces exactly once. Among fatal errors actually returned by started
groups, use the existing `app.FailurePrecedence` first, then original group
order to break ties; return the selected original error rather than joining
unrelated causes. Thus a later observed protected failure cannot be hidden by
an earlier ordinary failure. Keep nonfatal per-candidate qualification failures
under their existing policy; do not turn them into new fatal group errors.
Public routes/evidence still stop at the first failed group in original order,
even when a later group's fatal error wins precedence. Preserve cancellation
and cleanup-failure classification and retain undrained ownership. An unexpected
worker failure must not leak acquired namespaces.

Use channel/barrier tests for overlap, same-family exclusion and ordered
reduction. Use the sequential oracle for equivalent observed outcomes, plus an
explicit concurrency-only precedence matrix: earlier ordinary/later protected,
earlier protected/later ordinary, equal-class ties, cancellation and cleanup
failures. Enumerate success/failure combinations, including later acquisitions
and failures, cancellation, panics and failed drain. Preserve ZCode/AGY instance
keys and named Codex profile isolation. Prove deterministic multi-family
qualification routes and ZCode live verification during EPIC-013 before
claiming concurrency compatibility; non-ZCode live provider certification
(`grok`, `cursor`, `agy`, and `codex`) remains deferred to the `v0.1.26`
release gate. The coordinator wave barrier and
process-wide worker capacity are unchanged.

### TASK-059: Certify reuse and boundary preservation

Run the deterministic gates (`make test-prepare`, `make test-unit`,
`make test-int`, and `make test-release`) and ZCode-only live verification.
Compare normalized public outputs, stored bytes, typed errors, corrupt-status
projections and publication failure recovery to the EPIC-012 baseline. Promote
the chosen lifetime/ownership rules to architecture and verification guidance.
Record non-ZCode live provider gates (`grok`, `cursor`, `agy`, and `codex`) as
explicitly deferred to the `v0.1.26` release gate under Master's
quota-preservation decision. Hand the accepted exact candidate to EPIC-014 with
any independent residual explicitly owned; do not defer work needed for current
correctness.

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
