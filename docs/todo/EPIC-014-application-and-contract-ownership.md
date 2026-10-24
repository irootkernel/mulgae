# EPIC-014 execution dossier: application and contract ownership

[EPIC-014](../roadmap/README.md#epic-014-application-and-contract-ownership)
consolidates responsibility and removes retired writers without losing reads.

## Authority and execution boundary

The [roadmap](../roadmap/README.md) alone owns IDs, order, dependencies and
status. This dossier defines remaining work; the canonical owners describe
delivered capability. The planning baseline is `c4d717e282a426be0095533b94460c0cf40ae2db`.
Re-observe source, tests and contracts before each implementation task.

Master requested execution on 2026-10-24 under a separate bounded execution
envelope. The roadmap records Task progress; that envelope owns implementation,
checks and local commit authority. This dossier grants no installation,
configuration or credential changes, pushes, tags, publication or release
authority, and does not record Epic acceptance.

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

## Goal and migration strategy

Make transport parsing, use-case policy, persisted wire contracts and provider
mechanics have explicit owners. Delete only code that is both unreachable or
retired in production and unnecessary for retained compatibility. File size,
line-count reduction and interface ratios are not success criteria.

EPIC-013 supplies the accepted baseline. Frozen historical fixtures precede
writer removal. Shared format/JSON mechanics precede related deletions. Do not
resurrect EPIC-008's deferred execution or modify another repository.

## Task execution contracts

### TASK-060: Freeze a minimal historical compatibility corpus

Commit only synthetic, byte-fixed artifacts in ordinary testdata, with no
`.mulgae` path segment or runtime directory. Include captured v1/v2 ordinary,
no-change, artist, child/delta/followup, composite v1/v2, failed recovery and a
retired provider. Preserve each existing accepted or rejected outcome; a retired
provider fixture need not become readable when current policy rejects it.

Record each fixture's format, expected operation/result and integrity bindings.
Readers must not regenerate expected bytes from the writer being removed.
Keep missing/tampered/rebound/cross-run and wrong-lineage controls, including
DF-022. Verify read/report/export/recovery/cleanup outcomes as applicable.
No source archive, transcript, user credential or real review is fixture input.

Inputs from EPIC-013: the base query fixtures behind
`queryValidator` in `internal/app/query/service_test.go` are
schema-invalid, so those tests prove orchestration rather than
schema acceptance; this corpus should exercise real-schema
acceptance for the read families it covers. EPIC-013 certified
compatibility by comparing baseline and candidate binaries through
the frozen `test/e2e` helpers, as
[verification for the adopted review Epics](../implementation-tips/README.md#verification-for-the-adopted-review-epics)
describes.

### TASK-061: Consolidate matching wire and strict-JSON mechanics

Introduce a small leaf owner for shared persisted DTOs, format-version constants
and path grammar. Keep filesystem operations and application decisions in their
current layers. Migrate writer/reader pairs incrementally with byte-exact golden
controls; retain all historical schema versions and raw retired-provider names.

Extract strict-JSON mechanics only where the complete accepted/rejected sets
match. Preserve duplicate-key, unknown-field, trailing-data, numeric, UTF-8 and
Unicode-surrogate behavior, plus error class and precedence. Add DF-013 lone-low
and paired-surrogate cases before moving parsing. Distinct domain-separated
hashes and distinct canonical-byte formats remain distinct.

Do not tighten ZCode/Grok protocol-line tolerance through this refactor or
unify context-specific Git hardening environments (DF-026). Verify frozen
corpus bytes, parser negatives, schema examples and consumer projections.

### TASK-062: Construct typed review requests and share status policy

CLI flags and MCP tool JSON each map to a shared application-owned typed review
request/admission path. Remove MCP's synthetic argv construction and CLI parse
round trip. Keep syntax and transport-specific bounds at their entrypoints:
CLI objective remains 12000 bytes; MCP remains 4096 bytes. Preserve omitted vs
explicit roles, selector semantics, expected binding, artist defaults, no-change
zero-provider behavior and existing request/result identities.

Move shared run-status fallback and failure selection into an application use
case, with transport-specific envelopes outside it. Preserve legitimate
CLI/MCP projection differences and verify complete joined-error precedence;
do not manufacture parity by widening not-found fallback.

Cover DF-012 partial startup, DF-014 rejected-init projections and DF-024 MCP
identity/output bounds. Compare CLI/MCP success and failure results against
existing verified-consumer fixtures; test limit boundaries and JSON/usage exits.

### TASK-063: Move doctor and admission policy into the application

Move local doctor configuration/locality/native-account/provider readiness
policy out of handlers. Reuse one application admission sequence where init,
config, doctor and review enforce the same policy. Inject filesystem, config
proof/decoding, account lookup, executable/version observation and locality
capabilities; application code must not import adapters or acquire OS access.

Keep CLI projection in the entrypoint and graph construction in composition.
Preserve missing/unsafe/drifted/unverifiable/ready states, reason codes, exits,
cancellation and revalidation order. Do not merge sequences whose authorization
or failure behavior differ. Prefer a small owned port over moving policy into
ports or inventing a general admission framework.

Verify existing doctor v7 behavior for missing files, unsafe paths/credentials,
unsupported versions, native-home replacement, provider version/readiness and
post-observation drift; assert rejection before any prohibited provider effect.

### TASK-064: Share identical provider protocol mechanics

Characterize and extract small correlation, diagnostic-ID sanitization and
read-plan translation helpers. Leave each family adapter explicit and retain
family-specific prefixes, wire semantics, permission codecs, cancellation,
EOF and natural-exit rules. In particular retain ZCode's accepted post-turn
stream end and AGY's required natural exit.

Select simultaneous tool diagnostics deterministically without changing typed
refusal (DF-007). Derive shared live path admission from TASK-056; do not restore
body reads or skip final validation. Verify native-ID types, late tool updates,
unknown methods, permission denial, correlation and each family's exit path.
Do not add a generic driver/plugin system or a second provider registry.

### TASK-065: Remove proven retired execution and writer paths

Inventory production callers, build tags, interfaces, test generators and
retained reader/recovery/cleanup consumers. Use deadcode/unused output as
candidates, not deletion authority. Start with the DF-025 capture facade and
legacy in-memory review service, preserving helpers the live coordinator uses.

Remove retired capture/replay/child/followup/composite producer halves only when
TASK-060 fixtures and TASK-061 contracts replace their compatibility role.
Keep historical values/readers/validators, fake providers in active tests,
packetless version probes and lifecycle identity fields. A live P2 multi-file
composite commit is not the retired composite-review producer and must remain.
Move remaining fixture-only builders to testsupport only when still necessary.
Verify every supported tagged test set compiles and the complete corpus matrix
and live flow still pass; never delete an assertion solely to make removal pass.

### TASK-066: Enforce ownership and split along proven seams

Add targeted architecture checks for the boundaries actually established by
TASK-061 through TASK-065: entrypoints project requests/results, application
owns policy and has no adapter/OS capability imports, adapters implement inward
ports, and test doubles cannot enter production. Resolve newly introduced
violations before proceeding. Existing unrelated edges need an explicit owner;
no blanket ban on all adapter-to-adapter imports is part of this Epic.

Split remaining changed large files along established responsibilities through
pure moves. Do not combine those moves with new behavior or pursue a file-size
quota. Verify import direction, build tags and the affected behavior after each
move. Do not move code into ports merely to satisfy an import rule.

### TASK-067: Certify integrated ownership and retained compatibility

Run the deterministic gates (`make test-prepare`, `make test-unit`,
`make test-int`, and `make test-release`), `make test-mcp-clients`, and
ZCode-only live verification for the exact integrated candidate. Re-verify old
and new wire bytes, retained read/export/recovery/clean behavior, no source
snapshots, guard denials, failure precedence, no-change and all existing
role/provider assignments. Complete the dependency and caller inventory after
removals. Promote durable ownership and rationale, reconcile only actually
resolved deferred entries, and record non-ZCode live provider gates (`grok`,
`cursor`, `agy`, and `codex`) as explicitly deferred to the `v0.1.26`
five-provider release gate (`release-handler`) before preparing the explicit
Epic acceptance handoff without committing or publishing by implication.

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

### Verification profile

EPIC-014 execution uses the following verification profile. It records
verified project facts for selecting and recording checks. It grants no waiver
and relaxes no gate. Run every completion member as a separate command, never
with `-failfast`, on one frozen candidate. Do not overlap a member with another
`go test` process (DF-028).

```yaml
verification_profile:
  revision: VP-2
  completion_suite:
    prepare: make test-prepare
    unit: make test-unit
    integration: make test-int
    release: make test-release
    mcp_clients: make test-mcp-clients
    tagged_compile:
      - go vet -tags=liveprovider ./...
      - go vet -tags="live_e2e live_grok" ./test/e2e
      - go vet -tags="live_e2e live_cursor" ./test/e2e
      - go vet -tags="live_e2e live_agy" ./test/e2e
      - go vet -tags="live_e2e live_e2e_opt_in" ./test/e2e
      - go vet -tags=releasecheck ./internal/releasecheck
      - go vet -tags=mcpclientcheck ./internal/mcpclientcheck
    e2e_zcode: make test-e2e
  deferred_live_gates: # v0.1.26 five-provider release gate
    - make test-grok
    - make test-cursor
    - make test-agy
    - MULGAE_E2E_OPT_IN=1 make test-e2e-opt-in
  candidate_id: >-
    tree hash through a temporary index outside the worktree
    (git read-tree HEAD; git add -A; git write-tree); fallback is HEAD plus
    the binary patch hash and untracked file hashes
  shared_resources:
    - ZCode app-server and Z.AI quota (one live run at a time)
    - internal/adapters/process boundary tests invoke sandbox-exec and run
      outside agent sandboxes
  uncaptured_inputs:
    - Go toolchain, module cache and golangci-lint through go tool
    - ZCode.app bundle, launcher protocol and the account found by discovery
    - resolved codex and claude client binaries for mcp_clients
    - TMPDIR through the /private/var alias, installed-user and native-home
      identity, effective GOFLAGS and MULGAE_* overrides, host load
  contracts:
    - internal/builtin/assets/** and assets/roles.yaml
    - public JSON, typed failures, reason codes, exit codes and command grammar
    - persisted layout, format versions, digest domains, canonical bytes and
      historical readers, recovery and cleanup
  normative_docs: [docs/specs/**, AGENTS.md, assets/roles.yaml, internal/builtin/assets/**, skills/**]
  calibration: {production_files: 3, production_lines: 50}
  known_limits:
    - non-ZCode live provider behavior is not exercised in this Epic
    - non-ZCode tagged E2E files are compile-checked only
    - timing, benchmark, percentile and memory-peak results are not evidence
```
