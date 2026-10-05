# Deferred feedback

This index owns small actionable findings intentionally postponed from current
work.

- `DF-002` Live review runs intermittently lost every role to an unconditioned
  `internal_invariant` after invocation preparation and before process spawn.
  Spawn-path revalidation refusals are now typed: a proven environment change
  (`ports.ErrProviderSpawnEnvironmentDrift`: executable identity mismatch,
  locality drift) keeps the deterministic `provider_spawn_failed`
  classification, while an inability to establish the environment right now
  classifies as retryable `provider_unavailable` instead of destroying the
  run. Residual: the exact transient trigger (for example a subprocess or
  descriptor failure under concurrent spawn load) is still not captured as
  diagnostic text. Re-entry: when a run retries or fails through
  `provider_execution_failed` at the spawn boundary, capture the bounded
  underlying error in runtime diagnostics before considering further
  hardening.
- `DF-003` Verified reads of v2 reviews and composites reload and verify all
  captured or copied support artifacts; inspection can repeat the full pass.
  Large runs may increase memory use and read latency, especially across
  report chunks. Re-entry: measure an unacceptable memory peak or read delay
  on a large committed run, then reduce repeated loading while preserving
  support integrity checks.

- `DF-004` ZCode's admitted short native socket directory is shared by guarded
  sessions. The guard isolates each invocation's credentials and scratch, but
  its fixed runtime-directory exception permits one guarded session to alter
  another session's temporary entries or connect to its socket there. Random
  socket names avoid accidental collisions; they do not provide kernel
  isolation between sessions. This is a bounded residual of the approved
  native-IPC exception, rather than a promise of general process or IPC
  containment. Re-entry: a demonstrated interference failure, or a supported
  short per-invocation native temp path, warrants a separately approved
  runtime-directory change with real concurrent-provider certification.

- `DF-005` Optional run-authority observations: closed production adapters
  currently implement the observation capability. A future injected factory
  could omit it, and optional interfaces can shadow each other. Re-entry:
  before adding a factory or changing authority capability composition,
  assert observations are retained and incompatible combinations fail before
  invocation.

- `DF-006` Tool-observation memory: live review validation retains provider-
  chosen operation identities and variants. No problematic memory peak was
  reproduced. Re-entry: a measured peak from a large tool stream warrants
  reducing retained bookkeeping while preserving correlation and the no-
  content-byte-ceiling policy.

- `DF-007` Diagnostic order: simultaneous read-plan violations can yield a
  different first human diagnostic because observations use map iteration.
  Typed outcome and refusal are unchanged. Re-entry: a reproduced triage
  ambiguity warrants a deterministic diagnostic selection assertion.

- `DF-008` Compound qualification failures: an operational
  persistence/artifact failure may lose a secondary qualification cause. A
  simple error join changes terminal or public precedence. Re-entry:
  implement cause retention only with direct terminal, public class and
  original-cause assertions that preserve the current fail-closed precedence.

- `DF-009` Native status diagnostics: unsupported or incomplete native tool
  status correctly rejects a live role report. Re-entry: an observed native
  status that operators cannot distinguish warrants bounded status diagnostic
  tests and an explicitly verified provider-wire interpretation.

- `DF-010` Inspection defensive tests: direct assertions remain useful for
  malformed internal page projections, receipt suppression, paged fallback
  and publication re-observation. Current verified query and publication
  guards reject corrupted state. Re-entry: before changing projection, paging
  or diagnostic recheck code, add negative fake-reader and interleaving
  assertions for those guards. Include malformed expected-digest CLI flags;
  keep the existing shared digest parser and MCP guard as the current
  admission authority.

- `DF-011` Live source defensive tests: direct cases remain useful for non-
  branch HEAD, unsafe per-worktree config, post-open root/admission changes
  and replacement during a read. Descriptor checks and canonical-file guards
  already reject unsafe state; no accepted wrong bytes were demonstrated. Re-
  entry: before changing the owning reader or admission guard, add
  deterministic rejection cases; any production synchronization seam needs
  its own bounded scope. Cover an ignore-matched symlink present before non-
  Git admission and a synchronized successful read round before racing Close.

- `DF-012` MCP startup configuration: production composition supplies all
  tool fields and startup rejects incomplete configuration. Re-entry: before
  adding another composition caller, cover each partial configuration and
  prove no service starts.

- `DF-013` Provider JSON surrogate tests: the lone-low-surrogate rejection
  branch lacks a direct case; strict JSON parsing rejects malformed escapes
  and the scanner rejects unmatched surrogates. Re-entry: before changing
  semantic JSON parsing, add lone-low and paired-surrogate cases without
  accepting replacement bytes.

- `DF-014` Rejected init result tests: unchanged CLI routing and renderer
  preserve the compatible JSON envelope, but direct rejected-init flag
  combinations remain useful. Re-entry: before changing init grammar or
  result projection, assert invalid flags, duplicate JSON flags, mixed and
  human output modes produce their documented envelope and exit code.

- `DF-015` Source-read allocation: live file reads can retain large source
  bodies without a product byte ceiling. No out-of-memory failure was
  reproduced. Re-entry: measured unacceptable peak memory warrants streaming
  or spooling with complete content and existing file-identity checks
  preserved.

- `DF-016` ZCode fallback credential format: absent an environment secret,
  the current local fallback key is predictable. Native credential access
  requires accepted file ownership and mode 0600. External desktop-format
  behavior remains unverified. Re-entry: a verified provider-format change or
  new confidentiality requirement warrants an explicitly authorized
  credential-format investigation; do not migrate credentials from this
  report alone.

- `DF-017` Codex permission boundary: native Codex permission enforcement is
  the adopted design; Mulgae's outer filesystem guard applies to ZCode and
  Grok. Re-entry: a demonstrated native mutation-permission failure, or a
  newly supported outer guard integration, warrants a separately authorized
  boundary design and real provider certification. No bypass was demonstrated
  in the current receipts.

- `DF-018` Native notification operands: complete operations are checked
  after fragments merge under one tool identity. No malformed admitted
  operand was demonstrated. Re-entry: when a verified provider wire change
  introduces fragment assembly, assert split string operands and reject
  ambiguous assembly before changing admission.

- `DF-019` Grok variant fields: live ReadFile uses target_file and rejects
  the obsolete file_path representation. Legacy staged Write has a separate
  wire contract. Re-entry: before changing a variant or invocation purpose,
  assert its own input field and retain the existing rejection controls.

- `DF-020` Qualification guard tests: the production loop checks each
  successful observation; direct cases for multiple observations and
  duplicated malformed payloads would strengthen regression detection. Re-
  entry: before changing qualification aggregation or guard ownership, assert
  both first and later invalid observations fail closed.

- `DF-021` Native tool lifecycle tests: current terminal gates reject
  incomplete tools. Direct cases for a statusless update after terminal
  completion and multiple pending candidates would strengthen regression
  coverage. Re-entry: before changing stream state or event-loop
  coordination, assert terminal reopening cannot retain report acceptance and
  every candidate remains correlated.

- `DF-022` Historical v1 captured archive: ports tests cover the legacy
  codec, while ReadRuntimeTarget preserves the original archive bytes after
  target binding. Its query-service v1 branch lacks a direct fixture. Re-
  entry: before changing the retained support reader, verify exact v1 bytes
  and the wrong-binding, missing and tampered archive cases alongside v2
  controls.

- `DF-023` Live admission and artist brief tests: canonical root mismatch is
  rejected before admission, and a binary artist brief is rejected before
  provider task assignment. Direct negative fixtures remain useful. Re-entry:
  before changing either guard, assert a mismatched source root fails with no
  qualification or publication, and PNG, JPEG and WebP brief bodies fail as
  non-text while ordinary text briefs retain their current behavior.

- `DF-024` MCP defensive tests: request-ID allocation failure, malformed
  invocation IDs and oversized tool results already fail before the affected
  backend or transport operation. Direct negative assertions remain useful.
  Re-entry: before changing identity allocation, lifecycle admission or result
  rendering, cover failed and malformed request IDs with zero backend calls,
  malformed await/cancel IDs with no execution or cancellation, and both tool
  output limits with under/over-boundary controls. Assert the SDK and public
  error contracts actually reached by each case.

Promote an epic-sized finding to a TODO candidate or an adopted roadmap work
unit. Do not use this index as a second roadmap or status authority.
