# Live review reliability, extraction fidelity, and ZCode efficiency

## Execution authority and lifetime

The sole consumer is Mulgae `EPIC-018`. Its
[roadmap](../roadmap/README.md#epic-018-live-review-reliability-extraction-fidelity-and-zcode-efficiency)
alone owns work identity, order, dependencies, lifecycle, and status. This is
the temporary execution SOT for `EPIC-018`. Read repository guidance (`AGENTS.md`)
and the canonical owners below before planning or implementing any member Task.
Design adoption does not establish implementation, checks, release, or
acceptance.

At final Epic closeout, promote durable behavior, structure, rationale, and
verification guidance to their canonical owners, replace `Detailed SOT` in the
roadmap with `Canonical Outcomes`, and remove this dossier and its entry in
[`docs/todo/README.md`](README.md).

## Origin and operational motivation

Production multi-role live Git (`--stage`) reviews with optional explicit
requirements (`--requirements`) on ZCode exposed compounding reliability,
extraction, diagnostic, and latency failures:

1. **Completed multi-role runs discarded on timeout**: Any role hitting a
   provider timeout (`AttemptConditionProviderTimeout`) ends with
   `AttemptFailed` instead of `AttemptTimedOut` (via `transitionFailedInvocation`)
   while carrying `domain.FailureTimeout`, triggering
   `publication_candidate_invalid` at `PrepareLiveCandidate` and discarding
   every completed sibling role. A second instance of the same invariant
   mismatch occurs when a run deadline expires while a role is in
   `AttemptValidating` with a queued or running extraction trailer
   (`attempt.acceptedOutput != nil`), because `domain.AttemptValidating` forbids
   transitioning to `AttemptTimedOut`, yet `cancelAll` assigns `FailureTimeout`
   and drops the already-accepted primary report.
2. **Untrusted provider JSON and citation errors aborting entire runs in
   requirements mode**: In requirements mode, unexpected JSON keys in the
   requirements section (`requireOnlyKeys` in `provider_requirements.go`)
   escalate to `AttemptConditionSecurityViolation`, and provider-cited absent or
   excluded paths in `liveSourceReader.Read` wrap through
   `requirementsSourceFailure` (both in `DecodeProviderRequirements` and in
   findings verification via `requirementsSourceCondition`) into
   `FailureArtifact` (precedence 5 > bounded extraction ceiling 2) or
   `FailureSecurityPolicy`. Both cancel in-flight sibling roles and block
   publication of already-accepted reports. Furthermore,
   `coordinator_diagnostics.go` maps every `SecurityViolation` to the single
   cause `provider_observation_mismatch`, and `invokeRequirements` omits
   parse/validation diagnostic events across all purposes and skips raw stdout
   capture on fallback and protected extraction paths, creating a diagnostic
   blind spot.
3. **Near-zero structured extraction and requirements evaluation**:
   `internal/builtin/assets/prompts/root-review/extract-provider-review.v1.txt`
   (line 12) instructs the extraction invocation to re-read exact target lines
   through workspace access and explicitly forbids quoting the accepted report,
   while `internal/builtin/assets/prompts/live-review/requirements.v1.txt` (line
   15) tells extraction to confirm cited evidence against the admitted source
   side. Both conflict with tool-free extraction sessions (ZCode
   `toolAllowlist: []`, Cursor, AGY). Meanwhile, a single unverified requirement
   assessment rejects every sibling requirement owned by the same role.
4. **Prompt read-plan bloat**: `ComposeLiveRootReview` serializes the complete
   repository read list across both sides (`LiveSourceReadPlan`, thousands of
   `git --no-pager show` or `native_path` entries on medium repositories) into
   every initial prompt and re-injects that entire payload into `002-extract`
   prompts where it serves no purpose.
5. **ZCode startup and Git-scope execution inefficiencies**: Every ZCode role
   instance currently runs an independent sequential live qualification probe
   even when all capability-relevant runtime fields (including `ZCodeModel`,
   `ZCodeReasoningEffort`, and `ZCodeProviderConfigSHA256`) match, multiplying
   startup latency and safety-filter refusal exposure. Separately, the bare
   `root=<64-hex>` / `link=<64-hex>` qualification fixture wording has triggered
   LLM prompt-injection/credential-exfiltration refusals. During Git-backed live
   reviews (`--stage`, `--head`, `--commit`, `--diff`), ZCode enables `Grep` and
   `Glob` against the empty neutral cwd (`~/.mulgae/home`), inviting repeated
   read-failure loops.
6. **Coordinator wave barrier latency**: `Coordinator.execute` waits for the
   entire initial wave to finish before dispatching `002-extract`, `retry`, or
   `repair` for already-completed roles.

## Canonical owners

| Concern | Owner |
|---|---|
| Public contracts, extraction rules, and qualification scope | [Contracts](../specs/contracts.md) |
| Trust boundaries, ownership violations, and raw redaction | [Security](../specs/security.md) |
| Live source selection and reviewer execution | [Live workspace and Git review](../specs/live-workspace-and-git-review.md) |
| Optional explicit requirements assessment | [Review completeness and iteration](../specs/review-completeness-and-iteration.md) |
| Coordinator scheduling and package boundaries | [Architecture](../architecture/README.md) |
| Offline release invariants and ZCode text retention | [Release design gates](../gating-rules.md) |
| ZCode protocol and tool policy | [ZCode transport ADR](../architecture-decision-records/zcode-app-server-transport.md) |
| Embedded prompt templates and checksums | `internal/builtin/assets/prompts/` and `CHECKSUMS.sha256` |

## Verified design decisions and rejected alternatives

Design choices below were verified against Mulgae's codebase (`HEAD` `97e7697`),
specifications, and independent technical review feedback.

### 1. Timeout publication consistency (`TASK-088`)

- **Provider timeout state transition**: Fix `transitionFailedInvocation` (and
  mirror defensively in `terminalizeAttempt`) in
  `internal/app/review/coordinator.go` via a shared `conditionTimedOut` helper
  so both `AttemptConditionTimeout` and `AttemptConditionProviderTimeout`
  transition to `domain.InvocationTimedOut` / `domain.AttemptTimedOut`, matching
  `publication/model.go` (`prepareRoles`, `validatePreparedFailures`,
  `validateManifestFailures`) and `query/service.go`.
- **Run deadline during `AttemptValidating`**: In `coordinatorExecution.cancelAll`,
  when `attempt.attempt.State() == domain.AttemptValidating`,
  `attempt.acceptedOutput != nil`, and `roleCondition == AttemptConditionTimeout`
  (strictly `Timeout`, never `Cancelled`), preserve the already-accepted report
  whether the extraction invocation is `InvocationQueued` or `InvocationRunning`:
  reuse the `commitExtractionOutcome` non-success completion sequence (transition
  a queued extraction invocation to `InvocationCancelled` or a running one to
  `InvocationTimedOut`, call `terminalizeAttempt(&attempt.attempt, AttemptConditionValidReview)`
  -> `AttemptSucceeded`, transition role to `RoleTaskSucceeded`, set
  `state.output = acceptedOutput`, leave `failureClass`/`reasonCode` empty, and
  record `CoordinatorEventRoleTerminal` with `AttemptConditionValidReview`, empty
  reason, and succeeded attempt status so trace and diagnostics agree with
  publication).
- **Terminal run-state projection (`finishRun`)**: Update `finishRun` so that
  when `stopCondition == AttemptConditionTimeout` and every role ended
  `RoleTaskSucceeded` (whether optional extraction trailers were cut or a
  pre-close deadline fired after all roles already succeeded), the run projects
  `RunCompleted` from role states instead of `RunFailed` with zero failed roles
  (which `validateTerminalRun` rejects as `publication_candidate_invalid`).
  Update `TestCoordinatorRunDeadlineBeforeWorkerCloseForcesFailedRun`
  (`coordinator_test.go`) and document this terminal run-state rule in
  `docs/architecture/README.md`.
- **Expected outcome on partial timeout**: When any selected role itself times
  out (not merely its optional extraction trailer), the run publishes as
  `RunFailed` with `CoverageIncomplete` (`ExitIncompleteCoverage`), retaining
  all completed peer role reports and deriving `answer_omitted` for the
  timed-out role's requirements.
- **Matrix/property and live-service verification**: Test `AttemptTimedOut ==
  (FailureClass == FailureTimeout)` across BOTH assignment paths: all
  `AttemptConditions()` via `commitOutcome` AND `cancelAll ->
  stopCoordinatorAttempt` across `{Running, Validating(extraction
  queued|running), Repairing} x {Timeout, Cancelled}`; assert trace/diagnostic
  consistency (`ValidReview`, empty reason, `AttemptSucceeded`) when the run
  deadline fires during the final role's extraction after all peer roles have
  succeeded; and add one `reviewrun` live-service expired-deadline test verifying
  post-deadline steps (`RequirementsResult`, `DrainCaptures`, `finishCleanup`,
  `PublishLiveNextObserved` in `live_service.go`) still reach publication.

### 2. Requirements key ownership (`2C`), provider citation vs drift (`M1`), and diagnostics (`M2`, `P5`/`M3`) (`TASK-088`)

- *Rejected (extract-only relaxation `2A`)*: Treating identical bytes as a
  security violation on `001-initial` and bounded invalid output on `002-extract`
  violates the `"trailer must not launder"` invariant in `coordinator.go`.
- *Rejected (blanket downgrade of all ownership violations `2B`)*: Erodes
  `docs/specs/security.md` (requirements ownership boundary) and protected
  ownership-injection tests in `provider_requirements_test.go`.
- **Adopted (`2C` — exact closed protected key set)**:
  - Keep `requireOnlyKeys` ownership protection in `repair.go` unchanged.
  - In `internal/app/validation/provider_requirements.go`, classify unknown keys
    by **exact key-name match only** (never prefix/substring heuristics, so
    legitimate provider fields such as `visual.sha256` and `schema_version` are
    never misclassified):
    - **Requirements section**: `owner`, `owner_role`, `origin`, `counts`,
      `selected_count`, `evaluated_count`, `availability`, `input_path`,
      `input_sha256`, `input_digest`, `input_byte_length`, `verification`,
      `publication_status`, `review_id`, `run_id`, `session_id`, `attempt_id`,
      `invocation_id`, `execution_invocation_id`, `source_identity_sha256`,
      `target_sha256`.
    - **Assessment row**: `owner`, `owner_role`, `origin`, `counts`,
      `input_digest`, `input_sha256`, `verification`, `publication_status`,
      `review_id`, `run_id`, `session_id`, `attempt_id`, `invocation_id`,
      `execution_invocation_id`, `source_identity_sha256`, `target_sha256`,
      `content_path`, `content_sha256`, `content_byte_length`.
    - **Evidence wrapper**: `verification`, `owner`, `owner_role`, `origin`,
      `source_identity_sha256`, `target_sha256`, `current_excerpt_sha256`,
      `excerpt_sha256`.
    - **Current evidence object**: `verification`, `source_identity_sha256`,
      `target_sha256`, `current_excerpt_sha256`, `excerpt_sha256`, `owner`,
      `owner_role`, `origin`, `review_id`, `run_id`, `session_id`, `attempt_id`.
    - **Visual evidence object**: `verification`, `owner`, `owner_role`,
      `origin`, `source_identity_sha256`, `target_sha256` (explicitly excluding
      `sha256`, which is provider-supplied and verified against selected images).
  - Scan **every** unexpected key in an object before classifying (avoiding Go
    map iteration-order nondeterminism in `requireOnlyKeys`): if any unexpected
    key belongs to the closed protected set, protected keys always take
    precedence and return `ownershipViolation` ->
    `AttemptConditionSecurityViolation` (with `reject=true` non-serialization
    preserved per `provider_runtime.go`). Only when no unexpected key is
    protected does the object return an ordinary bounded content error
    (`invalid_assessment`, non-security, so raw streams persist normally through
    the secret-scanning diagnostic sink). Cover mixed protected + ordinary
    unknown keys with a deterministic regression test.
- **Adopted (`M1` — typed provider-citation fault vs real source drift across
  Git and `--workspace` scopes)**:
  - Add a distinct typed port error code or marker in `internal/ports/live_source.go`
    and apply one admission-based rule in
    `internal/adapters/gittarget/live_source_darwin.go` (`liveSourceReader.Read`)
    across both Git scopes and `--workspace`:
    - **Bounded provider citation fault**: (a) an invalid or excluded cited path
      before `revalidate`, (b) on Git scopes, a path absent from `entries` for
      the selected side, or (c) on `--workspace`, a path absent from the
      **admission-time** workspace inventory (`reader.target.Changes()` populated
      during `admit` in `live_source_darwin.go` — never by re-running
      `reader.list()`, which skips deleted files and would misclassify an
      admitted-file deletion as un-admitted) whose `readRegular` call fails
      (`ENOENT`, `ELOOP`, `ENOTDIR`, `errLiveDirectory`, or
      `errLiveNotRegular`) — while preserving existing non-excluded ignored
      regular support files when `readRegular` succeeds.
    - **Fail-closed real source drift / tamper**: any path that **was** in the
      admitted inventory for that side and now fails (`ENOENT`, `ELOOP`,
      `ENOTDIR`, directory/type or namespace change), as well as all
      `revalidate`, Git `cat-file`, and closed-reader failures, remain untouched
      as `LiveSourceUnsafe` / `LiveSourceUnavailable`. *(Wrong-side claims are
      already bounded via `DecodeProviderRequirements` / `LiveSourceInvalid`.)*
  - Apply the same rule across both `DecodeProviderRequirements` and findings
    evidence verification in requirements mode (`requirementsSourceCondition` in
    `provider_runtime.go`), and align non-requirements `VerifyCurrent` handling
    so real source/revalidation drift is fail-closed while bad provider
    citations stay bounded in both modes. Because strengthening non-requirements
    drift handling from `InvalidProviderOutput` to fail-closed is an intentional
    behavior change, cover both modes and both Git/`--workspace` scopes with
    regression tests and record it in `CHANGELOG.md` at closeout.
  - Amend `docs/specs/security.md` and
    `docs/specs/review-completeness-and-iteration.md` in `TASK-088` to explicitly
    distinguish bounded untrusted provider-cited path faults from fail-closed
    live-source drift.
  - Isolation granularity boundary: in `TASK-088`, bounded `2C`/`M1` failures in
    requirements remain section-scoped (`invalid_assessment` for that role's
    section); `TASK-089` narrows them to per-requirement isolation.
- **Adopted (`M2` — distinct security diagnostic causes without breaking public
  reason codes)**:
  - Keep public `AttemptConditionSecurityViolation` and public CLI/MCP reason
    codes unchanged (`internal/entrypoint/mulgae/application.go`).
  - Carry the originating `RuntimeDiagnosticCause` via an internal field to
    coordinator diagnostics instead of collapsing every `SecurityViolation` to
    `provider_observation_mismatch` in `coordinator_diagnostics.go`, and document
    any added `RuntimeDiagnosticCause` values in `docs/specs/contracts.md`.
- **Adopted (`P5`/`M3` — complete requirements-mode diagnostics and capture)**:
  - Emit `DiagnosticOutputParseStarted`, `DiagnosticValidationStarted`, and
    `DiagnosticOutputParsed` / `DiagnosticValidationFailed` consistently inside
    `invokeRequirements` across initial, repair, and extraction purposes.
  - Always invoke `runtime.capture` before returning on `InvocationExtract &&
    hasPrior` fallback and protected `acceptExtraction` failures (with
    `reject=true` strictly for genuine security rejections), and preserve
    requirements-bearing candidate bytes consistently with capture rules.

### 3. Extraction prompt alignment and per-item requirements isolation (`TASK-089`)

- **Remove `reads` from `002-extract` (`3B`)**: Add a dedicated extraction
  composition path in `live_prompt_source.go` / `live_template.go` (bumping
  the affected prompt layer version as needed) that omits the repository-wide
  `reads` array and carries only compact target metadata and `candidates`.
- **Single provider-agnostic extraction contract**:
  - Reconcile `extract-provider-review.v1.txt` (lines 12–13),
    `requirements.v1.txt` (lines 13–15), and `reviewer-guide.v1.txt`:
    - Instruct `001-initial` reports to include exact verbatim target excerpts
      with exact `(side, path, line_start..line_end)` and exact line bytes
      (preserving tabs, trailing whitespace, and terminating LF `\n`) for every
      reported finding and every `met`/`partially_met` requirement.
    - Instruct `002-extract` uniformly across all five providers as pure
      transcription from verbatim target excerpts already in `prior_report`
      (removing *"Re-read that exact target range..."*, *"Never quote the
      accepted report itself"*, line 13's *"Omit any claimed defect whose
      location you cannot confirm ... A smaller truthful finding set is
      correct"*, and *"Confirm cited evidence against the admitted source
      side"* so no provider is prompted to re-read without a read plan, open a
      second review pass, or silently drop defects into `findings: []`):
      - **Findings — non-requirements mode (`extract-provider-review.v1.txt`)**:
        if ANY defect claimed in `prior_report` lacks an exact verbatim target
        excerpt in `prior_report`, do **not** omit the finding or return
        `findings: []` (which would falsely turn a claimed defect into
        `no_findings` / `CI pass`); instead return no JSON / refuse
        transcription so findings extraction fails and Mulgae preserves the
        accepted report as `reports_only` (per line 17). Return `findings: []`
        **only** when `prior_report` claims no defect.
      - **Findings — `--requirements` mode (`requirements.v1.txt`, single JSON
        response `mulgae-provider-review-output.v3` split by
        `SplitRequirementsResponse`)**: do **not** return no JSON (which would
        discard the sibling `requirements` section too). Instead emit the valid
        JSON object with the `requirements` section intact and signal
        findings-only transcription refusal via one explicit ordinary
        (non-protected) findings validation failure — specifically **omitting
        the top-level `findings` key**. Because `invokeRequirements` decodes
        and saves `requirements` before findings validation and retains valid
        assessments on ordinary findings failure (`requirements.go`,
        `review-completeness-and-iteration.md`), verified requirement rows are
        preserved while the role stays `reports_only` (never `no_findings` /
        `CI pass`).
      - **Requirements (`requirements.v1.txt` / extraction contract)**: if
        `prior_report` lacks a verbatim target excerpt for a requirement, emit
        `verdict: "unverified"` with `reason: "insufficient_evidence"` (or omit
        that requirement so Mulgae normalizes it to `unverified`, which is never
        a pass).
- **Requirements-only per-item isolation**:
  - Upgrade `DecodeProviderRequirements`, `invokeRequirements`, and
    `NormalizeRequirements` from role/section-scoped reasons to per-requirement
    reasons so an invalid or unverified quote on one requirement downgrades only
    that requirement to `mulgae_derived` (`invalid_assessment`) while preserving
    valid sibling requirements owned by the same role.
  - Keep section-wide rejection for duplicate, foreign, or wrong-owner
    requirement IDs and fail-closed handling for real source/protected errors.
  - Define the bidirectional `initial -> extract` per-requirement merge rule and
    its scheduling trigger (`assessmentPending` in `internal/app/review/requirements.go`,
    which currently triggers only when `!state.present`): explicitly decide and
    test whether partial-invalid inline sections resolve directly via per-item
    isolation or schedule follow-up extraction, and when both phases produce
    rows enforce that a later valid verified row may replace an earlier
    invalid/unverified row while a later failed/invalid row never erases an
    already-verified assessment accepted in `001-initial`.
  - Amend `docs/specs/review-completeness-and-iteration.md` (section validation
    rules) and `docs/specs/security.md` ("Ordinary content failure in one
    section...") in `TASK-089`.
- *Rejected (findings per-item isolation)*: Explicitly excluded. Dropping an
  unverified high-severity finding while accepting zero remaining findings would
  turn an honest `reports_only` outcome into a false `no_findings` / `CI pass`
  (`docs/specs/contracts.md`, `domain/outcome.go`).
- *Hypothesis boundary*: Removing ~655 KB of unused read-plan JSON from
  `002-extract` eliminates confirmed prompt bloat and context pressure; the
  observed empty-text `provider_output_missing` (`finish: "stop"` after
  reasoning) remains a separate hypothesis to re-measure after `TASK-089`.

### 4. Lossless `001-initial` read-plan compaction (`TASK-090`)

- *Rejected (naive template-only replacement)*: Cursor enforces exact string
  equality via `liveReadPlanGitCommands` (`cursor_live_review.go`,
  `cursor_acp_protocol.go`) and AGY enforces exact string equality against its
  guarded command set (`agy_profile.go`, `agy_protocol.go`). Reconstructing
  single-quote escaping, spaces, non-ASCII characters, or JSON HTML-escaped
  characters (`&`, `<`, `>`) from a naive template causes
  `provider_permission_denied`.
- **Adopted (`3A'` lossless compaction)**:
  - Keep full in-memory `execution.Reads()` completely unchanged across all
    five adapters.
  - Bump `review:live-read-plan` trusted layer version from `"1"` to `"2"` in
    `internal/app/review/live_template.go` and disable JSON HTML escaping
    (`SetEscapeHTML(false)`).
  - Derive explicit candidate read commands strictly from the subset of
    `execution.Reads()` whose `(side, path)` matches `target.Changes()` (never
    synthesizing from `Changes()`, because added/deleted files exist on only one
    side).
  - Compact supporting unchanged paths using a strict **positive allowlist**
    (e.g., `^[A-Za-z0-9._/-]+$` with no leading `-` or `..` segments) into
    side-scoped path lists paired with one exact per-side command/path template;
    emit explicit commands for every path outside that positive allowlist. Never
    introduce a byte or item ceiling (`docs/specs/contracts.md`,
    `docs/specs/security.md`).
  - Update `internal/builtin/assets/prompts/live-review/common.v1.txt` (line 6)
    and `internal/adapters/providercli/agy_profile.go` (prompt guidance for
    guard-prefixed templated commands and fixing the `native_git_command` ->
    `git_command` field drift), and run both asset generators twice.
  - Live proof boundary: offline round-trip tests cannot prove real Cursor and
    AGY models expand templated commands without `provider_permission_denied`;
    `TASK-090` requires `make test-cursor` and `make test-agy` before claiming
    completion. This intentionally departs from `EPIC-014`'s quota-deferral
    precedent and therefore requires Master's explicit live-gate authorization
    prior to execution.

### 5. Same-profile ZCode qualification sharing and Git-scope tool hygiene (`TASK-091`)

- **Adopt same-profile ZCode qualification sharing**:
  - Update `familyRuntimeProfileKeyFor` (`internal/app/reviewrun/family_qualification.go`)
    to stop appending `definition.Instance()` for `FamilyZCode` (leaving
    `FamilyAgy` per-instance). Every ZCode capability-relevant field
    (`ZCodeModel`, `ZCodeReasoningEffort`, `ZCodeProviderConfig`,
    `ZCodeProviderConfigSHA256`, `ApplicationVersion`, `ApplicationMetadataSHA256`,
    `Executable`, `Launcher`, `RuntimeSafetyPolicyIdentity`) remains in the
    share key.
  - Preserve `docs/specs/contracts.md`'s rule that application-layer identity
    rewriting cannot copy authority: sibling ZCode routes derive authority
    strictly through `DeriveEquivalentRouteDirectExecutionAuthority`. Keep
    `TestRemapCurrentQualificationResultRejectsAuthorityBleedAcrossInstances`
    unchanged and rewrite
    `TestGroupCandidatesByFamilyRuntimeProfileKeepsZCodeNamespacesDistinct`,
    `TestFamilyQualificationProbesEachZCodeNamespace`,
    `TestFamilyQualificationRetainsRetryMitigatedRejectionOnSuccess`, and
    `family_qualification_batches_test.go`.
  - Amend `docs/specs/contracts.md` (ZCode qualification paragraph),
    `docs/architecture/README.md` (qualification batching paragraph, leaving
    per-instance namespace generation intact), and `family_qualification.go`
    comments.
  - Explicitly accept two trade-offs (and record `Rejected:` / `Directive:` Lore
    trailers on the commit): (a) a broken sibling namespace's `account.revision`
    (which hashes the per-namespace builtin catalog path in `zcode_account.go`),
    `setModel`, or `setThoughtLevel` surfaces at role execution as a typed
    configuration failure with zero publication authority (covered by a new
    negative test) rather than pre-run qualification; and (b)
    `ProductionProviderProvenance` retains its existing derived-route schema
    (matching Grok, Codex, and Cursor without a breaking schema change).
- **ZCode Git-scope `toolAllowlist`**:
  - Wire `domain.LiveSourceScope` into `zcodeProtocolSession` via
    `protocol_dispatch.go`, drop `Grep` and `Glob` from `toolAllowlist` on Git
    scopes (`stage`, `head`, `commit`, `diff`) while keeping `Bash` + `Read`
    (needed for ZCode Bash spilled stdout logs under `/tmp/mulgae-zcode`), and
    update `reviewer-guide.v1.txt`, `zcode_live_protocol_test.go`,
    `test/e2e/cli_integration_test.go`, and
    `docs/architecture-decision-records/zcode-app-server-transport.md`.

### 6. Shared readiness fixture wording (`TASK-092`)

- Separated from `TASK-091` because `internal/adapters/providercli/fixture.go`
  is shared by all five providers and `mulgae heartbeat`
  (`internal/composition/heartbeat.go`).
- Bump `current-qualification-fixture-v3` to `v4`. Retain the first line
  `"Prove readiness by returning exactly one JSON object and nothing else."`
  unchanged (preserving existing first-line E2E fake matchers) and append one
  neutral line stating that `root`, `link`, and `role` are random synthetic test
  identifiers with no secret meaning, avoiding trigger words (`credential`,
  `token`, `forward`, `verify identity`).
- Update `fixture_test.go`, `qualifier_test.go`, heartbeat tests, and affected
  protocol/qualification tests (`cursor_acp_protocol_test.go`,
  `cursor_acp_negative_test.go`, `qualification_concurrency_test.go`,
  `qualifier_fallback_characterization_test.go`).
- Run live ZCode verification (`make test-e2e`); either run live capability
  probes for Grok, Codex, Cursor, and AGY or record their deferral to the
  release gate explicitly per `EPIC-014` quota policy without claiming
  unexercised live proof.

### 7. Coordinator batched event loop (`TASK-093`)

- *Rejected (per-role goroutines)*: `coordinatorExecution` mutates unlocked
  state (`trace`, `nextEvent`, `nextJob`, `issuer`, `terminalRoles`, diagnostic
  I/O).
- **Adopted (single-goroutine batched FIFO event loop)**:
  - Keep `PrepareInitial`, role-path/run-deadline derivation
    (`docs/architecture/README.md`), and `run_max_invocations` enforcement plus
    `invocationScheduler` `jobs`/`results` channel capacity
    (`invocation_scheduler.go`) intact.
  - Wait for one completion from `invocationScheduler`, drain any already-ready
    completions into a batch, commit that batch, and immediately admit follow-up
    jobs (`002-extract`, `retry`, `repair`) in FIFO order (recording
    `InvocationDispatched` before releasing each follow-up gate).
  - Replace wave-scoped expected ordinal maps with a global outstanding-ordinal
    set.
  - Preserve stop semantics: bounded trailers never trigger run stops; on the
    first unbounded stop (or deadline/cancellation while waiting), invoke
    `persistInitiatingFailure` and `cancelDispatch`, drain all remaining
    in-flight results, run one final commit, and call `cancelAll` without
    emitting duplicate `CancellationRequested` events.
  - Update `docs/architecture/README.md` (wave barrier and trace-determinism
    contract: per-role trace ordering with strictly deterministic `summaries`,
    `findings`, `outcomes`, and `runState`). Keep
    `TestCoordinatorWaveBarrierPrecedesEveryRuntimeStart` unchanged (it guards
    the retained initial shared gate), and rewrite/invert
    `TestCoordinatorRepairStartsOnlyAfterInitialWaveCompletes` plus
    trace-identity assertions in `coordinator_test.go`. Touch specs only where
    wave behavior is actually referenced.

## Explicitly out of scope (held or separate tracks)

- **ZCode outer Seatbelt hardening (`DF-030`)**: Remains a separate security
  track in [`docs/deferred-feedback/README.md`](../deferred-feedback/README.md).
- **ZCode `001-initial` intermediate tool-call narration filtering**: Commit
  `dd91e69` deliberately preserves complete assistant text for review and
  qualification (`docs/gating-rules.md`,
  `TestZCodeNonExtractionPreservesToolCallNarration`). Held outside `EPIC-018`
  unless Master explicitly approves a separate contract change.
- **Per-item isolation for structured findings**: Excluded to prevent false
  `no_findings` / `CI pass` outcomes when an unverified high-severity finding is
  dropped (`docs/specs/contracts.md`).
- **Config v5 and public JSON Schema breaking changes**: Out of scope.

## Member delivery contracts

Membership and sequential execution order are owned exclusively by
[`docs/roadmap/README.md`](../roadmap/README.md#epic-018-live-review-reliability-extraction-fidelity-and-zcode-efficiency).

| Task | Required outcome | Verification and handoff |
|---|---|---|
| `TASK-088` | Fix `AttemptConditionProviderTimeout` -> `AttemptTimedOut` in `transitionFailedInvocation` (and defensively in `terminalizeAttempt`); fix `AttemptValidating` (`attempt.acceptedOutput != nil`, queued or running extraction) + `AttemptConditionTimeout` in `cancelAll` (recording `ValidReview`/empty reason/`AttemptSucceeded`) and unconditional role-derived `RunCompleted` projection in `finishRun` when all roles succeeded on timeout (updating `TestCoordinatorRunDeadlineBeforeWorkerCloseForcesFailedRun` and `docs/architecture/README.md`); implement `2C` exact-match closed Mulgae-owned key set with full-key protected-precedence scan in `provider_requirements.go` (keeping `repair.go` protected) and `M1` admission-based typed citation-fault split in `ports/live_source.go` / `live_source_darwin.go` across both Git and `--workspace` scopes and both requirements and findings verification (preserving real drift fail-closed in both modes, amending `security.md` and `review-completeness-and-iteration.md`, and noting non-requirements drift strengthening for `CHANGELOG.md`); preserve internal security cause to diagnostics (`M2`, updating `contracts.md` for any new causes) and emit complete `invokeRequirements` parse/validation diagnostics and raw capture (`P5`/`M3`). | End-to-end offline `Coordinator.ExecuteRun` -> `PrepareLiveCandidate` -> `WithRequirements` -> `PublishLiveNext` tests for required/non-required provider timeouts and deadline-during-last-role-extraction (including preserved-role trace/diagnostics checks), plus one `reviewrun` live-service expired-deadline test; dual-path property/matrix test (`commitOutcome` over all `AttemptConditions()` AND `cancelAll -> stopCoordinatorAttempt` over `{Running, Validating(queued\|running), Repairing} x {Timeout, Cancelled}`) proving `AttemptTimedOut == (FailureClass == FailureTimeout)`; `2C` mixed-key precedence and `M1` Git + `--workspace` (requirements + non-requirements) bounded-citation vs admitted-path drift tests; requirements diagnostics and raw-capture regressions; `-race`. |
| `TASK-089` | Remove repository-wide `reads` from `002-extract` prompts (`3B`, bumping layer version where changed); unify `extract-provider-review.v1.txt` (removing lines 12–13), `requirements.v1.txt`, and `reviewer-guide.v1.txt` so `001-initial` emits exact verbatim target excerpts (with exact line bytes and terminating LF) and `002-extract` is pure transcription from `prior_report` across all providers — in non-requirements mode refusing transcription (no JSON -> `reports_only`) if any claimed defect lacks a verbatim excerpt, and in `--requirements` mode emitting the JSON object with the `requirements` section intact while omitting the top-level `findings` key so verified requirements are retained and findings stay `reports_only` (never false `findings: []`), while ungrounded requirements emit `unverified` (`insufficient_evidence`); implement per-item requirement isolation, `assessmentPending` trigger handling, and bidirectional `initial -> extract` per-item merge in `DecodeProviderRequirements`, `invokeRequirements`, and `NormalizeRequirements` (keeping duplicate/foreign/wrong-owner IDs, real source drift, and findings all-or-nothing fail-closed); amend `review-completeness-and-iteration.md` and `security.md`; run both asset generators twice idempotently. | Extraction prompt size/content regressions (`002-extract` carries no repository read list); quote-fidelity tests covering tabs, CRLF, trailing whitespace, and terminating LF; regressions verifying a claimed high finding without verbatim excerpt stays `reports_only` (never false `no_findings` / `CI pass`) in non-requirements mode AND retains verified requirement rows while keeping role `reports_only` in `--requirements` mode (top-level `findings` key omitted); per-item requirements partial-isolation, bidirectional merge, duplicate/foreign, and source-drift tests; unchanged findings all-or-nothing contract tests; double `./dev go generate ./internal/app/init && ./dev go generate ./internal/builtin` with zero second-pass diff. |
| `TASK-090` | Implement lossless `3A'` `001-initial` read-plan compaction (`review:live-read-plan` v2, HTML escaping disabled, no size/count cap): explicit `candidates` from `execution.Reads()` matching `target.Changes()`, side-scoped supporting path lists + template for positive-allowlist paths (`^[A-Za-z0-9._/-]+$`), explicit commands for all other paths, keeping in-memory `execution.Reads()` unchanged across all adapters; update `common.v1.txt:6` and `agy_profile.go` (templated guard-prefix instructions + `native_git_command` -> `git_command` fix); regenerate assets twice idempotently. | Lossless round-trip parity tests (single quotes, spaces, `&<>`, Unicode, added/deleted single-side candidates) against Cursor `liveReadPlanGitCommands` and AGY guarded command sets; updated `live_execution_darwin_test.go` and `live_prompt_source_test.go`; double generator idempotence; live `make test-cursor` and `make test-agy` (intentional departure from `EPIC-014` quota deferral; requires Master's live-gate authorization) proving models accurately expand templated commands without `provider_permission_denied`. |
| `TASK-091` | Enable same-profile ZCode qualification sharing in `family_qualification.go` (keeping `FamilyAgy` per-instance and routing authority strictly through `DeriveEquivalentRouteDirectExecutionAuthority`), amending `docs/specs/contracts.md` and `docs/architecture/README.md` and accepting the `ProductionProviderProvenance` trade-off with Lore `Rejected:`/`Directive:` trailers; wire `LiveSourceScope` into `zcodeProtocolSession` to drop `Grep`/`Glob` on Git scopes while keeping `Bash` + `Read` (for spilled Bash output logs) and updating `reviewer-guide.v1.txt` and `zcode-app-server-transport.md`. | Rewritten `TestGroupCandidatesByFamilyRuntimeProfileKeepsZCodeNamespacesDistinct`, `TestFamilyQualificationProbesEachZCodeNamespace`, `TestFamilyQualificationRetainsRetryMitigatedRejectionOnSuccess`, and `family_qualification_batches_test.go` with `TestRemapCurrentQualificationResultRejectsAuthorityBleedAcrossInstances` unchanged; ZCode->ZCode derivation positive/negative tests plus sibling execution-time `account.revision`/`setModel`/`setThoughtLevel` typed failure test with zero publication authority; ZCode Git-scope `toolAllowlist` regressions; double generator idempotence. |
| `TASK-092` | Update `internal/adapters/providercli/fixture.go` to `current-qualification-fixture-v4`, keeping the first line intact and adding one neutral synthetic-test-identifier sentence preserving exact `{"root","link","role"}` JSON and nonce/link verification across all five providers and `mulgae heartbeat`; update `fixture_test.go`, `qualifier_test.go`, heartbeat tests, and affected protocol/qualification tests. | Deterministic fixture, qualifier, heartbeat, and five-provider protocol/E2E fake tests; live ZCode capability probe (`make test-e2e`), with non-ZCode live probes either executed or explicitly deferred to the release gate per `EPIC-014` quota policy. |
| `TASK-093` | Replace `Coordinator.execute`'s wave barrier with a single-goroutine batched FIFO event loop preserving `PrepareInitial`, role-path/run-deadline derivation, `run_max_invocations` enforcement and scheduler `jobs`/`results` channel capacity, `InvocationDispatched` ordering, global outstanding-ordinal validation, and stop-condition drain barriers; update `docs/architecture/README.md` and `coordinator_test.go` (keeping `TestCoordinatorWaveBarrierPrecedesEveryRuntimeStart` unchanged, rewriting `TestCoordinatorRepairStartsOnlyAfterInitialWaveCompletes`, and updating per-role trace determinism); certify the integrated Epic candidate. | `-race` coordinator concurrency, per-role trace determinism, cancellation/deadline drain, and overlapped-extraction tests; full `make test-offline`, `make test-release`, and live ZCode certification (`make test-e2e` plus multi-role `--stage` + `--requirements` review on a satisfiable fixture confirming 1 shared qualification probe, compact prompts, and at least one verified-evidence `met`/`partially_met`/`unmet` provider verdict). |

## Effect and release boundaries

Implementation approval does not authorize staging, commits, pushes, tags,
installation, release publication, host credential/configuration changes, or
unapproved live-provider campaigns outside the scoped verification gates.
Retire this dossier only after durable promotion and explicit Master Epic
acceptance.
