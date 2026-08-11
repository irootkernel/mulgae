# Mulgae Independent Execution Migration — Sequential Goal Plan

## Execution Principles

- Keep exactly one Goal active at a time.
- Close each executable Goal only after implementation, focused tests, every
  non-live gate, a complete diff review, a task-scoped commit, and a
  clean-worktree check. Documentation-only remediation Goals use their stated
  verification instead.
- The common Goal gate is `gaori run prepare`, `gaori run unit`,
  `gaori run integration`, `gaori run release`, and the tagged compile checks
  `go test -run '^$' -count=1 -tags=live_e2e ./test/e2e` and
  `go test -run '^$' -count=1 -tags=liveprovider ./internal/adapters/providercli`.
  No non-live gate compiles those live-tagged test files, and they reference
  symbols this plan deletes or renames.
- Defer `test-e2e` and mandatory live ZCode/AGY verification until every
  implementation Goal has been committed.
- Record the actual `Tested:` evidence and these `Not-tested:` entries in each
  executable Goal's Lore commit trailers: `Mandatory live ZCode/AGY E2E
  deferred to final gate`, and `Live concurrent same-instance execution
  (including AGY's shared real HOME) is not covered by any gate`.
- Do not commit a failed Goal or advance to the next Goal.

## Goal 1 — MCRL-001: Remove the User-Global Cross-Process Lock

- Remove `internal/adapters/lanelock`, production lock-root creation, and its
  composition wiring.
- Stop injecting a filesystem locker into the production coordinator.
- Add integration tests that use a deterministic barrier to overlap two CLI
  processes using the same provider-role, both across separate projects and
  inside the same project.
- Build the barrier machinery this requires: a two-process environment helper
  that shares one `TMPDIR` and `HOME` (the existing helpers assign each call
  separate directories, so two processes would never contend), and a
  pre-output file-marker hold/release in the fake provider CLI generators,
  following the ready/release pattern in the process runner test helper.
- Prove that the second provider starts while the first is still waiting, that
  two runs in the same project finish with distinct identities and valid
  publication, and that no global lock namespace is created. Assert the
  waiting run's exit code and typed reason under publication contention, and
  record in the commit body that same-project publication safety rests on the
  publication store's own lock.
- Update `docs/architecture.md` (the concurrency-key "cannot race" sentence)
  and `internal/builtin/assets/help/providers.md` (the shared-instance
  serialization sentence) to describe independent execution, state that
  cross-process provider load is the operator's responsibility, and regenerate
  the embedded-asset checksums.
- Record in the commit body that pre-existing lock residue under `$TMPDIR`
  (guard files are never unlinked by the removed code) requires manual cleanup
  with `chflags nouchg` plus removal; add no product cleanup code.
- Retain process-local keyed serialization and the v1 contract during this
  Goal.

Commit summary:

`Let concurrent CLI runs avoid user-global provider locks`

## Goal 2 — MCRL-002: Remove In-Process Provider Serialization

- Remove the coordinator's process-global keyed authority.
- Remove the provider registry's per-key semaphore.
- Replace run-local per-key worker queues with independent job workers.
- Remove `LaneLocker`, `LaneLease`, the lock-acquisition failure taxonomy, and
  the coordinator dependency on those types.
- Preserve the process-local `max_active_lanes` capacity bound.
- Preserve initial-to-repair ordering through the coordinator wave barrier
  that creates a repair job only inside outcome commitment, after the initial
  result has been collected; the attempt and invocation state machines remain
  supporting checks.
- Delete the legacy fixed-key assignment path (`NewAssignment`, the `legacy`
  concurrency key, and its service invariant); it has no non-test callers, and
  its whole-run serialization contract disappears with this Goal.
- Remove the process-termination lock failure classes and their registry
  consumers together with the coordinator's lane-acquisition condition
  mapping.
- Update `docs/architecture.md` ("serialized lanes") and `docs/security.md`
  ("per-instance serialization") to describe independent execution.
- Add regression tests proving that two independent coordinators and registries
  can invoke the same provider instance concurrently within capacity. Prove
  that a same-registry, same-instance overlap is rejected immediately as an
  internal configuration invariant, never as a provider timeout or rate limit.
  Pin the construction-time duplicate-instance guard, the capacity authority's
  minimum-across-registered-runs semantics, and the wave barrier that starts a
  repair only after its initial invocation completes.
- Retain `ConcurrencyKey` only as a non-execution identity required by the v1
  budget contract until the next Goal.

Commit summary:

`Make provider invocations independent within each process`

## Goal 3 — MCRL-003: Adopt Role-Path Budgets and the v2 Machine Contract

- Change budget calculation from keyed lanes to one initial-to-repair path per
  role.
- Define `budget.role_paths[]` with the following fields:
  - `role`
  - `provider_instance`
  - `invocation_count`
  - `transition_count`
  - `invocation_timeouts`
  - `deadline`
- Rename the `lane_deadline` ceiling field and the `lane_deadline_limit`
  budget reason code (a reason string, not a schema field) to
  `role_path_deadline` and `role_path_deadline_limit`.
- Rename the remaining lane vocabulary completely, with no backward
  compatibility: the diagnostics projection fields `lane_total`,
  `lane_completed`, and `lane_failed`; the `lanes` help topic and its help
  asset title; and the persisted diagnostic event codes and status keys
  (`lane_scheduled`, `lane_started`, `lane_completed`, `lane_cancelled`). Use
  role-path naming everywhere and document the intentional clean break:
  diagnostics recorded by earlier releases become unreadable to the new
  reader.
- Preserve the capacity-aware run-deadline formula and the pre-runtime check
  that requires enough remaining budget for a complete provider timeout
  window. Retain `max_active_lanes` as the v1 configuration key and explicit
  process-capacity bound; role-path naming applies to the independently
  versioned machine result and preflight contracts, not configuration.
- Give `budget.role_paths[]` bounds from the real maxima: at most seven
  entries with unique roles, `invocation_count` at most 2, and
  `transition_count` at most 1. Do not inherit the lane bounds.
- Prove that budget values are unchanged against v1 for an identical
  configuration, modulo the renames.
- Delete only the `mulgae-command-result.v1` and
  `mulgae-review-preflight.v1` schema/example pairs and replace them with v2
  pairs. Preserve all other independent v1 contracts.
- Emit only v2 for the current JSON envelope and review preflight. Do not add a
  v1 output option.
- Align the CLI registry, schema catalog, examples, automation help, and
  contract generator with v2, including the generator's hard-coded schema
  filenames, the hand-maintained file-catalog example pair authority, the
  schema README table, `docs/contracts.md`, and the live E2E schema URI.
- Run both generators twice and prove that the second run leaves no diff.

Commit summary:

`Publish role-path budgets as the v2 machine contract`

## Goal 4 — MCRL-004: Simplify Application Routes to Provider Identity

- Change `ProviderRoute` so it contains only `provider_instance`.
- Remove concurrency-key comparisons from assignments, planning, coordination,
  child runs, reruns, and budget consistency checks.
- Remove lane identity from coordinator traces and rely on attempt, role, and
  provider identity. Remove the lane field and its validation without adding a
  replacement trace field: the configured role already identifies its provider
  instance one-to-one.
- Continue deriving the same production provider instance from provider family
  and role.
- Verify that route copying, sorting, duplicate detection, and every child
  workflow preserve provider identity.

Commit summary:

`Bind review routes only to provider instances`

## Goal 5 — MCRL-005: Remove Remaining Keys from Provider and Process Layers

- Delete the `ConcurrencyKey` type completely.
- Remove key fields and constructor arguments from `ProcessRequest`, provider
  process requests, runtime specifications and definitions, qualification, and
  production candidate templates.
- Construct Kimi login and ZCode/AGY/Kimi provider requests without a separate
  execution key. Remove the fixed `provider` and `kimi-login` keys; the
  process adapter never read the request key, and Kimi login already ran
  outside every lane, so name Kimi login explicitly under `Not-tested:`.
- Limit registry responsibilities to unique namespaces, attempt identities,
  staging destinations, and active-call draining.
- Use `rg` to prove that neither `ConcurrencyKey` nor `concurrency_key` remains
  in production code. Use a scoped lane-vocabulary scan whose allowlist is the
  retained `max_active_lanes` capacity surface, literals that reject legacy
  diagnostics, regression coverage for old `.mulgae-lane-*.guard` residue, and
  unrelated dependency vocabulary such as `control-plane`.
- Run regression tests for provider request validation, workspace
  revalidation, staging cleanup, timeouts, and terminal draining.

Commit summary:

`Remove inert execution keys from provider adapters`

## Post-Review Remediation Goals

### Goal 6 — MCRL-006: Type Impossible Provider Overlap

- Classify a same-registry, same-instance overlap as a zero-wait internal
  invariant failure before the provider timeout window begins.
- Keep independent runs concurrent by proving that legitimate runs own distinct
  registries and namespaces.
- Never report the invariant as a provider timeout, rate limit, or provider
  diagnostic cause.

Commit: `61a2b0b9a5c0a770806378152856b6bdcf5c3a73`

### Goal 7 — MCRL-007: Keep Publication Locking Project-Local

- Remove the process-global publication mutex.
- Keep the existing context-aware on-disk flock as the same-project and
  cross-process serialization authority.
- Prove that different roots publish concurrently and that a same-root waiter
  observes its deadline without entering the mutation callback.

Commit: `06bca1299354ddd7af2874dab5d6c71de0151a10`

### Goal 8 — MCRL-008: Reconcile the Versioned Contract Guidance

- Describe configuration v1 and independently versioned machine contracts
  accurately in contributor documentation.
- Remove obsolete concurrency-key wording from runtime qualification comments.
- Keep this plan aligned with the final implementation and review consensus.
- Verify this documentation-only Goal by reading back the changed files,
  scanning for the superseded claims, and running `git diff --check`; broader
  executable gates are unnecessary for this Goal.

Commit summary:

`Align no-lock guidance with the versioned runtime contract`

## Per-Goal Commit Procedure

Follow this sequence for every executable Goal. Documentation-only remediation
Goals use their explicitly stated verification instead:

1. Check `git status` and the preceding Goal commit before starting.
2. Implement only the active Goal and run its focused tests first.
3. Pass `gaori run prepare`, `gaori run unit`, `gaori run integration`,
   `gaori run release`, and the tagged live-test compile checks.
4. Inspect the complete diff and worktree status after generation and testing.
5. Stage only the Goal's scope and create a Lore-formatted commit.
6. Confirm a clean worktree and the expected HEAD before starting the next
   Goal.
7. Record the preceding Goal's commit hash in the next commit's `Related:`
   trailer.

## Final Integration Verification

After all implementation and remediation Goals are committed and the worktree
is clean, run `gaori run full`. This is the first point at which `make test-e2e`
and mandatory live ZCode/AGY verification run.

After `gaori run full` passes, run one manual live concurrency spot check: two
`mulgae review` processes at the same time in two separate projects, so AGY
invocations (which share the user's real `HOME`) overlap once. Record the
outcome in the final report; on failure, apply the remediation-goal policy
below.

If the full gate fails:

- Inspect the Gaori summary first and identify the responsible subsystem.
- Create a separate, narrowly scoped remediation Goal instead of amending an
  existing Goal commit.
- Implement the fix, pass focused and non-live verification, and create a
  remediation commit.
- Rerun `gaori run full` from the new clean HEAD.
- Repeat until the full gate passes or a concrete external blocker is
  established.

Unless separately requested, exclude `make test-kimi` from the final gate and
report it explicitly as skipped. Do not push, tag, release, or install anything
as part of this plan.
