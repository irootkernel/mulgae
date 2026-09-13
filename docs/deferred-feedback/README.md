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

Promote an epic-sized finding to a TODO candidate or an adopted roadmap work
unit. Do not use this index as a second roadmap or status authority.
