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

Promote an epic-sized finding to a TODO candidate or an adopted roadmap work
unit. Do not use this index as a second roadmap or status authority.
