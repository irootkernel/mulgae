# Deferred feedback

This index owns small actionable findings intentionally postponed from current
work.

- `DF-001` Protocol-channel routing uses two dispatch bases: the registry
  decides conversation dispatch on the transport channel and then rejects
  non-ZCode families by family, while the qualification probe decides on the
  family alone. A second family adopting the protocol channel must find and
  edit both dispatch sites; the registry guard fails closed today, so the
  asymmetry is bounded. Re-entry: before adding a second protocol-channel
  provider family, derive both dispatch decisions from one channel-plus-driver
  authority so the driver constructor owns which protocol it speaks.
- `DF-002` Live review runs intermittently fail every role with an
  unconditioned `internal_invariant` after invocation preparation and before
  process spawn, cancelling accepted work; the underlying plain error is not
  recorded in diagnostics, so field diagnosis is impossible. Observed on a
  released pre-EPIC-003 orchestrator and once in an EPIC-003-era extraction
  trailer wave under provider throttling. Re-entry: when a run reproduces this
  signature, first capture the retry or extraction invocation's underlying
  error in runtime diagnostics, then decide whether the internal-class
  extraction-trailer failure may keep its bounded absorption.

Promote an epic-sized finding to a TODO candidate or an adopted roadmap work
unit. Do not use this index as a second roadmap or status authority.
