# KAR Runtime Diagnostics Architecture

## 1. Current Gaps

The existing coordinator trace is an immutable in-memory decision trace returned with `CoordinatorResult`; it is not a real-time durable sink. `ProviderInvocationRuntime` also holds captures and inventory in memory for later publication preparation.

The current failure chain loses evidence at several boundaries:

1. `ObservedReviewProvider.Observe` may return an error without a valid observation, so already produced stdout/stderr and process lifecycle evidence can be discarded.
2. Provider registry and process runner contracts separate a zero observation from an error instead of returning a typed partial result.
3. `runtimeProviderErrorCondition` uses message matching and collapses unrecognized causes into `internal_invariant`.
4. `reviewrun.Service` returns login-required and non-publishable failures before draining the runtime artifact inventory.
5. The entrypoint constructs safe command diagnostics without the artifact path that the command-result model can already carry.
6. The publication run selector treats a new top-level `diagnostics` directory as a malformed session.

These are lifecycle and interface problems, not a missing logger call.

## 2. Target Components

### Application model and ports

`RuntimeDiagnosticEvent` is a validated immutable event containing only closed codes, identifiers, bounded safe metadata, timestamps, and ordering fields.

`RuntimeDiagnosticSink` owns one run-wide sequence and exposes operations equivalent to:

- emit a validated event;
- persist invocation raw streams and safe metadata;
- atomically replace run/attempt/invocation status projections;
- finalize exactly one terminal state;
- return installed safe relative URIs.

`RuntimeDiagnosticSinkFactory` opens a sink for an allocated session/run identity beneath an approved artifact root. Application code depends only on this port, never the filesystem adapter.

`ProviderRuntimeCause` is a closed typed cause carried from process/provider/validation boundaries into the runtime event model. User-facing failure classification remains a separate safe projection.

Noop and in-memory sinks support unit tests. The production filesystem sink is injected at composition.

### Filesystem adapter

The filesystem adapter owns JSON encoding, serialized append, sequence allocation, status snapshot replacement, raw stream installation, secure drop metadata, sync points, and close/finalize durability. It composes the existing secure writer instead of weakening or duplicating its policy.

### Process and provider adapters

Process execution must retain a typed lifecycle result even when start, wait, transport verification, or process-group cleanup fails. Provider adapters translate family-native framing, login, timeout, authentication, quota, and rate-limit states into closed observations and causes.

The adapter boundary owns native parsing. The review application owns policy decisions such as repair and fallback eligibility.

### Coordinator and review runtime

The coordinator remains the single owner of scheduling decisions and logical ordering. Its existing trace events become sources for diagnostic events but remain distinct: coordinator ordinals describe authoritative decision order, while diagnostic `seq` orders the complete operational stream.

Provider runtime emits process, I/O, parsing, validation, and repair events and persists raw invocation artifacts without waiting for P2 publication.

### Reviewrun, publication, cleanup, and CLI

`reviewrun` owns the run diagnostic lifecycle. It opens the sink after identity allocation, passes it to subordinate services, finalizes it before every return, and exposes a diagnostic reference with the result or typed failure.

Publication may store a reference to the diagnostic run but never consumes diagnostics as validation or authority. Cleanup observes linked P2 diagnostics and diagnostics-only runs through an explicit private-namespace contract. CLI projection uses only installed safe URIs.

## 3. Dependency Direction

```text
domain / app diagnostic model
            ↑
ports: sink, factory, typed process/provider results
            ↑
application: coordinator, provider runtime, reviewrun
            ↑
adapters: process, providercli, filesystem diagnostics
            ↑
entrypoint composition and CLI projection
```

- Domain and application packages MUST NOT import filesystem, CLI, or entrypoint packages.
- Provider adapters MUST NOT decide coordinator fallback policy.
- Filesystem diagnostics MUST NOT import publication policy or manufacture P2 authority.
- CLI rendering MUST NOT read raw diagnostic content.

## 4. Normal Data Flow

```text
command accepted
  -> qualify and build plan
  -> allocate session/run identity
  -> open and validate diagnostic sink
  -> persist run_started
  -> schedule concurrent lanes
  -> persist process/I/O/parse/validation events and raw streams
  -> reduce role outcomes
  -> prepare and commit P2
  -> link P2 URI in diagnostic status
  -> drain namespaces and clean workspace
  -> persist run_completed and finalize
  -> return command result
```

The sink must exist before the first provider spawn. Events from concurrent lanes enter the same serialized run writer. Raw bytes are installed in invocation-specific files and referenced by safe metadata events.

## 5. Failure Data Flows

### Provider or parsing failure

The process/provider layer returns the best available observation plus a typed cause. Raw streams are scanned and installed, then the error event is made durable before repair, fallback, cancellation, or reduction begins.

### Login required

The provider adapter emits a typed login-required status. The runtime records provider attribution, prohibits repair/fallback/P2, cancels peers according to existing policy, finalizes the diagnostic run, and returns exit 4 with a safe URI.

### Security rejection

The secure writer drops unsafe bytes and returns safe drop metadata. The runtime records the security stop, prohibits repair/fallback/publication, finalizes what can be safely persisted, and preserves exit 8 semantics.

### Diagnostic persistence failure

Before provider spawn, failure to open or prove the sink prevents execution. After execution begins, write/finalize failure is a typed artifact failure; it cannot be hidden behind the initiating provider error or reported with a nonexistent URI.

### Cancellation and peer shutdown

The initiating cause is persisted before cancellation requests. Peer cancellation events remain distinct from the predecessor so reduction cannot hide the original failure.

## 6. State and Authority Separation

`kar-runtime.jsonl` is chronological operational evidence. Mutable `status.json` files are atomic convenience projections. Neither is an immutable review result.

P2 remains the only review publication authority. A successful P2 may reference its diagnostics and diagnostics may reference the P2, but neither reference changes validation, lineage, cleanup authorization, CI, or release semantics.

Diagnostics-only failed runs are first-class retention objects, not malformed or corrupt publications. Default export excludes them because they may contain sensitive provider/user bytes.

## 7. Implementation Boundaries by Epic

- Epic 1 introduces the normative contract, model, ports, and secure store without broad runtime instrumentation.
- Epic 2 changes process/provider result contracts and preserves typed causes and raw observations without changing fallback policy.
- Epic 3 wires the run-wide sink through coordinator/reviewrun/publication lifecycle and closes every terminal path.
- Epic 4 exposes safe URIs, integrates namespace/cleanup, verifies offline flows, and makes actual E2E failures discoverable for G010-T05.

