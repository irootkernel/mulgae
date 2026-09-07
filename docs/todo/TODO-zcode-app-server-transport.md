# TODO: ZCode app-server provider transport (EPIC-003 dossier)

Temporary execution dossier for adopted
[EPIC-003](../roadmap/README.md#epic-003-zcode-app-server-provider-transport).
The roadmap alone owns task identity, ordering, dependencies, lifecycle
vocabulary, and status; this dossier is the thin integration map for delivery
and is removed at epic closeout.

## Requirement owners

| Owner | Bears |
|---|---|
| [Roadmap](../roadmap/README.md#epic-003-zcode-app-server-provider-transport) | Epic goal, accepted design decisions, task identity, ordering, and per-task acceptance. |
| [Security requirements](../specs/security.md) | Provider isolation, trust boundaries, staged-output validation, and per-family write posture. TASK-010 rewrites the ZCode write-posture section for the protocol transport; isolation and staging invariants must not change. |
| [Public contracts](../specs/contracts.md) | Versioned manifest transport field (`staged_file` stays), qualification shareable-profile identity, and doctor version-probe argv. TASK-010 updates the qualification identity description for the protocol channel. |
| ADR `zcode-app-server-transport.md` (created in TASK-010) | Accepted transport decision and the wire-shape constraints pinned by the live spike. |

## Task map

TASK-009 (no production caller):
- `internal/ports/scheduling.go`: protocol packet channel, binding, and driver session interface.
- `internal/adapters/process`: conversation-mode run path reusing fd-exec, process-group kill, timeout, and termination classification, with tee-spooled stdout.
- Gate: focused fake-child tests, `make test-prepare`, `make test-unit`, `make test-int`.

TASK-010 (atomic cutover; starts with the live spike):
- Spike go/no-go questions: accepted `session/create` params (workspace, mode `yolo`, `toolDenylist` shape), `session/send` response timing and shape, `turn-completed`/`turn-failed` payloads, login-required representation, close and exit behavior, and `--stdio` necessity. Any failed assumption stops the epic with a concrete blocker.
- `internal/adapters/providercli`: NDJSON client, argv and transport swap, protocol-native failure classification, and `zcodeContent` removal; the qualification probe route and version floor move in the same change as the review path.
- `internal/app/reviewrun`: production candidate transport and qualification guidance.
- Documentation: security requirements, public contracts, and the new ADR; registry and e2e test pins.
- Gate: focused tests, live spike evidence, and `make test` with mandatory live ZCode certification.

## Cross-document acceptance and boundaries

- A certified route never diverges from the executed route: review execution, the qualification capability probe, and shareable-profile identity switch in one change.
- The staged-file report transport, prompt output-destination layer, manifest transport value, sealed workspace capture, and disposable credential namespaces are unchanged by both tasks.
- Roadmap-owned closeout begins only after the updated security requirements, public contracts, and completed ADR agree with the implemented behavior and acceptance results.
- Delivery preserves unrelated uncommitted worktree changes; overlapping edits are resolved before the cutover is applied.
- Safety-critical external actions are limited to live ZCode execution during the TASK-010 spike and the mandatory live certification in `make test`.
