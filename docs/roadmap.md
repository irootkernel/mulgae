# Mulgae roadmap

This roadmap owns the status and ordering of planned Mulgae work. Current
runtime behavior remains authoritative in source, tests, embedded contracts,
and the contributor documents linked from [README.md](README.md).

## EPIC-001: Token-efficient review waiting

Status: Completed

Goal: let an attached coding agent wait for a long Mulgae review without
repeated model turns while preserving exact run identity, explicit
cancellation, and fail-closed publication.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-001 | Completed | Guide attached clients to keep one foreground `run_review` pending and wait on the same deferred handle for up to five minutes at a time. | Validate `skills/use-mulgae`; read back the guidance; run `git diff --check`. |
| TASK-002 | Completed | Add a session-local MCP invocation registry that owns review execution independently of an individual wait request. | Prove monotonic lifecycle state, single execution ownership, bounded shutdown drain, and no restart recovery. |
| TASK-003 | Completed | Add `start_review`, `await_review`, and `cancel_review`, retain foreground compatibility, update the source-distributed skill to prefer the new workflow, and certify supported Codex and Claude clients. | Prove wait cancellation isolation, explicit execution cancellation, repeatable await, exact final identity, unchanged publication authority, legacy fallback, effective tool timeout behavior, and no repeated model turn during one await. |
| TASK-004 | Deferred | After MCP Tasks receives a stable protocol release, replace the custom session-local lifecycle when the Go SDK and supported Codex and Claude clients implement the released contract. | Confirm the stable specification and compatible SDK/client versions, preserve TASK-003 behavior and fallback guarantees, and record exact-client protocol evidence for the standard task surface. |

TASK-002 and TASK-003 share the planned design authority in
[todo/review-await.md](todo/review-await.md). TASK-004 begins only after both
are complete and MCP Tasks is no longer experimental. Until then it is the
deferred final goal of this epic. TASK-003 delivers the supported custom
start/await workflow; it does not promote TASK-004 or claim the stable MCP
Tasks contract. EPIC-001 is complete with TASK-004 retained as Deferred until
the stable MCP Tasks contract and required SDK and client support are released.
