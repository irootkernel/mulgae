# Review await design

Status: Planned

Roadmap: [EPIC-001](../roadmap.md#epic-001-token-efficient-review-waiting)

## Authority

This document is the design authority for planned TASK-002 and TASK-003
work. It does not describe current runtime behavior and does not override
source, tests, embedded contracts, or the current contributor documents. Until
the roadmap tasks are implemented and verified, `run_review` remains one
foreground request whose cancellation reaches the review execution.

When the planned work is delivered, move its accepted behavior into
`docs/goals.md`, `docs/architecture.md`, `docs/contracts.md`,
`docs/security.md`, the README, and affected embedded help and schemas in the
same change. Roadmap status is not implementation evidence.

## Problem

`run_review` already avoids Mulgae status polling by holding one MCP request
open until completion. An observed Codex host still deferred that long tool
call into short execution-cell waits, and every empty wait resumed model
reasoning with the accumulated conversation. Periodic MCP progress did not
provide completion authority or prevent those model turns.

The immediate skill guidance reduces that cost by waiting longer on the same
pending handle. The planned runtime work separately prevents a cancelled or
timed-out wait request from cancelling a review that was successfully started.
It does not attempt to make the CLI or an MCP server wake a suspended model;
that scheduling behavior belongs to the client host.

## Planned boundary

Mulgae will add a process-local MCP invocation registry. A review execution is
owned by the MCP server context, while each observer wait is owned by its own
request context. The registry is discarded when the MCP server exits.

The boundary remains deliberately narrow:

- no CLI detach, wait, suspend, resume, or cancellation commands;
- no daemon, durable job ledger, network listener, or cross-process executor;
- no invocation recovery after MCP server restart or machine reboot;
- no provider substitution, widened invocation budget, or live project-tree
  access;
- no new publication, merge, release, waiver, or acceptance authority.

Server shutdown cancels every active review and performs the existing bounded
terminal cleanup. A later server may inspect completed publication or terminal
diagnostics through existing run queries, but it cannot recover a session-local
invocation.

## Planned MCP surface

### `start_review`

`start_review` accepts the same target, objective, and role selection as
`run_review`. It synchronously admits one session-local invocation, starts the
review under the server-owned context, and returns its invocation identity
without waiting for provider completion.

The invocation identity is distinct from Mulgae's durable run identity. A
snapshot may expose a run ID only after trusted allocation establishes it. One
invocation starts at most one review. If the start result is lost or uncertain,
the client must not repeat the mutation blindly.

### `await_review`

`await_review` accepts one exact session-local invocation identity and blocks
until that invocation reaches its terminal result. It uses event-driven
completion rather than a timer or status polling loop.

Cancelling or timing out the await request ends only that observer. It does not
cancel provider processes, terminal publication, or cleanup. Another await in
the same MCP session observes the same invocation and never creates a new run.
The terminal response reuses the existing bounded `run_review` outcome and
error envelope, including exact session and run identity when allocated.

### `cancel_review`

`cancel_review` records the first explicit cancellation request for one active
invocation. It is the only client tool that cancels the server-owned review
context. Its acknowledgement is not a terminal result: the caller must still
await completion and use the final Mulgae failure and publication precedence.

### Compatibility

The current `run_review` remains available as the foreground compatibility
path. Its request-coupled cancellation behavior remains explicit. TASK-003
must update the source-distributed skill to prefer `start_review` followed by
one `await_review` and final run inspection when all three new lifecycle tools
are discovered. If that complete surface is unavailable, the skill must retain
the current foreground `run_review` workflow rather than mix lifecycle modes.

MCP Tasks remain a later compatibility candidate. They are not part of
TASK-002 or TASK-003 while the protocol feature and required client/SDK support
remain unverified. TASK-004 is Deferred until MCP Tasks has a stable
protocol release and that released contract is implemented by the Go SDK and
supported Codex and Claude clients. Mulgae will not implement a second private
durable task protocol in anticipation of it or mark the deferred goal active
from draft or experimental support alone.

## Planned agent workflow

The TASK-003 skill update must direct an attached agent to:

1. Run `preflight_review` with the exact intended target, objective, and roles.
2. Call `start_review` once with those same arguments and preserve its exact
   session-local invocation identity. Never retry an uncertain start.
3. Call `await_review` for that invocation. If the host defers the tool call,
   wait on the same pending handle for up to five minutes at a time rather than
   resume model reasoning for a shorter empty wait.
4. If an await request is cancelled or reaches the host tool timeout, re-await
   the same invocation only after confirming the MCP session is still alive.
   Never replace it with another start.
5. After the terminal envelope returns, inspect its exact durable run identity
   with `get_run` and query findings only when publication authority permits.
6. Call `cancel_review` only on explicit user intent, then await the terminal
   result instead of treating cancellation acknowledgement as completion.

The configured MCP tool timeout must exceed the admitted review deadline. The
skill must not combine a session-local invocation from one MCP server process
with another server process or infer recovery from completed-run listings.

## Progress and token behavior

Progress is bounded, optional observation and never lifecycle or publication
authority. The planned await path will not emit periodic heartbeat or log
stream messages merely to prove liveness. It may report admission or meaningful
phase transitions when the client supplies a progress token and the transition
can be projected without private content.

Token efficiency is an exact-client acceptance condition, not something the
MCP server can infer. Certification must show that one pending await does not
cause repeated model turns. The configured MCP tool timeout must exceed the
admitted review deadline; a timeout is not a cancellation request and does not
make a duplicate start safe.

## Required verification

Implementation must cover at least these scenarios:

- start returns before provider completion and creates only one execution;
- await returns immediately for an already terminal invocation;
- request cancellation and tool timeout release one awaiter without cancelling
  the review;
- a second await observes the same terminal result and exact allocated IDs;
- explicit cancel reaches provider processes and terminal cleanup exactly once;
- server shutdown cancels all active executions and leaves no late child start;
- publication, diagnostic fallback, failure precedence, and bounded public
  output remain identical to the foreground path;
- lost or unknown invocation identities fail closed without starting a review;
- exact Codex and Claude clients discover the surface and complete a long await
  without repeated model reasoning;
- the source-distributed skill passes its validator and selects the new flow
  only when the complete lifecycle surface is available;
- the skill falls back atomically to foreground `run_review` for older servers
  without mixing invocation identities or cancellation semantics;
- current foreground `run_review` behavior remains compatible.

The complete repository gate and mandatory live-provider certification remain
required before release readiness. MCP Tasks require a separate protocol, SDK,
security, and exact-client decision after this work is complete and their
stable-release prerequisites are satisfied.

## Decision history

Commits `f53925f`, `ef19d0a`, and `84c938b` rejected detached background jobs
and polling in favor of one attached foreground request. Their constraints on
bounded transport, exact identity, non-authoritative progress, and safe
cancellation remain valid. This planned design narrows the revision to an
ephemeral server-owned execution plus an event-driven await; it does not add a
daemon, durable recovery, or periodic status polling.
