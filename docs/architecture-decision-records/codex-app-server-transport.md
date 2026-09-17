# Codex app-server transport

Status: Accepted

Roadmap: [EPIC-005](../roadmap/README.md#epic-005-codex-app-server-provider-transport)

## Problem

Codex review and qualification used one-shot `codex exec`. The prompt traveled
on stdin and the review report was the process stdout. ZCode and Grok already
use the common protocol conversation runner, but Codex still used a separate
process-result path. The exec-only flags also made the Codex route depend on a
different CLI surface from other protocol providers.

## Decision

Launch `codex app-server` over stdio for each Codex invocation. Initialize the
connection, create an ephemeral thread in the immutable captured workspace,
start one turn, and accept only a correlated final assistant message after a
successful `turn/completed` event. Qualification sends its output schema on
`turn/start`; review and extraction retain free-form text. The runner owns the
same timeout, process group, private transcript, and bounded teardown used by
the other protocol routes.

Keep the existing `stdout` role-report transport value. It identifies text
carried by the Codex stdout channel after protocol decoding; raw JSON frames
remain private process evidence. `list-provider-profiles` changes Codex's
prompt transport from `stdin` to `protocol`. There is no exec fallback or
user-configurable transport selection.

The app server starts with a disposable `CODEX_HOME` containing only the selected
authentication file. Adapter-owned settings apply read-only permissions, disable
extension features, and set a zero-byte project-instruction allowance. The driver
rejects loaded instruction sources and server-initiated interaction requests.
It does not grant write access to a staged file. One process and ephemeral
thread are used per invocation, so Codex history does not persist between
review roles or attempts.

## Verified baseline and consequences

The installed Codex 0.154.0 supports the stdio initialization and ephemeral
thread exchange. Its isolated home leaves project-local configuration disabled
for an untrusted captured project. A real qualification turn completed through
the new driver with the fixture's structured response and unchanged native
credential file. This release is the provider qualification minimum; the
separate Codex MCP-client minimum stays at 0.149.0.

Malformed or uncorrelated frames, unexpected requests, missing final text,
failed turns, and missing completion fail closed with typed provider causes.
The existing opt-in two-profile exact-binary test remains required for this
epic's acceptance and optional in ordinary `make test` runs.
