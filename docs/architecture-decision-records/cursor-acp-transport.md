# Cursor ACP transport

Status: Accepted

Roadmap: [EPIC-010](../roadmap/README.md#epic-010-cursor-acp-review-provider)

## Problem

Operators need to name Cursor as a review provider. ZCode, Grok, and Codex
already own the default role preferences. Cursor selection has to stay out of
those defaults, and out of model, reasoning-effort, credential-profile, and
credential-home configuration.

## Decision

Publish `cursor` as an explicit family in init, CLI, MCP, schemas, help, and
the current contract versions. Historical contract versions stay in place and
continue to validate the documents they already describe.

Each Cursor invocation launches the selected executable with `acp` over stdio.
The driver sends `initialize` with `protocolVersion` 1 and accepts that
result only when it reports protocol version 1. `session/new` sets `cwd` to
the neutral reviewer directory and `mcpServers` to an empty list. The driver
then sends
`session/set_mode` with `modeId` `ask`. `session/prompt` waits until the
session from `session/new` acknowledges ask. A `current_mode_update` with
`currentModeId` `ask` is that acknowledgement and may arrive before an empty
`set_mode` response. An empty `set_mode` result does not acknowledge ask. A
result acknowledges ask when it reports `currentModeId` `ask`, and an echo of
`modeId` alone does not. The update and the response may arrive in either
order.

The prompt result is accepted when it correlates to that prompt and
`stopReason` is `end_turn`. Missing assistant text, another stop reason, or an
uncorrelated result fails closed. Qualification, extraction, and live
extraction reject every tool call and fail the turn, so a later `end_turn`
does not qualify.

Planned app-mediated workspace reads stay allowed. Each exact admitted
`LiveSourceReadPlan.GitCommand` is a separate `allow_once`. An unplanned,
forbidden, or mismatched live tool receives the non-authorizing answer and
then fails the turn. A later `end_turn` does not accept that turn. A general
read permission is not granted.

Live review rejects a write, a web tool, an MCP tool, and a subagent. An
unknown server request fails the turn. `cursor/task` fails the turn, including
a notification that has no request id. `cursor/ask_question` and
`cursor/create_plan` receive a cancellation that grants no authority, and the
turn may continue. A cancelled planned read may continue.

The process receives the selected `CURSOR_AUTH_TOKEN` and
`AGENT_CLI_CREDENTIAL_STORE=memory`. The launch uses a disposable `HOME` and a
private Cursor data child for that namespace. The outer guard denies every
configured credential home. User rules, skills, and MCP configuration are
not copied into the namespace. `GIT_DIR` is set only when an admitted Git
directory exists. `GIT_WORK_TREE` is the neutral directory on every Cursor
launch.

Default role preferences are unchanged. A text role receives Cursor only when
Cursor is the sole selected family and that role's preference list has no
configured match. Artist does not receive that fallback. A failed Cursor role
is reported and is not replaced by another provider.

Live Cursor certification is a standalone opt-in outside the default ZCode and
Grok gate. This epic still requires that exact-binary check to pass and to be
reported.

## Consequences

Command result v20 and doctor result v6 name Cursor. Older command, doctor,
heartbeat, preflight, and evidence assets remain readable. Heartbeat and
preflight enums that list the current families also accept `cursor`. Projects
that omit Cursor keep their existing ZCode, Grok, and Codex behavior.
