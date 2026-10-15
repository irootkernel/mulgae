# EPIC-010 development dossier: Cursor ACP review provider

This is an adopted temporary development dossier, not implementation evidence.
[Roadmap](../roadmap/README.md#epic-010-cursor-acp-review-provider) owns status
and dependencies. TASK-040 re-verifies every wire fact below against the
installed `agent` binary before later tasks start. A failed check stops the
epic.

The planning baseline is Cursor's public ACP documentation at
<https://cursor.com/docs/cli/acp>. That page describes the integration surface.
It does not certify Mulgae's read-only review boundary.

## Goal and scope

Add Cursor as an explicitly selected text-role provider. ZCode remains the
default provider. Grok remains the operator-selected recovery route. Codex
remains available through its existing explicit configuration. Provider failure
stays on the selected provider.

Cursor uses one ACP stdio conversation per invocation, on the protocol runner
already shared with Grok. The report is the correlated assistant text from that
conversation. There is no `agent -p` path and no user-facing transport switch.

Artist roles, Git-shareable model selection, and reasoning effort are outside
this epic. Live Cursor certification is opt-in and is not added to the
mandatory ZCode/Grok release gate.

## Wire

Launch `agent acp`. The client writes JSON-RPC 2.0 requests to the child
stdin. The agent writes responses and notifications to stdout, one JSON object
per line. Logs may appear on stderr and are not report text.

The planning-time session order is:

1. `initialize` with `protocolVersion` 1.
2. `authenticate` with `methodId` `cursor_login`, unless TASK-040 pins a
   smaller pre-started credential.
3. `session/new` with the neutral reviewer home as `cwd` and `mcpServers` set
   to an empty list.
4. Ask-mode acknowledgement.
5. `session/prompt` with the review text.
6. `session/update` notifications while the turn is open.
7. The `session/prompt` result. Accept assistant text only when the result
   correlates to that prompt and `stopReason` is `end_turn`.

`session/load` is not used. One process and one new session serve one
invocation, so Cursor history does not carry across roles or attempts.
`session/cancel` remains available for Mulgae cancellation. Bounded teardown
uses the existing protocol runner.

ZCode and Codex keep their own `app-server` drivers. Cursor does not join
those drivers. Grok's argv, tool names, and boundary TOML are also not reused.
Grok disables subagents, web search, and MCP with flags Cursor's public CLI
does not publish. The Cursor driver needs its own acknowledgement and
rejection rules.

## Ask mode and tools

Public ACP sessions advertise `agent`, `plan`, and `ask`. `ask` is the
required review mode. `plan` is not sufficient: the live-review contract
requires a proven read-only restriction, and planning mode alone does not
supply that proof.

The public page does not name the request that selects `ask` inside `agent
acp`. The CLI root flag `--mode=ask` exists separately. TASK-040 pins the argv
or ACP request the installed binary actually acknowledges. `session/prompt`
is withheld until that acknowledgement names `ask`.

Read tools are admitted only when their identity, path, and completion match
the review read plan. A missing permission request does not waive that check.
The same rule already applies to Grok live review.

These observations reject the turn:

- a shell, write, web, or MCP tool, whether it arrives as
  `session/request_permission` or as a tool update
- `cursor/task`, because that notification can report a subagent that already
  ran
- any other server request whose effect TASK-040 has not explicitly allowed

`cursor/ask_question` and `cursor/create_plan` are blocking. The driver
answers each with a rejection or cancellation outcome that grants no
authority, so an unanswered request cannot leave the turn blocked.
`allow-once` and `allow-always` are not valid answers for a review turn.

## Working directory, instructions, and credentials

Process cwd and `session/new` `cwd` are the neutral reviewer home under
`~/.mulgae/home/`. The canonical project root is a typed prompt input. The
provider may read admitted source through tools. It does not receive the
repository as its session workspace.

Cursor's CLI documentation says a launch from the project directory applies
`.cursor/rules`, `AGENTS.md`, and `CLAUDE.md`, and that ACP can load MCP
servers from project or user `.cursor/mcp.json`. Those files are untrusted
project content when a review reads them. They are not native execution
authority. The disposable `HOME` contains only the selected authentication
material. User rules, skills, CLI permissions, and MCP configuration from
`~/.cursor` are not projected.

The public authentication methods are `agent login`, `--api-key` or
`CURSOR_API_KEY`, and `--auth-token` or `CURSOR_AUTH_TOKEN`. TASK-040 chooses
the smallest material that authenticates an isolated process. The adapter
then admits only that material.

Live review and extraction launch inside the same app-owned Seatbelt guard
used for ZCode and Grok. The guard keeps source, Git, and the neutral guide
read-only, and it denies the configured credential roots. There is no
unguarded launch. Network access outside the guard's socket denials remains
possible, as it does for the current providers. Web tools are still rejected
on the wire.

## Qualification

Version and capability probes use the protocol channel. Version argv is the
family-closed base argv plus `--version`. Capability runs the existing probe
fixture through one ACP session, with no write grant and with the same
ask-mode and tool limits as review. TASK-040 records the installed version and
whether the fixture's assistant result is recognizable. An unrecognizable
result stops the epic.

Qualification identity includes the Cursor family, executable, and pinned
protocol behavior. Cursor does not share a qualification group with Grok.

## Stop conditions

TASK-040 stops EPIC-010 when any of these checks fail on the installed CLI.
Later tasks must not weaken a failed check or switch to print mode.

| Check | Required evidence |
|---|---|
| Neutral-cwd read | From the neutral home, the agent reads an admitted absolute path and returns that read in a correlated assistant turn. |
| Instruction discovery | Project `.cursor/rules`, `AGENTS.md`, and `mcp.json` are not applied as execution instructions. A source read of those files can still appear as ordinary review content. |
| Tool visibility | A write, shell, or subagent attempted without `session/request_permission` remains visible on the wire and fails the turn. |
| Ask acknowledgement | The pinned mode request reports `ask` before `session/prompt`. |
| Credential boundary | The process cannot read a configured credential root. |
| Report correlation | Accepted text comes from the completed assistant turn for that prompt. Missing completion, an unknown `stopReason`, or uncorrelated text fails closed. |

## TASK-040 probe record

`cursor-agent --version` printed `2026.10.14-0f9edde`. The cycle launched `cursor-agent acp` under the Seatbelt profile from `liveBoundaryArgv`. Process cwd and `session/new` `cwd` were a neutral directory, and `mcpServers` was empty.

Startup auth was one read-only Keychain lookup for account `cursor-user` and service `cursor-access-token`. The secret was projected only as `CURSOR_AUTH_TOKEN`, with `AGENT_CLI_CREDENTIAL_STORE=memory`. `authenticate` was not called, and `session/new` succeeded. `BROWSER` was `/usr/bin/false`. The operator `~/.cursor` directory was a Seatbelt credential deny root. `~/.config/cursor` was absent.

`session/set_mode` with `modeId` `ask` was confirmed by `session/update` `current_mode_update` `currentModeId` `ask` before `session/prompt`. The `session/set_mode` result was an empty object. `session/new` had reported `currentModeId` `agent`.

A direct child of that same Seatbelt profile could not read the synthetic credential file. `/bin/cat` exited 1 and its stderr was `Operation not permitted`. The nonce did not appear. `/usr/bin/touch` under the admitted source root and under the neutral directory also exited 1, with the same stderr.

The admitted absolute source read came back in the correlated assistant turn with `stopReason` `end_turn`. Project `.cursor/rules`, `AGENTS.md`, `CLAUDE.md`, and `mcp.json` were not applied as execution instructions.

Forbidden `tool_call` updates were visible for `kind` `edit`, `kind` `execute`, and `kind` `other` with `rawInput._toolName` `task`, including the task update that arrived without `session/request_permission`. Requests that advertised `reject_once` were answered on their own ids with `optionId` `reject-once`. No reply selected `allow-once` or `allow-always`. After those tools were visible, the probe sent `session/cancel` and tore the process down. That negative review did not depend on `stopReason` `end_turn`.

The qualification assistant text was one JSON object with `root`, `link`, and `role`, taken from the correlated `agent_message_chunk` updates, with `stopReason` `end_turn`.

All six stop conditions passed. TASK-040 is complete. TASK-041 has not started.

## Intended owners

| Owner | Responsibility |
|---|---|
| `internal/adapters/providercli/protocol_dispatch.go` | Register the Cursor family on the protocol channel and its own driver constructor. |
| New Cursor ACP driver beside `grok_acp_protocol.go` | Session order, ask acknowledgement, permission rejection, and report correlation. |
| `internal/adapters/providercli/live_execution.go` | Seatbelt launch and neutral-cwd execution. |
| Credential namespace and `internal/composition/production_graph.go` | Disposable `HOME`, selected authentication material, and family wiring. |
| `internal/app/reviewrun` | Family admission, qualification identity, and text-role routing. Artist assignment fails before execution. |
| Config, schemas, help, and contributor specs | TASK-042 only. TASK-041 leaves the public portfolio unchanged. |

## Non-goals

- No change to ZCode, Grok, or Codex transport, defaults, or recovery behavior.
- No automatic substitution when Cursor fails.
- No persistent or resumed Cursor session.
- No artist role, model catalog, or reasoning-effort policy.
- No mandatory Cursor credential in `make test`.
- No print-mode fallback and no shared Grok driver.

## Closeout

After TASK-042, promote the pinned wire, permission rules, and isolation
boundary into the provider contracts, security requirements, and one
architecture decision record. Remove this dossier and its TODO index entry,
replace the roadmap's Detailed SOT with Canonical Outcomes, and accept the epic
explicitly. Historical contract readers stay in place.
