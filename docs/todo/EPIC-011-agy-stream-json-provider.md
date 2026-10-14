# EPIC-011 development dossier: AGY stream-json review provider

This is an adopted temporary development dossier, not implementation evidence.
[Roadmap](../roadmap/README.md#epic-011-agy-stream-json-review-provider) owns
status and dependencies. TASK-043 re-verifies every wire, sandbox, and
credential-isolation fact below against the installed `agy` binary before later
tasks start. A failed check stops the epic.

The planning baseline is the installed Antigravity CLI (`agy` `1.2.9`) binary
and its embedded `printmode` and `steps` stream-JSON contracts.

## Goal and scope

Re-admit AGY (`FamilyAgy`, `"agy"`) as a protocol-driven provider over its
bidirectional `stream-json` stdio wire protocol, make AGY the first default
provider preference for the `documentation` role in `assets/roles.yaml`
(`[agy, zcode, grok, codex]`), and support multi-account Gemini credentials
through the same `default_credential_profile`, per-role `credential_profile`,
and machine-local `credential_homes` contract used by Codex.

ZCode remains the first default preference for `logic`, `security`,
`maintainability`, `product`, `testing`, and `artist`. Grok and Codex retain
their existing routes. A failure on AGY stays on AGY; Mulgae never substitutes
another provider or treats multiple provider outputs as consensus.

AGY uses one `stream-json` stdio conversation per invocation on the existing
protocol runner (`ports.ProviderPacketChannelProtocol`). There is no `-p` or
`--print` argv prompt path, no `BoundedPostOutputLifecycle` workaround, and no
loopback `--hub` gRPC server.

## Wire

Launch `agy` with `--input-format stream-json --output-format stream-json` and
no `-p` / `--print` flag. The client writes newline-delimited JSON
(`printmode.StreamInputMessage`) to child stdin, and `agy` writes
newline-delimited JSON (`steps.StreamEvent`) to stdout. Diagnostics on stderr
are not report text.

The single-turn session order is:

1. **Startup (`init`)**:
   - `agy` emits one `{"event":"init","conversation_id":"<uuid>","init":{...}}`
     line on stdout after authentication.
   - Require a non-empty `conversation_id`, record it as `ProviderSessionID`,
     and mark `CreateAccepted`.
2. **Turn request (`user`)**:
   - Write one `{"event":"user","message":{"content":"<prompt>"}}` line to
     stdin and mark `SendAccepted`.
3. **In-turn updates (`step_update`)**:
   - `agy` emits `{"event":"step_update","conversation_id":"<uuid>","step_update":{...}}`
     frames as the turn progresses.
   - Require every frame to match `conversation_id`, record `step_index` as
     `ProviderTurnID`, and mark `TurnObserved` and `MessagesReceived`.
4. **Completion (`result`)**:
   - `agy` emits `{"event":"result","result":{"conversation_id":"<uuid>","status":"SUCCESS","response":"...","structured_output":...,"denied_actions":[...]}}`.
   - Accept assistant evidence text only when `result.conversation_id` matches
     `conversation_id`, `result.status` is `"SUCCESS"`, `result.error` is empty,
     `result.denied_actions` is empty, and `result.response` (or
     `result.structured_output` for schema-bound probes) is non-empty.
   - Close child stdin so `agy` exits `0` cleanly.

One process and one new `conversation_id` serve one invocation; conversation
state never carries across roles, retries, repairs, or runs.

## Read-only live-source boundary and tools

Process `cwd` is pinned to the neutral reviewer home under `~/.mulgae/home/`.
The canonical project root is passed via `--add-dir <workspaceRoot>` and named
in the typed review prompt.

Live review, extraction, and qualification run inside Mulgae's app-owned macOS
Seatbelt read-only boundary (`ports.NewLiveReadOnlyBoundary(workspaceRoot,
gitAccessRoot, reviewerHomeRoot, protectedRoots)`), which kernel-enforces
read-only access to the workspace, Git directory, and neutral guide while
denying writes and unchosen credential roots.

Inside that outer Seatbelt boundary, `agy` launches with:

- `--mode plan`
- `--disable-slash-commands`
- `--dangerously-skip-permissions`
- `--add-dir <workspaceRoot>`

Why `--mode plan` is paired with `--dangerously-skip-permissions` inside the
Seatbelt boundary:

- `--mode plan --add-dir <workspaceRoot>` restricts `agy` to planning/read tools
  for workspace files, but `agy`'s headless `request-review` policy soft-denies
  `run_command` (`result.denied_actions`) when a review of `--staged`, `--base`,
  or `--commit` targets needs read-only `git` inspection commands.
- Pairing `--mode plan --dangerously-skip-permissions` with the mandatory outer
  `NewLiveReadOnlyBoundary` Seatbelt sandbox allows read-only `git` commands to
  execute while the kernel blocks any filesystem mutation.

In addition to Seatbelt enforcement, the protocol driver fails the turn closed
if any `step_update` frame reports a disallowed tool (`write_to_file`,
`replace_file_content`, `invoke_subagent`, `define_subagent`,
`manage_subagents`, `schedule`, browser/web tools, or any MCP mutation tool) or
if `result.denied_actions` is non-empty.

## Multi-account credentials and home isolation

By default on macOS, `agy`'s `CompositeTokenStorage` consults the shared macOS
Keychain service (`antigravity`) before falling back to
`<gemini_dir>/antigravity-cli/antigravity-oauth-token`. Without bypassing the
Keychain, multiple Gemini accounts on one machine collide on the single
Keychain item.

`agy`'s `shouldBypassKeyring` switches `CompositeTokenStorage` to pure
file-based token storage whenever `SSH_TTY` is set in the process environment:

- Mulgae always sets `SSH_TTY=/dev/null` for `agy` invocations and passes
  `--gemini_dir <resolvedHome>`, where `<resolvedHome>` is either the default
  `<operatorHome>/.gemini` or the canonical absolute `home` selected from
  `providers.agy.credential_homes`.
- Each account profile therefore reads and refreshes only its own mode-`0600`
  `<resolvedHome>/antigravity-cli/antigravity-oauth-token` file while `HOME`
  remains the operator home.
- Unchosen credential homes are added to `protectedRoots` so Seatbelt denies
  cross-profile credential reads during live review.

### Configuration contract

| Surface | Required behavior |
|---|---|
| Project policy (`.mulgae/config.yaml`) | Optional `providers.agy.default_credential_profile`, `providers.agy.model`, `providers.agy.reasoning_effort` (`low`, `medium`, `high`, `xhigh`, `max`), `providers.agy.timeout`, and per-role `credential_profile`. |
| Machine-local authority (`.mulgae/local.yaml`) | `providers.agy.executable` and optional lexical `providers.agy.credential_homes` (`profile` and canonical absolute `home`). |
| Default role preferences (`assets/roles.yaml`) | `documentation` uses `[agy, zcode, grok, codex]`; remaining text roles append `agy` after existing preferences (`[zcode, grok, codex, agy]`). |
| `--providers auto` | Discovers ZCode, Grok, and AGY (or preserves explicit portfolio selection per TASK-045 contract); when AGY is configured, `documentation` defaults to `agy`. |

## Qualification

Version and capability probes use the protocol runner:

- Version check runs `<executable> --version` and parses `antigravity-cli
  version <semver>`, with minimum floor `1.2.9`.
- Capability check runs a single-turn `stream-json` probe with `--json-schema`
  (or structured JSON response validation) under the same neutral-cwd,
  `--gemini_dir`, and `SSH_TTY=/dev/null` isolation as review.
- Qualification identity binds the `agy` family, executable identity, resolved
  credential profile/home, and optional `model` and `reasoning_effort`
  (preserving omitted-versus-explicit distinction).

## Stop conditions

TASK-043 stops EPIC-011 when any of these checks fail on the installed `agy`
binary. Later tasks must not weaken a failed check or fall back to `-p`.

| Check | Required evidence |
|---|---|
| `stream-json` handshake & correlation | `init` emits `conversation_id`, stdin `user` starts one turn, `step_update` and `result` carry the same `conversation_id`, and closing stdin exits `0`. |
| Neutral-cwd workspace & Git reads | From `~/.mulgae/home/`, `agy` reads admitted workspace files and runs read-only `git` diff/show commands under `NewLiveReadOnlyBoundary` without `denied_actions`. |
| Seatbelt write & credential denial | Any attempt to write inside the workspace/Git root or read a protected credential root is denied by Seatbelt and visible in `step_update`. |
| Tool visibility | Tool invocations appear in `step_update.tool_info` / `step_update.tool_name` so disallowed tools fail closed on the wire. |
| Multi-account file-token isolation | With `SSH_TTY=/dev/null` and distinct `--gemini_dir` homes, `agy` bypasses macOS Keychain and authenticates strictly from `<gemini_dir>/antigravity-cli/antigravity-oauth-token`. |

## Intended owners

| Owner | Responsibility |
|---|---|
| `internal/adapters/providercli/agy_protocol.go` | `stream-json` session order (`init`, `user`, `step_update`, `result`), tool-audit rejection, and report extraction. |
| `internal/adapters/providercli/protocol_dispatch.go` | Register `ports.FamilyAgy` across all protocol purposes. |
| `internal/adapters/providercli/live_execution.go` & `qualifier.go` | Seatbelt launch, neutral-cwd execution, `--gemini_dir` + `SSH_TTY=/dev/null` binding, and qualification probes. |
| `internal/app/config` & `internal/adapters/yamlconfig` | `AgyProviderConfig` (`executable`, `default_credential_profile`, `credential_homes`, `model`, `reasoning_effort`, `timeout`). |
| `assets/roles.yaml`, schemas, help, and contributor specs | TASK-045 only. TASK-044 leaves public schemas and default role routing unchanged. |

## Non-goals

- No `-p` / `--print` fallback and no `BoundedPostOutputLifecycle` resurrection.
- No loopback TCP `--hub` or internal gRPC/Connect transport.
- No automatic provider or profile substitution when AGY fails.
- No persistent multi-turn sessions across review roles or attempts.

## Closeout

After TASK-045, promote the pinned `stream-json` wire, Seatbelt permission
rules, multi-account `--gemini_dir` credential boundary, and `documentation`
default routing into the provider contracts, security requirements,
`final-provider-portfolio.md`, and one transport ADR. Remove this dossier and
its TODO index entry, replace the roadmap's `Detailed SOT` with `Canonical
Outcomes`, and accept the epic explicitly.
