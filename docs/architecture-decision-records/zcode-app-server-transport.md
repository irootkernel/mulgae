# ZCode app-server transport

Status: Accepted

Roadmap: [EPIC-003](../roadmap/README.md#epic-003-zcode-app-server-provider-transport)

## Authority

This document records the transport decision accepted by TASK-010. Current
runtime behavior is owned by source, tests, embedded contracts, and the
contributor documents. ZCode review and qualification invocations speak the
app-server protocol; there is no compatibility layer or print fallback.

The accepted behavior is reflected in `docs/specs/contracts.md`,
`docs/specs/security.md`, and the qualification guidance in
`internal/app/reviewrun`, together with the conversation runner and driver
session interface introduced by TASK-009.

## Problem

The ZCode family's one-shot print invocation launched
`[node, launcher, --mode, yolo, --prompt, <packet>, --json, --disallowed-tools, <list>]`
and parsed a terminal JSON envelope from stdout. The print surface is a
headless compatibility mode: it cannot express the protocol's session
lifecycle, it interleaves provider narration with the result frame, and it
pins the packet transport to a single argv index. The installed ZCode app's
bundled launcher protocol 0.16.5 instead ships a stable app-server protocol
over stdio. Its own TUI and desktop clients use that surface.

## Decision

Replace the print invocation with the app-server protocol conversation and
remove the print path, `zcodeContent`, and `zcodeResponseText` in one atomic
change. Review execution, the qualification capability probe, and the
shareable-profile identity switch together so a certified route never
diverges from the executed route. The qualification version floor rises to
0.16.5, the first locally verified app-server-capable release at the time of
this decision. The current certification floor is recorded separately below.

The staged-file report transport, prompt output-destination layer, manifest
`transport` value `staged_file`, sealed workspace capture, and disposable
credential namespaces are unchanged. The AGY, Kimi, and Codex transports are
unchanged. No user-facing transport configuration is introduced; the transport
stays adapter-owned.

The installed app bundle is the only configured launch authority. Mulgae derives
its Electron runtime and `zcode.cjs`, starts
`[runtime, launcher, app-server, --stdio]` with `ELECTRON_RUN_AS_NODE=1`, and
does not depend on an external Node.js installation.

The conversation runs on TASK-009's runner contract: one dedicated process
group, one request timeout across the whole exchange, a tee-spooled protocol
transcript, and bounded teardown with termination classification. The driver
owns protocol semantics and records its terminal phase, session and turn
correlation, and accepted-operation receipts. The runner owns process facts.

## Wire shapes pinned by the live spike

The live wire-shape spike against bundled launcher protocol 0.16.5 pinned the
following facts, verified end to end including one real model turn:

- Framing is newline-delimited JSON over the child's stdin and stdout. Requests
  are `{"id","method","params"}` without a JSON-RPC `jsonrpc` field; that field
  is rejected as an unrecognized key. Responses echo the request id with either
  `result` or `error`. Notifications are `{"method","params"}` without an id.
  Parse errors return `{"error":{"code":-32700},"id":"parse-error"}`.
- `session/create` requires `workspace` as
  `{"workspacePath","workspaceKey"}` and accepts `mode` from
  `plan|build|edit|yolo|auto` and `toolDenylist` as a string array.
  `titleGenerationEnabled:false` suppresses the auxiliary title model call.
- Immediately after `session/create` the server sends a server-initiated
  `session/requestRuntimePreferences` request (id `server-N`, scope
  `runtime-materialization`, and again at `user-execution` before the first
  turn). The client must answer with an object; `null` is rejected. Mulgae
  answers with a fixed local-only preference object.
- The server also issues non-essential interaction requests such as
  `interaction/requestOfficialMcpAuthHeaders`. Left unanswered they time out
  harmlessly; Mulgae deliberately does not answer them, and a turn that never
  completes fails closed through the conversation's own terminal
  classification.
- `session/send` takes `{"sessionId","content"}` and returns an immediate
  acceptance `{"accepted":true,"sessionId","stateRevision"}`. The turn's
  outcome arrives as notifications: `state.updated` with reason
  `prompt_started`, `prompt_completed`, or `prompt_failed`, and an
  operation-event notification whose params carry `kind:"turn-completed"` or
  `kind:"turn-failed"` with the `turnId`. Telemetry and MCP lifecycle
  notifications stream alongside and must be tolerated.
- After a completed turn, `session/messages` with `{"sessionId","limit"}`
  returns the conversation's messages; the assistant text parts carry the
  qualification probe's controlled evidence, which never appears in the
  protocol transcript itself.
- `session/close` returns `{"closed":true}`, and the server exits 0 after its
  stdin closes. In the 0.16.5 spike, no `--stdio` flag was required;
  `app-server` used its standard pipes by default.
- The plan flow persists `plan-<session>.md` under the workspace's `.zcode`
  area through the plan tools, and session startup can rehydrate plan files
  for persisted sessions found in the credential home. Disposable namespaces
  hold no persisted sessions, and the review denylist denies
  `EnterPlanMode` and `ExitPlanMode`, so the sealed snapshot's drift
  detection keeps rejecting any workspace write.
- The server binds a per-process unix socket under `os.tmpdir()`, so a
  namespace-rooted temp path exceeds the kernel socket path limit and crashes
  the server at startup. ZCode namespaces redirect `TMPDIR`, `TMP`, and
  `TEMP` to the short shared mode-`0700` directory `/tmp/mulgae-zcode`; the
  disposable namespace environment contract admits that one fixed temp
  location alongside the namespace root.

## Consequences

The current adapter passes `--stdio` explicitly in its app-owned launch shape.
This makes the selected wire visible in the fixed argv even though the original
0.16.5 observation showed that standard pipes were already the default.

- Protocol-native failure classification is typed: an unparseable message is
  an output decode failure, a reported `turn-failed` or a missing turn
  completion is a provider turn failure, an unavailable selected model is a
  configuration failure, and a failed create, send, messages, or close exchange
  is a provider execution failure. Stderr token
  classification remains the fallback, notably for login-required states the
  protocol does not represent on the wire.
- A protocol conversation succeeds through its driver: the bounded teardown
  that ends a live server classifies the child as signaled, so one-shot exit
  semantics no longer decide provider success for ZCode.
- A failed conversation keeps the same driver-owned session observation through
  process teardown. Expected SIGTERM cleanup therefore does not overwrite the
  typed protocol failure with a process/observation mismatch. Raw provider
  session and turn identifiers stay in private invocation diagnostics; public
  status uses provider- and kind-bound SHA-256 fingerprints.
- If the adapter cannot assemble a coherent provider observation, it returns
  the stable `provider_execution_observation_rejected` invariant with the
  available process and protocol facts. The provider runtime records those
  facts before failing the attempt.
- Qualification evidence moved from stdout envelope parsing to the
  conversation's captured assistant text, preserving the controlled
  nonce/link/role proof.

## Current certification

ZCode app 3.12.3 is the minimum and currently verified app release for this
adapter. Newer app releases remain eligible as `newer_than_verified`. Mulgae
reads `Contents/Info.plist` without launching the app, binds its
`CFBundleShortVersionString`, path, and SHA-256 identity into qualification, and
revalidates the metadata identity immediately before every provider spawn. Its
bundled `zcode.cjs --version` reports launcher protocol 0.16.5; that protocol
version is what provider qualification observes, so 0.16.5 remains both the
runtime minimum and verified-latest guidance. Certification covers the
app-owned Electron runtime, explicit `zcode.cjs app-server --stdio` launch
shape, projection of API-key personal provider configuration, and
`session/setModel` after create and before the prompt. Mulgae tries the bounded
ZCode reasoning-level vocabulary from strongest to weakest until the selected
provider/model is admitted. No prompt is sent if the selection is unavailable;
that is a configuration failure rather than a registry-order fallback. The app
release and launcher protocol version are distinct axes and must not be compared
or substituted for one another.
