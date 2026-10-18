# EPIC-011 development dossier: AGY stream-json review provider

This adopted temporary dossier records the design and bounded feasibility
findings. Production AGY integration remains owned by TASK-044 and TASK-045.
[Roadmap](../roadmap/README.md#epic-011-agy-stream-json-review-provider) owns
status and dependencies. TASK-043 re-verifies every wire, sandbox, and
credential-isolation fact below against the installed `agy` binary before later
tasks start. A failed check stops the epic.

The original planning baseline was Antigravity CLI (`agy` `1.2.9`) and its
embedded `printmode` and `steps` stream-JSON contracts. TASK-043 preflight
observed version `1.4.0`. That single-account native profile demonstrated workspace/Git reads,
natural exit, tested credential denials and instruction/plugin isolation.
The Judge and two independent Workers passed the final Task result review;
Main accepted TASK-043 under Master's delegation. The declared minimum version
remains `1.2.9`. During TASK-044, the installed CLI changed to `1.4.2`; its
current-binary controls are recorded separately below.

## Goal and scope

Re-admit AGY (`FamilyAgy`, `"agy"`) as a protocol-driven provider over its
bidirectional `stream-json` stdio wire protocol, make AGY the first default
provider preference for the `documentation` role in `assets/roles.yaml`
(`[agy, zcode, grok, codex]`), using one existing Gemini account. Multiple-account
configuration and validation are deferred to the
[AGY multiple-account candidate](agy-multiple-accounts.md). A second account is
not required to implement, verify, or accept EPIC-011.

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
   - Installed `1.4.0` emits `{"event":"step_update","step_update":{"conversation_id":"<uuid>",...}}`
     frames as the turn progresses.
   - Require `step_update.conversation_id` to match the `init` session, record
     `step_index` as `ProviderTurnID`, and mark `TurnObserved` and `MessagesReceived`.
4. **Completion (`result`)**:
   - `agy` emits `{"event":"result","result":{"conversation_id":"<uuid>","status":"SUCCESS","response":"...","structured_output":...,"denied_actions":[...]}}`.
   - Accept assistant evidence text only when `result.conversation_id` matches
     `conversation_id`, `result.status` is `"SUCCESS"`, `result.error` is empty,
     `result.denied_actions` is empty, and `result.response` (or
     `result.structured_output` for schema-bound probes) is non-empty.
   - Close child stdin and verify that `agy` exits `0` cleanly.
   - Native denial-terminated turns can report `SUCCESS` with an empty response
     and nonempty `denied_actions`. Reject them as reviews; they are usable only
     as explicitly expected negative-test evidence.

One process and one new `conversation_id` serve one invocation; conversation
state never carries across roles, retries, repairs, or runs.

## Read-only live-source boundary and tools

Process `cwd` is pinned to the neutral reviewer home under `~/.mulgae/home/`.
The canonical project root is passed via `--add-dir <workspaceRoot>` and named
in the typed review prompt.

Live review, extraction, and qualification must run inside Mulgae's app-owned
macOS Seatbelt boundary. `ports.NewLiveReadOnlyBoundary` receives the
workspace, Git directory, and neutral home as read-only roots; all original
credential homes as denied credential roots; and the disposable namespace as
its writable root. TASK-043 must prove these restrictions with the actual
process adapter before a live AGY route is implemented.

The verified `1.4.0` feasibility profile uses `--mode plan`,
`--disable-slash-commands`, `--add-dir <workspaceRoot>`,
`--gemini_dir <projectedGeminiHome>` and `--agent <appOwnedName>` with the
stream formats above. Before sending `user`, require native `init.agent` to
match the authored name and `init.permission_mode` to be `request-review`.
These are provider configuration acknowledgements, not Mulgae-owned identity.

Create app-owned mode-`0600` settings under the projected home, with
`toolPermission: request-review`, `allowNonWorkspaceAccess: false`, exact
`read_file(...)` and `command(...)` grants for the trusted read plan, and
denies for the projected credential directory, token and protected canary.
Native `strict` discards selective allows; headless approval requests cannot
replace the tested selective policy. No skip-permissions or nested-sandbox
flag is part of this profile. The external CLI rejects
`--include-default-customizations=false` despite its internal compiled binding.

The app-owned Markdown agent lives at
`<projectedGeminiHome>/config/agents/<appOwnedName>.md`. Its tested frontmatter
sets `mainAgent: true`, `subagent: false`, `inheritCustomizations: false`,
`inheritMcp: false`, and `tools: [view_file, run_command]`. Its body is trusted
application policy; import no user agent files. Omitting `tools` from a
selected custom agent chooses native defaults that omit `run_command`, even
when the broad startup inventory includes it. Workspace instructions and
plugin configuration remain untrusted source data.

The outer `NewLiveReadOnlyBoundary` owns filesystem restrictions; native tool
permissions protect the writable projected token from model tools. The plan
flag is not read-only enforcement when slash-command expansion is disabled.
This boundary claims no general network or IPC containment. TASK-044 implements
the tested native profile internally; TASK-045 owns its public route and
real-provider certification.

In addition to Seatbelt enforcement, the protocol driver fails the turn closed
if any `step_update` frame reports a disallowed tool (`write_to_file`,
`replace_file_content`, `invoke_subagent`, `define_subagent`,
`manage_subagents`, `schedule`, browser/web tools, or any MCP mutation tool) or
if `result.denied_actions` is non-empty.

## Single-account credentials and home isolation

By default on macOS, `agy`'s `CompositeTokenStorage` consults the shared macOS
Keychain service (`antigravity`) before falling back to
`<gemini_dir>/antigravity-cli/antigravity-oauth-token`. TASK-043 must verify
file-only authentication for the one account used by this epic.

The adopted design requires `shouldBypassKeyring` to select file-based
`CompositeTokenStorage` whenever `SSH_TTY` is set in the process environment.

The approved execution plan protects original credential homes and projects
only the selected token into a disposable Gemini home:

- Resolve the source home from the default `<operatorHome>/.gemini`.
  Admit only its `antigravity-cli/antigravity-oauth-token` regular, single-link,
  mode-`0600` file through the existing descriptor-anchored projection pattern.
  Missing or unsafe files stop admission; do not scan for alternative tokens.
- Set `SSH_TTY=/dev/null` and pass `--gemini_dir <projectedGeminiHome>`.
  The projected home stays inside the invocation's writable namespace, while
  `HOME` remains the disposable namespace home. Import only the selected token;
  copy no native settings, instructions, plugins, history or logs. The settings
  and agent descriptor above are authored by Mulgae rather than imported.
- Protect the original default Gemini home. Only the trusted projector reads its
  token; the provider child cannot read or modify that original home.
- Confine token refresh to the disposable copy. Never write it back to the
  original home. A need for original-home writes stops the epic.

TASK-043 must verify the installed binary's file-token authentication and
Keychain bypass. Projection alone does not prove that model tools cannot read
the disposable token. Observed model-tool access to that token stops execution
for a security/design decision; event auditing must not be described as
preventing an operation that already ran.

### Configuration contract

| Surface | Required behavior |
|---|---|
| Project policy (`.mulgae/config.yaml`) | Optional `providers.agy.model`, `providers.agy.reasoning_effort` (`low`, `medium`, `high`, `xhigh`, `max`), and `providers.agy.timeout`. No AGY `default_credential_profile` or per-role `credential_profile`. |
| Machine-local authority (`.mulgae/local.yaml`) | `providers.agy.executable`. No AGY `credential_homes`; credentials come from the default Gemini home. |
| Default role preferences (`assets/roles.yaml`) | `documentation` uses `[agy, zcode, grok, codex]`; remaining text roles append `agy` after existing preferences (`[zcode, grok, codex, agy]`). |
| `--providers auto` | Discovers ZCode, Grok, and AGY (or preserves explicit portfolio selection per TASK-045 contract); when AGY is configured, `documentation` defaults to `agy`. |

## Qualification

Version and capability probes use the protocol runner:

- Version check runs `<executable> --version`. Installed `1.4.0` emits plain
  semver; the parser must admit that observed form with minimum floor `1.2.9`.
  This preflight does not establish wire compatibility for an untested binary.
- Capability check runs a single-turn `stream-json` probe with Mulgae-owned
  strict JSON response validation under the same neutral-cwd,
  `--gemini_dir`, and `SSH_TTY=/dev/null` isolation as review.
- Qualification identity binds the `agy` family, executable identity, default
  credential-source identity, and optional `model` and `reasoning_effort`
  (preserving omitted-versus-explicit distinction).

## Stop conditions

TASK-043 stops EPIC-011 when any of these checks fail on the installed `agy`
binary. Later tasks must not weaken a failed check or fall back to `-p`.

| Check | Required evidence |
|---|---|
| `stream-json` handshake & correlation | Receive authenticated `init` before sending `user`; correlate `step_update` and nested `result.conversation_id`; close stdin after the result and require natural exit `0`, complete stdin delivery, no signal requests, and process-group absence. |
| Neutral-cwd workspace & Git reads | From `~/.mulgae/home/`, `agy` reads admitted workspace files and runs read-only `git` diff/show commands under `NewLiveReadOnlyBoundary` without `denied_actions`. |
| Seatbelt write & credential denial | Separate workspace and Git-metadata mutation attempts and protected credential-root reads are denied by Seatbelt and visible in `step_update`. Verify workspace, Git metadata, and credential-canary integrity before and after. |
| Tool visibility | Tool invocations appear in `step_update.tool_info` / `step_update.tool_name` so disallowed tools fail closed on the wire. |
| Single-account file-token isolation | Project the default account token into a disposable `--gemini_dir`; prove file-token authentication with `SSH_TTY=/dev/null`, no Keychain fallback, no provider access to the original home, and refresh confined to the copy. Use an empty-token negative control. Multiple-account isolation is deferred. |

Positive probes use `process.Runner.Converse` through the actual live-source
boundary. The reviewed recovery amendment adds opt-in kernel-owned PTY access
and an explicit exchange stdin half-close. After a correlated result, the
scratch driver must close stdin and drain clean stdout EOF before returning.
A generic protocol-success result after SIGTERM or SIGKILL does not satisfy
the natural-exit check. The existing natural-exit grace remains `150ms`.
This bounded TASK-043 prerequisite supersedes the earlier prohibition on
runner changes; it does not weaken the feasibility criteria.

Authentication-negative probes have separate acceptance conditions. An empty
or malformed projection must produce a bounded, explicit authentication
rejection without successful `init` or a user message. A natural nonzero exit
may be expected. Silence, timeout, forced teardown, or generic launch failure
alone does not prove isolation. Authenticated deliberate-denial probes may
return an expected error or `denied_actions`; they never count as successful
reviews.

## TASK-043 feasibility findings

Installed AGY is `1.4.0`, with SHA-256
`a4502aaf310b2fd6eb657fcfec2fcc31a690fbbd0c2d14c8eefbb556409024ce`.
Observations below are bounded to that binary and the single default account.
They do not establish compatibility for every binary above the declared
`1.2.9` floor. TASK-044 owns production protocol and qualification work;
TASK-045 owns public integration and the exact-binary full review.

### Shared process prerequisites

The production guard initially denied AGY's PTY creation. Its reviewed opt-in
capability uses the kernel-owned PTY extension rather than a general device
exception. Default PTY denial, foreign terminal path and mutating-ioctl denial,
`/dev/tty` denial, source/Git read access, write denial and protected credential
reads are covered. Filesystem denial does not revoke access to a descriptor
that was already open.

An inherited-descriptor experiment exposed that distinction. The correction
uses atomic close-on-exec duplication in the parent and sanitizes inherited
non-stdio descriptors in the trusted launch child, without changing parent
flags or imposing a numeric cutoff. Ordinary and high descriptor canaries fail
to reach providers after the correction. Bound and unbound launches preserve
cwd, arguments, environment and stdin receipts. A real-runner/registry/app
regression verifies that trusted launch failure yields no accepted output,
repair or extraction authority. Existing bounded same-provider retry remains;
exit code `10` is not trusted spawn classification.

A correlated AGY result must be followed by stdin half-close and stdout EOF
draining. The exchange supports explicit `CloseInput`; the shared `150ms`
teardown grace is unchanged. Native positive comparisons exit `0` without
signals and leave no process group. Cancellation and blocked-send tests cover
bounded cleanup.

### Native configuration and account boundary

Default native file and command tools could read the projected synthetic
token. The outer filesystem guard alone is insufficient because the namespace
must remain writable for native authentication. Native `--sandbox` did not
prove denial: nested Seatbelt application returned `Operation not permitted`.
Native permission-reply events are recognized but unsupported in this version.

The final selective `request-review` policy uses exact `command(...)` grants;
`unsandboxed(...)` grants are invalid configuration. Sparse serialization omits
the known defaults `request-review` and `false`; the comparison accepts only
those two absent defaults and rejects explicit unsafe values. Native
credential-canary reads and compound command near-misses produce
operation-specific permission errors before execution, not successful tools.

Root `GEMINI.md` and `AGENTS.md` at source and neutral cwd influenced default
responses. A controlled native agent with inheritance disabled keeps all six
tested instruction tokens absent while preserving actual file/Git reads, unknown
marker values and its body-only selection token. This verifies the tested
route, without attributing the result exclusively to an individual setting.
Four source/neutral tokens appeared on the default route; the two passive parent
tokens did not. This does not establish a general parent-discovery guarantee.

File-only authentication uses `SSH_TTY=/dev/null` and the one projected token.
The empty-token control explicitly rejects authentication before `init` or
`user`, exits naturally nonzero and leaves no group. Original-token integrity
holds. Native logs and compiled file-storage/refresh branches support Keychain
bypass and disposable-file refresh confinement, with original roots denied by
the outer boundary. No live or forced refresh, process-wide Keychain trace,
writeback or second account is claimed.

### Plugin MCP controls and negative-turn interpretation

Native plugin discovery can load source `.agents/plugins/<name>/plugin.json`.
The tested plugin carries both native `mcp.json` and documented
`mcp_config.json` with the same harmless stdio sentinel. A default normal read
turn affirmatively launches it, completes MCP initialize/tool discovery and
EOF, and leaves no matching process. All three plugin files remain intact.
An exact zero-byte global `mcp_config.json` means no global servers; it does
not itself prove source-plugin isolation.

The selected-profile denial turn preserves the complete plugin fixture and
reports no sentinel launch or remaining process. It separately denies both
synthetic credential operations before execution. Its final response is empty,
matching the earlier accepted denial control. The originally required response
nonce therefore fails and that failed run stays failed. Independent assessment
separates native configuration applicability and denial evidence from any
unavailable model response; empty or denied results never become valid reviews.
A matched normal read turn under the selected profile also completes all three
operations, reports both unknown Git marker values and its body-only nonce,
keeps all six instruction tokens absent, and leaves no sentinel journal or
matching process. Its complete source-plugin fixture remains intact, and native
logs show no plugin/MCP discovery errors. This compares the same positive prompt
class with the default control, resolving the denial-turn confound for this
tested profile. The final independent Task assessment passed.

Two credential-free inventory attempts failed before discovery because the
scratch harness placed a global log option after the native subcommand.
The argument order was corrected and regression-tested without replaying those
attempts. Authenticated control calls used no subcommand and were unaffected.
No discovery or suppression claim comes from those failed inventories.

### Verification and remaining delivery boundary

The Judge and two nonauthoring Workers independently reviewed plans and scoped
results, including the matched positive plugin comparison. Main accepted
TASK-043 under Master's delegation. This accepts the bounded feasibility and
shared prerequisites; production integration remains TASK-044 and TASK-045.
Multiple-account configuration and checks remain outside this epic.

Focused process/ports race checks, architecture checks, lint and vet pass.
`make test-unit`, `make test-int` and `make test-release` pass for the shared
candidate. `make test` fails during preparation because `govulncheck` reports
eight installed Go `1.27.1` standard-library vulnerabilities. Master directed
this workflow to retain that toolchain and reserved upgrades for Master. No
upgrade or waiver was made. Mandatory live ZCode/Grok and opt-in Codex targets
were not reached by that full gate; supplementary passes do not replace it.
Non-`EBADF` descriptor-error injection remains untested; inspection confirms
that such errors stop execution. No whole-Epic, release-ready or installed
AGY capability claim follows from these Task-scoped results.

## TASK-044 internal adapter

The internal adapter now implements the pinned profile. Public configuration,
CLI/MCP selection, schemas and default role routing remain TASK-045 work.

The driver accepts one authenticated session and one correlated final result.
It checks the native agent and permission mode before sending the prompt,
correlates tool identity, operands and completion, and returns report text only
after stdin half-close and clean stdout EOF. The registry separately requires
natural exit zero, complete input, no signals and process-group absence. A
successful app-server teardown receipt cannot satisfy AGY's natural-exit rule.

Each invocation authors settings, an explicit two-tool agent and an empty global
MCP configuration through retained private directory descriptors. Auditing
rejects changed policy, agent content, file ownership, links or parent identity;
cleanup unlinks only files created by that installation. An unverified process
drain preserves the protection files and namespace, rejects reuse, and prevents
a successful terminal cleanup receipt. Authentication may refresh the
disposable token, without changing its original source. Source revalidation
checks ownership and the single-link requirement as well as identity and content.

Qualification stays prompt-bound and tool-denied. Its final JSON must bind the
fixture's root, link and role. The proof hashes the final namespace-bound argv
and binds the admitted default credential source. The observed CLI version and
exact runtime identity authorize later codec comparison. The explicitly
inspected `1.4.0` and `1.4.2` codecs may omit the two established defaults.
Other omissions fail closed; the version floor does not certify an untested
intermediate or future codec.
AGY qualification is not shared across independently seeded namespaces. Model,
effort, executable or source changes invalidate the applicable authority.
Its read-only cwd uses the namespace's separate scratch directory, so the
projected Gemini home remains writable. The plain version probe uses the
one-shot runner's successful exit; stream conversations additionally require
their explicit lifecycle receipt.

Scripted tests cover wire rejection, profile drift and rollback, token admission,
qualification and live review/extraction request composition. These tests do not
replace TASK-045's exact-binary review with the real single-account provider.
An actual process-runner test separately verifies that the qualification
boundary permits disposable token writes while denying source and neutral-cwd
writes and original credential reads. This fixture uses synthetic credentials.
Explicit model/effort selection with this profile has not yet been certified by
a live review.

Independent result review found that native `command(...)` grants use token
prefix matching for ordinary POSIX Git reads. Additional safe arguments and
compounds composed of covered commands can pass; equivalent quoting can also
match. The driver's byte-exact check runs after native execution and therefore
does not prove prevention. Main accepted the Judge's rework finding. A fixed
`LC_ALL=C` assignment does not change that selector and was rejected as a
correction without being implemented. An indexed assignment alone was also
rejected because its tokenized grant admits a separate numeric fallback.

AGY translates each app-owned Git read into
`MULGAE_READ_GUARD[1]=1 <native_git_command>` inside the AGY adapter and adds
`command(1)` to the native deny list whenever command reads exist. The
inspected native matcher compares indexed-assignment requests as raw commands;
its alternate tokenized grant begins with `1`, which the deny blocks before
allows and hardcoded allowances. Native raw comparison trims surrounding
whitespace; the driver's completed-operation map remains byte-exact. Policy,
agent instructions and driver authority use the same guard. Shared read plans,
packets and other providers' commands are unchanged.

Command-bearing profiles accept only the established `1.4.0` and `1.4.2`
codecs, bound to the qualified runtime and executable identity. Other command
codecs fail before prompt/tool execution, including uninspected `1.4.1`.
Command-free profiles retain explicit-policy validation, and the `1.2.9`
admission floor stays unchanged. The safety-policy identity changed to
invalidate earlier qualification authority.

### Current `1.4.2` native controls

The installed binary is `1.4.2`, SHA-256
`74935642426b5bb1fcf07a5555f847c478f4517dd002c72b9c98159cb773b932`.
The earlier `1.4.0` observations remain historical. Rebuilt current-binary
inspection confirmed the matching, deny precedence, sparse defaults and
`SSH_TTY` file-mode paths. Its Markdown parser instruction sequence changed,
so static inspection alone did not establish effective profile isolation.

One authenticated startup control reached `init` but found no MCP journal in
its immediate pre-user snapshot. It sent no user frame and stopped. That
inconclusive result establishes no general startup-order rule or suppression
claim. The reviewed replacement used identical positive prompt bytes instead.

Six authenticated controls then passed using one immutable synthetic
source/plugin fixture and fresh disposable namespaces for the default account:

| Control | Observed result |
|---|---|
| Default-agent positive | The explicit guarded Git read returned its hidden marker. The source MCP sentinel completed initialize, tools/list and EOF. The response, input and process lifecycle completed naturally. This is a control observation, not a qualified review. |
| Selected-agent matched positive | The production driver received exactly the same user prompt and completed the same guarded read. The sentinel did not launch at init, during the turn or after verified drain. |
| Canonical read-plan positive | The production prompt supplied only the original bare `native_git_command`. The selected agent issued the guarded command and returned the hidden source marker through the unmodified driver. |
| Appended safe operand | The exact extended command received a native pre-execution permission denial. |
| Numeric fallback | `1 1 git ...` received a native pre-execution permission denial, not command-not-found. |
| Guard omitted | The bare Git command received a native pre-execution permission denial. |

Both selected positives had zero occurrences of all six undisclosed instruction
canaries across response, frames, stdout, stderr, native log and ANSI carriers.
Their native agent/mode acknowledgements and policy/agent/MCP audits passed.
All positive turns completed input, half-close and EOF with natural exit zero,
no signals and process-group absence. The negatives returned no accepted
report. Original credentials, source/Git metadata, canaries and plugin files
stayed intact; namespaces were removed only after verified drain. The single
inconclusive control plus six passing controls consumed seven authenticated
invocations, without automatic retries.

The matched pair uses a test-only baseline driver and the production selected
driver. The result applies to that fixture/profile and exact binary; individual
native flags were not tested separately. The tests' diagnostic
`--log-file` argument preserves the original request's executable, environment,
packet binding, timeout, launch descriptor and filesystem/PTY authority.
In-memory codec selection in these controls issues no production qualification
certificate. TASK-045 still owns public qualification and the exact
release-binary review. No process-wide Keychain tracing, live refresh, forced
refresh, general network/IPC isolation or second-account validation is claimed.

Focused race checks and the offline sentinel/request-authority/baseline-admission
checks pass. Repository unit, integration and release-binary checks also pass,
along with lint, vet, architecture tests and vet with the live-provider tag.
The Judge and two independent Workers passed the actual implementation and
final check evidence. Main accepted TASK-044 under Master's delegation.
TASK-045 retains public integration and exact release-binary AGY certification.
The prior full `make test` failed at the fixed Go `1.27.1` standard-library
vulnerability check, with no waiver. Whole-Epic readiness remains blocked.

## TASK-045 integration findings

Public configuration, optional automatic AGY discovery, role defaults, runtime
composition, CLI/MCP projections and current live-publication readers now admit
the single-account route. Command-result v21, doctor v7, heartbeat v4 and
preflight v9 have paired schemas and examples; earlier contracts retain their
bytes and meanings. Legacy provider-evidence v4 does not acquire an AGY
certificate producer or production reader. Current live AGY reads require
validated source/target/support binding; historical captured/composite AGY and
all Kimi lineage remain retired.

Focused regressions cover configuration ownership, role generation, strict
parsing, optional native settings, capability admission, current/historical
readers, parenthesized grants and undrained namespace preservation. An isolated
compiled-binary regression proves that heartbeat acquires its dedicated
`agy-logic` namespace even when generated AGY routing is documentation-only.
That fake-version fixture is wiring evidence, not native certification.

The first public native gate exposed a missing AGY case in the offline version
observer; its regression failed before the correction and passed afterward.
The next native qualification exposed 1.4.2 saving an empty allow list by
omitting `permissions.allow`. A diagnostic-only build recovered the nested
profile-audit error, with instrumentation removed byte-for-byte from source.
The correction recognizes that equivalent empty set only for 1.4.2. Exact
negative cases retain rejection of null, added grants, nonempty omissions,
other codecs and altered deny policy. The focused race gate passes.

After that correction, native qualification returned four identical JSON
proofs with `num_turns: 4` while `--json-schema` was supplied. Omitting only
that native flag in a diagnostic overlay produced one exact proof and
`num_turns: 1`; the authorized synthetic heartbeat succeeded. Production now
uses the dossier's structured-response-validation alternative. The strict
three-field proof validator is unchanged and still rejects repeated JSON,
narration, extra or duplicate fields, and incorrect bindings. The argv binding
regression failed before the correction and the focused race checks passed
afterward. Diagnostic overlays are investigation evidence, not the production
binary's final certification.

The standalone `make test-agy` gate uses one default account, one top-level
review attempt and a source-only nonce on a parenthesized path. The production
gate passed on native 1.4.2: one initial documentation invocation returned the
marker, published a valid live-source review, and supported status, inspection,
complete report reads, report rendering and redacted export. All seven exported
JSON members were read back. Original token/source/Git state remained unchanged
and private namespace/workspace roots were removed. Successful diagnostics
retain natural process exit data; trusted driver and lifecycle checks enforce
half-close, EOF, complete input, no requested signals and process-group absence
before publication. Earlier failed gates retain their failed outcomes.
Unit, integration, release-binary, static and mandatory ZCode/Grok live checks
pass. One mixed-provider run failed when the logic report transcribed one source
marker digit incorrectly; the native read result contained the correct marker.
The unchanged gate then passed, including its independent capability checks.
The Judge and two nonauthor Workers found no new implementation defect and
verified the passing live evidence. Main accepted TASK-045 under Master's
delegation; Epic integration review remains pending. The
current `make test` still stops at eight Go 1.27.1 standard-library advisories;
the toolchain stays fixed and no waiver is recorded. This section records
Main's delegated Task acceptance, not Master's Epic acceptance.

## Intended owners

| Owner | Responsibility |
|---|---|
| `internal/adapters/providercli/agy_protocol.go` | `stream-json` session order (`init`, `user`, `step_update`, `result`), tool-audit rejection, and report extraction. |
| `internal/adapters/providercli/protocol_dispatch.go` | Register the adapter-owned `FamilyAgy` across all protocol purposes. |
| `internal/adapters/providercli/live_execution.go` & `qualifier.go` | Seatbelt launch, neutral-cwd execution, `--gemini_dir` + `SSH_TTY=/dev/null` binding, and qualification probes. |
| `internal/app/config` & `internal/adapters/config` | Single-account `AgyProviderConfig` (`executable`, `model`, `reasoning_effort`, `timeout`). |
| `assets/roles.yaml`, schemas, help, and contributor specs | TASK-045 only. TASK-044 leaves public schemas and default role routing unchanged. |

## Non-goals

- No `-p` / `--print` fallback and no `BoundedPostOutputLifecycle` resurrection.
- No loopback TCP `--hub` or internal gRPC/Connect transport.
- No automatic provider or profile substitution when AGY fails.
- No persistent multi-turn sessions across review roles or attempts.
- No AGY named credential profiles, multiple-account selection, or
  multiple-account validation in EPIC-011.

## Closeout

After TASK-045, promote the pinned `stream-json` wire, Seatbelt permission
rules, single-account `--gemini_dir` credential boundary, and `documentation`
default routing into the provider contracts, security requirements,
`final-provider-portfolio.md`, and one transport ADR. Remove this dossier and
its TODO index entry, replace the roadmap's `Detailed SOT` with `Canonical
Outcomes`, and accept the epic explicitly.
