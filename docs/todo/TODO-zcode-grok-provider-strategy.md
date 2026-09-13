# ZCode-first review with Grok recovery

Status: Adopted active dossier

Consumer epic: [EPIC-004](../roadmap/README.md#epic-004-zcode-first-review-with-grok-recovery)

## Outcome

Mulgae ends the epic with exactly three provider families: ZCode, Grok, and
Codex. ZCode remains the configured provider for every default role. Grok is a
supported operator-selected route for text-role recovery and separate new
reviews. Grok does not support the artist role in this epic. Codex remains
available for selective use. Kimi and AGY are retired from current
configuration, execution, artifact consumption, and release certification.

The implementation must preserve the product boundaries and ownership in the
[goals](../specs/goals.md), [architecture](../architecture/README.md),
[contracts](../specs/contracts.md), and [security requirements](../specs/security.md).
Delivery must add an architecture decision record for the structural and
compatibility rationale. This dossier is temporary and does not become a
second owner of durable runtime behavior.

## Fixed decisions

### Portfolio and release boundaries

- TASK-011 retains the current provider order and automatic selection. It adds
  no production Grok route.
- TASK-012 publishes a five-provider contract ordered `kimi`, `zcode`, `agy`,
  `grok`, `codex`. Grok is fully supported for text roles and rejects artist
  assignments before execution. Automatic init still selects only ZCode.
- TASK-013 publishes the final order `zcode`, `grok`, `codex`. Automatic init
  configures ZCode and Grok and assigns every enabled default role to ZCode.
  Codex is configured only when explicitly selected.
- The root `assets/roles.yaml` owns role defaults. Generated Go must not restate
  them. One role still runs on one provider, with no automatic substitution or
  consensus semantics.

Each completed task has its own internally consistent public contract. A later
task never narrows an already published schema version in place.

| Completion boundary | Provider set | Command result | Doctor result | Provider contract evidence | Heartbeat result | Review preflight |
|---|---|---|---|---|---|---|
| TASK-011 | Kimi, ZCode, AGY, Codex | v8 | v2 | v2 | v1 | v3 |
| TASK-012 | Kimi, ZCode, AGY, Grok, Codex | v9 | v3 | v3 | v2 | v4 |
| TASK-013 | ZCode, Grok, Codex | v10 | v4 | v4 | v3 | v5 |

For each new version, update CLI and MCP projections, discovery arrays, enum
values, cardinality bounds, registry entries, one paired valid example, and
semantic tests. Historical generic schema bytes and their required examples
remain available for explicit backward validation. They do not grant current
consumption authority to a Kimi or AGY artifact.

### Recovery and reassessment

| Situation | Operator workflow | Admission rule |
|---|---|---|
| An admissible root has a missing selected-role result | Assign that role to Grok explicitly, run `rerun --replay recompose` for the failed attempt, then compose after every missing selected role is recovered | Preserve every accepted root result and bind recovery to the immutable source target and lineage |
| The operator dislikes an accepted role result | Assign the role to Grok explicitly and start a new `review` | Capture a new target and keep the result separate; never compose it over the accepted root role |
| A failure has no admissible recovery source | Reconcile the failure and start a new review when appropriate | Do not bypass recovery admission or reconstruct authority from diagnostics |

Provider-changing recomposed recovery requires a verified captured archive. If
that source is unavailable, fail closed and use a new review rather than
recapturing the live tree while claiming same-target recovery. Exact replay
retains its source provider and is not a provider-switch mechanism. Compose
continues to reject accepted-role replacement with
`composite_role_already_satisfied`.

### Invocation output authority

| Invocation purpose | Output authority | Required handling |
|---|---|---|
| Initial, retry, and repair role reports | Exact invocation-owned staged report file | ACP events and stdout never substitute for the report |
| Structured extraction | Typed assistant-message content from the matching ACP conversation | Correlate the JSON-RPC request and session, accept only selected `agent_message_chunk` text after valid prompt completion, then apply existing structured and semantic validation |
| Qualification | Version and capability result for the admitted executable and driver | Never grants role-report publication authority |
| Heartbeat | Purpose-specific liveness result | Never grants role-report or qualification authority |

Raw JSON-RPC stdout, reasoning content, tool output, completion metadata, and
unrelated session events never become extraction content. Malformed output,
cancellation, or protocol failure discards the extraction result without
changing the semantics of an already accepted free-form report. Preserve the
existing invocation budget and do not add retries, provider substitution, or a
provider-content byte ceiling.

### Grok transport and configuration

- Use the native Apple Silicon Grok CLI only through `grok agent stdio`. Do not
  use `--single`, headless print extraction, a shell wrapper, a fallback
  transport, or persistent provider sessions. The adapter uses the CLI's
  default model and reasoning behavior; no public Grok model or reasoning
  setting is added.
- Reuse the existing workspace lease, provider namespace, credential projection,
  generic conversation runner, and ZCode staged-file lifecycle. Do not add a
  second isolation framework. Mulgae creates one invocation-owned directory and
  exact report filename, validates it descriptor-safely, and cleans it on every
  exit. Cleanup failure overrides an otherwise successful result.
- `.mulgae/config.yaml` may set only `providers.grok.timeout`.
  `.mulgae/local.yaml` owns `providers.grok.executable`. Init and local refresh
  add `--grok-executable`; no authentication-home, model, reasoning, transport,
  permission, or sandbox flag becomes public configuration.
- Extend the existing namespace with `home/.grok` and `GROK_HOME`. Project only
  a descriptor-verified regular `<native_user.home>/.grok/auth.json` with mode
  `0600`. Generate the Grok sandbox and configuration policy inside the same
  disposable namespace. Grok may create session, cache, and generated default
  files there; none survive namespace drain.
- The generated `mulgae` sandbox profile extends Grok's `workspace` profile and
  denies the canonical native user home plus the canonical live project root
  when it is outside that home. The captured workspace and staged output remain
  under the existing Mulgae namespace authorities. Do not add an external
  `sandbox-exec` layer or depend on Grok's built-in `strict` or `read-only`
  profiles.
- The sterile home contains no folder-trust grant, and the adapter never passes
  `--trust`. Generated configuration disables plugins, managed remote
  configuration, codebase indexing, vendor compatibility discovery, and managed
  MCP gateways. A generated managed policy uses an empty MCP allowlist and
  disables project MCP servers. A discovered project MCP entry may remain
  visible as disabled metadata, but it must never start or expose tools.
- TASK-011 must bind the admitted executable and generated policy to this exact
  review launch:

  ```text
  grok --no-auto-update --sandbox mulgae --disable-web-search --no-subagents \
    --permission-mode dontAsk --tools read_file,grep,list_dir,Write \
    --deny MCPTool agent --no-leader stdio
  ```

  Qualification, heartbeat, and extraction expose no filesystem tools they do
  not need.

### Validated ACP planning baseline

An authorized planning spike on 2026-09-13 used the local native Grok CLI
1.0.30 and ACP v1. It used disposable fixtures and deleted every temporary
artifact. These results define the implementation direction, but do not
replace TASK-011 tests or release-binary live evidence.

| Observation | Planning consequence |
|---|---|
| `initialize`, projected `cached_token` authentication, `session/new`, `session/prompt`, and `session/close` succeeded | Use one ACP v1 conversation per invocation and reject an incompatible negotiated protocol |
| Matching `agent_message_chunk` updates produced the requested assistant text and `end_turn` completed a normal prompt | Use correlated assistant chunks only for structured extraction; keep staged files authoritative for role reports |
| The client advertised no filesystem or terminal callbacks; Grok still used its own tools | Enforce the built-in tool surface with argv, Grok's sandbox, and ACP permission decisions rather than client capability omission |
| A custom `workspace` profile denied an existing native-home sentinel while allowing captured input | Reuse Mulgae isolation and add a generated Grok policy that denies the native home and live project root |
| Built-in `strict` and `read-only` refused to start because `/var/run/docker.sock` is an OrbStack symlink | Do not make either built-in profile a prerequisite for Grok support |
| `bypassPermissions` allowed an unexpected sibling write | Never use `bypassPermissions` or `always-approve` |
| Under `dontAsk`, `session/request_permission` carried structured `kind`, `toolCallId`, and `rawInput.file_path`; exact `allow_once` produced only `role-report.md` | Authorize exactly one correlated write to the invocation-owned destination and validate the final directory independently |
| Rejecting an unexpected write prevented the file and ended the prompt with `stopReason=cancelled` | Treat any rejected or unrecognized request as a terminal security failure; do not expect the turn to continue |
| A project MCP definition was discovered but the empty managed allowlist marked it disabled and its sentinel process did not start | Require policy lockdown plus `mcpServers: []`; discovery metadata alone is not a violation, but any started server is |
| `promptCapabilities.image` was `false` | Support Grok for text roles only and reject artist assignment in preflight |
| The ACP server remained alive after `session/close` and exited by adapter-owned SIGTERM | Accept intentional post-close termination only after valid completion and close receipts; still prove process-tree drain and cancellation |

### Remaining ACP enforcement gate

TASK-011 turns the observed shapes into adapter contracts and completes the
unverified lifecycle cases. Command availability and capability negotiation
alone do not satisfy this gate.

| Boundary | Required evidence |
|---|---|
| Captured input | Preserve the observed captured read and native-home denial; add live-project, traversal, symlink, `grep`, and `list_dir` fixtures |
| Report writes | Correlate session, `toolCallId`, `kind=edit`, `rawInput.variant=Write`, `rawInput.file_path`, and tool-update location; permit one exact `allow_once`; reject sibling, traversal, symlink, and a second write |
| Shell, web, subagents, escalation | Prove the final tool allowlist and defense-in-depth denies remove each path; every unexpected server request fails the invocation |
| Ambient state | Prove project instructions, hooks, plugins, compatibility sources, remote managed configuration, and active MCP tools are absent; disabled MCP metadata is allowed only when no server starts |
| Credentials | Preserve successful projected authentication and prove ambient credential fallback cannot succeed |
| Process and leader lifecycle | Prove timeout and external cancellation, request drain, `session/close`, process-group termination, namespace cleanup, and non-interference with unrelated leaders |
| Executable identity | Qualification and execution use the same admitted executable and driver; update behavior cannot replace the certified route |

Use 1.0.30 as the minimum observed CLI baseline and ACP v1 as the required wire
major. A future CLI version enters the supported release matrix only after the
same live contract checks pass. Pin the authentication, initialization, session,
content-update, completion, permission, and cancellation shapes in tests. If the
remaining access, credential, update, or process boundary cannot be established
on macOS, TASK-012 remains blocked. Do not weaken the boundary, switch
transports, import the user's full configuration, or treat mocked success as
live certification.

This gate verifies Mulgae's declared provider and tool boundaries. It does not
claim a general-purpose sandbox against an arbitrarily malicious executable.

Official design references:

- [Grok headless and ACP scripting](https://docs.x.ai/build/cli/headless-scripting)
- [Grok permissions](https://docs.x.ai/build/features/permissions)
- [Grok sandbox](https://docs.x.ai/build/features/sandbox)
- [ACP initialization and capabilities](https://agentclientprotocol.com/protocol/v1/initialization)
- [ACP tool calls and permission requests](https://agentclientprotocol.com/protocol/v1/tool-calls)

### Artist capability

Grok CLI 1.0.30 advertised `promptCapabilities.image: false` during the live ACP
initialization. TASK-012 therefore supports Grok only for text roles. A Grok
artist assignment fails before provider execution with
`provider_capability_unsupported` and exit `4`. ZCode remains the default artist
provider, and Mulgae never redirects that role silently. Image support requires
a separate future roadmap task with PNG, JPEG, and WebP body-inspection evidence.

### Retirement admission and structural cleanup

TASK-013 owns one application-level retirement predicate. An artifact is
retired when Kimi or AGY appears in its selected assignments, attempts,
accepted-report provenance, recovery manifest, or any transitive source
lineage. Generic filesystem, schema, and digest-validation primitives do not
own this provider policy.

| Case | Required behavior |
|---|---|
| Mixed supported and retired assignments | Reject the complete run; do not filter evidence or recompute historical authority |
| Supported effective composite with a retired root or ancestor | Reject the composite through the transitive predicate |
| Failed-run recovery naming a retired provider | Reject status consumption, replay, and composition; retain cleanup protection until structural checks pass |
| Retired and supported runs coexist | Exact supported-run queries and new execution remain unaffected |
| Cleanup inspects a retired run | Permit trusted structural identity, integrity, dependency, and safe-path reads without exposing reports or restoring execution support |
| Old config still names Kimi or AGY | Block normal config-consuming commands, but allow the existing confirmed cleanup flow to use its narrow structural authority |

`status`, `findings`, `report`, `export`, `followup`, `delta`, `rerun`, and
`compose` fail with `retired_provider_artifact` and exit `7` for a retired
artifact. Generic `clean` may delete an otherwise eligible retired run only
after existing exact-identity, manifest and digest, dependency, state, safe-path,
and operator-confirmation checks. Retirement does not manufacture corruption
or override protection for active, uncommitted, corrupt, or dependency-protected
runs. No public bypass flag, migration, or automatic deletion is added.

Configuration remains v3 as an explicit provider-retirement exception. A
`config.yaml` or `local.yaml` containing a Kimi or AGY provider block, role
assignment, credential field, or provider-semantic local field fails with
`config_provider_retired`. Normal config-consuming commands exit `2`; `doctor`
reports degraded readiness and exits `4`. Inspect parsed provider-semantic
fields, not arbitrary text containing a retired name. Diagnostics direct the
operator to ZCode, Grok, or Codex without rewriting or deleting either file.
Removed init names and Kimi/AGY override flags are invalid usage and exit `2`.

Removal acceptance requires no active Kimi/AGY configuration, discovery,
execution, credential projection, transport, help, or release route. Historical
roadmap, changelog, decision records, schema bytes, retirement diagnostics, and
negative fixtures may retain the names.

## Ordered delivery

### TASK-011: dispatch authority and live go/no-go

Move review, extraction, qualification, and heartbeat protocol selection behind
one channel-plus-driver authority owned by the provider adapter registry. The
driver constructor, not a second family switch, determines the wire protocol.
Preserve the existing ZCode purpose-specific output behavior and resolve
`DF-001`. Turn the validated ACP planning baseline into deterministic contracts,
then complete the remaining enforcement and lifecycle matrix before any
production Grok route is added.

Focused verification includes
`TestZCodeProtocolDriveRequestShapes`,
`TestZCodeProtocolDriveCompletesAndPreservesEvidence`, and
`TestZCodeProtocolDriveClassifiesFailureBranches`, plus new Grok driver tests
for correlation, structured permission admission, project-policy suppression,
output selection, denial, cancellation, leader lifecycle, and cleanup. Run
`make test-prepare`, `make test-unit`, and `make test-int`. Exact-binary live
completion of the remaining matrix requires separate authorization and isolated
fixtures. A failed security or lifecycle gate blocks TASK-012.

### TASK-012: complete five-provider Grok support

Implement Grok through the established domain, application, port, adapter,
composition, CLI, MCP, schema, help, and test boundaries. Add explicit init,
qualification, heartbeat, text-role review, provider-changing recomposed
missing-role recovery, and Grok artist preflight rejection. Publish the
five-provider contract in the TASK-012 versions above. Existing automatic
selection and all four outgoing provider routes remain supported at this
boundary.

Tests cover every provider in valid single and mixed configurations, Grok's
purpose-specific output, a free-form report followed by extraction through
final findings and CI projection, exact write authorization, hostile project
configuration suppression, failure and cleanup precedence, text-role Grok
recovery, artist rejection, and continued rejection of accepted-role
replacement. Run
`make test-prepare`, `make test-unit`, `make test-int`, and `make test-release`,
then use the new `make test-grok` target for an authorized live review through
the exact release binary.

### TASK-013: atomic final portfolio and retirement

Remove active Kimi and AGY implementation, configuration, overrides, discovery,
qualification, credentials, transports, fixtures, generated assets, help, and
release routes. Preserve the historical and negative material allowed above.
Publish the final three-provider contract versions. Change automatic init to
configure ZCode plus Grok with every default role assigned to ZCode.

Replace mandatory live certification with ZCode and Grok. Keep deterministic
Codex configuration, credential-profile, routing, output, failure-mapping,
CLI/MCP, and exact-binary coverage in mandatory non-live gates. Convert
`test-e2e-opt-in` to Codex-only primary and secondary profile scenarios and
remove `make test-kimi` plus every Kimi/AGY live prerequisite. Update the
Makefile, Gaori configuration, `AGENTS.md`, embedded help, public documentation,
implementation guidance, and the new decision record together so their release
instructions agree.

Tests cover typed retirement for both config files, mixed and transitive
artifact lineage, cleanup-only inspection, supported ZCode/Codex historical
reads, and isolation from unrelated retired history. Run both required
generators twice; the second pass must add no diff. Final acceptance requires
`make test`, including mandatory live ZCode and Grok certification. When Codex
live testing is authorized, run
`MULGAE_E2E_OPT_IN=1 make test-e2e-opt-in`; otherwise record its stable skip.
Once enabled, missing or unsafe Codex prerequisites and provider failures are
hard failures.

## Acceptance and handoff

- TASK-011 establishes one driver authority, preserves all current ZCode
  purposes, codifies the observed text-only Grok boundary, and proves the
  remaining ACP enforcement matrix. Protocol negotiation alone is insufficient.
- TASK-012 exposes a release-binary Grok route with a valid five-provider
  contract, purpose-specific output handling, typed failures, safe cleanup, and
  explicit text-role recovery while rejecting artist assignments before launch.
- TASK-013 proves ZCode/Grok automatic configuration, ZCode-only default role
  assignment, optional Codex use, strict retirement, structural cleanup, and
  aligned live and deterministic release evidence.
- Every embedded schema keeps exactly one valid example and semantic tests.
  Both generators run twice whenever embedded assets change.
- Implementation, installation, authentication changes, provider configuration,
  commit, tag, push, release, and activation retain separate later authorization
  boundaries. EPIC-004 closeout promotes durable behavior to its canonical
  owners, replaces `Detailed SOT` with canonical outcomes, then removes this
  dossier and its TODO index entry.

## Non-goals

- Automatic failover, multi-provider consensus, or accepted-role replacement.
- Same-target claims for a new reassessment review.
- New Codex transport, profile, model, or reasoning behavior.
- A generic provider plugin framework, persistent provider sessions, new
  platforms, or Grok transports other than ACP stdio.
- Migration, conversion, or automatic deletion of Kimi/AGY configuration,
  credentials, or artifacts.
