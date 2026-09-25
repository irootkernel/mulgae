# Mulgae

![Six seal reviewers independently inspect an immutable code snapshot and file separate reports in a local archive.](docs/assets/mulgae-hero.webp)

Mulgae is a local, multi-provider AI code review CLI and attached MCP server. It captures an immutable
review target, asks role-specific reviewers to inspect it, publishes their
free-form role reports, transcribes those reports into structured findings whose
evidence it verifies against the captured target, and commits durable artifacts
under `.mulgae/`.

Mulgae is advisory. It reports findings and recommendations; it does not grant
merge, release, waiver, or organizational approval.

## Platform and providers

The initial release supports macOS on Apple silicon (`darwin/arm64`) and these
provider families:

- ZCode
- Grok CLI
- Codex CLI

The default `mulgae init` topology requires a ZCode app bundle with a current
Z.AI Individual Coding Plan connection and an authenticated Grok installation,
and assigns every default role to ZCode. Codex remains available
through explicit `--providers codex` selection. Mulgae records
provider identity and capabilities at runtime and fails closed when a required
capability is unavailable. Other operating systems, architectures, and provider
families are not supported by the initial release.

### Use Codex from Mulgae

Install Codex CLI 0.154.0 or newer and sign in with the CLI before initializing
Mulgae with Codex as a review provider. A legacy single-profile configuration
uses Codex's native `~/.codex/auth.json` login state. Mulgae does not accept an
API-key environment variable or a project-configured credential.

```bash
codex --version
mulgae init --providers codex
mulgae providers --include-unverified
```

The model and reasoning effort are optional. Omitting them preserves Codex CLI's
current defaults. Set them at initialization only when the project requires a
pinned choice:

```bash
mulgae init --providers codex \
  --codex-model gpt-5.3-codex \
  --codex-reasoning-effort high
```

Mulgae starts one ephemeral Codex app-server thread and turn per invocation over
stdio. It accepts the final assistant message as the role report after successful
turn completion. Each invocation uses a disposable `CODEX_HOME`, a
descriptor-anchored copy of `auth.json`, the immutable captured workspace, a
read-only permission profile, and disabled web, app, plugin, browser, hook,
image-generation, and multi-agent features. Project instructions and user
configuration are ignored.

To use more than one authenticated Codex environment, declare the default
credential profile in the Git-shareable project policy and bind each profile to
an explicit `CODEX_HOME` in the private local configuration:

```yaml
# .mulgae/config.yaml
providers:
  codex:
    default_credential_profile: "personal"
roles:
  logic: {enabled: true, primary_provider: "codex"}
  security: {enabled: true, primary_provider: "codex", credential_profile: "work"}
```

```yaml
# .mulgae/local.yaml
providers:
  codex:
    executable: "/Users/operator/.local/bin/codex"
    credential_homes:
      - profile: "personal"
        home: "/Users/operator/.codex"
      - profile: "work"
        home: "/Users/operator/.codex-work"
```

Profile IDs are operator-chosen authentication aliases, not executable names;
they use lowercase kebab-case. The local entries must match the default profile
plus every role override exactly and remain in lexical order. Mulgae
reads only `auth.json` from each configured home. Model, reasoning, and timeout
remain shared Codex project policy; `config.toml`, rules, skills, plugins,
hooks, and ambient `CODEX_HOME` are not inherited. Use the real `codex` binary
for every profile rather than a wrapper that rewrites `CODEX_HOME`.

### Use ZCode from Mulgae

ZCode is distributed as a macOS app rather than as a `zcode` executable on
`PATH`. Mulgae runs the app's own Electron runtime and bundled app-server
launcher, so a separate Node.js installation, wrapper, or symlink is not
required. Install ZCode, sign in to Z.AI, and select the Individual Coding Plan
in the app. ZCode app 3.12.3 is the minimum and currently
verified app release; newer app versions remain eligible but are reported as
newer than verified. Its bundled launcher reports protocol version 0.16.5,
which has its own independent minimum and verified-latest value. Then initialize Mulgae:

```bash
mulgae init --providers zcode
mulgae providers --include-unverified
```

The standard app location is `/Applications/ZCode.app`. If the app is installed
elsewhere, provide its canonical absolute bundle path:

```bash
mulgae init --providers zcode \
  --zcode-app-bundle "/path/to/ZCode.app"
```

Mulgae derives the app runtime and launcher from that bundle, binds their exact
identities and the bundled provider config, and invokes app-server with
`ELECTRON_RUN_AS_NODE=1`. The certified provider catalog is
`Contents/Resources/config/provider/zcode-builtin.json`. Mulgae reads the
current account connection and credential from ZCode's v2 app state and bridges
them to app-server without copying credentials into the disposable review home.
Mulgae does not read or migrate `~/.zcode/cli/config.json`.
An optional shared model and reasoning effort can be recorded independently:

```bash
mulgae init --providers zcode \
  --zcode-model account:zai-individual-coding-plan/GLM-5.3 \
  --zcode-reasoning-effort high
```

If either value is omitted, app-server keeps its default for that dimension.

### Use Grok from Mulgae

Install Grok CLI 1.0.34 or newer and sign in before selecting it explicitly.
Version 1.0.40 is the latest release verified for Mulgae's exact ACP selection
contract; newer releases remain eligible but require a current qualification:

```bash
grok --version
mulgae init --providers grok --grok-executable "$(command -v grok)"
mulgae providers --include-unverified
```

New projects default Grok to `grok-4.7` with `high` reasoning effort and record
both values in Git-shareable policy. Either dimension can be overridden
independently during initialization:

```bash
mulgae init --providers grok \
  --grok-executable "$(command -v grok)" \
  --grok-model grok-4.5 \
  --grok-reasoning-effort high
```

The values are stored only in `.mulgae/config.yaml`; the executable remains in
untracked `.mulgae/local.yaml`. Mulgae preserves their exact spelling and
requires Grok to acknowledge the configured selection before it sends a prompt.
Existing Config v4 projects that omit either field continue to use Grok's
provider default for that dimension; removing a generated field restores that
behavior.
Grok uses ACP v1. Mulgae copies
only the native Grok authentication file into a disposable home, suppresses
project and user configuration, disables MCP servers, and installs an
adapter-owned workspace policy. A text-role review may authorize one correlated
`Write` request to its exact staged `role-report.md`; assistant text is used only
for qualification and structured extraction. Grok does not advertise image
prompt support, so assigning it to `artist` fails before provider execution with
`provider_capability_unsupported` and exit 4.

## Install

Mulgae requires Go 1.27.1 or newer.

```bash
go install github.com/irootkernel/mulgae@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`, then verify the installation:

```bash
mulgae version
mulgae version --json
mulgae --help
```

No asset archive is installed beside the binary. Schemas, prompts, roles,
examples, and help text are embedded in the executable.

## Quick start

Run Mulgae from the root of the Git repository you want to review:

```bash
cd /path/to/repository
mulgae init
mulgae config
mulgae providers --include-unverified
mulgae review --diff origin/main...HEAD \
  --objective "Review this change before merge."
```

`doctor --output json` returns `mulgae-doctor-result.v5`. It checks Config v4,
project-local security, provider and role identities, exact executable/launcher
availability, and adapter-owned local CLI version compatibility. The only
provider process it may run is the fixed `--version` command; it does not
authenticate, send a prompt or source, contact a provider API, create a review
run, or start MCP. Versions above the latest verified version remain eligible
but are reported as `newer_than_verified`. Static-admission evidence and review
qualification do not gate this offline readiness.
The v5 result retains the v4 JSON member name `config_v3` for compatibility;
that member evaluates the currently supported Config v4 pair.

`providers --output json` reports `offline_ready_provider_count` separately
from `static_evidence_ready_provider_count`. A missing static-evidence source
therefore cannot turn a valid offline installation into a generic provider
failure, and a prior live review never mutates either diagnostic result.

A live heartbeat is separate and always requires an explicit authorization:

```bash
mulgae heartbeat --provider grok --authorize-live-request --output json
```

The heartbeat may authenticate, use the network, incur cost, and create remote
logs. It sends only Mulgae's fixed synthetic qualification packet—never source,
diffs, review prompts, or user content—and does not establish durable review
qualification. Without `--authorize-live-request`, Mulgae returns
`not_authorized` before composing or executing the provider.

Before spending provider time, inspect the exact staged directory view and
configured routing envelope:

```bash
mulgae review --stage --preflight --output json
```

Preflight uses the complete immutable capture path but does not discover, qualify, or
invoke providers and does not create a session, run, diagnostic, or publication.
It reports `qualification: not_run`, the exact source files sent to each role,
PNG/JPEG/WebP binary metadata, each role's provider route, effective timeouts,
and enclosing role-path/run budgets. The generated workspace manifest is
declared separately as `generated_at_execution`.

Automatic initialization configures ZCode and Grok, with ZCode as the reviewer
for every enabled role.

These defaults are declared in one place: `assets/roles.yaml` at the repository
root, which also holds each role's review guidance. Every role lists an ordered
`provider_preferences`; `mulgae init` intersects that order with the providers it
actually configured and takes the first match as the role's provider. Editing
that file and rebuilding changes what `mulgae init` writes. It never changes an
existing `.mulgae/config.yaml`, which remains the shared project-policy
authority once a project is initialized.

Each role runs on exactly one provider, and Mulgae never switches providers on
its own. An operator may explicitly recompose a failed, missing role on another
configured provider; an accepted role cannot be replaced. A published review
therefore reflects one reviewer per role rather than
a mix of models chosen by whichever one happened to fail. When a provider fails,
that role is reported as failed with its typed reason while every other role
continues on its own provider; the report's "Provider issues" section names each
failed role, the provider it ran on, why it stopped, and the `mulgae rerun`
command to run it again on a provider you choose.

Earlier config versions, including v1 fallback-provider files and Config v2,
are rejected rather than partially interpreted. Back up the old private file and
initialize Config v4 deliberately; Mulgae does not migrate it automatically.
For a Config v3 ZCode setup, change the shared and local `version` fields to
`4`, remove `providers.zcode.node_executable` and
`providers.zcode.launcher` from `local.yaml`, and set
`providers.zcode.app_bundle` to the app bundle that contains them. The standard
value is `/Applications/ZCode.app`. Run `mulgae init --refresh-local` only after
the shared file is already a valid Config v4 policy.

`mulgae init` creates Config v4 as two authorities: the shareable project policy
at `.mulgae/config.yaml` and machine-local paths at `.mulgae/local.yaml`. It
never overwrites an existing complete configuration. On a clone that already
contains the project policy, `mulgae init` discovers the configured provider
families and creates only the local file; project-policy options are rejected.
Each file is installed atomically. Because the two pathnames cannot commit as a
single filesystem transaction, interruption after the shared file commits may
leave a supported shared-only state. A failed command reports
`project_committed_local_missing`; rerun `mulgae init` after resolving any
reported local-path collision to create only `local.yaml`.

Track only the project policy. Keep every runtime artifact and the local file
out of Git with these root-anchored rules:

```gitignore
/.mulgae/*
!/.mulgae/config.yaml
```

Then commit `.gitignore` and `.mulgae/config.yaml`. The shared file carries
roles, provider families and models, timeouts, review/validation policy,
resource budgets, and CI policy. It never contains credentials, the native user
home, provider executables, ZCode app-bundle paths, or Codex credential-home
paths. Those remain in the mode-`0600` `.mulgae/local.yaml`, so collaborators
share review policy without assuming identical account names or installation
paths.

After cloning, run `mulgae init` once to create `.mulgae/local.yaml`. If the
shared provider set changes or local installations move, explicitly refresh
only the machine file:

```bash
mulgae init --refresh-local
mulgae config --mode provenance
```

`--refresh-local` preserves `.mulgae/config.yaml` and atomically replaces only
the admitted local file. It accepts machine-path overrides but rejects project
policy options. Earlier config versions are not migrated or read: back them up,
remove the old private configuration, and initialize Config v4 deliberately.

Every review command requires exactly one target:

```text
--workspace              tracked files at the current workspace state
--stage                  staged changes
--dirty                  staged and unstaged changes
--diff REVISION_RANGE    a Git revision range, such as origin/main...HEAD
--patch RELATIVE_PATH    a patch file in the project
--stdin                  a patch read from standard input
```

Tracked `.gitignore`, `.mulgaeignore`, and exact `.mulgae/config.yaml` files
remain trusted capture controls and are never sent to providers. Their presence
does not invalidate `--dirty`; their paths and contents are removed from
captured files and patch targets. Every other tracked `.mulgae/**` path is
rejected.
Patch/stdin input containing only excluded control changes fails with
`no_reviewable_content`.

Use `mulgae version --json` for the machine-readable name and version. Workflow
commands use `--output json` when integrating Mulgae with another tool.

An MCP client can start one attached stdio server for the current canonical
project root, or select another root explicitly:

```bash
mulgae mcp
mulgae mcp --project-root /absolute/path/to/repository
```

The server speaks newline-delimited JSON-RPC on stdout. Its `server/discover`
flow prefers MCP protocol `2026-07-28`. Legacy `initialize` negotiates
`2025-11-25` or `2025-06-18`; a legacy request naming the newer protocol falls
back to `2025-11-25`. Older versions fail with a structured unsupported-version
error.
Diagnostics use stderr. The process fixes the canonical project root at startup
and exits when its client closes stdin. It exposes nine bounded tools:

- `preflight_review` captures and summarizes the execution-free target,
  transmission plan, and budget without invoking providers or publishing a run.
- `run_review` captures and completes one foreground review for `workspace`,
  `stage`, `dirty`, `diff`, or `patch`; MCP stdin is transport-only and cannot
  be a review target.
- `start_review` accepts the same review arguments, admits one process-local
  invocation, and returns its `i_...` identity before provider completion.
- `await_review` waits on that exact invocation without polling or transferring
  cancellation from the wait request to the review execution.
- `cancel_review` records the first explicit cancellation request for an active
  invocation; its acknowledgement is not terminal, so the client must still
  call `await_review`.
- `compose_review` atomically publishes one self-contained composite from an
  exact incomplete root run and one to seven exact recovery run IDs. It never
  selects `latest` or invokes a provider.
- `list_runs` returns a newest-first page of safely admitted runs, with a limit
  from 1 through 100 and an opaque continuation cursor.
- `get_run` returns verified publication state and public artifact identities,
  or a bounded diagnostic-only status when that run never published.
- `list_findings` returns at most 1,000 committed finding summaries at or above
  a selected severity; it does not return report or source bodies.

Committed run and finding results include `mulgae://` resource URIs. The
`verified_review_report` and `verified_finding_evidence` templates read only
integrity-checked content and return at most 16 KiB per request. Resource
metadata includes the full-content SHA-256, byte offset, total byte length,
completion flag, and a canonical `nextURI` when another chunk exists. Reports
are UTF-8 Markdown; evidence chunks preserve exact bytes.

Every call returns the common `mulgae-mcp-tool-result.v1` structured envelope.
`request_changes` is a completed review outcome, while failures use bounded,
typed, redacted errors. Error results carry nullable `session_id` and `run_id`
fields; when a failed `run_review` or terminal `await_review` allocated a run,
both identify the exact run to inspect with `get_run`. Diagnostic-only results set
`publication_authority: false`, expose no artifact or report URI, and cannot be
used with `list_findings`. If diagnostic persistence also failed, `get_run`
returns `run_status_unavailable`; the returned identity remains valid but has
no durable status to inspect. A failed `run_review` is never marked retryable
because another call creates a new run. `start_review` is likewise not safe to
repeat after an uncertain response. Its invocation is retained only by that MCP
server process, with at most 64 identities and no restart recovery. Oldest
terminal identities may be discarded to admit a new start.
`await_review` is event-driven and may be repeated for the same identity; an
`await_cancelled` error ends only that observer and is retryable while the same
MCP session remains alive. A successful terminal result echoes the exact
`invocation_id` beside the durable run identity. Unknown identities fail closed
without starting a review. `invocation_limit_reached` is non-retryable and
occurs only when 64 reviews are still running. A non-retryable
`invocation_registry_closed` means an await observed the server session ending
while its transport could still deliver a result. Closing MCP stdin ends that
transport, so pending calls may end without a response. Server shutdown still
closes admission, cancels active invocations, and waits within a one-minute
drain bound before the process exits.

The foreground `run_review` remains compatible and holds its request open until
the review reaches a terminal result. When a client supplies an MCP progress
token, `run_review` sends an admitted notification,
monotonic periodic heartbeats, and a terminal notification before its result.
Cancelling the MCP request cancels the same foreground review context and its
provider processes. Lifecycle `await_review` emits no heartbeat loop, and
cancelling its request does not cancel the server-owned review.

### Configure the MCP host timeout

Installing or upgrading Mulgae does not create or update an MCP host
registration. Configure each host separately, revisit existing registrations,
and set its hard tool-call timeout above the `budget.run_deadline` reported by
Mulgae preflight. This is the admitted run budget; `budget.ceilings.run_deadline`
is the policy ceiling and must not be used for this comparison. This is a host
setting, not a provider timeout. Generated project configuration gives every
selected role an active lane, so roles run in parallel. The default and maximum
provider timeout is 60 minutes per
invocation, not per role; one role still reserves its initial provider call and
one possible retry, repair, or structured extraction in sequence. That standard
topology has a `2h0m7s` run deadline. The examples below round up to three hours:
`10800` seconds for Codex and the equivalent `10800000` milliseconds for Claude
Code. A shorter host timeout can be used with the complete lifecycle tool
surface only when the client is prepared to re-await the same invocation after
an observer timeout; it does not cover one uninterrupted await or the foreground
`run_review` fallback. If project policy reduces `max_active_lanes` below the
selected role count, use that project's preflight deadline instead of this
default.

### Configure Codex

Codex's default MCP tool timeout is too short for a foreground multi-provider
review. Add an absolute Mulgae binary and project root to a trusted project
`.codex/config.toml`. The three-hour value below covers the standard fully
parallel topology:

```toml
[mcp_servers.mulgae]
command = "/absolute/path/to/mulgae"
args = ["mcp", "--project-root", "/absolute/path/to/repository"]
cwd = "/absolute/path/to/repository"
required = true
startup_timeout_sec = 30
tool_timeout_sec = 10800
```

With Codex CLI 0.149.0, `codex mcp get mulgae --json` reports the server name,
enabled state, disabled reason, stdio command/arguments/environment forwarding
and working directory, enabled/disabled tool filters, and startup/tool
timeouts. It does not report `required`. Absence of that field means “not
observable through this command,” not `required = false`; `config.toml` remains
the authority for the configured value. Mulgae does not claim a minimum Codex
version for observing `required`: the compatibility test accepts either an
absent field or an observed literal `true`, and rejects an observed false value.
The Codex MCP client minimum is 0.149.0; using Codex as a Mulgae review provider
requires 0.154.0 or newer.

Codex also supports `codex mcp add mulgae -- /absolute/path/to/mulgae mcp
--project-root /absolute/path/to/repository`; add the timeout to the resulting
configuration before running a review. See the official
[Codex MCP configuration](https://developers.openai.com/codex/mcp/).

### Configure Claude Code

Add a project-scoped `.mcp.json` with the same absolute process and project
binding. Claude Code expresses the per-server hard timeout in milliseconds:

```json
{
  "mcpServers": {
    "mulgae": {
      "type": "stdio",
      "command": "/absolute/path/to/mulgae",
      "args": ["mcp", "--project-root", "/absolute/path/to/repository"],
      "timeout": 10800000
    }
  }
}
```

Progress notifications keep an active stdio call observable but do not extend
Claude Code's hard timeout, so keep it above the admitted preflight deadline.
See the official [Claude Code MCP configuration](https://code.claude.com/docs/en/mcp).

## Optional: configure an AI coding agent

Installing Mulgae does not modify a project's `AGENTS.md` and does not install
an agent skill. Mulgae works normally without either integration. You may use
the `AGENTS.md` template below, the source-distributed skill, both together, or
neither.

Copy this minimal project-wide template into the reviewed project's
`AGENTS.md` when you want an agent to operate Mulgae there:

````markdown
### Mulgae code review

- Use Mulgae only when the user explicitly requests it. Confirm that `mulgae`
  is available; never install it automatically.
- Run Mulgae from the Git repository root. Confirm that both
  `.mulgae/config.yaml` and `.mulgae/local.yaml` exist; never run `mulgae init`
  without explicit user intent.
- Derive each action from current machine-readable configuration, preflight,
  and run status. Select exactly one review target (`--diff BASE...HEAD`,
  `--stage`, `--dirty`, `--workspace`, `--patch`, or `--stdin`) and use
  `--output json`.
- Prefer attached Mulgae MCP tools when available: call `preflight_review`, then,
  only when `start_review`, `await_review`, and `cancel_review` are all present,
  call `start_review` once and preserve its exact invocation ID. Call
  `await_review` on that identity until completion. If the host defers the call,
  wait on the same pending handle for up to five minutes at a time, or the
  longest shorter duration the host and higher-priority instructions permit.
  Do not poll `get_run`, `list_runs`, CLI status, files, or OS processes.
  Required progress reports do not require another status query.
- Check a readable host tool timeout against preflight's `budget.run_deadline`,
  the admitted run budget, without changing configuration. Do not compare against
  the policy ceiling `budget.ceilings.run_deadline`. An unknown host timeout
  does not justify abandoning async.
  An await timeout ends only the observer: re-await the same invocation while
  the same MCP session lives. On disconnect, `invocation_not_found`, or
  `invocation_registry_closed`, stop automated waiting and never guess an
  invocation identity. If an exact run ID was returned, reconcile it through
  `get_run` or CLI `status`; otherwise report the outcome as unknown. Never
  start another review to recover a wait.
- Choose fallback before starting: if any lifecycle tool is absent, use one
  foreground `run_review` only when the host timeout is verified to exceed
  preflight's `budget.run_deadline`, allowing transport overhead. If the timeout
  is insufficient or unverifiable, choose the CLI before starting: cancelling a
  foreground request cancels the review itself. Also use the CLI when MCP
  execution is unavailable or for unsupported targets such as `stdin`. Await
  the same host process handle; use nonblocking handle checks only when host
  completion waiting is unavailable, with 50 seconds between checks. If timed
  waiting is unavailable, stop automated polling and report the limitation.
  Never switch an already-started invocation to another execution path.
- After terminal completion, preserve the exact returned run ID and inspect it
  with `get_run`. Call `list_findings` only for publication-backed status and
  follow resource `nextURI` values exactly.
- Read the JSON envelope even when Mulgae exits `1`: exit `1` is a policy
  outcome, not an execution failure. Treat other non-zero exits per
  `mulgae help exit-codes`. Preserve returned run IDs and inspect runs with
  `mulgae status --run r_... --output json`.
- Treat Mulgae as advisory. Verify findings against the captured target before
  changing code, and record only claims supported by current evidence.
- On explicit user cancellation, use `cancel_review` only for a preserved
  invocation returned by `start_review`, then await the terminal result; its
  acknowledgement is not completion. For a foreground `run_review`, cancel
  the MCP request itself; `cancel_review` cannot cancel that path.
  Require explicit user intent before cleanup, cancellation, configuration or
  goal changes, or another lifecycle-changing action. Re-read configuration
  after configuration changes
  and run status after review completion; never blindly retry an uncertain
  mutation.
- Commit only `.mulgae/config.yaml`. Never commit or share
  `.mulgae/local.yaml`, any other `.mulgae/**` path, provider credential
  directories, raw transcripts, or exported review bundles.
````

For the complete reusable workflow, see the
[`use-mulgae` skill directory](skills/use-mulgae/). It is included in the
source repository and source archives, but it is not embedded in or installed
with the Mulgae binary. Install it under `~/.agents/skills/` as shown below.
The default `main` reference installs the latest guidance; replace it with a
release tag newer than `v0.1.12` when you need a version matched to an installed
Mulgae release — earlier releases do not ship the skill:

```bash
(
set -eu

agent_skills_dir="$HOME/.agents/skills"
mulgae_skill_dir="$agent_skills_dir/use-mulgae"
mulgae_ref=main

mkdir -p "$agent_skills_dir"
mulgae_stage_dir="$(mktemp -d "$agent_skills_dir/.use-mulgae.install.XXXXXX")"
mulgae_staged_skill="$mulgae_stage_dir/use-mulgae"
mulgae_previous_skill="$mulgae_stage_dir/previous"
mulgae_installed=false

cleanup_mulgae_skill_install() {
  mulgae_install_status=$?
  if [ "$mulgae_installed" != true ] && \
    [ -e "$mulgae_previous_skill" ] && [ ! -e "$mulgae_skill_dir" ]; then
    mv "$mulgae_previous_skill" "$mulgae_skill_dir" || true
  fi
  if [ "$mulgae_installed" = true ] || [ ! -e "$mulgae_previous_skill" ]; then
    rm -rf "$mulgae_stage_dir"
  else
    echo "Mulgae skill backup preserved at $mulgae_previous_skill" >&2
  fi
  return "$mulgae_install_status"
}
trap cleanup_mulgae_skill_install EXIT

mkdir -p "$mulgae_staged_skill/references"
curl -fsSLo "$mulgae_staged_skill/SKILL.md" \
  "https://raw.githubusercontent.com/irootkernel/mulgae/$mulgae_ref/skills/use-mulgae/SKILL.md"

for reference in lifecycle authoring recovery; do
  curl -fsSLo "$mulgae_staged_skill/references/$reference.md" \
    "https://raw.githubusercontent.com/irootkernel/mulgae/$mulgae_ref/skills/use-mulgae/references/$reference.md"
done

if [ -e "$mulgae_skill_dir" ]; then
  mv "$mulgae_skill_dir" "$mulgae_previous_skill"
fi
mv "$mulgae_staged_skill" "$mulgae_skill_dir"
mulgae_installed=true
rm -rf "$mulgae_stage_dir"
trap - EXIT
)
```

## Review results

A successful publication creates a run beneath:

```text
.mulgae/{session_id}/{run_id}/
```

The directory contains a manifest, accepted free-form role reports, provider
attempts, validation records, runtime diagnostics, a reference-only v2 capture
manifest with deduplicated SHA-256 blobs, and at most one final `review_*.json`
artifact. Provider stdout, stderr, and accepted reports are preserved without a
product byte ceiling. Public diagnostic metadata and optional structured
extraction retain their separate structural contracts. Mulgae
alone normalizes, validates, and commits the top-level final artifact.

Inspect a run with its exact ID:

```bash
mulgae status --run r_...
mulgae findings --run r_... --severity high
mulgae report --run r_... --output-path reports/review.md
mulgae export --run r_...
```

If a review failed without publishing a final result, inspect
`status --run r_... --output json` or MCP `get_run` first. When
`failed_run_recovery.available` is true, use each returned retry attempt with
`mulgae rerun --run r_... --attempt a_... --replay exact --output json`.
Accepted roles are retained. A missing recovery source requires a new review
when authorized; old diagnostic-only runs cannot be recovered retrospectively.

After every missing selected role has a committed rerun, combine the results:

```bash
mulgae compose --root-run r_... --recovery-run r_... --output json
```

The same exact mapping is idempotent. If publication returns
`reconciliation_state: status_required`, inspect the returned composite
`run_id`; do not blindly retry an uncertain mutation. Composite findings remain
available through `findings`, but they do not support CLI `excerpt` reads or MCP
current-target evidence resources. Composite `status`, `report`, and `export`
reads remain supported.

The MCP `compose_review` equivalent reports an uncertain publication as
`composite_publication_incomplete` with deterministic non-null `session_id`
and `run_id` values and `retryable: false`; inspect that exact run before
repeating the mapping.

Exports default to `.mulgae/exports/<run-id>.zip` with a neighboring
`.manifest.json` sidecar. Use `--output-path <relative-path>` only when you
intentionally want the export elsewhere beneath the project root. Mulgae does
not edit Git ignore configuration. Use the allowlist rules shown in Quick start,
commit only `.mulgae/config.yaml`, and keep every other `.mulgae/**` path
private.

Create a focused follow-up after changing the code:

```bash
mulgae followup --run latest --finding F001 --dirty \
  --objective "Check whether the original finding is resolved."
```

## Help

The binary includes focused help topics:

```bash
mulgae help workflows
mulgae help config
mulgae help providers
mulgae help artifacts
mulgae help security
```

Available topics are `quickstart`, `config`, `providers`, `role-paths`, `prompts`,
`workflows`, `artifacts`, `validation`, `ci`, `exit-codes`, and `security`.

## Documentation

Contributor documentation lives in [`docs/`](docs/README.md):

- [Product specifications](docs/specs/README.md)
- [Architecture](docs/architecture/README.md)
- [Architecture decision records](docs/architecture-decision-records/README.md)
- [Implementation and release guidance](docs/implementation-tips/README.md)
- [Operations ownership](docs/ops/README.md)
- [Roadmap](docs/roadmap/README.md)
- [Changelog](CHANGELOG.md)

## License

Mulgae is available under the [MIT License](LICENSE).
