# Mulgae

![Six seal reviewers independently inspect selected source and file separate local reports.](docs/assets/mulgae-hero.webp)

Mulgae is a local, multi-provider AI code review CLI and attached MCP server.
It reads the original workspace, actual index or resolved Git objects from a
neutral reviewer directory, runs configured role-specific reviews, verifies
finding evidence and publishes durable results under `.mulgae/`. Source files
are not copied into snapshots, checkouts, worktrees or full-source replay archives.

Roles are independent review lenses, not people, teams or approval authorities.
Mulgae reports findings and recommendations; it never approves a merge,
release, policy waiver or security exception.

## Platform and providers

The initial release supports macOS on Apple silicon (`darwin/arm64`) and these
provider families:

- ZCode
- Grok CLI

The default `mulgae init` topology requires a ZCode app bundle with a current
Z.AI Individual Coding Plan connection and an authenticated Grok installation.
Default core roles prefer ZCode with Grok as secondary preference, and artist
uses ZCode. Existing configured assignments remain unchanged. Mulgae records
provider identity and capabilities at runtime and fails closed when a required
capability is unavailable. Other operating systems, architectures, and provider
families are not supported by the initial release.

### Use ZCode from Mulgae

Install ZCode Desktop 3.18.2 or newer, `herdr-zcode` 0.2.0 or newer, and
`herdr-core` (`hc` or `herdr-core`). Sign in to Z.AI and select the Individual
Coding Plan in ZCode. Mulgae verifies the companion package and checks Desktop
compatibility through the companion. The verified Desktop release is 4.0.0.

Initialize Mulgae:

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

Mulgae runs ZCode through an isolated `herdr-core` terminal. The companion
prepares the current Desktop account and catalog in an owned namespace. Each
pane sees only its own projection, and Mulgae drains the namespace after the
pane ends.

An optional shared model and reasoning effort can be recorded independently:

```bash
mulgae init --providers zcode \
  --zcode-model account:zai-individual-coding-plan/GLM-5.3 \
  --zcode-reasoning-effort high
```

If either value is omitted, ZCode keeps its current session setting for that dimension.

### Use Grok from Mulgae

Install Grok CLI 1.0.89 or newer, install `herdr-core` (`hc` / `herdr-core`),
and sign in to Grok before selecting it explicitly. Version 1.0.89 is the
minimum and latest release verified for Mulgae's isolated `herdr-core` terminal
runtime contract; newer releases remain eligible as `newer_than_verified` and
require a current qualification:

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
untracked `.mulgae/local.yaml`. Mulgae passes `-m` and `--reasoning-effort`
preserving their exact spelling; Grok `1.0.89`'s interactive TUI applies them
best-effort with silent provider-side fallback for unrecognized values, without
Mulgae substituting another model or provider. Existing Config v5 projects that
omit either field continue to use Grok's provider default for that dimension;
removing a generated field restores that behavior.

Grok runs through an isolated per-run Mulgae-owned `herdr-core` terminal runtime
inside the mandatory macOS Seatbelt guard (`PaneTTY`-only, never contacting the
operator's `default` `herdr-core` session). Mulgae copies only `.grok/auth.json`
into a disposable `GROK_HOME` alongside a minimal `requirements.toml` disabling
compat hooks, MCP servers, rules, skills, plugins, and managed configs, while
keeping native `~/.grok` kernel-denied in `CredentialRoots`; `--trust` applies
strictly to Mulgae's verified read-only neutral `~/.mulgae/home` `--cwd` inside
disposable `GROK_HOME`.
Tools are purpose-scoped: workspace review (`read_file,grep,list_dir,Write`),
extraction, and qualification (`read_file,Write`) run strictly shell-free, while
index and commit reviews enable `Bash` only under all five `B-1` controls.
Outputs are staged inside private namespace scratch, validated strictly after
`ESRCH` teardown with a per-invocation completion nonce, and published under
`result_transport: "stdout"`. Grok does not advertise image prompt support, so
assigning it to `artist` fails before provider execution with
`provider_capability_unsupported` and exit 4. Run `make test-herdr` for the isolated `herdr-core` runtime suite and
`make test-grok` for the full live Grok release-binary gate.

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

`doctor --output json` returns `mulgae-doctor-result.v9`. It checks Config v5,
project-local security, provider and role identities, exact executable/launcher
availability, and adapter-owned local CLI version compatibility. The only
provider process it may run is the fixed `--version` command; it does not
authenticate, send a prompt or source, contact a provider API, create a review
run, or start MCP. Versions above the latest verified version remain eligible
but are reported as `newer_than_verified`. Static-admission evidence and review
qualification do not gate this offline readiness.
The current result retains the v4 JSON member name `config_v3` for compatibility;
that member evaluates the currently supported Config v5 pair.

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

Before spending provider time, inspect the native index selection and
configured routing envelope:

```bash
mulgae review --stage --preflight --output json
```

Preflight lists native source reads and configured routes, validates selected
artist inputs, and reports source selection identity, candidate count, timeouts
and enclosing budgets. It discovers and invokes no provider and creates no
session, run, diagnostic or publication. `qualification` remains `not_run`.
The source identity hashes selection metadata; it is not a content snapshot.

You can also validate a local [requirements JSON file](internal/builtin/assets/examples/requirements-input.v1.valid.json):

```bash
mulgae review --stage --preflight --requirements requirements.json \
  --objective "Review this change." --roles logic --output json
```

The file may be untracked or absent from the reviewed commit. Preflight reports
selected IDs and owners, its exact input digest and the configured extraction
policy. It exposes no requirement prose and locks neither the input nor source.
Omit `--preflight` to assess these requirements through their selected owner
roles. Execution requires the existing Git/common-directory project binding;
`context` advertises `requirements_assessment: v1` there. Non-Git preflight
reports execution unavailable, and requirements execution fails before private
writer or provider effects. Objective-only non-Git reviews remain supported.

Inspect every selected item independently of finding severity:

```bash
mulgae inspect --run r_... --requirements-limit 20 --output json
mulgae read-report --run r_... --requirement RCI-001 --output json
```

Follow `requirements.next_cursor` with `--requirements-cursor` and the same
requirements limit and publication receipt. The nested result keeps whole-run
selected/evaluated counts, owner, verdict, reason and provider/derived origin.
`requirement_content_uris` supplies MCP content resources; CLI content chunks
retain rationale, evidence, scope and limitations without a prose byte ceiling.
Rendered reports disclose unmet/unverified and omitted owner answers. A valid
provider unverified answer counts as evaluated; a derived placeholder does not.
No-change targets publish explicit unverified/not-run rows without providers.
Old intact results have unavailable assessment counts, while new requests without
input have known zero counts. Reads use retained verified support, never current
source. Export omits private requirements; clean removes retained run copies,
never this original project file.

Automatic initialization configures ZCode and Grok, with ZCode as the reviewer
for every enabled role.

These defaults are declared in one place: `assets/roles.yaml` at the repository
root, which also holds each role's review guidance. Every role lists an ordered
`provider_preferences`; `mulgae init` intersects that order with the providers it
actually configured and takes the first match as the role's provider. Editing
that file and rebuilding changes what `mulgae init` writes. It never changes an
existing `.mulgae/config.yaml`, which remains the shared project-policy
authority once a project is initialized.

Each role runs on exactly one configured provider. Failure leaves that role's
typed reason visible while peer roles continue. Mulgae never changes providers
or treats several opinions as consensus. There is no automatic recovery or
substitution; an independently authorized new review uses current source state.

Config v5 removes the snapshot-only `execution.workspace_access` block.
To migrate a Config v4 pair deliberately, back up the private file, set both
`version` fields to `5`, and remove that shared block. Older ZCode configurations
must first adopt the app-bundle machine-path contract. Mulgae does not migrate,
initialize over, or rewrite existing user configuration automatically.

`mulgae init` creates Config v5 as two authorities: the shareable project policy
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
home, provider executables, or ZCode app-bundle paths. Those remain in the
mode-`0600` `.mulgae/local.yaml`, so collaborators
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
remove the old private configuration, and initialize Config v5 deliberately.

Every review requires exactly one target:

| CLI selector | Source and scope |
|---|---|
| `--workspace` | Tracked and nonignored untracked files in the original workspace |
| `--stage` | HEAD to the actual index; unborn HEAD uses an empty base |
| `--head` | Whole resolved HEAD tree |
| `--commit REVISION` | First-parent-to-commit transition; a root uses an empty base |
| `--diff LEFT..RIGHT` | Direct comparison of resolved endpoints |
| `--diff LEFT...RIGHT` | Merge-base-to-right comparison |

Committed operands are resolved once. Conflicted index selections fail before
provider execution. Keep workspace and index unchanged throughout the review;
Mulgae has no atomic source view, full-tree fingerprint, lock or drift monitor.
Git ignore rules select workspace candidates, while tracked files still
participate. `.mulgaeignore` is neither generated nor processed, and existing
user files are left alone. Ignoring a path does not physically deny provider
access. Git internals and Mulgae/provider runtime and credential roots are
excluded from candidate discovery and protected by the native execution boundary.

`--dirty`, `--patch`, `--stdin`, `followup`, `delta`, `rerun`, `compose` and
capture-bound request guards are retired and rejected before providers run.
Historical artifacts remain supported by verified readers and exports.

Use `mulgae version --json` and workflow `--output json` for automation.
From the intended root, obtain `mulgae context --output json` and compare its
`project_binding` with attached MCP `get_context`. A binding identifies this
local worktree, not portable authentication or matching file contents. Context
advertises live/source evidence and verified-read capability versions; empty
`execution_guard` and `capture_identity` fields are normal for the live path.

Preflight and execution optionally accept the independently obtained binding:

```bash
mulgae review --stage --preflight --expected-project-binding "$binding" --output json
mulgae review --stage --expected-project-binding "$binding" --output json
```

Use the same target, roles, objective and artist inputs. A different or replaced
worktree fails with `project_binding_mismatch`. No request digest or content-drift
guarantee applies. A repeated start creates a distinct run; the binding is not
an idempotency key. A no-change selection invokes no provider.

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
and exits when its client closes stdin. It exposes ten bounded tools:

- `get_context` returns the startup worktree binding and implemented capability versions.
- `preflight_review` admits and summarizes the execution-free source selection,
  transmission plan, and budget without invoking providers or publishing a run.
  Optional `requirements_path` adds validated local requirements metadata.
- `run_review` completes one foreground review for `workspace`, `stage`, `head`,
  `commit`, or `diff`; optional `requirements_path` uses the same admitted local
  input and requires a Git binding. Stdin carries only the MCP protocol.
- `start_review` accepts the same review arguments, admits one process-local
  invocation, and returns its `i_...` identity before provider completion.
- `await_review` waits on that exact invocation without polling or transferring
  cancellation from the wait request to the review execution.
- `cancel_review` records the first explicit cancellation request for an active
  invocation; its acknowledgement is not terminal, so the client must still
  call `await_review`.
- `list_runs` returns a newest-first page of safely admitted runs, with a limit
  from 1 through 100 and an opaque continuation cursor.
- `get_run` returns verified publication state and public artifact identities,
  or a bounded diagnostic-only status when that run never published.
- `inspect_review` returns publication state, coverage, extraction state, and a
  finding page plus an independent requirements page from one verified snapshot
  with its publication receipt.
- `list_findings` pages through committed finding summaries at or above a
  selected severity, with a limit from 1 through 1,000 and a receipt-bound cursor.
  It does not return report or source bodies.

Inspection and finding pages include `mulgae://` resource URIs for full finding
JSON, original role reports, complete requirement items and each available
evidence index. A client's inspection-tool support does not establish native
resource support; the guarded CLI content route remains available when the host
does not expose a resource reader. For the rendered
report, use the advertised `verified_review_report` resource template with the
exact run ID, project binding, and publication receipt, or CLI `read-report`.
Resources return at most 16 KiB per request, with the publication receipt,
full-content SHA-256, byte offset, total byte length, and a canonical
`io.mulgae/nextURI` when another chunk exists. Follow that URI unchanged. Reports
are UTF-8 Markdown; evidence chunks preserve exact bytes. The CLI provides the
same reads without writing a report file:

```bash
mulgae inspect --run r_... --expected-project-binding "$binding" --output json
mulgae read-finding --run r_... --finding F001 --expected-project-binding "$binding" --expected-publication-receipt "$receipt" --output json
mulgae read-report --run r_... --role logic --expected-project-binding "$binding" --expected-publication-receipt "$receipt" --output json
mulgae excerpt --run r_... --finding F001 --source-identity-sha256 "$source_identity" --evidence-index 0 --expected-project-binding "$binding" --expected-publication-receipt "$receipt" --output json
```

Obtain the exact finding ID, source identity, and publication receipt from
inspection. Omit `--role` to read the rendered report. Read every chunk until
`next_offset` is null, carrying the returned offset and both
`--expected-publication-receipt` and `--expected-content-sha256` to the next call.
For finding pages, follow `next_cursor` with the same command, query selectors,
and receipt until the cursor is empty. The default `low` severity excludes `info`.

Historical composites retain original finding content, portable source provenance, and
all copied evidence indices. These reads survive allowed source-run cleanup.
Historical items can return `evidence_unavailable` or
`capture_identity_unavailable`; corrupt bound support fails the read. Capability
support and complete coverage do not establish verification of an unavailable
item. Legacy resource URIs retain their original continuation behavior and do not gain
publication receipt binding.

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
The Codex MCP client minimum is 0.149.0. Codex is supported here only as an
external MCP client; Codex is retired as a Mulgae review provider.

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
  `--stage`, `--workspace`, `--head`, or `--commit REVISION`) and use
  `--output json`.
- Independently select the requested canonical Git worktree root. From that
  root, run `mulgae context --output json` and compare `result.project_binding`
  with attached MCP `get_context`'s `data.project_binding`. Require matching
  bindings and the needed `v1` capabilities before using the attached server.
  A target hash or tool registration does not prove the server root. On a
  mismatch or unavailable binding support, choose the CLI from the requested
  root before starting; do not retarget by starting another MCP server.
- Keep the complete Review Brief on one objective line with explicit separators.
  Reject NUL, CR, or LF and count UTF-8 bytes. MCP admits at most 4096 bytes;
  use the CLI for 4097 through 12000 bytes, and stop above 12000 without truncating.
- Preflight the selected target, objective and roles with the independently
  obtained `expected_project_binding`; use that same binding and selected
  arguments on start. Keep workspace/index state unchanged until completion.
  The CLI equivalent is `--expected-project-binding`. Stop on a mismatch.
  Source identity is metadata, not a content/request drift guard or idempotency key.
- Prefer attached Mulgae MCP tools after those checks: only when `start_review`,
  `await_review`, and `cancel_review` are all present,
  call `start_review` once and preserve its exact invocation ID. Call
  `await_review` on that identity until completion. Wait for the start response
  before calling await; never batch these dependent calls or invent an ID.
  If the host defers the call,
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
  execution is unavailable or the complete objective exceeds its input limit. Await
  the same host process handle; use nonblocking handle checks only when host
  completion waiting is unavailable, with 50 seconds between checks. If timed
  waiting is unavailable, stop automated polling and report the limitation.
  Never switch an already-started invocation to another execution path.
- A passive CLI wait timeout leaves its process running; continue on the same
  handle. If a host deadline signals the process or its effect is unknown,
  treat the run as cancelled or uncertain, preserve any returned run ID, and
  never start a replacement review.
- After terminal completion, inspect the exact returned run with
  `inspect_review` and `expected_project_binding`, or CLI `inspect --run r_...`
  with `--expected-project-binding` and `--output json`. Check publication
  authority, coverage, structured extraction, and CI independently. An incomplete
  or diagnostic-only result is not a completed review verdict; preserve its
  recovery information. No returned run ID means there is no exact run to query.
- Use the inspection's finding IDs, publication receipt, and content references.
  Follow finding cursors with the same command, selectors, and expected receipt; the
  broadest severity query is `low`, which excludes `info`. Read full finding
  details, original role reports, and each available evidence index through the
  returned MCP resource URIs or CLI `read-finding`, `read-report`, and indexed
  `excerpt`. Read the rendered report with CLI `read-report` without `--role`,
  or the advertised MCP report template with the exact run, binding, and receipt.
  Follow MCP `io.mulgae/nextURI` unchanged.
  CLI chunks continue with `next_offset`, the expected publication receipt, and
  the expected full-content digest until `next_offset` is null. Keep the expected
  project binding on every read. These commands need no output-file write.
- Treat per-item historical unavailability separately from corruption. Historical
  composites expose copied evidence where retained; older ones may not.
  Stop an evidence-dependent judgment when its evidence is unavailable, and
  never replace a failed integrity check with a live-file or raw artifact read.
  Keep historical child inspection and provider-free publication reconciliation
  bound to the same root. Historical recovery inventory grants no child, rerun
  or compose execution authority.
- If a client cannot expose a needed native capability, use the CLI from the
  requested root. With an older CLI, report its verification limits: count-only
  findings and separate status reads do not form one snapshot, and a written
  report supplies only advisory candidate IDs. Use an authorized `report` write
  and an ordinary finding's verified legacy `excerpt` only when that path is
  available; otherwise stop ID-dependent judgment or follow-up. Do not infer
  support from the binary version or install an upgrade automatically.
- Read the JSON envelope even when Mulgae exits `1`: exit `1` is a policy
  outcome, not an execution failure. Treat other non-zero exits per
  `mulgae help exit-codes`. Preserve returned run IDs and inspect runs with
  `mulgae status --run r_... --output json`.
- Treat Mulgae as advisory. Verify findings against retained source evidence before
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

for reference in lifecycle authoring recovery legacy verified-reads; do
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

A successful publication creates `.mulgae/{session_id}/{run_id}/` with a v4
manifest and final review, complete accepted role reports, attempt/validation
records, private runtime diagnostics, `source/source.json`, verified excerpts
and selected PNG/JPEG/WebP observations. Requirements requests also retain exact
input and hash-bound per-item assessment content; absent input is explicit null
in both v4 records. It creates no source snapshot or
full-source replay archive. Prompt payloads, reports and complete provider
streams have no product byte ceiling. Source closure and provider drain are
separate provenance; atomic publication retains at most one top-level final.

```bash
mulgae status --run r_... --output json
mulgae inspect --run r_... --output json
mulgae read-report --run r_... --output json
mulgae findings --run r_... --severity low --output json
mulgae export --run r_... --output json
```

Read publication authority, coverage, extraction state and CI independently.
Incomplete coverage, diagnostic-only status or reports-only extraction is not
proof of a clean review. An allocated failed run may have no durable status;
`run_status_unavailable` must not trigger a blind retry. Preserve the exact
returned identity and verify complete reports and receipt-bound evidence.

Historical ordinary, child, composite, failed and no-change records remain
unchanged and readable/exportable. Their manifests, complete bound captures,
blobs, lineage and retained composite support keep fail-closed integrity.
Provider-free P0/P1/P2 reconciliation and cleanup ancestry protections remain.
Retained recovery inventory grants no new rerun, compose or source replay
operation. Any new review requires authority and uses current source state.

Exports default to `.mulgae/exports/<run-id>.zip` with a `.manifest.json`
sidecar. An explicit relative `--output-path` selects another project-local
destination. Commit only `.mulgae/config.yaml`, and keep all other runtime
artifacts, local paths, transcripts and exports private. Cleanup requires an
explicit authorized native plan; never delete private artifacts manually.

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
