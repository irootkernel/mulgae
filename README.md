# Mulgae

![Six seal reviewers independently inspect an immutable code snapshot and file separate reports in a local archive.](docs/assets/mulgae-hero.webp)

Mulgae is a local, multi-provider AI code review CLI and attached MCP server. It captures an immutable
review target, asks role-specific reviewers to inspect it, publishes their
free-form role reports, optionally validates structured findings and their
evidence, and commits durable artifacts under `.mulgae/`.

Mulgae is advisory. It reports findings and recommendations; it does not grant
merge, release, waiver, or organizational approval.

## Platform and providers

The initial release supports macOS on Apple silicon (`darwin/arm64`) and these
provider families:

- Kimi CLI
- ZCode
- AGY

The default `mulgae init` topology requires authenticated ZCode and AGY
installations. Kimi remains available only when selected explicitly with
`--providers kimi`. Mulgae records provider identity and capabilities at runtime
and fails closed when a required capability is unavailable. Other operating
systems, architectures, and provider families are not supported by the initial
release.

### Use ZCode from Mulgae

ZCode is distributed as a macOS app rather than as a `zcode` executable on
`PATH`. Mulgae runs the app's bundled launcher with Node.js, so no wrapper or
symlink is required. Install Node.js and ZCode, sign in through the ZCode app,
then verify the two components:

```bash
zcode_node="$(command -v node)"
zcode_launcher="/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs"

test -n "$zcode_node"
test -x "$zcode_node"
test -r "$zcode_launcher"
"$zcode_node" "$zcode_launcher" --version
"$zcode_node" "$zcode_launcher" doctor
```

The bundled launcher uses ZCode's shared login state. With the standard app
location, `mulgae init` discovers the Node.js executable from its startup
`PATH` and the launcher automatically:

```bash
mulgae init --providers zcode
mulgae providers --include-unverified
```

Use explicit absolute paths when Node.js or the ZCode app is installed
elsewhere:

```bash
mulgae init --providers zcode \
  --zcode-node-executable "$(command -v node)" \
  --zcode-launcher "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs"
```

#### Set ZCode reasoning effort to max

Mulgae's ZCode adapter does not set reasoning effort for each invocation.
Headless reviews inherit ZCode's per-user reasoning preference, so set it to
`max` before using ZCode with Mulgae. In the ZCode app, select `max` for
**Thought Level**, or enter these slash commands in a ZCode conversation:

```text
/effort max
/effort
```

The second command should report `Current reasoning effort: max.` ZCode
persists this as a user-level preference. Mulgae does not currently enforce or
verify the value, so check it again after reinstalling or updating ZCode, or
after changing the reasoning setting in another ZCode session.

## Install

Mulgae requires Go 1.26.6 or newer.

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

Before spending provider time, inspect the exact staged directory view and
configured routing envelope:

```bash
mulgae review --stage --preflight --output json
```

Preflight uses the complete immutable capture path but does not discover, qualify, or
invoke providers and does not create a session, run, diagnostic, or publication.
It reports `qualification: not_run`, the exact source files sent to each role,
PNG/JPEG/WebP binary metadata, each role's provider route, effective timeouts,
AGY's permission mode, and enclosing role-path/run budgets. The generated workspace
manifest is declared separately as `generated_at_execution`. AGY safe mode is
explicitly warned because headless permission requests may be denied.

Automatic initialization configures ZCode as the reviewer for logic, security,
maintainability, product, and testing, and AGY for documentation.

These defaults are declared in one place: `assets/roles.yaml` at the repository
root, which also holds each role's review guidance. Every role lists an ordered
`provider_preferences`; `mulgae init` intersects that order with the providers it
actually configured and takes the first match as the role's provider. Editing
that file and rebuilding changes what `mulgae init` writes. It never changes an
existing `.mulgae/config.yaml`, which remains the shared project-policy
authority once a project is initialized.

Each role runs on exactly one provider, and Mulgae never switches providers on
its own. A published review therefore reflects one reviewer per role rather than
a mix of models chosen by whichever one happened to fail. When a provider fails,
that role is reported as failed with its typed reason while every other role
continues on its own provider; the report's "Provider issues" section names each
failed role, the provider it ran on, why it stopped, and the `mulgae rerun`
command to run it again on a provider you choose.

Earlier config versions, including v1 fallback-provider files and Config v2,
are rejected rather than partially interpreted. Back up the old private file and
initialize Config v3 deliberately; Mulgae does not migrate it automatically.

`mulgae init` creates Config v3 as two authorities: the shareable project policy
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
home, provider executables, launchers, or provider data-home paths. Those remain
in the mode-`0600` `.mulgae/local.yaml`, so collaborators share review policy
without assuming identical account names or installation paths.

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
remove the old private configuration, and initialize Config v3 deliberately.

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

The server speaks newline-delimited JSON-RPC on stdout. It prefers MCP protocol
`2026-07-28` and accepts `2025-11-25` and `2025-06-18` for current stdio client
compatibility; older versions fail with a structured unsupported-version error.
Diagnostics use stderr. The process fixes the canonical project root at startup
and exits when its client closes stdin. It exposes five bounded tools:

- `preflight_review` captures and summarizes the execution-free target,
  transmission plan, and budget without invoking providers or publishing a run.
- `run_review` captures and completes one foreground review for `workspace`,
  `stage`, `dirty`, `diff`, or `patch`; MCP stdin is transport-only and cannot
  be a review target.
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
fields; when a failed `run_review` allocated a run, both identify the exact run
to inspect with `get_run`. Diagnostic-only results set
`publication_authority: false`, expose no artifact or report URI, and cannot be
used with `list_findings`. If diagnostic persistence also failed, `get_run`
returns `run_status_unavailable`; the returned identity remains valid but has
no durable status to inspect. A failed `run_review` is never marked retryable
because another call creates a new run. Because `run_review` holds the request
open until the review reaches a terminal result, clients do not need to poll run
state merely to learn that the requested review completed. When a client
supplies an MCP progress token, `run_review` sends an admitted notification,
monotonic periodic heartbeats, and a terminal notification before its result.
Cancelling the MCP request cancels the same foreground review context and its
provider processes; no separate Mulgae cancellation tool or polling loop is
required.

### Configure Codex

Codex's default MCP tool timeout is too short for a foreground multi-provider
review. Add an absolute Mulgae binary and project root to a trusted project
`.codex/config.toml`, and set the tool timeout above the `run_deadline` reported
by preflight. The 15-hour value below covers Mulgae's current maximum admitted
run ceiling:

```toml
[mcp_servers.mulgae]
command = "/absolute/path/to/mulgae"
args = ["mcp", "--project-root", "/absolute/path/to/repository"]
cwd = "/absolute/path/to/repository"
required = true
startup_timeout_sec = 30
tool_timeout_sec = 54000
```

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
      "timeout": 54000000
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
- Prefer attached Mulgae MCP tools when available: call `preflight_review`, then
  call `run_review` once and wait for its foreground result without polling.
  Preserve the exact run ID, inspect it with `get_run`, call `list_findings`
  only for publication-backed status, and follow resource `nextURI` values
  exactly. Fall back to the CLI when MCP is unavailable; MCP cannot accept the
  `stdin` review target.
- Read the JSON envelope even when Mulgae exits `1`: exit `1` is a policy
  outcome, not an execution failure. Treat other non-zero exits per
  `mulgae help exit-codes`. Preserve returned run IDs and inspect runs with
  `mulgae status --run r_... --output json`.
- Treat Mulgae as advisory. Verify findings against the captured target before
  changing code, and record only claims supported by current evidence.
- Require explicit user intent before cleanup, cancellation, configuration or
  goal changes, or another lifecycle-changing action. Re-read status after
  every mutation and never blindly retry an uncertain mutation.
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

- [Project goals](docs/goals.md)
- [Architecture](docs/architecture.md)
- [Contracts and artifacts](docs/contracts.md)
- [Security model](docs/security.md)
- [Development and release workflow](docs/development.md)

## License

Mulgae is available under the [MIT License](LICENSE).
