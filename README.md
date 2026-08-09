# Mulgae

![Six seal reviewers independently inspect an immutable code snapshot and file separate reports in a local archive.](docs/assets/mulgae-hero.webp)

Mulgae is a local, multi-provider AI code review CLI. It captures an immutable
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

Mulgae requires Go 1.26 or newer.

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

Preflight uses the real bounded capture path but does not discover, qualify, or
invoke providers and does not create a session, run, diagnostic, or publication.
It reports `qualification: not_run`, the exact source files sent to each role,
PNG/JPEG/WebP binary metadata, each role's provider route, effective timeouts,
AGY's permission mode, and enclosing lane/run budgets. The generated workspace
manifest is declared separately as `generated_at_execution`. AGY safe mode is
explicitly warned because headless permission requests may be denied.

Automatic initialization configures ZCode as the reviewer for logic, security,
maintainability, product, and testing, and AGY for documentation.

These defaults are declared in one place: `assets/roles.yaml` at the repository
root, which also holds each role's review guidance. Every role lists an ordered
`provider_preferences`; `mulgae init` intersects that order with the providers it
actually configured and takes the first match as the role's provider. Editing
that file and rebuilding changes what `mulgae init` writes. It never changes an
existing `.mulgae/config.yaml`, which remains the sole authority once a project
is initialized.

Each role runs on exactly one provider, and Mulgae never switches providers on
its own. A published review therefore reflects one reviewer per role rather than
a mix of models chosen by whichever one happened to fail. When a provider fails,
that role is reported as failed with its typed reason while every other role
continues on its own provider; the report's "Provider issues" section names each
failed role, the provider it ran on, why it stopped, and the `mulgae rerun`
command to run it again on a provider you choose.

A configuration written before this rule carries `roles.<role>.fallback_provider`
and `resources.fallback_repair_attempts`. Both keys are gone, and a configuration
that still holds either is rejected rather than reread with them ignored. Run
`mulgae init` in a fresh directory to generate a current configuration, or delete
those keys and set `role_max_invocations` to 2 and `run_max_invocations` to twice
your enabled role count.

`mulgae init` creates the only configuration authority:
`.mulgae/config.yaml`. It never overwrites an existing configuration.

Every review command requires exactly one target:

```text
--workspace              tracked files at the current workspace state
--stage                  staged changes
--dirty                  staged and unstaged changes
--diff REVISION_RANGE    a Git revision range, such as origin/main...HEAD
--patch RELATIVE_PATH    a patch file in the project
--stdin                  a patch read from standard input
```

Tracked `.gitignore` and `.mulgaeignore` files remain trusted capture controls
and are never sent to providers. Their presence does not invalidate `--dirty`;
their paths and contents are removed from captured files and patch targets.
Patch/stdin input containing only excluded control changes fails with
`no_reviewable_content`.

Use `mulgae version --json` for the machine-readable name and version. Workflow
commands use `--output json` when integrating Mulgae with another tool.

## AI agent instructions

Copy the following block into a project's `AGENTS.md` or `CLAUDE.md` to tell AI
agents how to use Mulgae safely and consistently:

````markdown
### Mulgae code review

Use Mulgae only when the user explicitly asks for a Mulgae review.

- Run Mulgae from the Git repository root. Verify that `mulgae` is installed and
  `.mulgae/config.yaml` exists before starting. If either prerequisite is
  missing, stop and tell the user what is required. Do not run `mulgae init`
  unless the user separately and explicitly asks you to initialize the project.
- Select exactly one target that matches the requested scope: use `--diff
  origin/main...HEAD` for a branch or pull request (replacing `origin/main` with
  the actual base), `--stage` for staged changes, `--dirty` for staged and
  unstaged changes, or `--workspace` only when the user explicitly requests all
  tracked files at the current workspace state.
- State the review goal with `--objective` and use `--output json`. For example:

  ```bash
  mulgae review --diff origin/main...HEAD \
    --objective "Review this change before merge." \
    --output json
  ```

- Read the JSON result even when Mulgae exits with status 1: status 1 is a policy
  outcome, not an execution failure. Treat any status other than 0 or 1 as an
  operational failure; report it instead of bypassing Mulgae.
- Preserve the exact run ID returned by the review. Inspect that run with:

  ```bash
  mulgae status --run r_... --output json
  mulgae findings --run r_... --severity low --output json
  ```

- Treat every finding as an advisory hypothesis. Verify it against the captured
  target and current code before changing anything, and make fixes only within
  the user's authorized scope. Report findings that are valid, invalid, or
  outside scope.
- After an authorized fix, use the original run ID and finding ID with a target
  that contains the fix. For an uncommitted fix, for example:

  ```bash
  mulgae followup --run r_... --finding F001 --dirty \
    --objective "Check whether the original finding is resolved." \
    --output json
  ```

- Do not commit or share `.mulgae/`, provider credential directories, raw
  transcripts, or exported review bundles.
````

## Review results

A successful publication creates a run beneath:

```text
.mulgae/{session_id}/{run_id}/
```

The directory contains a manifest, accepted free-form role reports, provider
attempts, validation records, runtime diagnostics, a reference-only v2 capture
manifest with deduplicated SHA-256 blobs, and at most one final `review_*.json`
artifact. Provider reports are admitted as UTF-8 without a fixed size ceiling;
diagnostic previews and optional structured extraction remain bounded. Mulgae
alone normalizes, validates, and commits the top-level final artifact.

Inspect a run with its exact ID:

```bash
mulgae status --run r_...
mulgae findings --run r_... --severity high
mulgae report --run r_... --output-path reports/review.md
```

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

Available topics are `quickstart`, `config`, `providers`, `lanes`, `prompts`,
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
