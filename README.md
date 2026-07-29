# Mulgae

Mulgae is a local, multi-provider AI code review CLI. It captures an immutable
review target, asks role-specific reviewers to inspect it, validates their
structured output, verifies evidence against the captured target, and publishes
durable artifacts under `.mulgae/`.

Mulgae is advisory. It reports findings and recommendations; it does not grant
merge, release, waiver, or organizational approval.

## Platform and providers

The initial release supports macOS on Apple silicon (`darwin/arm64`) and these
provider families:

- Kimi CLI
- ZCode
- AGY

Install and authenticate at least one supported provider before initializing a
project. Mulgae records provider identity and capabilities at runtime and fails
closed when a required capability is unavailable. Other operating systems,
architectures, and provider families are not supported by the initial release.

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

Use `mulgae version --json` for the machine-readable name and version. Workflow
commands use `--output json` when integrating Mulgae with another tool.

## Review results

A successful publication creates a run beneath:

```text
.mulgae/{session_id}/{run_id}/
```

The directory contains a manifest, provider attempts, validation records,
runtime diagnostics, and at most one final `review_*.json` artifact. Provider
output is never treated as a final artifact until Mulgae has normalized,
validated, and committed it.

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
