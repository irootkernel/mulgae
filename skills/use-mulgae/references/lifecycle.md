# Mulgae lifecycle operations

Load this reference only for installation diagnosis, initialization, session
selection, cancellation, cleanup, reset, repair, or service-control requests.

## Diagnose installation and workspace state

Use read-only machine output first:

```bash
command -v mulgae
mulgae version --json
mulgae doctor --output json
mulgae config --mode effective --output json
mulgae providers --include-unverified --output json
```

Do not install, upgrade, authenticate, or rewrite provider paths on the user's
behalf unless separately authorized. A missing `.mulgae/config.yaml` means the
workspace has no shared project policy. A present project file with missing
`.mulgae/local.yaml` means this machine still needs bootstrap. Neither state
authorizes initialization.

## Initialize a workspace

Require explicit user intent. Confirm the canonical project root and intended
providers and roles before running one of the supported forms:

```bash
mulgae init --output json
mulgae init --providers zcode,agy --roles logic,security --output json
```

In a new project, `mulgae init` creates shared `.mulgae/config.yaml` and private
mode-`0600` `.mulgae/local.yaml` without overwriting an existing complete pair.
After a clone with only the shared file, the same command discovers the shared
provider families and creates only `local.yaml`; project-policy options are
rejected. Bare init for a new project enables only the required `logic` role,
so list every intended role explicitly with `--roles`; `logic` is always
included. If the outcome of init is uncertain, inspect both files and run
`mulgae config --mode effective --output json`; do not retry blindly.

The two files are individually atomic, not one joint filesystem transaction.
`project_committed_local_missing` means shared policy committed without an
admitted matching local file. Resolve any reported local-path collision, then
rerun plain `mulgae init`; it must preserve the shared file and create only the
machine-local file.

When provider installations move or the shared provider family set changes,
refresh only the machine file with explicit authorization:

```bash
mulgae init --refresh-local --output json
```

Refresh preserves `config.yaml`, atomically replaces only `local.yaml`, accepts
machine-path overrides, and rejects project-policy options. Config v1 is
rejected; there is no automatic migration.

## Start or associate a review

A normal `review` creates a new session and run. `followup`, `delta`, and
`rerun` create new runs with explicit lineage; they do not resume or replace a
prior run:

```bash
mulgae delta --since-run r_... --dirty --roles logic,testing --output json
mulgae rerun --run r_... --attempt a_... --output json
```

`delta` requires `--since-run`, `--roles`, and one target; `rerun` selects one
committed attempt with `--attempt` or with `--role` plus `--provider`. Use an
imported session only when the user supplied and authorized the canonical
session ID (not combinable with `--preflight`):

```bash
mulgae review --dirty --session s_... --output json
```

Mulgae has no task start, task replacement, or session replacement command.
Do not delete or rewrite state to simulate one.

## Cancel foreground work

Mulgae has no durable cancellation command. It handles interrupt or termination
signals for the foreground process and projects cancellation as exit `9`. Only
interrupt a running command when the user explicitly asks. Preserve any emitted
run ID and inspect it afterward:

```bash
mulgae status --run r_... --output json
```

Do not report cancellation as publication rollback; protected artifact,
security, and internal failures may take precedence.

## Clean durable artifacts

Cleanup is destructive and requires explicit user intent. Plan first:

```bash
mulgae clean --older-than 30d --dry-run --output json
mulgae clean --all --dry-run --output json
```

Apply only the reviewed selector, without `--dry-run`, after authorization.
Mulgae protects active, incomplete, corrupt, unknown, and required-lineage
state; never bypass those protections by deleting `.mulgae/` manually.

## Unsupported lifecycle controls

Mulgae is a foreground CLI with no daemon or service to start, stop, restart,
or repair. It has no reset command and no user-invoked repair command. Structured
output repair is an internal, constrained validation transition on the same
provider. Do not invent commands or modify private artifacts to simulate these
operations. For uncertain state, follow [recovery.md](recovery.md).
