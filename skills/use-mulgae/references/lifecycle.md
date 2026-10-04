# Mulgae lifecycle operations

Load this reference only for installation diagnosis, initialization, session
selection, cancellation, cleanup, reset, repair, or service-control requests.

## Diagnose installation and workspace state

Use read-only machine output first:

```bash
command -v mulgae
mulgae version --json
mulgae context --output json
mulgae doctor --output json
mulgae config --mode effective --output json
mulgae providers --include-unverified --output json
```

`mulgae-doctor-result.v5` is an offline contract. Read its independent config,
local-security, provider-identity, binary-availability, and CLI-compatibility
dimensions. A configured provider can be offline-ready while static evidence is
unavailable; `static_evidence_ready_provider_count` is separate from
`offline_ready_provider_count`. Doctor may execute only the adapter-owned local
`--version` command and never authenticates, sends a prompt, captures source, or
contacts a provider API. A live review cannot change doctor readiness.

Do not use heartbeat during ordinary diagnosis. When the user explicitly asks
for a live check, disclose its effects and require both the provider selection
and authorization flag:

```bash
mulgae heartbeat --provider zcode --authorize-live-request --output json
```

Omitting the flag must return `attempted: false`. A heartbeat uses only
Mulgae-owned synthetic material and neither establishes offline readiness nor
records review qualification.

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
mulgae init --providers zcode,grok --roles logic,security --output json
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

A normal `review` creates a new session/run. Use one of the five live selectors
and the independently checked project binding. An optional `--session` groups
a new run; it does not resume provider execution. Attached lifecycle is one
`start_review`, repeated waiting on the same exact `await_review`, and explicit
`cancel_review` followed by terminal await. No invocation survives server restart.

Historical child, replay and composite artifacts remain readable, but their
creation commands are retired. Retained recovery inventories confer no execution
authority. Obtain explicit intent for any new source review.

## Cancel foreground work

Mulgae has no durable cancellation command. It handles interrupt or termination
signals for the foreground process and projects cancellation as exit `9`. Only
interrupt a running command when the user explicitly asks. Preserve any emitted
run ID and inspect it afterward:

```bash
mulgae status --run r_... --output json
```

A host-imposed deadline may send the same signals. If the host merely stops
waiting, continue on the original process handle; if it signals the process or
the signal effect is unknown, treat the run as cancelled or uncertain and do
not start a replacement review. An exit `9` is terminal cancellation, not an
observer-only timeout.

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
state, including protected failed-recovery roots; never bypass those protections
by deleting `.mulgae/` manually. Self-contained composite evidence does not
authorize source deletion. Only the native cleanup plan establishes eligibility.

## Unsupported lifecycle controls

Mulgae is a foreground CLI with no daemon or service to start, stop, restart,
or repair. It has no reset command and no user-invoked repair command. Structured
output repair and structured extraction are both internal, constrained validation
transitions on the same provider; `002-extract` artifacts record one that already
ran and are not a command to re-run. Do not invent commands or modify private
artifacts to simulate these operations. For uncertain state, follow
[recovery.md](recovery.md).
