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

Current `mulgae-doctor-result.v9` is an offline contract. Read its independent config,
local-security, provider-identity, binary-availability, and CLI-compatibility
dimensions. A configured provider can be offline-ready while static evidence is
unavailable; `static_evidence_ready_provider_count` is separate from
`offline_ready_provider_count`. Doctor may execute only fixed offline
compatibility commands (`--version`, plus `herdr-zcode --version --json` and
`herdr-zcode --check-desktop --json` for ZCode) without starting a daemon, and
never authenticates, sends a prompt, captures source, or contacts a provider
API. A live review cannot change doctor readiness.

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
machine-path overrides, and rejects project-policy options. Upgrading Mulgae
preserves an existing valid Config v5 pair and retained `.mulgae/` history;
never replace an existing configured pair with a fresh `mulgae init`. Config v1
is rejected; there is no automatic migration.

## Start or associate a review

A normal `review` creates a new session/run. Use one of the five live selectors
and the independently checked project binding. An optional `--session` groups
a new run; it does not resume provider execution. Attached lifecycle is one
`start_review`, repeated waiting on the same exact `await_review`, and explicit
`cancel_review` followed by terminal await. No invocation survives server restart.

Before live provider qualification, role execution, or structured extraction,
the shared CLI, foreground MCP (`run_review`), and asynchronous MCP
(`start_review`) review path coordinates through the selected private
`HAEPARI_HOME` Installation (`advisory-lock/v1`) and its capacity-one
`mulgae-review` resource. Local `--preflight`/`preflight_review`,
`context`/`get_context`, receipt-bound verified reads, `clean`, and admitted
no-change targets require no controller or lock grant.

- Owned grant lifecycle: When `HAEPARI_LOCK_GRANT` is absent, Mulgae
  acquires `mulgae-review` once for the admitted review, waits in queue inside
  the original review invocation, renews in process through provider/source
  drain, and releases after terminal completion, failure, or cancellation before
  returning for any user decision. The registered maximum hold and remaining
  hold budget must cover the full admitted run budget (`budget.run_deadline`),
  preparation, and two minutes of terminal cleanup. Missing, unsafe, or
  under-budget coordination prerequisites fail admission closed; review
  execution never registers or mutates `mulgae-review` policy, and setup or
  policy changes require separate authority. After a queue wait and before
  provider dispatch, Mulgae revalidates the admitted local source, project
  binding, configuration, and remaining budget; the caller must keep workspace
  and index state unchanged throughout waiting and execution.
- Borrowed grant lifecycle (`HAEPARI_LOCK_GRANT`): When `HAEPARI_LOCK_GRANT`
  is set, Mulgae validates the closed JSON grant reference (`installation_id`,
  `lock_id`, `grant_id`, positive `generation`) read-only against the selected
  Installation (`hello`, `resource.inspect`, and bounded `locks.list` for
  `mulgae-review`) and monitors parent validity during child execution. A
  borrower never acquires, waits, renews, cancels, releases, or force-releases
  its parent's grant; invalid, mismatched, stale, ended, or expired parent
  grants fail closed without reacquisition or uncoordinated fallback.
- Advisory limits: `mulgae-review` serializes cooperating reviews across
  project roots on the same Installation, while parallel roles inside one
  admitted review share that run's grant. Advisory serialization does not
  prevent provider rate limits, block callers that skip the lock, or forcibly
  terminate an unverified local provider process (`haepari_local_drain_unverified`)
  after hold expiry or lost renewal, so overlap remains possible after lost
  protection.

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
state, including protected failed-recovery roots, legacy unknown-drain
coordination records, and owned or borrowed runs whose local provider/source
drain is unverified (`haepari_local_drain_unverified`); never bypass those
protections by deleting `.mulgae/` manually. Once a borrowed child run verifies
its own local drain, its child artifacts can be cleaned independently while the
parent grant remains live. Self-contained composite evidence does not
authorize source deletion. Only the native cleanup plan establishes eligibility.

## Unsupported lifecycle controls

Mulgae is a foreground CLI with no daemon or service to start, stop, restart,
or repair. It has no reset command and no user-invoked repair command. Structured
output repair and structured extraction are both internal, constrained validation
transitions on the same provider; `002-extract` artifacts record one that already
ran and are not a command to re-run. Do not invent commands or modify private
artifacts to simulate these operations. For uncertain state, follow
[recovery.md](recovery.md).
