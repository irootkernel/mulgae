# ZCode herdr-core terminal runtime migration via herdr-zcode

## Execution authority and lifetime

The sole consumer is Mulgae `EPIC-019`. Its
[roadmap](../roadmap/README.md#epic-019-zcode-herdr-core-terminal-runtime-migration-via-herdr-zcode)
alone owns work identity, order, dependencies, lifecycle, and status. This is the
temporary execution SOT for sequential Task execution (`TASK-094` through
`TASK-098`). Read repository guidance (`AGENTS.md`) and the canonical owners
below before planning or implementing any member Task. Design adoption does not
establish implementation, verification, release, or Epic acceptance.

On explicit Epic acceptance, promote all durable behavior, structure, rationale,
verification guidance, and operational facts to their canonical owners, remove
this temporary dossier and its `docs/todo/README.md` index entry, replace
`Detailed SOT` with `Canonical Outcomes` in `docs/roadmap/README.md`, and mark
`EPIC-019` as `Completed`.

## Goal and phase boundary

Migrate Mulgae's `zcode` review provider (`FamilyZcode`) from direct ZCode
Desktop coupling (`zcode_protocol.go`, `zcode_account.go`, `zcode_keychain.go`,
and `ZCode.app` internal bundle probing) onto Mulgae's shared isolated
`herdr-core` terminal runtime (`ProviderPacketChannelTerminal`,
`__mulgae_paneexec_v1`, hardened outer macOS Seatbelt `PaneTTY` + five-control
`B-1` `BashGate`, and scratch-file `staged_file` delivery established in
`EPIC-017`), driven through the installed `herdr-zcode` CLI's `--runtime core`
mode.

Three product objectives govern this migration:

1. **Unified Grok/ZCode terminal interface**: Both active providers (`zcode` and
   `grok`) run behind the same `herdr-core` + `__mulgae_paneexec_v1` + Seatbelt +
   OSC 7501 + `staged_file` boundary.
2. **True robustness against ZCode Desktop upgrades**: `herdr-zcode` becomes the
   sole owner of every ZCode Desktop internal (`ZCode.app` bundle layout,
   `zcode.cjs` path/version, `app-server` NDJSON protocol, `zcode-builtin.json`
   schema and Desktop cache discovery, `setting.json`, `credentials.json`, and
   Keychain `keyring.node`/`codesign` decryption). Future ZCode Desktop upgrades
   update and reinstall `herdr-zcode` alone; Mulgae requires zero code changes.
3. **Model default policy (`GLM-5.4` + `max`, omit-to-keep-current-model)**:
   New projects initialized via `mulgae init` without `--zcode-model` or
   `--zcode-reasoning-effort` write
   `account:zai-individual-coding-plan/GLM-5.4` and `max` into
   `.mulgae/config.yaml` with `"mulgae_default"` provenance (symmetric with
   Grok's `grok-4.7` / `high`). Omitting `providers.zcode.model` and/or
   `providers.zcode.reasoning_effort` in Config v5 omits `--model` /
   `--reasoning-effort` at runtime so `herdr-zcode` preserves ZCode's current
   session model and effort.

**Preserved unchanged in `EPIC-019`**:
- Config v5 schemas (`.mulgae/config.yaml` and `.mulgae/local.yaml`, where
  `providers.zcode.app_bundle` remains an optional machine-local path passed
  opaquely to `herdr-zcode --app-bundle`).
- Grok's `herdr-core` terminal runtime (`EPIC-017`), role routing, invocation
  budgets, source-admission model (no source snapshots or copied checkouts),
  and frozen historical artifact/manifest readers.
- `mulgae-doctor-result.v9.schema.json` (additive `herdr_zcode_*` reason codes
  conform to the existing `^[a-z][a-z0-9_]{0,63}$` pattern).

**Versioned contract evolution owned by `EPIC-019`**:
- `TASK-097` introduces `mulgae-command-result.v26.schema.json` (retaining `v25`
  frozen for backward reads) to add `"mulgae_default"` to
  `init_discovery_zcode.model_source` and
  `init_discovery_zcode.reasoning_effort_source`.

## Canonical owners

| Concern | Owner |
|---|---|
| Structural decision and rejected alternatives | [ADR: ZCode herdr-core terminal transport](../architecture-decision-records/zcode-herdr-core-transport.md) |
| Shared `herdr-core` terminal runtime decision | [ADR: herdr-core terminal transport](../architecture-decision-records/herdr-core-terminal-transport.md) |
| Legacy ZCode transport record (to be superseded in `TASK-098`) | [ADR: ZCode app-server transport](../architecture-decision-records/zcode-app-server-transport.md) |
| Architecture and dependency direction | [Architecture](../architecture/README.md) |
| Trust boundaries and provider isolation | [Security](../specs/security.md) |
| Public contracts and provider transport | [Contracts](../specs/contracts.md) |
| Live workspace and Git review model | [Live workspace and Git review](../specs/live-workspace-and-git-review.md) |
| Release design gates | [Gating rules](../gating-rules.md) |
| Verification and release workflow | [Implementation guidance](../implementation-tips/README.md) |
| Deferred ZCode control-plane hardening (`DF-030`) | [Deferred feedback](../deferred-feedback/README.md) |

Until `TASK-096` and `TASK-097` land their owning cutovers, `docs/specs/`,
`docs/architecture/README.md`, `docs/gating-rules.md`,
`docs/deferred-feedback/README.md`, and embedded assets continue describing the
currently implemented ZCode app-server runtime. Each cutover Task updates every
affected canonical document, schema, example, embedded help asset (with
idempotent double regeneration), and test in the same change.

## External companion prerequisite in `herdr-zcode` (gates `EPIC-019` execution)

Direct inspection of `herdr-zcode` (`0.2.0`, verified producer commit
`16e2647b396fa84c62086ae9766bacdf4fe334a6`, docs closeout
`5a0a30cc25766f8b7395aba4c50f86b686650857`, installed to `~/.local`) and
`ZCode.app 4.0.0` (bundled launcher `0.18.0`) established the exact
cross-repository contract:

1. `herdr-zcode`'s `--runtime core --non-interactive` mode already delivers
   OSC 7501 status transitions (`idle`, `working`, `done`, `blocked:kind=*`,
   `error`), `detached: false` same-PGID child ownership, bounded `SIGHUP`/
   `SIGTERM` teardown (`<= 1s` `ESRCH` target), `--auth-file --consume-auth-file`, `--runtime-dir`,
   `--no-copy-catalog`, `--skip-desktop-inspect`, `--tool-allowlist`/
   `--tool-denylist`/`--additional-dir`, `--disable-{mcp,title-gen,offpeak,dynamic-workflow}`,
   `--persistence deferred`, `--interaction-policy block|deny`, `--model`,
   `--reasoning-effort`/`--thought-level`, and omit-`--model` session-default
   preservation.
2. On `ZCode.app 4.0.0`, the bundled catalog
   (`Contents/Resources/config/provider/zcode-builtin.json`) is **revision `44`**
   containing only `["GLM-5.3", "GLM-5.3-Flash"]` (no `GLM-5.4`). `GLM-5.4`
   exists only in ZCode Desktop's cached catalog (revision `48`:
   `["GLM-5.4", "GLM-5.3", "GLM-5.3-Flash"]`). In `herdr-zcode 0.1.0`,
   projected `--auth-file` sessions were locked to bundled revision `44`.

To resolve the `GLM-5.4` projected-catalog blocker AND remove 100% of ZCode
Desktop internal coupling from Mulgae, the following three generic,
non-Mulgae-specific CLI capabilities in `herdr-zcode 0.2.0` must be committed,
live-certified against a signed Z.AI Coding Plan account (`GLM-5.4` `max`), and
installed to `~/.local` before starting `EPIC-019` execution:

1. **`--catalog-file <path>`**:
   - Accepted in `--runtime core` / projected (`--auth-file`) mode alongside
     `--no-copy-catalog`.
   - Validates the target path with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK` as a
     regular file (`nlink == 1`, owned by current UID, no group/other write
     bits `(mode & 0o022) === 0`, size `1..4 MiB`), JSON object with
     `schemaVersion === 1`, positive integer `revision`, Coding Plan rule
     present, and exact `api.type` + `api.baseUrl` compatibility against the
     bundled `ZCode.app` Coding Plan rule (`compatibleCodingPlanRule`); fails
     closed otherwise.
   - Binds the validated catalog consistently for both `projectedAccount` model
     validation and `ZCODE_BUILTIN_PROVIDER_CONFIG_FILE`.
2. **`prepare-isolated --out-dir <path> [--app-bundle <path>] [--json]`**:
   - Runs on the trusted host (outside Seatbelt) using `ZCode.app`'s signed
     embedded Electron runtime and `herdr-zcode`'s existing `inspectDesktop`,
     `desktopAccount`, `createKeychainSource`, and `desktopCatalogCachePath`
     helpers under a bounded 12s deadline (10s work + 2s cleanup reserve).
   - Requires `<path>` to be an existing caller-created private `0700` directory
     owned by the current UID (verified with `O_DIRECTORY | O_NOFOLLOW` and
     re-checked by `(dev, ino)` around every write).
   - Atomically creates (`O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`) exactly
     two files inside `<path>`:
     - `auth.json` (`0600`, `<= 64 KiB`) containing the projected credentials
       consumed by `--auth-file --consume-auth-file`, where `accountAccess` is
       the structured object
       `{"type":"zhipu-account","mode":"individual-coding-plan","accountType":"zai"}`.
     - `catalog.json` (`0400`, `<= 4 MiB`) containing the active resolved
       public provider catalog (preferring valid compatible cached Desktop
       catalog such as rev `48` with `GLM-5.4` over bundled rev `44`).
   - Emits either a **secret-free 9-field JSON receipt** on stdout (exit `0`):
     `{"authFile":"...","catalogFile":"...","catalogRevision":48,"catalogSHA256":"...","catalogSource":"desktop-cache","appVersion":"4.0.0","minZcodeAppVersion":"3.18.2","providerId":"account:zai-individual-coding-plan","accountIdentitySHA256":"..."}`
     or a **closed `{reason, message}` JSON error** on stdout (exit `1`) where
     `reason` is one of `invalid_arguments`, `app_bundle_missing`,
     `app_bundle_invalid`, `app_version_below_minimum`,
     `embedded_runtime_invalid`, `output_dir_invalid`, `output_exists`,
     `desktop_account_unavailable`, `desktop_keychain_unavailable`,
     `catalog_invalid`, `preparation_timeout`, `preparation_interrupted`, or
     `projection_failed`.
   - Security invariant: never prints API keys, auth tokens, headers, or raw
     `identity` to stdout or stderr on success or failure; zero-fills and
     unlinks partial `auth.json` on abort/error; never mutates `~/.zcode` or
     Keychain entries. After `SIGKILL`, pre-consumption errors, or producer
     cleanup failure, Mulgae's namespace drain owns zero-fill/unlink cleanup of
     any remaining `auth.json`.
3. **`--check-desktop --json [--app-bundle <path>]` and `--version --json` capabilities**:
   - Exposes offline desktop compatibility inspection with zero account reads,
     zero Keychain reads, and zero network calls (working under empty `HOME`,
     unset `NVM_DIR`, `cwd=/private/var/empty`, `PATH=/usr/bin:/bin`).
   - Prints structured JSON:
     `{"compatible":true,"appVersion":"4.0.0","build":"...","minZcodeAppVersion":"3.18.2","appBundle":"...","nodeVersion":"...","electronVersion":"..."}`
     (or `compatible: false` with closed `reason` and `message` on exit `1`).
   - Advertises the companion capabilities in `herdr-zcode --version --json`:
     `"version":"0.2.0"` and
     `"capabilities":["core","osc7501","catalogFile","prepareIsolated","checkDesktop"]`
     (alongside `"name"`, `"runtimes"`, `"osc7501"`, and `"minZcodeAppVersion"`).

**Prerequisite status register**:
- Repository: `herdr-zcode` (`herdr-zcode:EPIC-002` **`Completed`**; verified
  producer commit `16e2647b396fa84c62086ae9766bacdf4fe334a6`, docs closeout
  `5a0a30cc25766f8b7395aba4c50f86b686650857`, version `0.2.0`, npm archive
  SHA-256 `9bca9ae6132e26b43c31c3329c287f98b375ee9905aca32eddb0521c21e53511`).
- **Status: Satisfied & verified on host.** Installed `~/.local/bin/herdr-zcode`
  reports `0.2.0` with all 5 capabilities (`--version --json`),
  `compatible: true` on `ZCode.app 4.0.0` (`--check-desktop --json`), and exact
  20-runtime-file aggregate SHA-256
  `e23505b5eac11bac202461fad2c1882e61347edfc21c9e658a499510bc794111` matching the
  committed checkout bit-for-bit. Elapsed teardown latency (`<= 1s` `ESRCH`)
  and Mulgae Seatbelt/`B-1` `BashGate` qualification remain owned by
  `TASK-095`.

## Requirement-to-Task Traceability Matrix

| Req ID | Requirement | Owning Task(s) | Primary Packages / Assets | Verification Owner |
|---|---|---|---|---|
| `REQ-01` | Discover `herdr-zcode` safely (`MULGAE_HERDR_ZCODE_BIN` -> safe `PATH` -> `<nativeHome>/.local/bin/herdr-zcode`), verify canonical symlink chain and complete 20-runtime-file SHA-256 digest before every spawn | `TASK-094`, `TASK-096` | `internal/adapters/herdr`, `internal/adapters/providercli` | `-race` unit/tamper tests + `TASK-095` control #1 |
| `REQ-02` | Execute host `prepare-isolated` outside Seatbelt (`cwd=/private/var/empty`, minimal env, 15s cap), validate `0600` `auth.json` + `0400` `catalog.json` via `O_NOFOLLOW`, classify stdout JSON `reason`, and register drain zeroing | `TASK-094`, `TASK-095`, `TASK-096` | `internal/adapters/providercli` | `-race` negative tests + `TASK-095` control #2 |
| `REQ-03` | Narrow `BashGate` `process-exec` denial to exact Herdr multiplexers (`hc\|herdr\|herdr-core\|herdr-app\|herdrd`) while keeping repo-hosted executables, Herdr sockets, and `~/.zcode`/`Keychains` kernel-denied | `TASK-094`, `TASK-095`, `TASK-096` | `internal/adapters/process` | Darwin kernel Seatbelt tests + `TASK-095` control #8 |
| `REQ-04` | Drive `FamilyZcode` through shared `ProviderPacketChannelTerminal` + `zcodeTerminalProfile` (`--runtime core --non-interactive --auth-file --consume-auth-file --catalog-file --no-copy-catalog --skip-desktop-inspect --runtime-dir`), preserving `RuntimeTempRoot` (`/tmp/mulgae-zcode`) and `<= 1s` `ESRCH` teardown | `TASK-094`, `TASK-095`, `TASK-096`, `TASK-098` | `internal/adapters/providercli`, `internal/app/reviewrun`, `internal/composition` | `TASK-095` controls #2–#10 + `make test-e2e` |
| `REQ-05` | Retire and delete `zcode_protocol.go`, `zcode_account.go`, `zcode_keychain.go`, and internal `ZCode.app` component probing while keeping frozen historical readers and opaque `providers.zcode.app_bundle` Config v5 pass-through | `TASK-096` | `internal/adapters/{providercli,environment}`, `internal/app/reviewrun`, `internal/architecture` | Architecture/import guards + `make test-offline` |
| `REQ-06` | Preserve `EPIC-018 TASK-091` same-profile ZCode qualification sharing while binding `herdr-core`, 20-file `herdr-zcode` digest, observed desktop/catalog receipt, and omitted-vs-explicit model/effort; add synthetic `zcode-logic` heartbeat | `TASK-096`, `TASK-098` | `internal/app/reviewrun`, `internal/adapters/providercli`, `internal/composition` | Qualification sharing/partition tests + `heartbeat --provider zcode` |
| `REQ-07` | Run offline `mulgae doctor` checks via `herdr-zcode --version --json` + `--check-desktop --json` with additive `herdr_zcode_*` reasons under `doctor-result.v9` (zero Keychain/network/`herdr-core` starts) | `TASK-096` | `internal/app/doctor`, `internal/adapters/environment` | Doctor `-race` + schema tests |
| `REQ-08` | Unify ZCode workspace reviews (`Read,Grep,Glob,Write`, incl. `artist`) and extraction/qualification/heartbeat (`Read,Write`) as shell-free, confining `Bash` strictly to Git scopes under 5-control `B-1` `BashGate`, closing `DF-030` | `TASK-095`, `TASK-096`, `TASK-098` | `internal/adapters/{providercli,process}`, `docs/deferred-feedback/README.md` | `TASK-095` controls #7–#9 + live `make test-e2e` |
| `REQ-09` | Default new `mulgae init` ZCode policy to `account:zai-individual-coding-plan/GLM-5.4` + `max` (`"mulgae_default"` under `mulgae-command-result.v26`, `v25` frozen) while existing Config v5 omission keeps ZCode's current session model/effort | `TASK-097`, `TASK-098` | `internal/app/init`, `internal/builtin/assets/schemas/`, `internal/entrypoint/{mulgae,mcp}` | `init`/schema `-race` tests + double generator + live `GLM-5.4` & omitted-model runs |
| `REQ-10` | Certify integrated candidate on native Apple Silicon (`test-offline`, `test-release`, `test-herdr`, live ZCode `test-e2e`, live `test-grok`), promote ADR (superseding `zcode-app-server-transport.md`), close `DF-030`, and retire this dossier after Master acceptance | `TASK-098` | Canonical `docs/`, `CHANGELOG.md`, `README.md`, `skills/use-mulgae` | Full release-candidate gate + `ps`/host-hygiene + doc readback |

## Dependency DAG & Member Scope Classification

```text
herdr-zcode 0.2.0 (committed + live certified + ~/.local installed)
  └── TASK-094 (substantive: dark resolver, 20-file SHA-256, narrowed BashGate, host prepare-isolated, dark profile)
        └── TASK-095 (substantive: build-tagged 10-point live go/no-go spike)
              └── TASK-096 (substantive: atomic cutover, Go internal retirement, doctor, heartbeat, canonical docs)
                    └── TASK-097 (substantive: init GLM-5.4/max defaults + command-result.v26)
                          └── TASK-098 (validation & closeout: live certification, ADR promotion, DF-030 closure, dossier retirement)
```

| Member | Scope Classification | Predecessors | Release-Note Obligation |
|---|---|---|---|
| `TASK-094` | `substantive` | `herdr-zcode 0.2.0` installed prerequisite | `intentional no-note` (dark internal groundwork) |
| `TASK-095` | `substantive` | `TASK-094` committed | `intentional no-note` (build-tagged live spike) |
| `TASK-096` | `substantive` | `TASK-095` committed (all 10 controls green) | `CHANGELOG.md` entry (ZCode `herdr-core` migration & `DF-030`) |
| `TASK-097` | `substantive` | `TASK-096` committed | `CHANGELOG.md` update (`init` `GLM-5.4`/`max` default & `command-result.v26`) |
| `TASK-098` | `mixed` (Validation & Closeout) | `TASK-094`–`TASK-097` committed | Final verification of `CHANGELOG.md` + ADR/`DF-030`/dossier closeout after Master acceptance |

## Disposable Artifact & Host Residue Cleanup Contract

Every Task execution and whole-Epic validation check must enforce clean ownership of disposable outputs before advancing:

| Artifact / Surface | Owner | Required Cleanup / Invariant |
|---|---|---|
| `<namespace>/auth/iso-<invID>/auth.json` | Mulgae namespace drain + `--consume-auth-file` | Zero-filled and unlinked (`nlink == 0`) before pane prompt delivery, or zero-filled and unlinked during namespace drain on `SIGKILL`/pre-consumption failure |
| `<namespace>/auth/iso-<invID>/catalog.json` and `<namespace>/tmp/` | Mulgae namespace drain (`cleanupRoots()`) | Removed atomically with the disposable namespace |
| `/private/tmp/mgh-<uid>/<16hex>/` (`herdr-core` session dir) | `productionRuntimeGraph.closeTerminalSession()` + Go watchdog | Empty `/private/tmp/mgh-<uid>` after every test/live run; zero surviving `hc`/`holder` processes |
| `/tmp/mulgae-zcode/zcode-official-*/endpoint.sock` | `herdr-zcode` fast teardown + test cleanup | Zero surviving `ZCode`/`node`/`Electron`/`herdr-zcode` processes (`ESRCH <= 1s`) |
| Temporary build/test binaries & scratch fixtures | Task verification executor | Removed before staging/commit; never staged or committed |
| Operator host state (`~/.zcode`, `~/.grok`, operator `default` `herdr-core`) | Read-only host invariant | SHA-256 digests of `~/.zcode` and `~/.grok` unchanged; operator `default` `herdr-core` PIDs untouched |

## Approved architecture and invariants

### 1. Clean responsibility boundary (`mulgae` vs `herdr-zcode`) and retirement inventory

| Concern | Owner | Upgrade-resilience effect |
|---|---|---|
| `ZCode.app` internal bundle layout (`Contents/MacOS/ZCode`, `zcode.cjs`, `zcode-builtin.json`, `Info.plist`) | `herdr-zcode` | Bundle restructures require zero Mulgae changes |
| Desktop account & Keychain decryption (`setting.json`, `credentials.json`, `enc:v1`, `enc:v2:os`, `keyring.node`, `codesign`) | `herdr-zcode` (`prepare-isolated`) | Auth/Keychain upgrades require zero Mulgae changes |
| Active catalog resolution (Desktop cache rev `48` with `GLM-5.4` vs bundled rev `44`) | `herdr-zcode` (`prepare-isolated` + `--catalog-file`) | Catalog schema/path changes require zero Mulgae changes |
| ZCode `app-server` NDJSON wire protocol, session/model/effort verification, OSC 7501 framing, fast teardown | `herdr-zcode` (`--runtime core`) | Protocol/wire changes require zero Mulgae changes |
| `herdr-zcode` package tamper verification (canonical symlink chain + full package SHA-256) | `mulgae` | Trusted execution across both host `prepare-isolated` and sandboxed pane |
| Isolated `herdr-core` daemon, `__mulgae_paneexec_v1`, outer Seatbelt (`PaneTTY`, `CredentialRoots`, `TerminalSecretRoots`, `RuntimeTempRoot`, `B-1` `BashGate`), `staged_file` prompt/output & completion nonce, review/validation/publication | `mulgae` | Shared across both `grok` and `zcode` with zero provider-internal coupling |

**Retirement inventory (`TASK-096`)**:
- Delete `internal/adapters/providercli/zcode_protocol.go` and its protocol-only
  tests.
- Delete `internal/adapters/providercli/zcode_account.go` and its account-bridge
  tests.
- Delete `internal/adapters/providercli/zcode_keychain.go` and its Keychain
  decryption tests.
- Remove ZCode Desktop internal-file inspection (`Contents/MacOS/ZCode`,
  `Contents/Resources/zcode/zcode.cjs`, `zcode-builtin.json`, `Info.plist`
  parsing) from `internal/adapters/environment/executable.go`,
  `internal/adapters/providercli/qualifier.go`, and
  `internal/app/reviewrun/qualification.go` (preserving `providers.zcode.app_bundle`
  as an opaque canonical path verified for safe ownership/directory semantics
  and passed to `herdr-zcode --app-bundle`).
- Retain all frozen historical artifact/manifest readers and historical domain
  values untouched.

### 2. `herdr-zcode` package discovery and full package SHA-256 verification

Mirror `internal/adapters/herdr/resolve_darwin.go` for `herdr-zcode`:

- **Discovery order**:
  1. `MULGAE_HERDR_ZCODE_BIN` (explicit absolute override; rejects relative
     paths, project-root / `WritableRoot` entries, and unsafe permissions).
  2. Safe `PATH` entries (same safe-directory filters as `herdr-core`).
  3. `<nativeHome>/.local/bin/herdr-zcode`.
- **Canonical symlink & ownership verification**:
  - Resolve symlink chain component-by-component with bounded depth (`O_NOFOLLOW`
    checks on each ancestor and target), verifying every ancestor directory and
    file is owned by `euid` or `root` with no group/world write bits.
  - Note: `~/.local/lib/node_modules/herdr-zcode` sits outside Mulgae's
    `TerminalSecretRoots` (which denies `~/.local/state`, not `~/.local/bin` or
    `~/.local/lib`).
- **Complete 20-runtime-file package SHA-256 digest** (agreed with `herdr-zcode` `0.2.0`):
  - Because `herdr-zcode`'s entry path (`bin/herdr-zcode`) executes both
    `scripts/desktop-bootstrap.pl`, `scripts/toolchain.sh` (and
    `scripts/tool-bin/{npm,npx}`), and the Node/ESM entrypoint
    `bin/herdr-zcode-app.mjs` + `lib/*.mjs`, verifying only `bin/` + `lib/` is
    insufficient.
  - Compute one deterministic canonical aggregate SHA-256 over the exact **20
    runtime files** sorted strictly by UTF-8 byte order of package-relative
    POSIX path:
    `bin/herdr-zcode`, `bin/herdr-zcode-app.mjs`, `lib/app-server-client.mjs`,
    `lib/app-server-controller.mjs`, `lib/desktop-account.mjs`,
    `lib/desktop-catalog.mjs`, `lib/desktop-keychain.mjs`,
    `lib/desktop-runtime.mjs`, `lib/error-classification.mjs`,
    `lib/herdr-reporter.mjs`, `lib/osc7501-reporter.mjs`,
    `lib/prepare-isolated.mjs`, `lib/runtime-profile.mjs`, `lib/toolchain.mjs`,
    `package.json`, `scripts/desktop-bootstrap.pl`, `scripts/tool-bin/npm`,
    `scripts/tool-bin/npx`, `scripts/toolchain.sh`, and `toolchains.env`.
  - Reject symlinks, non-regular files, `nlink != 1`, wrong ownership, missing
    members, or group/other write bits `(mode & 0o022) != 0` on any member or
    package root.
  - Canonical manifest serialization: one UTF-8 line per file formatted as
    `<relpath>\t<decimal-byte-length>\t<lowercase-hex-sha256>\n` (single TAB
    separators, single LF per line, no trailing extra newline); aggregate
    digest is the lowercase hex SHA-256 of the serialized manifest bytes.
  - Bind the canonical launcher path, binary `(dev, ino)`, and complete
    20-file package SHA-256 into `RuntimeSafetyPolicyForZCodeTerminal`,
    qualification proofs, and a `SpawnVerifier` hook revalidated immediately
    before host `prepare-isolated` AND immediately before sandboxed pane
    launch. Any package-file drift fails closed as a security/integrity error
    without retry.

### 3. Trusted-host `prepare-isolated` boundary and drain zeroing

Before each sandboxed ZCode pane invocation (review, extraction, qualification,
or heartbeat):

1. Revalidate the `herdr-zcode` complete package SHA-256.
2. Create a per-invocation private directory `<namespace>/auth/iso-<invID>`
   (`0700`, `O_NOFOLLOW`) inside the disposable namespace.
3. Run `<canonical-herdr-zcode> prepare-isolated --out-dir <namespace>/auth/iso-<invID>`
   (adding `--app-bundle <canonical-configured-bundle>` when configured) on the
   trusted host outside Seatbelt with:
   - `cwd = /private/var/empty`
   - bounded timeout `<= 15s` (derived from parent context)
   - minimal explicit env (`HOME=<nativeHome>`, `PATH=/usr/bin:/bin`,
     `TMPDIR=/tmp`, zero project paths, zero prompt content, zero inherited
     `HC_*`/`HERDR_*`/`DYLD_*`/`LD_*`/`NODE_OPTIONS`).
4. Parse the secret-free stdout JSON receipt (bounded reader, strict schema
   check, rejecting unexpected extra/secret fields).
5. Stat and validate emitted files using `O_NOFOLLOW`:
   - `auth.json`: regular file, single hardlink (`Nlink == 1`), mode `0600`,
     owner `euid`, size `1..65536` bytes.
   - `catalog.json`: regular file, single hardlink (`Nlink == 1`), mode `0400`,
     owner `euid`, size `1..4194304` bytes, matching `catalogSHA256` from the
     receipt.
6. Register `auth.json` immediately with the namespace drain cleaner so that
   even if pane launch fails or cancels before `--consume-auth-file` executes,
   Mulgae zero-fills and unlinks `auth.json` during namespace drain.
7. Bind `appVersion`, `catalogRevision`, `catalogSHA256`, and
   `accountIdentitySHA256` from the receipt into qualification/runtime proofs
   and fail closed on drift between qualification and execution.

### 4. Sandboxed `herdr-core` pane execution, Seatbelt rules, and `DF-030`

- **Exact `zcodeTerminalProfile` pane argv** (launched via `terminal.run` ->
  `__mulgae_paneexec_v1` -> `/usr/bin/sandbox-exec -D PANE_TTY=<slave> -f <profile> <canonical-herdr-zcode> ...`):
  - `--runtime core --non-interactive --interaction-policy block`
  - `--cwd <neutralCWD>` (`~/.mulgae/home`, read-only)
  - `--mode yolo`
  - `[--app-bundle <canonical-configured-bundle>]` (when configured)
  - `--skip-desktop-inspect` (host pre-check already ran offline)
  - `--auth-file <namespace>/auth/iso-<invID>/auth.json --consume-auth-file`
  - `--catalog-file <namespace>/auth/iso-<invID>/catalog.json --no-copy-catalog`
  - `--runtime-dir <namespace>/tmp` (keeps `herdr-zcode`'s disposable state
    inside `WritableRoot`)
  - `--disable-mcp --disable-title-gen --disable-offpeak --disable-dynamic-workflow --persistence deferred`
  - `--additional-dir <sourceRoot>` (review only; omitted on extraction,
    qualification, and heartbeat)
  - `--additional-dir <scratch>/input/<invID>`
  - `--additional-dir <scratch>/output/<invID>`
  - `--model <providers.zcode.model>` **only when non-empty in Config v5**
  - `--reasoning-effort <providers.zcode.reasoning_effort>` **only when
    non-empty in Config v5**
- **Short `TMPDIR` for `endpoint.sock`**:
  - ZCode `app-server` binds `os.tmpdir()/zcode-official-*/endpoint.sock`, which
    exceeds macOS's 104-byte `sun_path` limit if pointed into deep namespace
    paths.
  - Retain `RuntimeTempRoot` (`/tmp/mulgae-zcode`, `0700`) in the Seatbelt
    profile and set `TMPDIR`/`TMP`/`TEMP` to `/tmp/mulgae-zcode` inside the
    pane env while passing `--runtime-dir <namespace>/tmp` to `herdr-zcode`.
  - Keep native `~/.zcode` and `~/Library/Keychains` 100% kernel-denied inside
    `CredentialRoots` / `TerminalSecretRoots`.
- **Narrowed `BashGate` `process-exec` regex**:
  - `internal/adapters/process/live_boundary_darwin.go` currently denies
    `(regex #"^(.*/)?(hc|herdr[^/]*)$")` under `BashGate`, which blocks
    executing `herdr-zcode` itself on Git scopes.
  - Narrow this regex to exact Herdr multiplexer binaries:
    `(regex #"^(.*/)?(hc|herdr|herdr-core|herdr-app|herdrd)$")`.
  - Repo-hosted executables remain denied by `WritableRoot` / `ReadOnlyRoots` /
    `RuntimeTempRoot` `process-exec` denials, and all `herdr-core` sockets
    remain denied by `ControlPlaneRoots` and default-deny outbound
    `unix-socket`.
- **Unix-socket verification under `B-1` `BashGate`**:
  - `TASK-095` must empirically verify whether ZCode `app-server`'s
    `/tmp/mulgae-zcode/zcode-official-*/endpoint.sock` requires an explicit
    scoped Seatbelt `unix-socket` allow rule restricted solely to
    `subpath "/tmp/mulgae-zcode"` (or `/private/tmp/mulgae-zcode`) when
    `B-1` `BashGate` is active on Git scopes. Any required allow rule must
    stay strictly confined to Mulgae's private `RuntimeTempRoot` and never
    widen access to operator sockets (`/private/tmp/mgh-*`, `ssh-agent`,
    operator `herdr`, `~/.grok/leader.sock`).
- **Purpose-scoped tools and `DF-030` closure**:

| Purpose | `--tool-allowlist` | `--tool-denylist` | `BashGate` (`B-1`) |
|---|---|---|---|
| Workspace Review (incl. `artist`) | `Read,Grep,Glob,Write` | `Bash,Edit,Agent,TodoWrite,NotebookEdit,WebSearch,WebFetch,EnterPlanMode,ExitPlanMode` | Off (Shell-Free) |
| Git Review (`stage`/`head`/`commit`/`diff`, incl. `artist`) | `Read,Bash,Write` | `Grep,Glob,Edit,Agent,TodoWrite,NotebookEdit,WebSearch,WebFetch,EnterPlanMode,ExitPlanMode` | **On** (5-control `B-1`) |
| Extraction (`002-extract`) & Qualification / Heartbeat | `Read,Write` | `Bash,Grep,Glob,Edit,Agent,TodoWrite,NotebookEdit,WebSearch,WebFetch,EnterPlanMode,ExitPlanMode` | Off (Shell-Free) |

  - Pending `TASK-095` confirming `artist` multimodal image reads succeed via
    `Read` alone on workspace scope, workspace reviews run shell-free and Git
    reviews run under all five `B-1` `BashGate` controls, closing `DF-030` in
    `TASK-096`/`TASK-098`.
  - If `TASK-095` discovers that `artist` image inspection unexpectedly
    requires `Bash` on workspace scope, stop before `TASK-096` and reconcile
    explicitly rather than silently weakening workspace isolation.
- **Prompt delivery, staged output, and failure classification**:
  - Reuse `EPIC-017`'s `0400` `<scratch>/input/<invID>/prompt.md` + pre/post
    digest receipt + mandatory end-of-prompt completion nonce + concise
    `terminal.send` instruction + post-`ESRCH` `stagedOutputLease.Validate()`
    (`role-report.md`, `extraction.json`, `probe.json`) + `B-1` Control 5
    survivor/`mtime`/`ctime` checks.
  - Map `herdr-zcode` OSC 7501 `error` / non-zero pre-`reported` exit codes
    and bounded screen/stderr markers into Mulgae's typed failure classes:
    - invalid/unavailable model or reasoning effort -> `zcode_model_selection`
      (configuration failure, fail-closed, zero fallback or model rewrite)
    - invalid/missing/expired desktop auth or prepare-isolated account error ->
      `zcode_account_configuration` (configuration failure)
    - `blocked:kind=*` under `--interaction-policy block` -> typed terminal
      blocked failure (fail-closed)
    - `ErrUnsafeExecutable` / package-digest drift / `ControlPlaneRoots` /
      process-group cleanup failure -> fail-closed security/integrity errors.

### 5. Model default policy (`GLM-5.4` + `max`) and `mulgae-command-result.v26`

Match `EPIC-006` (`grok-4.7` / `high`) and `AGENTS.md`:

- **New project `mulgae init`** (when ZCode is selected and no `--zcode-model`
  or `--zcode-reasoning-effort` override is passed):
  - Writes `providers.zcode.model: "account:zai-individual-coding-plan/GLM-5.4"`
    and `providers.zcode.reasoning_effort: "max"` into `.mulgae/config.yaml`.
  - Reports each dimension independently in `init_discovery_zcode` as
    `"override"`, `"mulgae_default"`, `"provider_default"`, or `"not_selected"`.
  - Passing only `--zcode-model` yields `model_source: "override"` and
    `reasoning_effort_source: "mulgae_default"` (`"max"`); passing only
    `--zcode-reasoning-effort` yields `model_source: "mulgae_default"`
    (`"account:zai-individual-coding-plan/GLM-5.4"`) and
    `reasoning_effort_source: "override"`.
- **Existing Config v5 omission and `init --refresh-local`**:
  - `init --refresh-local` continues rejecting `--zcode-model` and
    `--zcode-reasoning-effort` and leaves `.mulgae/config.yaml` byte-identical.
  - Any Config v5 file omitting `providers.zcode.model` and/or
    `providers.zcode.reasoning_effort` (including projects where the operator
    deletes those fields) omits `--model` and/or `--reasoning-effort` when
    invoking `herdr-zcode`, letting `herdr-zcode` preserve ZCode's current
    session model and effort.
  - Never consult the embedded role/init defaults at runtime to fill omitted
    fields (`AGENTS.md` configuration authority invariant).
- **Schema bump (`v25` -> `v26`)**:
  - Create `internal/builtin/assets/schemas/mulgae-command-result.v26.schema.json`
    and its single paired valid example, extending
    `init_discovery_zcode.{model_source,reasoning_effort_source}` with
    `"mulgae_default"`.
  - Retain `mulgae-command-result.v25.schema.json` frozen for historical reads.

### 6. Config v5, `doctor`, qualification sharing, and heartbeat

- **Config v5 preservation**:
  - `.mulgae/local.yaml` keeps `providers.zcode.app_bundle` unchanged (optional
    opaque canonical path forwarded to `herdr-zcode --app-bundle`). No Config v6
    schema change is introduced.
- **`mulgae doctor` (`doctor-result.v9`)**:
  - Offline checks invoke `herdr-zcode --version --json` and
    `herdr-zcode --check-desktop --json [--app-bundle <path>]` (zero Keychain
    or account reads, zero `herdr-core` daemon starts, zero network calls).
  - `binary_available`: verifies both `herdr-core` (`hc`) and `herdr-zcode`
    package resolution/SHA-256 (`herdr_core_*`, `herdr_zcode_*`).
  - `cli_compatible`: validates `herdr-zcode --version --json` reports
    `core`, `osc7501`, `catalogFile`, `prepareIsolated`, and `checkDesktop`.
  - `application_compatible`: reports ZCode Desktop compatibility as observed
    from `herdr-zcode --check-desktop --json` (using `herdr-zcode`'s own
    `minZcodeAppVersion` floor rather than Mulgae-hardcoded `Info.plist`
    floors).
  - All additive `herdr_zcode_*` reason codes conform to `doctor-result.v9`'s
    existing `^[a-z][a-z0-9_]{0,63}$` pattern (no doctor schema version bump).
- **Qualification identity, sharing, and heartbeat**:
  - `RuntimeSafetyPolicyForZCodeTerminal` binds `herdr-core` path/SHA-256/`hello`
    version, `herdr-zcode` canonical path and complete package SHA-256,
    configured `app_bundle` (or default), observed `appVersion`, `catalogRevision`,
    `catalogSHA256`, `accountIdentitySHA256`, and omitted-vs-explicit
    `model`/`reasoning_effort`.
  - Preserve `EPIC-018 TASK-091` same-profile ZCode qualification sharing via
    `DeriveEquivalentRouteDirectExecutionAuthority`: identical role profiles
    share one live probe while any model, effort, omission-vs-explicit,
    `app_bundle`, `herdr-zcode` package digest, `herdr-core` digest, or catalog
    receipt difference partitions qualification groups.
  - Register synthetic `zcode-logic` in `productionInstanceFamilies` (mirroring
    `grok-logic`) so `mulgae heartbeat --provider zcode` runs cleanly through
    `zcodeTerminalProfile` without mutating project config.

## Pre-cutover live go/no-go spike matrix (`TASK-095`)

Build-tagged live harness (`//go:build darwin && arm64 && live_zcode_herdr`)
executing against real `hc 0.1.20` + `__mulgae_paneexec_v1` + Seatbelt +
installed `herdr-zcode` (with companion capabilities) + `ZCode.app 4.0.0`.
**Every item must pass before `TASK-096` begins.** If any item fails, record the
exact blocker and stop to reconcile with Master rather than weakening isolation.

| # | Control | Required proof |
|---|---|---|
| 1 | Package integrity & offline discovery | Full `herdr-zcode` package SHA-256 verification succeeds; `--version --json` advertises `core`, `osc7501`, `catalogFile`, `prepareIsolated`, `checkDesktop`; `--check-desktop --json` reports `compatible: true` with zero Keychain/network calls. |
| 2 | Host `prepare-isolated` & auth consumption | `prepare-isolated` writes `0600` `auth.json` + `0400` `catalog.json` (rev `>= 48` containing `GLM-5.4`) with secret-free JSON receipt; `--consume-auth-file` zero-fills and unlinks `auth.json` before prompt delivery; native `~/.zcode` and `~/Library/Keychains` stay kernel-denied (`EPERM`) inside Seatbelt. |
| 3 | Default model (`GLM-5.4` + `max`) | Passing `--model account:zai-individual-coding-plan/GLM-5.4 --reasoning-effort max` completes one OSC 7501 `idle -> working -> done` staged-file turn on `GLM-5.4`/`max` with verified completion nonce. |
| 4 | Omitted model/effort preservation | Omitting `--model` and `--reasoning-effort` completes a staged-file turn preserving ZCode's current session model/effort without injecting defaults. |
| 5 | Effort-only selection | Omitting `--model` while passing `--reasoning-effort low` (or `max`) applies the requested effort on ZCode's current session model. |
| 6 | Invalid model/effort fail-closed | Passing an unknown model (e.g. `account:zai-individual-coding-plan/GLM-NONEXISTENT`) fails closed before/without fallback and maps to `zcode_model_selection`. |
| 7 | Workspace review + `artist` multimodal `Read` (shell-free) | Workspace scope (`Read,Grep,Glob,Write`, no `Bash`, no `BashGate`) completes both a text review and an `artist` binary PNG/JPEG/WebP inspection using `Read` alone, while writes to `<sourceRoot>` and `~/.zcode` fail with `EPERM`. |
| 8 | Git scope under 5-control `B-1` `BashGate` | Git scope (`Read,Bash,Write` + `B-1` `BashGate` with narrowed `hc\|herdr\|herdr-core\|herdr-app\|herdrd` regex) proves `zcode-official-*/endpoint.sock` compatibility, executes `git show` against original `.git` (read-only), passes `artist` Git image inspection, denies `hc`/`herdr`/operator sockets/localhost IP/secret roots, and passes Control 5 survivor/`mtime`/`ctime` checks. |
| 9 | Extraction & qualification staging | Shell-free `Read,Write` extraction (`extraction.json`) and qualification (`probe.json` against `current-qualification-fixture-v4`) succeed with read-only `input/<id>/prompt.md` digest verification and completion-nonce checks. |
| 10 | Bounded teardown & zero side effects | `terminal.kill` achieves Mulgae-verified `ESRCH` teardown within `<= 1s` with zero surviving `zcode`/`node`/`Electron`/`herdr-zcode` processes, empty `/private/tmp/mgh-<uid>` session dir, untouched `~/.zcode` SHA-256 digests, and `ps`-verified untouched operator `default` `herdr-core` session. |

## Exact Go Code Anchor Map (Copy-From Patterns per Task)

Implementers must reuse Mulgae's existing `EPIC-017` and `EPIC-006` seams
rather than inventing parallel abstractions. Use these exact file and symbol
anchors:

| Concern | Exact Existing Reference / Target Anchor | Action (`EPIC-019`) |
|---|---|---|
| `herdr-zcode` binary/package discovery & 20-file SHA-256 | Mirror `internal/adapters/herdr/resolve_darwin.go` (`resolve_darwin_test.go`) | `TASK-094`: add `internal/adapters/herdr/resolve_zcode_darwin.go` + `resolve_zcode_darwin_test.go` (exact 20-file sorted manifest + offline `--version --json` / `--check-desktop --json`) |
| Narrowed `BashGate` `process-exec` regex | `internal/adapters/process/live_boundary_darwin.go:250` (`(regex #"^(.*/)?(hc\|herdr[^/]*)$")`) | `TASK-094`: narrow to `(regex #"^(.*/)?(hc\|herdr\|herdr-core\|herdr-app\|herdrd)$")`; add Darwin kernel tests allowing canonical `herdr-zcode` while denying multiplexers & repo-hosted executables |
| Reusable terminal driver hooks | `internal/adapters/providercli/terminal_provider.go:46,65` (`terminalProfileInvocation`, `terminalProviderProfile`) | `TASK-094`: extend cleanly with optional host pre-launch hook (returns extra `ReadOnlyRoots`/`WritableRoots`, `RuntimeTempRoot`, drain-zero callbacks, dynamic argv, `SpawnVerifier`) and provider failure-class hook |
| ZCode terminal profile | Mirror `internal/adapters/providercli/grok_terminal.go:77` (`grokTerminalProfile`) | `TASK-094`: add `internal/adapters/providercli/zcode_terminal.go` + `zcode_terminal_test.go` |
| ZCode runtime safety policy | Mirror `internal/adapters/providercli/policy.go:57` (`RuntimeSafetyPolicyForGrokTerminal`) | `TASK-094`/`TASK-096`: add `RuntimeSafetyPolicyForZCodeTerminal` binding `herdr-core`, 20-file `herdr-zcode` digest, `app_bundle`, desktop/catalog receipt, and omitted-vs-explicit model/effort |
| ZCode typed configuration failure preservation | `internal/adapters/providercli/registry.go:1120` (`zcode_model_selection`, `zcode_account_configuration`) | `TASK-094`/`TASK-096`: keep exact stage names (`zcode_model_selection`, `zcode_account_configuration`) and `domain.FailureConfiguration` classification |
| Live go/no-go spike harness | Mirror `internal/adapters/providercli/grok_terminal_spike_live_test.go` | `TASK-095`: add `internal/adapters/providercli/zcode_terminal_spike_live_test.go` (`//go:build darwin && arm64 && live_zcode_herdr`) covering all 10 controls |
| Same-profile qualification sharing & partitioning | `internal/adapters/providercli/qualifier.go:273` (`equivalentFamilyRuntimeProfiles`) + `internal/app/reviewrun/family_qualification.go:83` (`familyRuntimeProfileKeyFor`, `groupCandidatesByFamilyRuntimeProfile`) | `TASK-096`: bind `herdr-core` + 20-file `herdr-zcode` digest + desktop/catalog receipt + omitted-vs-explicit model/effort in BOTH places while preserving `EPIC-018 TASK-091` same-profile sharing |
| Synthetic `zcode-logic` heartbeat | `internal/composition/production_graph.go:303` (`productionInstanceFamilies`) | `TASK-096`: register synthetic `zcode-logic` mirroring `grok-logic` |
| Offline `mulgae doctor` checks (`doctor-result.v9`) | `internal/app/doctor/local_service.go`, `internal/adapters/environment/{inspector.go,executable.go}` | `TASK-096`: switch to offline `herdr-zcode --version --json` + `--check-desktop --json` with additive `herdr_zcode_*` reasons; remove internal `ZCode.app/Contents/...` probing |
| Exact Go files to DELETE in `TASK-096` | `internal/adapters/providercli/{zcode_protocol.go,zcode_protocol_test.go,zcode_live_protocol_test.go,zcode_account.go,zcode_account_test.go,zcode_keychain.go,zcode_keychain_live_test.go}` | `TASK-096`: delete all 7 files + add architecture/import guards confirming zero remaining ZCode Desktop internal coupling |
| `mulgae init` ZCode defaults + `command-result.v26` | `internal/app/init/{service.go,contracts.go,generate_contract.go}`, `internal/entrypoint/mulgae/parser.go`, `internal/builtin/generate_portfolio_contracts.go:369`, `internal/builtin/assets/schemas/{README.md,mulgae-command-result.v25.schema.json}` | `TASK-097`: default new-project ZCode to `account:zai-individual-coding-plan/GLM-5.4` + `max` (`"mulgae_default"`), introduce `mulgae-command-result.v26.schema.json` + paired example, retain `v25` frozen, double-generate |

## Mandatory Anti-Footgun Guardrails (Do NOT Do This)

1. **Never invoke system `go` or bare `golangci-lint`**: Always use `./dev go ...` and `./dev go tool golangci-lint run ...` (`tools/toolchains.env` pins exact toolchains).
2. **Never hand-edit `internal/builtin/assets/CHECKSUMS.sha256` or generated schema goldens**: Change canonical assets/generators and run `./dev go generate ./internal/app/init && ./dev go generate ./internal/builtin` **twice**; the second pass must produce an empty `git diff`.
3. **Never inject `GLM-5.4` or `max` at runtime when omitted in `.mulgae/config.yaml`**: Defaults apply **only** during new-project `mulgae init`. When `providers.zcode.model` and/or `reasoning_effort` are empty/omitted in Config v5, omit `--model` and/or `--reasoning-effort` from `herdr-zcode` argv so ZCode preserves its current session selection.
4. **Never delete frozen historical readers or historical schemas**: When retiring `zcode_protocol.go` (`TASK-096`) or adding `mulgae-command-result.v26` (`TASK-097`), keep `mulgae-command-result.v25.schema.json` and all historical artifact/manifest readers strictly intact.
5. **Never weaken `prepare-isolated` file or environment hygiene**: Never pass `os.Environ()`, `HERDR_ZCODE_APP_BUNDLE`, `HC_*`, `HERDR_*`, `DYLD_*`, or `NODE_OPTIONS` to `prepare-isolated`. Always validate emitted `auth.json` (`0600`, `<= 64 KiB`) and `catalog.json` (`0400`, `<= 4 MiB`) using `O_NOFOLLOW` + `fstat` (`Nlink == 1`, owner `euid`, matching `catalogSHA256`), and register `auth.json` with namespace drain zeroing **before** spawning the pane.
6. **Never forget existing ZCode test fixtures on `TASK-096` cutover**: Update fake ZCode test fixtures in `test/e2e`, `internal/adapters/environment/inspector_test.go`, `internal/app/doctor/local_service_test.go`, `internal/adapters/providercli/qualifier_test.go`, and `internal/app/reviewrun/qualification_test.go` to speak the fake `herdr-zcode` CLI contract instead of mocking `ZCode.app/Contents/Resources/glm/zcode.cjs`.

## Copy-Paste Verification Command Cheat Sheet

- **`TASK-094` (dark offline & Darwin Seatbelt kernel checks)**:
  ```bash
  ./dev go test -race ./internal/adapters/process ./internal/adapters/herdr ./internal/adapters/providercli ./internal/adapters/environment ./internal/architecture
  ./dev go vet ./... && ./dev go tool golangci-lint run ./...
  ```
- **`TASK-095` (10-point live go/no-go spike on native Apple Silicon)**:
  ```bash
  ./dev go test -v -race -tags 'live_zcode_herdr' -run 'TestLiveZCodeHerdrSpike' ./internal/adapters/providercli
  ```
- **`TASK-096` (atomic cutover, double-generator, 4-tag-matrix lint/vet, offline & release gates)**:
  ```bash
  ./dev go generate ./internal/app/init && ./dev go generate ./internal/builtin
  ./dev go generate ./internal/app/init && ./dev go generate ./internal/builtin && git diff --check
  for tags in "" "live_herdr" "liveprovider" "live_e2e,live_grok"; do
    if [ -z "$tags" ]; then
      ./dev go vet ./... && ./dev go tool golangci-lint run ./...
    else
      ./dev go vet -tags "$tags" ./... && ./dev go tool golangci-lint run --build-tags "$tags" ./...
    fi
  done
  make test-offline && make test-release
  ```
- **`TASK-097` (`init` defaults, `v25`/`v26` schema compatibility, double-generator)**:
  ```bash
  ./dev go generate ./internal/app/init && ./dev go generate ./internal/builtin
  ./dev go generate ./internal/app/init && ./dev go generate ./internal/builtin && git diff --check
  ./dev go test -race ./internal/app/init ./internal/app/config ./internal/builtin ./internal/entrypoint/mulgae ./internal/entrypoint/mcp
  ```
- **`TASK-098` (integrated Apple Silicon certification)**:
  ```bash
  make test-offline && make test-release && make test-herdr && make test-e2e && make test-grok
  ```

## Sequential Task execution checklists

### `TASK-094`: Dark `herdr-zcode` resolver, host isolation step, narrowed `BashGate`, and dark `zcodeTerminalProfile`

- **Scope** (dark — zero production ZCode cutover yet):
  - `internal/adapters/herdr/resolve_zcode_darwin.go` (or paired package file):
    `herdr-zcode` discovery (`MULGAE_HERDR_ZCODE_BIN` -> safe `PATH` ->
    `<nativeHome>/.local/bin/herdr-zcode`), symlink/ownership/mode validation,
    complete 20-runtime-file aggregate SHA-256 computation (`bin/herdr-zcode`,
    `bin/herdr-zcode-app.mjs`, all 12 `lib/*.mjs`, `package.json`,
    `scripts/desktop-bootstrap.pl`, `scripts/toolchain.sh`,
    `scripts/tool-bin/npm`, `scripts/tool-bin/npx`, `toolchains.env`;
    UTF-8-sorted `<relpath>\t<bytes>\t<sha256>\n` manifest), and offline
    `--version --json` + `--check-desktop --json` parser/observer.
  - `internal/adapters/process/live_boundary_darwin.go`: narrow `BashGate`
    `process-exec` denial regex from `^(.*/)?(hc|herdr[^/]*)$` to
    `^(.*/)?(hc|herdr|herdr-core|herdr-app|herdrd)$` (plus any scoped
    `RuntimeTempRoot` socket predicate needed once verified).
  - `internal/adapters/providercli/terminal_provider.go`: generalize hooks for
    a provider-supplied host pre-launch step (running outside Seatbelt and
    returning extra `ReadOnlyRoots`/`WritableRoots`, `RuntimeTempRoot`,
    drain-zero targets, and dynamic argv args), plus provider-specific
    failure-class mapping.
  - `internal/adapters/providercli/zcode_terminal.go`: dark
    `zcodeTerminalProfile` implementing host `prepare-isolated` execution
    (`cwd=/private/var/empty`, 15s cap, `O_NOFOLLOW` `0600`/`0400` stat/size/
    digest checks, `accountAccess` object compatibility, stdout JSON `reason`
    classification, drain-zeroing registration),
    `RuntimeSafetyPolicyForZCodeTerminal`, exact `--runtime core` argv assembly
    (including omit-when-empty `--model`/`--reasoning-effort`), and
    `zcode_model_selection` / `zcode_account_configuration` error
    classification.
- **Required negative tests (`-race`)**:
  - `BashGate` allows canonical `herdr-zcode` execution while denying `hc`,
    `herdr`, `herdr-core`, `herdr-app`, `herdrd`, and repo-hosted executables
    named `herdr-zcode`.
  - 20-file package SHA-256 tamper rejections (single-byte edit in
    `scripts/desktop-bootstrap.pl`, `scripts/toolchain.sh`, or
    `lib/prepare-isolated.mjs`; symlink, hardlink `nlink > 1`, or
    group/world-writable `0664`/`0666` file; missing required runtime member)
    fail closed before spawn.
  - `prepare-isolated` stdout JSON `reason` failures, secret-leaking or
    malformed receipt, symlinked or wrong-mode (`0644`) `auth.json`, oversized
    `catalog.json`, digest mismatch, and early-cancel/`SIGKILL` drain zeroing
    of unconsumed `auth.json`.
  - Omitted model, model-only, effort-only, both, and `zcode_model_selection`/
    `zcode_account_configuration` classification.
  - Zero regression in currently active production ZCode app-server tests.

### `TASK-095`: Live go/no-go spike (`live_zcode_herdr`)

- **Prerequisite**: Companion `herdr-zcode` release with `--catalog-file`,
  `prepare-isolated`, and `--check-desktop --json` installed to `~/.local`.
- **Scope**:
  - Add build-tagged `internal/adapters/providercli/zcode_terminal_spike_live_test.go`
    (`//go:build darwin && arm64 && live_zcode_herdr`) covering all 10 matrix
    items above against real `hc 0.1.20` and `ZCode.app 4.0.0`.
  - Record empirical results (especially `endpoint.sock` under `B-1` `BashGate`,
    `artist` multimodal `Read` without `Bash`, exact failure markers for
    invalid models/auth, and measured `ESRCH` latency).
  - If any control fails or reveals a needed Seatbelt/flag adjustment, reconcile
    before starting `TASK-096`.

The Apple Silicon spike used `hc 0.1.20`, `herdr-zcode 0.2.0` (20-file SHA-256
`e23505b5eac11bac202461fad2c1882e61347edfc21c9e658a499510bc794111`), and
`ZCode.app 4.0.0` with catalog revision 48. The Git turn under `B-1` observed
`zcode-official-*/endpoint.sock` and read the original object with `git show`.
The workspace artist read the PNG with shell tools disabled. The invalid
model returned `zcode_model_selection`. Extraction and qualification passed
after the delivery instructions separated the JSON body from its completion
line. From the last observed working state through verified `ESRCH`, the
upper bounds were 272.41 ms for the explicit-model review, 166.90 ms for
extraction, and 159.73 ms for qualification. These controls combine results
from several runs. Earlier full runs recorded selection-capture and staging
failures.

### `TASK-096`: Atomic cutover of `FamilyZcode`, retirement of ZCode internals, and canonical docs

- **Scope**:
  - Atomically switch `FamilyZcode` across `providercli`, `reviewrun`,
    `doctor`, `composition`, and `environment` onto
    `ProviderPacketChannelTerminal` + `zcodeTerminalProfile`.
  - Bind `herdr-core` + `herdr-zcode` package digest + observed desktop/catalog
    receipt into `RuntimeSafetyPolicyForZCodeTerminal` and qualification proofs
    while preserving `EPIC-018 TASK-091` same-profile qualification sharing.
  - Register synthetic `zcode-logic` in `productionInstanceFamilies` for
    `mulgae heartbeat --provider zcode`.
  - Update `doctor` offline checks (`doctor-result.v9`, additive
    `herdr_zcode_*` reasons) to rely exclusively on `herdr-zcode --version --json`
    and `herdr-zcode --check-desktop --json` without touching `ZCode.app`
    internals.
  - Retire and delete `zcode_protocol.go`, `zcode_account.go`,
    `zcode_keychain.go`, and obsolete `ZCode.app` internal-file probing, while
    retaining all frozen historical readers.
  - Update offline fake E2E harness (`test/e2e`), `Makefile` `test-e2e`,
    embedded help Markdown assets (double-run `./dev go generate ./internal/app/init && ./dev go generate ./internal/builtin` idempotently), and
    canonical docs (`docs/specs/{contracts,security,live-workspace-and-git-review}.md`,
    `docs/architecture/README.md`, `docs/gating-rules.md`,
    `docs/implementation-tips/README.md`, `README.md`, `CHANGELOG.md`), and
    update `DF-030` status in `docs/deferred-feedback/README.md` if workspace
    shell-free unification was confirmed in `TASK-095`.
- **Verification**:
  - Focused `-race` tests across all affected packages + architecture/import
    guards confirming zero remaining ZCode-internal file/Keychain coupling in
    Mulgae.
  - Double generator idempotence (`git diff` empty on second pass).
  - 4-tag-matrix `go vet` / `golangci-lint`, `make test-offline`, and
    `make test-release`.

### `TASK-097`: ZCode `init` defaults (`GLM-5.4` / `max`) and `mulgae-command-result.v26`

- **Scope**:
  - Update `internal/app/init` and `internal/entrypoint/mulgae` so new project
    initialization writes `account:zai-individual-coding-plan/GLM-5.4` and
    `max` with independent `"mulgae_default"` provenance when `--zcode-model`
    and/or `--zcode-reasoning-effort` are not provided.
  - Preserve existing Config v5 omission semantics (empty/omitted fields pass
    no `--model` / `--reasoning-effort` to `herdr-zcode`, keeping ZCode's
    current session model/effort) and `init --refresh-local` rejection of both
    flags.
  - Create `internal/builtin/assets/schemas/mulgae-command-result.v26.schema.json`
    and its paired valid example (retaining `v25` frozen for backward reads),
    run both generators twice idempotently, and update `docs/specs/contracts.md`,
    `README.md`, and `skills/use-mulgae`.
- **Verification**:
  - Focused `-race` tests across `init`, `config`, `jsonschema`, `builtin`,
    `entrypoint/mulgae`, and `entrypoint/mcp` covering neither/model-only/
    effort-only/both, `--refresh-local`, existing-config omission preservation,
    `v25` backward compatibility, `v26` schema validation, and double generator
    idempotence.

### `TASK-098`: End-to-end certification, ADR promotion, and Epic closeout preparation

- **Scope**:
  - Run complete exact-candidate gates on native Apple Silicon macOS:
    `make test-offline`, `make test-release`, `make test-herdr`, mandatory live
    ZCode `make test-e2e` (covering `GLM-5.4`/`max`, omitted-model preservation,
    Git `B-1` `BashGate`, `--requirements`, `artist` multimodal review,
    same-profile qualification sharing, and `mulgae heartbeat --provider zcode`),
    and live `make test-grok` regression.
  - Verify via `ps` zero surviving Mulgae/ZCode/herdr-zcode/herdr-core
    processes, empty `/private/tmp/mgh-<uid>`, untouched operator `default`
    `herdr-core`, and unchanged `~/.zcode` and `~/.grok` SHA-256 digests.
  - Promote `docs/architecture-decision-records/zcode-herdr-core-transport.md`
    to `Accepted` (marking `zcode-app-server-transport.md` as `Superseded`) and
    close `DF-030` in `docs/deferred-feedback/README.md`.
  - Hold temporary dossier retirement and `EPIC-019` `Completed` transition for
    Master's explicit Epic acceptance.
