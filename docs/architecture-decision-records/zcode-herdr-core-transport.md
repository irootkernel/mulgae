# ZCode herdr-core terminal transport

Status: Accepted. Supersedes [ZCode app-server transport](zcode-app-server-transport.md).

Roadmap: [EPIC-019](../roadmap/README.md#epic-019-zcode-herdr-core-terminal-runtime-migration-via-herdr-zcode)

## Context

In `EPIC-003`, Mulgae migrated ZCode (`FamilyZcode`) from print mode onto
`ZCode.app`'s bundled `zcode.cjs app-server --stdio` NDJSON wire protocol
([ZCode app-server transport](zcode-app-server-transport.md)). That design
required Mulgae itself to own four tightly coupled layers of ZCode Desktop
internals in Go:

1. `ZCode.app` internal bundle layout (`Contents/MacOS/ZCode`,
   `Contents/Resources/zcode/zcode.cjs`, `Contents/Resources/config/provider/zcode-builtin.json`,
   and `Contents/Info.plist`).
2. ZCode Desktop account storage (`~/.zcode/v2/setting.json`, `credentials.json`,
   `enc:v1`, `enc:v2:os`) and macOS Keychain decryption (`keyring.darwin-arm64.node`
   and `codesign` checks in `zcode_account.go` and `zcode_keychain.go`).
3. Provider catalog resolution (where `ZCode.app 4.0.0`'s bundled catalog is
   revision `44` containing only `GLM-5.3`/`GLM-5.3-Flash`, while `GLM-5.4`
   lives only in ZCode Desktop's version-scoped cache revision `48`).
4. The `app-server` NDJSON protocol (`zcode_protocol.go`) and its server-initiated
   runtime-preference and auth-header callbacks.

Every ZCode Desktop upgrade that alters Keychain encryption, catalog layout,
bundle paths, or `app-server` frames forces synchronized fixes inside Mulgae
(for example `TASK-082` for ZCode 3.18.2 Keychain changes). In addition, keeping
ZCode on a bespoke wire adapter left Mulgae's two active review providers
(`zcode` and `grok`) on two completely separate execution stacks, while
shell-capable ZCode workspace sessions kept `DF-030` open.

Meanwhile, `EPIC-017` established Mulgae's reusable isolated `herdr-core`
terminal runtime ([herdr-core terminal transport](herdr-core-terminal-transport.md)),
and the companion `herdr-zcode` CLI already encapsulates ZCode Desktop bundle
inspection, Keychain credential decryption, version-scoped catalog loading, and
a `--runtime core --non-interactive` terminal surface emitting OSC 7501 status
transitions with fast same-PGID teardown.

## Decision

Migrate `FamilyZcode` onto Mulgae's shared `herdr-core` terminal runtime
(`ProviderPacketChannelTerminal`, `__mulgae_paneexec_v1`, outer macOS Seatbelt
`PaneTTY` + five-control `B-1` `BashGate`, and `staged_file` scratch-file
delivery) driven through the installed `herdr-zcode` CLI, and **fully decouple
Mulgae from ZCode Desktop internals**:

1. **Single ownership of ZCode Desktop internals in `herdr-zcode`**:
   Mulgae retires and deletes `zcode_protocol.go`, `zcode_account.go`,
   `zcode_keychain.go`, and all `ZCode.app` internal-file probing. Three small,
   generic CLI capabilities in `herdr-zcode` (`--catalog-file <path>`,
   `prepare-isolated --out-dir <path> [--app-bundle <path>]`, and
   `--check-desktop --json [--app-bundle <path>]`, advertised via
   `--version --json`) isolate Mulgae from every ZCode Desktop layout,
   Keychain, catalog, and protocol change. Future ZCode upgrades require
   updating and reinstalling `herdr-zcode` alone.
2. **Full 20-runtime-file `herdr-zcode` package verification and two-stage isolation boundary**:
   Mulgae discovers `herdr-zcode` via `MULGAE_HERDR_ZCODE_BIN` -> safe `PATH` ->
   `<nativeHome>/.local/bin/herdr-zcode`, validates its canonical symlink chain,
   ownership, and modes, and computes a complete 20-runtime-file aggregate
   SHA-256 across `bin/herdr-zcode`, `bin/herdr-zcode-app.mjs`, all 12
   `lib/*.mjs`, `package.json`, `scripts/desktop-bootstrap.pl`,
   `scripts/toolchain.sh`, `scripts/tool-bin/npm`, `scripts/tool-bin/npx`, and
   `toolchains.env` (revalidated immediately before every spawn).
   - **Host pre-launch step (outside Seatbelt)**: Runs `herdr-zcode prepare-isolated`
     with `cwd=/private/var/empty`, minimal explicit env, and a 15s cap into a
     private `0700` `<namespace>/auth/iso-<invID>` directory. Mulgae validates
     emitted `0600` `auth.json` and `0400` `catalog.json` via `O_NOFOLLOW`,
     checks the secret-free JSON receipt and catalog SHA-256, and registers
     `auth.json` for namespace drain zero-fill/unlink even on early abort.
   - **Sandboxed pane step (inside Seatbelt)**: Runs `herdr-zcode --runtime core --non-interactive --interaction-policy block --auth-file ... --consume-auth-file --catalog-file ... --no-copy-catalog --skip-desktop-inspect --runtime-dir <namespace>/tmp`.
     A separate private child at `/tmp/mulgae-zcode/<16hex>` hosts
     `endpoint.sock` through the pane's `TMPDIR`, `TMP`, and `TEMP`.
     Seatbelt denies peer children, and Mulgae drains the owned child at
     teardown. Native `~/.zcode` and
     `~/Library/Keychains` remain kernel-denied, with narrowed `BashGate`
     `process-exec` denial (`^(.*/)?(hc|herdr|herdr-core|herdr-app|herdrd)$`)
     so canonical `herdr-zcode` executes while all Herdr multiplexers stay
     denied.
3. **Default model policy (`GLM-5.4` + `max`) with omit-to-preserve-current-model**:
   New `mulgae init` invocations without `--zcode-model` or
   `--zcode-reasoning-effort` write
   `account:zai-individual-coding-plan/GLM-5.4` and `max` into
   `.mulgae/config.yaml` with `"mulgae_default"` provenance (bumping
   `mulgae-command-result.v25` -> `v26` while keeping `v25` frozen). Existing
   Config v5 files or configs omitting those fields pass no `--model` or
   `--reasoning-effort` to `herdr-zcode`, preserving ZCode's current session
   model and effort. Unknown/unavailable models or efforts fail closed as
   `zcode_model_selection` without fallback.
4. **Config v5 preservation and additive `doctor-result.v9` reasons**:
   `.mulgae/local.yaml` keeps `providers.zcode.app_bundle` as an optional opaque
   path passed to `herdr-zcode --app-bundle`. `mulgae doctor` runs offline
   `herdr-zcode --version --json` and `--check-desktop --json` checks with
   additive `herdr_zcode_*` reasons fitting `doctor-result.v9`'s existing
   pattern, requiring no Config v6 or doctor schema bump.
5. **Workspace shell-free unification and `DF-030` closure**:
   `TASK-095` confirmed workspace image reads via `Read` alone for `artist`.
   ZCode workspace reviews run with `Read,Grep,Glob,Write`, Git reviews run
   `Read,Bash,Write` strictly under
   all five `B-1` `BashGate` controls, and extraction/qualification/heartbeat
   run shell-free (`Read,Write`), unifying ZCode's confinement with Grok and
   resolving `DF-030`.

## Consequences

- **Uniform execution layer across active providers**: Both `zcode` and `grok`
  share `internal/adapters/herdr`, `__mulgae_paneexec_v1`, `PaneTTY` + `B-1`
  Seatbelt isolation, OSC 7501 status tracking, `staged_file` delivery, and
  graph-owned `herdr-core` lifecycle management.
- **Upgrade insulation**: ZCode Desktop changes to bundle paths, catalog cache
  schemas, Keychain encryption, or `app-server` NDJSON frames are absorbed in
  `herdr-zcode` without modifying Mulgae (~1,600+ lines of fragile Go coupling
  retired).
- **Consistent security posture**: Native `~/.zcode` and Keychains remain
  kernel-denied inside Seatbelt, projected auth tokens are single-use and
  zeroed on consume or drain. Native certification in `TASK-098` covered
  shell-free workspace and `artist` reviews and the Git `B-1` boundary.
- **Trade-offs**:
  - **Two host wrapper dependencies**: ZCode execution requires both
    `herdr-core` (`hc`) and `herdr-zcode` installed on the host, mitigated by
    deterministic offline `doctor` diagnostics, full package SHA-256
    verification, and version capability checks.
  - **Pre-launch subprocess step**: Each ZCode invocation runs one short,
    bounded (`<= 15s`), isolated-cwd host `herdr-zcode prepare-isolated`
    process before pane launch rather than reading Keychain inside Mulgae's Go
    process; mitigated by package-digest pinning, strict output validation, and
    drain zeroing.
  - **Merged PTY diagnostics**: As with Grok (`EPIC-017`), terminal transport
    provides bounded post-kill screen diagnostics rather than raw NDJSON
    protocol transcripts, while preserving complete unbounded `staged_file`
    role reports and extraction payloads.

## Native certification

`TASK-098` verified the existing host access restrictions and checked that the
operator's `default` Herdr session and protected ZCode and Grok files remained
unchanged. In separate native runs, Grok and ZCode left no execution-owned
processes or temporary paths. Whole-home hash comparisons recorded changes
even during intervals with no model invocation. They remain observations of
shared host state under the revised TASK-098 criterion.

## Rejected alternatives

- **Hybrid Go-coupled design (retaining `zcode_account.go`, `zcode_keychain.go`,
  and `ZCode.app` internal bundle probing in Mulgae while adding only
  `--catalog-file` to `herdr-zcode`)**:
  Rejected because duplicating 640+ lines of ZCode Desktop internals
  (`zcode.cjs`, `zcode-builtin.json`, `setting.json`, `credentials.json`,
  `keyring.node`) across both repositories means ZCode upgrades break Mulgae
  and `herdr-zcode` together, directly undermining the primary upgrade-resilience
  goal of migrating off the direct wire adapter.
- **Running `herdr-zcode` with native `~/.zcode` / Keychain access inside Seatbelt**:
  Rejected because exposing native `~/.zcode` or `~/Library/Keychains` inside a
  sandboxed provider pane breaks Mulgae's `CredentialRoots` and
  `TerminalSecretRoots` invariants, risks mutating operator desktop sessions,
  and widens blast radius on shell-capable Git scopes.
- **Invoking `bin/herdr-zcode-app.mjs` directly via `ZCode.app`'s Electron binary**:
  Rejected because it re-couples Mulgae to `ZCode.app/Contents/MacOS/ZCode` and
  `herdr-zcode`'s internal launcher script layout.
- **Embedding Mulgae-specific prompt, staging, or output logic inside `herdr-zcode`**:
  Rejected because Mulgae owns prompt staging, completion nonces, validation,
  and publication, while `herdr-zcode` must remain a generic ZCode terminal
  adapter reusable outside Mulgae.
- **Bumping project configuration to Config v6 to add a `herdr_zcode_binary` field**:
  Rejected because `MULGAE_HERDR_ZCODE_BIN` -> safe `PATH` ->
  `~/.local/bin/herdr-zcode` mirrors `herdr-core` discovery cleanly without
  breaking existing Config v5 repositories.
- **Keeping the legacy ZCode app-server wire adapter alongside `herdr-zcode` as a dual-mode fallback**:
  Rejected because maintaining dual transports preserves the exact upstream
  ZCode Desktop coupling this migration exists to eliminate and doubles test
  and security surface.
