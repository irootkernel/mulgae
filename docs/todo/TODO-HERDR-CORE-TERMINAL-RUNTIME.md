# herdr-core terminal runtime and Grok migration

## Execution authority and lifetime

The sole consumer is Mulgae `EPIC-017`. Its
[roadmap](../roadmap/README.md#epic-017-herdr-core-terminal-runtime-and-grok-migration)
alone owns work identity, order, dependencies, lifecycle, and status. This is the
temporary execution SOT for sequential Task execution (`TASK-084` through
`TASK-087`), following standalone maintenance task `TASK-083` (Grok version-tag
parsing and synthetic `grok-logic` heartbeat registration). Read repository
guidance (`AGENTS.md`) and the canonical owners below before planning or
implementing any member Task. Design adoption does not establish implementation,
verification, release, or Epic acceptance.

## Goal and phase boundary

Replace Mulgae's brittle per-provider CLI protocol and native policy-file
coupling with a reusable, provider-agnostic `herdr-core` terminal execution
layer backed by Mulgae's trusted launch trampoline, hardened outer macOS
Seatbelt guard, disposable provider home, and scratch-file (`staged_file`)
prompt/output delivery.

- **Prerequisite maintenance (`TASK-083`)**: Fix `grokVersionOutput` in
  `internal/adapters/providercli/qualifier.go` to accept optional release
  channel tags (`(?: \[[A-Za-z0-9._-]+\])?$`, unblocking `1.0.89` and future
  releases such as `1.0.90+` as yellow above `VerifiedLatest`), invert the
  deliberate negative test at `qualifier_test.go:615`, reconcile the existing
  docs/code mismatch at `docs/specs/contracts.md:1035`, and extract a testable
  `productionInstanceFamilies` helper in `internal/composition/production_graph.go`
  to register synthetic `grok-logic` for `mulgae heartbeat --provider grok`
  (projecting `auth.json` only when acquired). Keep `VerifiedLatest` at
  `"1.0.40"` in `TASK-083` so frozen doctor goldens stay intact and unverified
  live ACP `1.0.89` support is not claimed; raise `VerifiedLatest` (and
  `Minimum`) only with live `1.0.89` certification in `EPIC-017`.
- **Phase 1 (`EPIC-017`, `TASK-084`–`TASK-087`)**: Build the reusable
  `herdr-core` terminal runtime ports, trusted pane trampoline
  (`__mulgae_paneexec_v1`), hardened macOS Seatbelt control-plane, secret-root,
  and exact-TTY rules, isolated `herdr-core` session adapter, and declarative
  terminal provider driver, then migrate **Grok CLI (`FamilyGrok`)** across
  live review, structured extraction, qualification, and heartbeat.
- **Preserved unchanged in Phase 1**: ZCode, Codex, Cursor, and AGY transports
  (while adding missing-tolerant `ControlPlaneRoots` and Cursor credential
  denials to shared boundaries, verified with `make test-e2e` in `TASK-087`),
  Config v5 schemas (`.mulgae/config.yaml` and `.mulgae/local.yaml`), embedded
  JSON schemas and examples (while updating affected embedded help Markdown
  files and running both generators twice in `TASK-086`), and public manifest
  JSON schemas (`result_transport: "stdout"` documented explicitly).
- **Phase 2+ (future Epics)**: Migrating remaining interactive CLIs (`codex`,
  `cursor`, `agy`) or adding new AI CLIs onto the `herdr-core` terminal runtime
  belongs to separate future Epics after `EPIC-017` is certified and accepted.
  (Non-TUI Electron app-servers such as ZCode are not required to migrate.)
  Non-`herdr-core` local control planes reachable from shell-capable ZCode
  (such as operator `herdr`, `ssh-agent`, `opencode`, or localhost APIs) remain
  tracked as a separate prioritized security follow-up outside `EPIC-017`.

## Canonical owners

| Concern | Owner |
|---|---|
| Structural decision and rejected alternatives | [ADR: herdr-core terminal transport](../architecture-decision-records/herdr-core-terminal-transport.md) |
| Architecture and dependency direction | [Architecture](../architecture/README.md) |
| Trust boundaries and provider isolation | [Security](../specs/security.md) |
| Public contracts and provider transport | [Contracts](../specs/contracts.md) |
| Live workspace and Git review model | [Live workspace and Git review](../specs/live-workspace-and-git-review.md) |
| Release design gates | [Gating rules](../gating-rules.md) |
| Verification and release workflow | [Implementation guidance](../implementation-tips/README.md) |

Until `TASK-086` lands the cutover, `specs/`, `architecture/README.md`,
`gating-rules.md`, and embedded help assets continue to describe the currently
implemented Grok ACP runtime. `TASK-086` updates affected canonical
documentation, embedded help assets (with idempotent regeneration), and tests
in the same change so documentation and code never diverge.

## Approved architecture and invariants (Round 2 hardened design)

### 1. Trusted pane trampoline (`__mulgae_paneexec_v1`) and macOS Seatbelt

Every `herdr-core` pane launches Mulgae's verified binary (`os.Executable()`
canonicalized via `EvalSymlinks`, always an absolute `argv[0]` to avoid `hc`
template lookup) in a new hidden trampoline mode (`__mulgae_paneexec_v1`,
extending `internal/adapters/process/fdexec_darwin.go`, dispatched from
`internal/composition/run.go:60` via `process.ExecInheritedDirectory`, and
exposed to `herdr` through a narrow `ports` launch-builder interface injected
by `composition` to avoid ad-hoc adapter-to-adapter coupling):

1. **Private per-pane control files (not provider-readable)**: Store each
   pane's `0400` env file and compiled Seatbelt profile file in a private
   per-pane directory under the session root
   `/private/tmp/mgh-<uid>/<16hex>/panes/<id>/`. Because that root is denied by
   `ControlPlaneRoots` (`file-read* file-write* file-link`), the trampoline
   reads both files *before* Seatbelt activates, invokes `/usr/bin/sandbox-exec`
   (compiled-in constant, never argv-supplied) with `-f <profile-file>` (avoiding
   huge `-p` strings echoed in `hc terminal.list`/`ps`), and the sandboxed
   provider can never read either file.
2. **Integrity-bound trampoline inputs in Mulgae-authored argv**: Pass and
   validate in the trampoline before `execve`:
   - env-file path, `(dev, ino)`, and SHA-256 (opened via anchored `O_NOFOLLOW`
     walk + `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, requiring regular file,
     `uid == euid`, mode `0400`, `nlink == 1`, bounded size, closed before the
     `O_CLOEXEC` sweep);
   - Seatbelt profile file path, `(dev, ino)`, and SHA-256 (same validation);
   - neutral `cwd` path and `(dev, ino, btime, euid)`, opened via
     `openLiveBoundaryDirectory` (`O_NOFOLLOW` + `F_GETPATH`), `fchdir`ed, and
     re-verified;
   - provider executable path and `(dev, ino)`, re-verified after `fchdir`.
3. **Standard descriptor & exact controlling-PTY binding (`PANE_TTY`, no cgo)**:
   - Verify **all three** standard descriptors (`0, 1, 2`) via `fstat`: each
     must be `S_IFCHR` with identical `st_rdev` (rejecting any pipe or socket
     leaked on stdout/stderr). Open `/dev/tty` (`O_NOCTTY|O_CLOEXEC`), verify
     matching `st_rdev`, and close it.
   - Resolve the controlling slave path without cgo (`x/sys/unix` v0.48.0 omits
     `ttyname`/`Tcgetsid` on Darwin): call `F_GETPATH` on fd `0` (with a
     `/dev/ttys*` `Rdev` scan fallback if needed), require match against
     `^/dev/ttys[0-9]+$` and `lstat(path).Rdev == fstat(0).Rdev`, and verify
     `Getsid(0) == getpid()` and `IoctlGetInt(0, TIOCGPGRP) == getpgrp()`.
   - Mark every inherited descriptor above stderr (`fd >= 3`) `O_CLOEXEC`.
   - Pass `-D PANE_TTY=<exact-slave>` to `sandbox-exec` (never splicing the
     path into SBPL text). Inside the profile, exempt `(literal (param "PANE_TTY"))`
     and `(literal "/dev/tty")` **inside** the global write-deny predicate, keep
     all other `^/dev/ttys[0-9]+$` explicitly denied for
     `file-read* file-write* file-ioctl`, and add a `TIOCSTI` ioctl deny if
     supported on target macOS (documenting any macOS filter limit). Composing
     `PaneTTY` with `OwnedPTY` nested-PTY clauses is decided by Spike item 7;
     existing AGY `OwnedPTY` clauses remain byte-identical.
4. **Exact `envp` isolation (never `os.Environ()`)**:
   - Mulgae writes fixed literal values (`TERM=xterm-256color`,
     `COLORTERM=truecolor`, `TERM_PROGRAM=ghostty`, `LANG=en_US.UTF-8`) into
     `request.Environment()` so `effectiveEnvironmentIdentity` hashes them
     deterministically.
   - The trampoline calls an exact-`envp` `execve` variant (never reusing
     `execWithSanitizedDescriptors` with `os.Environ()`), appending **only**
     one inherited variable, `HC_TERMINAL_ID`, after validating it against a
     closed regex (represented in `effectiveEnvironmentIdentity` by a fixed
     `HC_TERMINAL_ID` pass-through domain marker). Reject any `DYLD_*`, `LD_*`,
     `GODEBUG`, `HC_*` other than `HC_TERMINAL_ID`, or out-of-namespace `XDG_*`.
5. **Control-plane and secret-root Seatbelt rules**:
   - **`ControlPlaneRoots`**: Add a missing-tolerant root group (excluded from
     `validateLiveRootFileLinks` so missing `/private/tmp/mgh-<uid>` or live
     operator state never breaks non-Grok launches) emitting
     `(deny file-read* file-write* file-link (subpath ...))` and
     `(deny network-outbound (remote unix-socket (subpath ...)))` for:
     - `/private/tmp/mgh-<uid>` and `/private/tmp/mgh-<uid>/<16hex>`,
     - `~/.local/state/herdr-core` and `~/.config/herdr-core`,
     - inherited `HC_SOCKET` (literal path, plus parent only when dedicated and
       never a shared root like `/private/tmp`).
   - Add `~/.cursor` and `~/.config/cursor` to `liveSourceBoundaries`
     (`internal/composition/live_source.go`, updating `live_source_test.go` by
     name and checking Codex argv tests).
   - **Terminal-provider secret-root denials**: For `PaneTTY` profiles, deny
     `file-read* file-write* file-link` and outbound `unix-socket` on
     missing-tolerant secret roots (`~/.ssh`, `~/.gnupg`, `~/.aws`,
     `~/.config/gh`, `~/.docker`, `~/.kube`, `~/.netrc`, `~/.git-credentials`,
     `~/.npmrc`, `~/.pypirc`, `~/Library/Keychains`, `~/.claude`,
     `~/.config/herdr`, `~/.local/state`), add literal denies for
     `~/AGENTS.md`, `~/CLAUDE.md`, and `~/.mcp.json`, and reject configurations
     where the project root is an ancestor of `~/.mulgae/home`.
   - **Hard review-lane `Bash` decision rule**:
     - **Default**: review `--tools` is a closed, **shell-free** list
       (`read_file,grep,list_dir,Write`, exact argv validated).
     - **Only if** index/commit Git reads provably require `Bash` in the live
       spike, **all five** of the following `PaneTTY`-only controls must land
       with kernel tests before `TASK-086`:
       1. `(deny network-outbound (remote unix-socket))` with narrow literal
          allows proven necessary by the spike (e.g., `/private/var/run/mDNSResponder`),
       2. `(deny network-outbound (remote ip "localhost:*"))`,
       3. the terminal secret-root denies above,
       4. `process-exec` denials for `/usr/bin/security`, `/usr/bin/osascript`,
          `/usr/bin/open`, `/bin/launchctl`, `git-credential-*`, `tmux`,
          `hc`/`herdr*`, `ssh*`, and `docker` (or narrow `process-exec`
          allowlist),
       5. session-scoped + profile-sentinel survivor check plus `mtime`/`ctime`
          stability in `readStagedFile`.

### 2. Disposable `HOME` + disposable `GROK_HOME` (sterile isolation retained)

- Grok keeps Mulgae's disposable namespace `HOME` and disposable `GROK_HOME`
  (`<namespace>/home/.grok`), projecting only the validated `0600` regular
  single-link `~/.grok/auth.json` copy (`ports.CredentialProjectionGrokAuth`)
  with zero write-back.
- `~/.grok` remains in `CredentialRoots` for Grok as well as every other
  provider — kernel-denying `~/.grok/leader.sock`, `~/.grok/downloads/grok-*`,
  `config.toml`, `hooks/`, `AGENTS.md`, `plugins/`, `skills/`, `sandbox.toml`,
  `trusted_folders.toml`, and `memory-v2/`, while keeping all existing `HOME`
  authority validators and full `validateLiveRootFileLinks` intact.
- Retire Grok ACP (`grok_acp_protocol.go`, `grok_live_review.go`) and
  `grok_boundary.go`'s `sandbox.toml` / post-drain TOML audits. Prove via Spike
  item 12 (ancestor & nested-repo hook/MCP/rule canaries) whether a minimal
  disposable `requirements.toml` (with zero native-home coupling or post-drain
  audit) should be retained in disposable `GROK_HOME` as defense in depth.
- Move Grok **qualification and heartbeat** to the Cursor/AGY pattern: neutral
  `cwd` (`~/.mulgae/home/`) + `LiveReadOnlyBoundary` (with the fixture snapshot
  in `ReadOnlyRoots`), keeping `--version` on the plain process runner with
  zero `herdr-core` starts.

### 3. Isolated per-run `herdr-core` daemon, ownership, and truthful teardown

- **Lazy foreground `serve` daemon (no `launchd`)**: Spawn `<herdr-core> serve`
  with an explicit minimal `exec.Cmd.Env`, `Setpgid: true`, canonical short
  private directory `/private/tmp/mgh-<uid>/<16hex>/` (`0700`, `O_NOFOLLOW`,
  `uid == euid`), `HC_SOCKET=<dir>/s.sock`, `HC_SESSION=mulgae-<16hex>`,
  `XDG_STATE_HOME=<dir>/state`, `XDG_CONFIG_HOME=<dir>/cfg`, and `config.toml`
  (`notes = false`, `draft_wait = 0`, `notes_quiet = 0`, disabling self-update
  and non-required OSC side effects where configurable).
- **Binary trust & version pinning**: Discover `herdr-core`/`hc` via
  `MULGAE_HERDR_CORE_BIN` -> safe `PATH` (rejecting relative paths, project
  root / `WritableRoot` entries, and group/world-writable dirs or binaries) ->
  `<nativeHome>/.local/bin/{hc,herdr-core}`. Verify regular file, user/root
  ownership, safe mode, `hello.generation == 1` and required methods, and bind
  canonical path, SHA-256, and `hello` version into
  `currentProbeDirectExecutionRoleProof`, Grok's `RuntimeSafetyPolicy`, and an
  additive typed doctor readiness reason.
- **Graph-owned session lifecycle (including retained-cleanup & MCP safety)**:
  - `productionRuntimeGraph` is the **sole owner** of `terminalSession.Close()`
    (idempotent no-op if never started, internally bounded timeout context).
  - In `productionRuntimeGraph.cleanupRoots()`, call
    `graph.closeTerminalSession(...)` **first** (before
    `removeDrainedNamespaceParent`); if holder exit cannot be proven, skip
    namespace removal and return a retained failure.
  - In the retained error branch of `rootCleaningReviewRunService.StartReviewRun`
    (`internal/composition/review.go:335-338`), explicitly call
    `graph.closeTerminalSession(...)` so core & holder stop immediately (in
    both CLI and long-lived MCP modes) while leaving retained namespace,
    workspace, and source leases intact.
  - Track both core PID and `server.status.holder.pid` (separate PGID), add a
    parent-death watchdog (pipe EOF / kqueue `NOTE_EXIT` supervisor) for
    `SIGKILL` resilience, refuse new `RunTerminal` calls once `Close` starts,
    and write a `{pid, process_start_time}` owner lock file for safe startup
    reaping without PID-reuse hazards.
  - `Registry` and `CurrentProbe` borrow the graph's session, tag panes with
    `labels: {"mulgae_registry": "<generation>"}`, and `Registry.Close` drains
    only its own labeled panes retryably (`terminal.list` -> `kill` ->
    `ESRCH` -> `rm`) without ever calling `server.stop`.
- **Truthful teardown & complete `internal/ports` validation**:
  - Verify both `unix.Kill(-pid, 0) == ESRCH` AND session-scoped absence
    (`sysctl KERN_PROC_SESSION`) before setting `ProcessGroupAbsent() == true`;
    fail closed with `DiagnosticCauseProcessGroupCleanupFailed` on timeout.
  - Add `ProviderPacketChannelTerminal`, closed Mulgae status enums in
    `internal/ports/terminal_runtime.go`,
    `ProcessGroupSignalRequestTerminalTeardown{,Escalation}`,
    `ProcessObservation.TerminalSessionCompleted()`, prompt-file pre/post
    digest binding in `ProviderPacketTransportReceipt`, full terminal branches
    in `ProviderExecutionObservation.Validate()` and
    `providerExecutionStatusMatchesProcessObservation`, signal names via
    `unix.SignalName`, and amended `ProcessRequest` doc comments (`scheduling.go:531-534`).
  - Document non-GUI (`SSH`/`launchd`) and macOS `/Volumes/...` TCC behavior.

### 4. Universal scratch-file delivery, prompt/output integrity, and contracts

- **Read-only prompt integrity**: Write unbounded `packet.Bytes()` to
  `<scratch>/input/<id>/prompt.md` (`0400`, parent `<scratch>/input/` in
  `ReadOnlyRoots` covering sibling input dirs too so concurrent roles cannot
  interfere), bind pre-start and post-teardown SHA-256 digests in the terminal
  transport receipt, and append a mandatory per-invocation end-of-prompt nonce
  for review and extraction (verified and stripped before publication) to catch
  silent Read-tool truncation or spoofed early `done`.
- **Adapter-owned staged output**: Create per-invocation staging directories
  directly via `createStagedOutputDirectory` (parameterizing filename:
  `role-report.md` for review, `extraction.json` for extraction, `probe.json`
  for qualification), validate strictly after `ESRCH` teardown, bind
  `OutputSHA256` in qualification proofs to the accepted staged bytes (not the
  screen capture), and return `NewIsolatedSuccessfulProviderExecutionObservation`
  (`result_transport: "stdout"` documented explicitly in `contracts.md` during
  `TASK-086`, alongside bounded post-kill `terminal.read(lines: 0)` diagnostics
  routed through Mulgae's credential scanner and no stdout/stderr separation).
- **Budget & version discipline**: Carve `StartupTimeout` out of the family
  timeout budget (`ProcessRequest.Timeout()`); classify "pane exited before
  `reported`" as a launch-boundary failure without keying on exit code `10` vs
  `125`; derive auth/quota failures from structured core state (`blocked`
  `kind=auth`), never allowing screen tokens to override security/staging
  failures. Raise Grok `Minimum` and `VerifiedLatest` to `"1.0.89"` (updating
  doctor/application test fixtures accordingly) only after spike and live
  certification in `TASK-086`/`TASK-087`.

## Pre-cutover live spike gate (between `TASK-085` and `TASK-086`)

Run via a dedicated build-tagged harness (`//go:build liveprovider` in
`internal/adapters/providercli`, authorized by Master, few turns) verifying all
12 items before `TASK-086` starts:

1. Disposable `HOME`/`GROK_HOME` (`auth.json` only) shows zero startup/welcome/trust dialogs.
2. Reading absolute `prompt.md` + original source and writing `<scratch>/output/<id>/role-report.md` outside `--cwd` succeeds without prompts.
3. `Terminal.reported == true` with trampoline `envp` (`HC_TERMINAL_ID` kept, `HC_TERMINAL_SOCKET` stripped) and quiet-window `terminal.send` succeeds reliably.
4. Shell-free `--tools` (`read_file,grep,list_dir,Write`) refuses a bash-canary injection; determine whether index/commit Git reads require `Bash` (triggering the mandatory `B-1` Seatbelt controls).
5. Zero detached leftover processes survive `terminal.kill` under `--no-leader`.
6. Invalid `-m` and unknown `--reasoning-effort` behavior and effective model/effort observability (`contracts.md` update decision).
7. Whether Grok tools open `/dev/ptmx` under `PaneTTY` (deciding `PaneTTY` + `OwnedPTY` composition vs exclusivity).
8. Model compliance when app packet says "final message" vs `terminal.send` directing file write.
9. Large `prompt.md` (≥256 KB) fully ingested with mandatory end-of-prompt nonce echoed.
10. Two concurrent Grok panes (two roles) in one isolated core with separate namespaces.
11. Shell-free extraction (`--tools read_file,Write`) writes valid JSON to `extraction.json`.
12. Ancestor and nested-repo hook/MCP/rule canary test (verifying zero unauthorized loading without `requirements.toml`, or confirming minimal disposable `requirements.toml` retention).

## Member delivery contracts

Membership and sequential order are defined only in the
[roadmap](../roadmap/README.md#epic-017-herdr-core-terminal-runtime-and-grok-migration).
Standalone maintenance `TASK-083` precedes `EPIC-017`. Each member Task consumes
the preceding accepted Task's result.

| Task | Required outcome | Verification and handoff |
|---|---|---|
| `TASK-083` *(Maintenance)* | Fix `grokVersionOutput` (`qualifier.go:762`) to accept `(?: \[[A-Za-z0-9._-]+\])?$`, invert negative test at `qualifier_test.go:615`, reconcile `docs/specs/contracts.md:1035`, and extract `productionInstanceFamilies` in `production_graph.go` to register synthetic `grok-logic` (projecting `auth.json` only when acquired). Keep `VerifiedLatest` at `"1.0.40"`. | Focused `-race` tests in `internal/adapters/providercli`, `internal/app/reviewrun`, `internal/composition`, `internal/entrypoint/mulgae`, and `internal/app/doctor` proving tagged (`[stable]`, `[beta]`) and untagged Grok versions, `1.0.89`/`1.0.90` yellow pass, untouched doctor goldens, and `grok-logic` heartbeat registration. |
| `TASK-084` | Add dark terminal-transport ports (`ProviderPacketChannelTerminal`, closed Mulgae status enums, `TerminalSessionRunner`, `PaneLaunch` port interface, `ProcessGroupSignalRequestTerminalTeardown{,Escalation}`, `TerminalSessionCompleted`, prompt-file digest receipt, full `ProviderExecutionObservation.Validate()` success & failure branches, amended `ProcessRequest` doc comments) and Seatbelt/trampoline foundations (missing-tolerant `ControlPlaneRoots` excluded from hardlink walk, Cursor roots in `live_source.go` + `live_source_test.go` + Codex argv check, terminal secret-root & ancestor literal denies, `PaneTTY` parameter mode + `B-1` controls ready, and `__mulgae_paneexec_v1` in `fdexec_darwin.go` dispatched from `composition/run.go:60` with per-pane private env/profile files, argv integrity binding, cgo-free FD `0,1,2` + TTY check, exact `envp` + `HC_TERMINAL_ID` pass-through marker). | Comprehensive `internal/ports` tests, `internal/architecture` checks, and `internal/adapters/process` kernel tests using synthetic `/dev/ptmx` + `Setsid`/`Setctty` proving `__mulgae_paneexec_v1` FD set `{0,1,2}` (and rejecting pipe/socket fd 2), exact `envp` scrubbing, `cwd`/executable/env/profile integrity binding, control-plane & secret-root denials, Cursor credential denial, and byte-identical AGY `OwnedPTY` clauses. Hand to `TASK-085`. |
| `TASK-085` | Implement `internal/adapters/herdr` (`resolve_darwin.go`, `rpc.go`, `session_darwin.go`, `runner_darwin.go`): verified safe-PATH `hc`/`herdr-core` discovery, pure-Go Unix-socket JSON-RPC 2.0 client (`hello.generation == 1`), lazy isolated `herdr-core serve` under canonical `/private/tmp/mgh-<uid>/<16hex>/s.sock` with minimal `Env`, `{pid, start_time}` owner lock + stale-session reaper, parent-death watchdog, `server.status.holder.pid` tracking, per-pane private dir `panes/<id>/`, `__mulgae_paneexec_v1` launch, OSC 7501 (`reported == true` + turn tracking, launch failure classification independent of exit code `10`/`125`), `terminal.kill` -> `ESRCH` + session absence -> post-kill `terminal.read(lines: 0)` -> `terminal.rm`, label-scoped drain, idempotent `Session.Close` refusing new runs, `TestMain`, and the build-tagged live spike harness. | Deterministic offline fake-RPC tests in `make test-offline` plus build-tagged (`live_herdr`) real-`hc` isolated-core tests (wired into `Makefile` `test-herdr` and `test-grok`, never silently skipped) verifying: `idle` -> `send` -> `working` -> `done`, `blocked(auth)`, `error`, exit, timeout check-ins, cancellation, **every core/holder Unix socket enumerated and `EPERM`-denied** (incl. symlink/hardlink alias), **own-slave raw mode OK + foreign `/dev/ttys*` denied**, `F_GETPATH` on real holder slave, exact `envp` (zero `DYLD_*`/`GODEBUG`/`HC_TERMINAL_SOCKET`), `/dev/fd == {0,1,2}`, zero leftover cores/holders/dirs, and `ps`-verified untouched `default` core. Execute approved 12-item Grok live spike before `TASK-086`. |
| `TASK-086` | Add reusable `internal/adapters/providercli/terminal_provider.go` and `grok_terminal.go`; atomically migrate `FamilyGrok` across `providercli`, `reviewrun`, and `composition` (disposable `HOME`/`GROK_HOME` + `.grok/auth.json` projection, neutral-cwd + Seatbelt qualification/heartbeat, read-only `input/` + `prompt.md` digest receipt + mandatory end-of-prompt nonce, parameterized `stagedOutputLease` `role-report.md`/`extraction.json`/`probe.json`, `OutputSHA256` bound to staged bytes, `StartupTimeout` inside family budget, `herdr-core` proof/policy/doctor binding, purpose-scoped `--tools` obeying the `B-1` rule, graph-owned `Session.Close` in both `cleanupRoots()` first-step and `review.go:336` retained branch, label-scoped `Registry.Close`, second fake non-OSC multi-home terminal profile test); delete obsolete Grok ACP & `grok_boundary` files; update ALL affected tests (`live_admission_counting_test.go`, `live_neutral_execution_test.go`, `namespace_test.go`, `credential_source_test.go`, `registry_live_test.go`, `grok_live_test.go`, `test/e2e/grok_live_test.go`, `Makefile`), embedded help assets (`help/{providers,security,prompts}.md` + both generators twice), and canonical docs (`security.md`, `contracts.md`, `live-workspace-and-git-review.md`, `architecture/README.md`, `gating-rules.md`) in the same change. | Focused `-race` tests across `internal/{architecture,ports,adapters/process,adapters/herdr,adapters/providercli,app/reviewrun,composition,builtin,entrypoint/mulgae}` covering staged prompt/output negatives, OSC spoofing/truncation rejection, second fake terminal profile extensibility, Grok review/extraction/qualification/heartbeat flows, zero `herdr-core` starts for non-Grok providers, idempotent generator check, and `git diff --check`. Hand integrated cutover to `TASK-087`. |
| `TASK-087` | Run complete exact-candidate certification: `make test-offline`, `make test-release`, `make test-herdr` (tagged real-`hc` tests), `make test-e2e` (mandatory ZCode live regression for cross-provider Seatbelt changes), and live `make test-grok` against real Grok 1.0.89 (capability, release-binary workspace/index/commit review & extraction, retained-run & MCP-mode `ps` leak checks, unchanged source/`.git`/`~/.grok/auth.json`/`grok` binary, zero leftover cores/holders/panes/`/private/tmp/mgh-<uid>/*`/`mulgae-review-*`, `ps`-verified untouched `default` core); promote `herdr-core-terminal-transport.md` ADR from planned to accepted and prepare final Epic closeout diff. | Pass `make test-offline`, `make test-release`, `make test-herdr`, `make test-e2e`, and live `make test-grok`; verify all canonical doc backlinks and `git diff --check`. Present complete Epic acceptance handoff to Master. |

## Required scenario coverage

| Scenario group | Required observation |
|---|---|
| Trampoline & Seatbelt (real holder PTY) | `__mulgae_paneexec_v1` validates FDs `0,1,2` as identical controlling TTY (rejects pipe/socket fd 2), leaves only `{0,1,2}` FDs, verifies neutral `cwd` + executable + env/profile integrity from argv, reads env/profile from `ControlPlaneRoots`-denied `panes/<id>/`, strips `HC_TERMINAL_SOCKET`/`HC_SOCKET`/`HC_SESSION`/`HC_SCOPE`/`DYLD_*`/`GODEBUG`, binds exact `PANE_TTY` so own-slave `tty`/`stty raw` succeeds while foreign `/dev/ttys*` fails `EPERM`; every core/holder Unix socket + `~/.local/state/herdr-core` + `~/.grok/leader.sock` fails `EPERM` (incl. symlink/hardlink alias); secret roots + `~/.cursor`/`~/.config/cursor` denied; `B-1` rules enforced if `Bash` enabled; AGY `OwnedPTY` clauses byte-identical. |
| Isolated `herdr-core` lifecycle | Lazy start only on terminal invocation; canonical `/private/tmp/mgh-<uid>/<16hex>/s.sock`; no `launchd` entry; `hello.generation == 1`; `terminal.kill` -> `ESRCH` + session absence -> post-kill `terminal.read(lines: 0)` -> `terminal.rm`; label-scoped `Registry.Close` fails retryably on survivor; graph-owned `Session.Close` runs first in `cleanupRoots()` and on `review.go` retained branch (CLI and MCP) stopping both core and `holder.pid`; parent-death watchdog + `{pid, start_time}` stale reaper; `ps`-verified untouched `default` core. |
| Disposable Grok home & scratch delivery | Disposable `HOME`/`GROK_HOME` + projected `0600` `.grok/auth.json` (zero write-back, `~/.grok` kernel-denied); neutral-cwd + Seatbelt qualification/heartbeat; read-only `input/` (`prompt.md` pre/post digest + mandatory end-of-prompt nonce); parameterized `stagedOutputLease` validated strictly after `ESRCH` teardown; rejects missing, empty, symlink, hardlink, or extra entries; OSC 7501 spoofing cannot bypass validation or mask security/staging errors. |
| Grok review, extraction, qualification & heartbeat | Live workspace, index, and commit reviews read original source without copying, complete shell-free extraction (`extraction.json`), preserve Config v5 and documented `result_transport: "stdout"`, leave source/`.git`/`~/.grok/auth.json`/`grok` binary byte-identical; heartbeat works when Grok is not assigned to `logic`. |
| Cross-provider & extensibility | ZCode passes `make test-e2e` with updated `ControlPlaneRoots` + Cursor denials; Codex, Cursor, and AGY pass `make test-offline` and `make test-release` with zero `herdr-core` starts; a second fake non-OSC multi-home terminal profile passes unit tests proving provider-agnostic extensibility. |

## Effect and release boundaries

- Roadmap adoption authorizes no code edits, commits, pushes, tags, releases,
  installations, or host account/provider-setting mutations.
- Never stop, restart, or contact the operator's live `default` `herdr-core`
  daemon (avoid `hc server status` / `hc ls` in verification scripts because
  they can start a stopped `default` core; use `ps`-based PID/start-time checks
  instead).
- The pre-`TASK-086` live Grok spike and `TASK-087` live gates (`make test-e2e`,
  `make test-grok`) require explicit live-provider authorization. Release
  publication and the five-provider release-candidate gate remain owned by
  `$aquarium:release-handler`.

## Final acceptance and dossier retirement

Before Epic closeout, verify `TASK-083` (maintenance prerequisite) and every
member Task (`TASK-084` through `TASK-087`) have implementation and
exact-candidate verification evidence, confirm durable outcomes are present in
`docs/architecture/README.md`, `docs/specs/security.md`,
`docs/specs/contracts.md`, `docs/specs/live-workspace-and-git-review.md`,
`docs/gating-rules.md`, embedded help assets, and
`docs/architecture-decision-records/herdr-core-terminal-transport.md` (moved
from planned to accepted in `docs/architecture-decision-records/README.md`),
record the deferred security follow-up for non-`herdr-core` local control
planes on shell-capable ZCode in `docs/deferred-feedback/README.md`, replace
`EPIC-017`'s `Detailed SOT` link in `docs/roadmap/README.md` with
`Canonical Outcomes`, update `docs/README.md`, remove every dangling backlink
to this file, and delete this dossier and its `docs/todo/README.md` entry only
in the approved Epic closeout diff.
