# herdr-core terminal transport

Status: Accepted

Roadmap: [EPIC-017](../roadmap/README.md#epic-017-herdr-core-terminal-runtime-and-grok-migration)

## Context

Prior to `EPIC-017`, Mulgae integrated every AI review provider through a bespoke,
CLI-specific wire protocol (`zcode app-server`, `codex app-server`,
`cursor acp`, `grok agent stdio` ACP, `agy stream-json`), paired with
provider-specific settings and policy-file generation. Upstream CLI releases
frequently change internal configuration files, permission flags, or wire
frames (for example, Grok CLI 1.0.70 overwriting `config.toml` and removing
`managed_config.toml`), making direct protocol and native-policy maintenance
brittle and making new AI CLI onboarding costly.

Meanwhile, `herdr-core` (`hc`) provides a local JSON-RPC 2.0 terminal
multiplexer over Unix domain sockets that executes argv vectors directly (no
shell wrapper), manages PTY lifecycles, and tracks OSC 7501 program-status
transitions (`idle`, `working`, `done`, `blocked`, `error`), which modern
coding CLIs including Grok 1.0.89 emit natively when `HC_TERMINAL_ID` is
present.

## Decision

Introduce a reusable, provider-agnostic `herdr-core` terminal execution layer
(`internal/adapters/herdr` and `internal/adapters/providercli/terminal_provider.go`)
protected by Mulgae's trusted pane trampoline (`__mulgae_paneexec_v1`) and
hardened outer macOS Seatbelt guard, and migrate **Grok CLI (`FamilyGrok`)**
onto it first in Phase 1 (`EPIC-017`), while leaving `zcode`, `codex`,
`cursor`, and `agy` transports unchanged for incremental migration in
subsequent Epics. (Grok `1.0.89+` release-channel version parsing and synthetic
`grok-logic` heartbeat registration are delivered separately ahead of
`EPIC-017` in maintenance `TASK-083`.)

1. **Trusted pane trampoline (`__mulgae_paneexec_v1`) and exact-TTY Seatbelt**:
   Empirical testing against `hc 0.1.20` established that launching
   `sandbox-exec` directly from `herdr-core`'s holder breaks four security and
   functional invariants: (a) `herdr-core` injects `HC_TERMINAL_SOCKET` and
   inherits the core's environment without allowing key removal, enabling a
   sandbox escape via `terminal.run` over the control socket; (b)
   holder-allocated PTY slaves lack macOS's `com.apple.sandbox.pty` extension,
   so denying unextended `/dev/ttys*` breaks TUI raw mode; (c) inherited holder
   descriptors above stderr are not closed; and (d) string `cwd` opens a launch
   TOCTOU.
   Therefore, `terminal.run` launches Mulgae's canonicalized verified binary as
   `__mulgae_paneexec_v1` (extending `internal/adapters/process/fdexec_darwin.go`,
   dispatched via `internal/composition/run.go`, behind a narrow `ports`
   launch-builder interface). The trampoline reads the `0400` env file and
   Seatbelt profile file from a `ControlPlaneRoots`-denied per-pane directory
   (`/private/tmp/mgh-<uid>/<16hex>/panes/<id>/`), verifies Mulgae-authored
   argv integrity bindings (`(dev, ino)` + SHA-256 for env/profile files,
   `(dev, ino)` for the provider binary, `(dev, ino, btime, euid)` for neutral
   `cwd`), `fchdir`s into the verified neutral `cwd`, verifies all three
   standard descriptors (`0, 1, 2`) are the same controlling PTY slave without
   cgo (`F_GETPATH` + `Rdev` + `Getsid` + `TIOCGPGRP`), closes all FDs > 2
   (`O_CLOEXEC`), builds an exact `envp` (never calling `os.Environ()`; keeping
   fixed terminal identity values plus validated `HC_TERMINAL_ID` while
   stripping `HC_TERMINAL_SOCKET`, `HC_SOCKET`, `HC_SESSION`, `HC_SCOPE`,
   `DYLD_*`, `LD_*`, `GODEBUG`, and core `XDG_*`), and `execve`s compiled-in
   `/usr/bin/sandbox-exec -D PANE_TTY=<exact-slave> -f <profile-file> <provider> ...`.
   The Seatbelt profile allows ONLY that single `PANE_TTY` device inside the
   global write-deny predicate (plus `/dev/tty`), denies every other
   `/dev/ttys[0-9]+`, adds missing-tolerant `ControlPlaneRoots` denials
   (`/private/tmp/mgh-<uid>`, `~/.local/state/herdr-core`,
   `~/.config/herdr-core`, and inherited `HC_SOCKET`) plus `~/.cursor` and
   `~/.config/cursor` denials to shared boundaries, and adds secret-root and
   ancestor-file denials (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/Library/Keychains`,
   `~/.claude`, `~/.config/herdr`, `~/.local/state`, `~/AGENTS.md`,
   `~/CLAUDE.md`, `~/.mcp.json`) to `PaneTTY` profiles. Grok uses `PaneTTY`
   only (never `OwnedPTY`); existing AGY `OwnedPTY` clauses remain
   byte-identical.
2. **Disposable `HOME` + disposable `GROK_HOME` (retaining sterile isolation)**:
   Original project sources and `.git` remain uncopied and read-only under
   Seatbelt with neutral `cwd` (`~/.mulgae/home/`). Grok retains Mulgae's
   disposable namespace `HOME` and disposable `GROK_HOME`, containing only a
   minimal `requirements.toml` (disabling compat hooks, MCP servers, rules,
   skills, plugins, and managed configs, with no `sandbox.toml`) and a
   validated `0600` regular single-link copy of `~/.grok/auth.json` with zero
   write-back. Grok launches with `--permission-mode bypassPermissions`,
   `--trust`, and `--no-alt-screen`, where `--trust` applies strictly to
   Mulgae's verified read-only neutral `--cwd` inside disposable `GROK_HOME`
   so `~/.mulgae/home/AGENTS.md` does not trigger Grok's interactive
   folder-trust prompt. Native `~/.grok` stays kernel-denied in
   `CredentialRoots` for Grok as well as every other provider (blocking
   `~/.grok/leader.sock`, `config.toml`, `hooks/`, `AGENTS.md`, `plugins/`,
   `skills/`, `sandbox.toml`, `trusted_folders.toml`, and `memory-v2/`, while
   installed `~/.grok/downloads/grok-*` binaries execute directly without
   widening `~/.grok` denies), preserving all existing `HOME` authority checks
   in `policy.go` and `scheduling.go`, preventing concurrent OAuth refresh
   conflicts, and moving Grok qualification and heartbeat onto the neutral-cwd
   + Seatbelt pattern.
3. **Isolated per-run `herdr-core` daemon, graph ownership, and truthful teardown**:
   Mulgae lazily launches a foreground `herdr-core serve` child per run (no
   `launchd`, never touching the user's `default` core) with explicit minimal
   `Env`, canonical `/private/tmp/mgh-<uid>/<16hex>/` (`0700`, `O_NOFOLLOW`,
   owner-verified), `{pid, start_time}` owner lock + startup stale-session
   reaper, parent-death watchdog, and `config.toml` (`notes = false`,
   `draft_wait = 0`, `notes_quiet = 0`). `productionRuntimeGraph` is the sole
   owner of `Session.Close()` — called first inside `cleanupRoots()` AND
   explicitly on the retained error branch of `review.go` (preventing MCP
   daemon leaks) — stopping both the core PID and `server.status.holder.pid`.
   `Registry` and `CurrentProbe` borrow the session and tag panes with
   `mulgae_registry` labels; `Registry.Close` drains only its own labeled panes
   retryably and never stops the shared daemon. `ProcessGroupAbsent()` requires
   Mulgae-observed `unix.Kill(-pid, 0) == ESRCH` and session-scoped absence.
4. **Universal scratch-file delivery, tool limits, and contract honesty**:
   Full unbounded prompts are written to `input/<id>/prompt.md` (`0400`) inside
   a pane `ReadOnlyRoots` `input/` directory with pre-start and post-teardown
   SHA-256 digests and a mandatory end-of-prompt completion nonce (for review
   and extraction). Concise fixed
   instructions travel via `terminal.send` (requiring `Terminal.reported == true`
   and turn advancement). Strictly after proven `ESRCH` teardown,
   descriptor-bound `stagedOutputLease.Validate()` reads back exact unbounded
   bytes (`role-report.md` for review, `extraction.json` for extraction,
   `probe.json` for qualification), bound as `result_transport: "stdout"`
   (documented explicitly in `contracts.md` alongside bounded post-kill screen
   diagnostics and merged PTY stream semantics). Tools are purpose-scoped:
   workspace reviews (`read_file,grep,list_dir,Write`), extraction, and
   qualification (`read_file,Write`) run strictly shell-free, while index and
   commit Git reviews enable `Bash` (`read_file,grep,list_dir,Write,Bash`)
   solely under all five `B-1` Seatbelt and post-`ESRCH` stability/survivor
   controls (default-deny outbound Unix sockets with narrow system-resolver
   allowlist, localhost IP denial, terminal secret-root and ancestor-literal
   denials, sensitive-binary and `WritableRoot`/`RuntimeTempRoot`/`ReadOnlyRoots`
   `process-exec` denials, and post-`ESRCH` session/sentinel survivor and
   `mtime`/`ctime` stability checks). Config v5 and embedded JSON
   schemas/examples remain unchanged; affected embedded help Markdown assets
   are updated with idempotent regeneration.

## Consequences

- **Reduced provider-protocol coupling**: Grok upgrades no longer break Mulgae
  on ACP wire extensions or `sandbox.toml` post-drain audits.
- **Reusable onboarding path**: Future migrations of interactive CLIs (`codex`,
  `cursor`, `agy`) or new AI CLIs reuse `internal/adapters/herdr`,
  `__mulgae_paneexec_v1`, control-plane Seatbelt isolation, and
  `terminal_provider.go`. (Non-TUI app-servers such as ZCode do not need to
  migrate.)
- **Targeted `herdr-core` control-plane hardening**: Adding `ControlPlaneRoots`
  and `~/.cursor`/`~/.config/cursor` denials closes `herdr-core` control-plane
  and Cursor-credential access across guarded providers. (Other same-UID local
  control planes reachable from shell-capable ZCode — such as operator `herdr`,
  `ssh-agent`, `opencode`, or localhost APIs — remain recorded in
  [`DF-030`](../deferred-feedback/README.md) outside `EPIC-017`.)
- **Trade-offs**:
  - **TUI / onboarding / OSC churn**: Trading a versioned wire protocol for a
    TUI shifts maintenance risk toward startup dialogs, CLI flag renames, and
    OSC 7501 reporting; mitigated by fail-closed `Terminal.reported == true`,
    disposable `HOME`/`GROK_HOME`, and the pre-cutover live spike.
  - **Reduced read-plan granularity & single-write authorship**: Without ACP
    per-tool interception, Grok read containment relies on kernel-denied secret
    and credential roots plus purpose-scoped `--tools` rather than exact
    per-read correlation, and terminal staging proves post-teardown file
    identity rather than mediated single-write authorship (documented in
    `docs/specs/security.md`).
  - **Merged PTY diagnostics & model acknowledgement**: Terminal mode provides
    bounded screen capture rather than separated unbounded stdout/stderr, and
    replaces pre-prompt ACP model/effort acknowledgement with syntax-validated
    CLI flags (`-m`, `--reasoning-effort`) bound to qualification identity,
    where Grok `1.0.89`'s interactive TUI applies unrecognized tokens
    best-effort with silent provider-side fallback (confirmed during the spike
    and documented in `docs/specs/contracts.md`).
  - **Detached process residual & host dependency**: `setsid()` escapers remain
    a residual risk when a shell is enabled (matching `Setpgid` runner
    limits), and Grok execution requires `herdr-core` (`hc`) on the host.

## Rejected alternatives

- **Keeping Grok ACP (dropping only `requirements.toml`/`sandbox.toml`) or
  building a generic ACP driver / headless print-JSON driver**:
  Considered during independent architecture review because recent Grok
  breakages stemmed from policy TOML churn and version-banner parsing rather
  than ACP framing. Rejected by Master's strategic decision to standardize
  Mulgae on a single terminal-native execution layer (`herdr-core`) that can
  drive interactive CLIs uniformly without chasing per-vendor headless or ACP
  dialects.
- **Writable native `~/.grok` home (`ProviderHomeRoot` carve-out)**:
  Rejected during independent security and architecture review. The operator's
  `~/.grok` contains the `grok` binary (`downloads/`), `config.toml`, `hooks/`,
  `AGENTS.md`, `plugins/`, `skills/`, `sandbox.toml`, `trusted_folders.toml`,
  `memory-v2/`, and `leader.sock`. Making it writable exposes cross-session
  persistence, contaminates reviews with user global rules/memory, risks
  concurrent OAuth refresh races, and conflicts with existing `HOME` authority
  invariants.
- **Direct `sandbox-exec` launch from `herdr-core` holder without trampoline**:
  Rejected after empirical testing on `hc 0.1.20` reproduced (a) a full
  Seatbelt escape through injected `HC_TERMINAL_SOCKET` and (b) broken raw mode
  (`stty: TIOCGETD: Operation not permitted`) because holder-allocated PTYs
  lack `com.apple.sandbox.pty`.
- **Widening Seatbelt to allow all `/dev/ttys[0-9]+`**:
  Rejected because it would allow a sandboxed provider to read input from or
  write to the operator's other terminals.
- **Using Grok `--permission-mode plan` alone without outer Seatbelt**:
  Rejected after inspecting Grok 1.0.89's embedded plan-mode rules: interactive
  `plan` mode blocks `Write` to non-plan files (breaking `staged_file`), does
  not inspect `Bash` redirection, and runs project hooks before the plan gate.
- **Reusing the operator's shared `default` `herdr-core` session**:
  Rejected because Mulgae panes would pollute interactive `hc ls` state,
  inherit user draft/notes configuration, and create cleanup collisions.
- **Extracting review reports from `hc read` or `grok export`**:
  Rejected because scrollback mixes TUI chrome and narration with report text
  and `grok export` reintroduces CLI-specific coupling.
- **Keeping Grok ACP alongside `herdr-core` as a dual-mode fallback**:
  Rejected because dual paths double security and test maintenance without
  removing upstream coupling.
