# Security

The project, project context, selected source and provider output are untrusted.
Trusted Mulgae code owns admission, role/provider identity, process policy,
evidence verification, reduction and atomic publication. Project configuration
cannot supply executable commands.

Providers read the admitted original project and Git objects from a pinned
neutral `~/.mulgae/home` process/session directory. Mulgae preserves a safe
regular guide there and injects it once. It does not load project or ancestor
instruction files as authority. Project context remains framed untrusted data.

ZCode, Grok, Cursor and AGY require an outer Seatbelt policy for review and
extraction, and every provider live boundary (including Codex's
`permissions.mulgae` profile) denies shared `herdr-core` control-plane roots
and sockets. The Seatbelt guard denies source, Git and guide writes;
credential-root reads, writes and links; control-plane root and socket access;
and Unix sockets at protected roots.

Grok runs inside an isolated Mulgae-owned `herdr-core` terminal pane with a
trampoline-verified `PaneTTY` (blocking foreign `/dev/ttys*` and `TIOCSTI`),
disposable `HOME` and `GROK_HOME` containing only a minimal `requirements.toml`
and projected `0600` `auth.json` (never written back, while `~/.grok` remains
protected in `CredentialRoots`). Workspace review, extraction and qualification
are strictly shell-free; index and commit reviews enable `Bash` only under all
five `B-1` controls (Seatbelt process/socket/file limits plus post-`ESRCH`
same-UID sentinel survivor and `mtime`/`ctime` stability checks). Staged
prompts live read-only (`0400`) under `<scratch>/input/` (protected in
`ReadOnlyRoots`), and staged outputs are read strictly after `ESRCH` via
`O_NOFOLLOW` single-file `Nlink == 1` validation and completion-nonce
verification.

Cursor review and extraction require that same outer Seatbelt policy. The
adapter does not launch Cursor without it. Cursor uses ACP ask mode from the
neutral cwd. Planned reads stay admitted, and each exact Git command is a
separate `allow_once`. The process receives the selected `CURSOR_AUTH_TOKEN`
and forces an in-memory credential store. User rules, skills and MCP
configuration are not projected. Codex uses its native read-only profile,
approvals never, and explicit credential-root and control-plane denial. All
configured credential homes are protected, including unselected profiles and
aliases. Provider namespaces and scratch are private and are removed after
verified process drain and terminal-session close.

AGY requires native plan mode and the outer guard. It imports only the default
Gemini token into a private writable Gemini directory. The original token is
never written back. Adapter-owned settings, agent policy and an empty MCP
configuration are audited after execution. Indexed command guards and an
explicit `command(1)` denial prevent native prefix grants from authorizing
appended commands. Mulgae checks exact tool identity, inputs and completion.
Unknown tools or failed lifecycle checks cannot publish a report. An uncertain
drain retains the namespace, policy and token copy; cleanup does not erase them.

The outer guard denies writes outside the invocation's admitted private runtime
directories as well as reads, links and Unix sockets at protected credential
roots. These controls are not general process, IPC, read or network containment.
Reads outside credential roots and ordinary network requests remain permitted.
Ignoring source paths is not a filesystem access restriction. Workspace
selection uses `.gitignore`; `.mulgaeignore` is not processed or generated.
Keep sensitive material outside the admitted readable source boundary.

Original workspace and index state must remain unchanged during review.
Directory identity checks do not establish an atomic content view or detect
all content drift. Committed scopes use fixed object IDs. Trusted Git reads use
fixed argv and environment with hooks, fsmonitor, external diff, textconv and
lazy fetch disabled.

Preflight and provider execution reject local Git settings outside the supported
data-only set with `unsafe_source`. Repository metadata, sparse checkout/index,
user name/email, remote URL/fetch and branch remote/merge are supported. Hooks
and fsmonitor settings are overridden. Aliases, includes, external diff/textconv,
filters, pagers, credential helpers and unknown settings are rejected. Both main
and worktree configuration are checked again during execution; caller Git
configuration is not rewritten. Provider Git transport protocols are disabled.

Protocol providers return correlated assistant reports directly; terminal
providers (Grok) write one invocation-scoped staged file inside the private
writable namespace that Mulgae validates strictly after `ESRCH` and publishes
under `result_transport: "stdout"`. Reports, prompt payloads and complete
provider streams have no product byte ceiling. Optional repair and extraction
use the same provider and bounded role path; protected failures always deny
repair or publication.

New runs retain source selection metadata, verified excerpts, selected
PNG/JPEG/WebP evidence, findings and role reports, never a full-source archive.
Raster extension and signature must agree, and binary bodies remain binary.
Historical capture readers verify stored manifests and blobs without current
source fallback. Missing historical evidence is distinct from corruption.

Commit only `.mulgae/config.yaml`. Keep `.mulgae/local.yaml` mode `0600` and
untracked, along with credentials, provider homes, runtime artifacts, raw
transcripts and exports. Public diagnostics and redacted exports must not leak
native paths, credentials or raw provider transcripts.
