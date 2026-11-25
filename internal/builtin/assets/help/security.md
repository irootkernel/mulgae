# Security

The project, project context, selected source and provider output are untrusted.
Trusted Mulgae code owns admission, role/provider identity, process policy,
evidence verification, reduction and atomic publication. Project configuration
cannot supply executable commands.

Providers read the admitted original project and Git objects from a pinned
neutral `~/.mulgae/home` process/session directory. Mulgae preserves a safe
regular guide there and injects it once. It does not load project or ancestor
instruction files as authority. Project context remains framed untrusted data.

ZCode and Grok require an outer Seatbelt policy for review and extraction, and
every provider live boundary denies shared `herdr-core` control-plane roots and
sockets. The Seatbelt guard denies source, Git and guide writes;
credential-root reads, writes and links; control-plane root and socket access;
and Unix sockets at protected roots.

ZCode and Grok run in isolated Mulgae-owned `herdr-core` panes. The
trampoline-verified `PaneTTY` blocks foreign `/dev/ttys*` and `TIOCSTI`.
The ZCode companion prepares private auth and catalog files on the host.
The pane cannot read `~/.zcode` or the native Keychains. Grok uses disposable
`HOME` and `GROK_HOME` with a minimal `requirements.toml` and projected
`0600` `auth.json`. The native `~/.grok` stays protected, and projected
credentials are never written back.

Workspace review, extraction and qualification are shell-free. Index and
commit reviews enable `Bash` under the five `B-1` controls, including
process, socket and file limits and post-`ESRCH` checks for same-UID
sentinel survivors and `mtime`/`ctime` stability. Prompts live in `0400`
files under `<scratch>/input/`, protected by `ReadOnlyRoots`.
After verified `ESRCH`, Mulgae checks staged outputs
using `O_NOFOLLOW` and `Nlink == 1` and verifies the completion nonce
required by the invocation. Provider namespaces are private and drain
with verified process and terminal-session cleanup.

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

Mulgae publishes accepted staged report bytes under
`result_transport: "stdout"`. Reports, prompt payloads and complete provider
streams have no product byte ceiling. Optional repair and extraction use the
same provider and bounded role path. Protected failures deny repair and
publication.

New runs retain source selection metadata, verified excerpts, selected
PNG/JPEG/WebP evidence, findings and role reports, never a full-source archive.
Raster extension and signature must agree, and binary bodies remain binary.
Historical capture readers verify stored manifests and blobs without current
source fallback. Missing historical evidence is distinct from corruption.

Commit only `.mulgae/config.yaml`. Keep `.mulgae/local.yaml` mode `0600` and
untracked, along with credentials, provider homes, runtime artifacts, raw
transcripts and exports. Public diagnostics and redacted exports must not leak
native paths, credentials or raw provider transcripts.
