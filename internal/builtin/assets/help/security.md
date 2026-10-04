# Security

The project, project context, selected source and provider output are untrusted.
Trusted Mulgae code owns admission, role/provider identity, process policy,
evidence verification, reduction and atomic publication. Project configuration
cannot supply executable commands.

Providers read the admitted original project and Git objects from a pinned
neutral `~/.mulgae/home` process/session directory. Mulgae preserves a safe
regular guide there and injects it once. It does not load project or ancestor
instruction files as authority. Project context remains framed untrusted data.

ZCode and Grok require an outer Seatbelt policy for review and extraction.
It denies source, Git and guide writes; credential-root reads, writes and links;
and Unix sockets at protected roots. Grok's native sandbox is off only inside
this mandatory guard. Codex uses its native read-only profile, approvals never,
and explicit credential-root denial. All configured credential homes are
protected, including unselected profiles and aliases. Provider namespaces and
scratch are private and are removed after verified process drain.

These controls are not general process, IPC, read or network containment.
Reads outside credential roots and ordinary network requests remain permitted.
Ignoring source paths is not a filesystem access restriction. Workspace
selection uses `.gitignore`; `.mulgaeignore` is not processed or generated.
Keep sensitive material outside the admitted readable source boundary.

Original workspace and index state must remain unchanged during review.
Directory identity checks do not establish an atomic content view or detect
all content drift. Committed scopes use fixed object IDs. Trusted Git reads use
fixed argv and environment with hooks, fsmonitor, external diff, textconv and
lazy fetch disabled.

Every provider returns a complete correlated protocol assistant report. There
is no live-review report-file write grant. Reports, prompt payloads and complete
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
