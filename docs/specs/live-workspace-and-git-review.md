# Live workspace and Git review

This specification owns [EPIC-009](../roadmap/README.md#epic-009-live-workspace-and-git-review).
TASK-038 connects original-source execution to CLI and MCP. TASK-034 through
TASK-037 own provider feasibility, source access, native restrictions and evidence.
Complete provider/client/release certification remains TASK-039 work. The
[execution dossier](../todo/EPIC-009-live-workspace-and-git-review.md) retains
temporary delivery detail; the roadmap owns lifecycle and acceptance.

## Review targets

Mulgae reviews the original project through read-only source access. It creates no copied checkout, source snapshot, temporary repository, or worktree and retains no complete source archive for replay.

| CLI selector | MCP target kind | Candidate source |
|---|---|---|
| `--workspace` | `workspace` | Current eligible workspace files, including non-ignored untracked files; worktree bytes take precedence over index bytes. |
| `--stage` | `stage` | Current HEAD-to-index transition; changed files and supporting context use index versions. |
| `--head` | `head` | Tree of the commit resolved from HEAD. |
| `--commit REV` | `commit` | First-parent-to-commit transition, or empty-tree-to-root-commit transition. |
| `--diff A..B` or `--diff A...B` | `diff` | A-to-B transition, or merge-base(A,B)-to-B transition, preserving the operator. |

Keep explicit target selection and existing role routing. Resolve mutable committed revisions once at admission. Never substitute worktree or index bytes for committed targets, or worktree bytes for stage. Reject conflicted index targets and invalid or unavailable revisions before provider execution. Empty Git transitions retain the provider-free no-change outcome. Workspace and head whole-tree reviews remain eligible with no diff.

Git ignore rules select workspace candidates; tracked files participate even when an ignore pattern matches. Exclude Git internals and Mulgae/provider runtime or credential directories from review candidates. Remove `.mulgaeignore` processing and generation without automatically deleting user-owned ignore files. Ignore rules do not physically deny provider access to ignored files.

Workspace and index remain live. The caller keeps them unchanged during review. Mulgae adds no full-tree fingerprint, lock, or drift monitor and does not claim atomic source consistency. Missing required content or failed source reads remain failures. Fixed Git objects supply committed evidence while available.

## Reviewer execution

Both provider process cwd and native session cwd are `~/.mulgae/home/`; the canonical project root is a separate typed input. Preserve independently established project binding and reject wrong-root admission before any provider call. Credential HOME, CODEX_HOME, GROK_HOME, sessions, caches, and temporary output remain isolated per invocation.

Mulgae creates a default reviewer `AGENTS.md` in that directory when absent, preserves an existing regular file, and reads its contents once for explicit injection. Reject unsafe path types. Keep common static-review guidance separate from role prompts and defaults in `assets/roles.yaml`. Native instruction discovery must not import project or ancestor guides as execution authority. Source AGENTS.md and CLAUDE.md may be reviewed as untrusted project content.

Use each provider's supported planning/review policy and read-only restrictions, including application-owned permission rejection where the protocol supports it. Prove the effective restrictions; planning mode alone is insufficient. Reviewers may read the selected target and relevant support but cannot edit source, index, refs, Git configuration, or the shared guide. Tests, builds, formatters, installers, authentication, web activity, and unrelated tools stay outside static review. Native scratch writes belong outside the source tree.

Require external source access and exact read-only Git inspection for all three providers. Keep Git execution free of optional locks, external diff/textconv commands, hooks, and project-selected executables. Scope native tools to the review and reject mutations. If a provider cannot satisfy these requirements, stop the cutover; do not substitute a provider, broaden permissions silently, or restore snapshots.

Collect complete role reports from correlated native assistant responses. Review providers no longer write a report into a copied source tree. Retain bounded process lifetimes, cancellation, diagnostics redaction, image handling, and existing content-size policy.

The public execution path uses a neutral reviewer home that admits current-user-owned directories without group
or other write permissions and a safe, regular, single-link UTF-8 guide. It
creates the default exclusively when
absent, and rejects guide or directory identity changes before launch. The
process adapter consumes the pinned neutral directory descriptor. Source and
guide bindings are revalidated after provider work, including cancellation.

ZCode and Grok live review and extraction require an app-owned Seatbelt launch
guard in addition to their native planning and tool restrictions. Source, Git
and neutral roots remain read only; credential roots deny reads, writes, links
and protected Unix socket access. The same socket denial applies to the other
protected roots. Writable filesystem roots are the owned invocation
namespace and, for ZCode only, its existing private short native socket
directory; writes to `/dev/null` are also allowed. Explicit protected denials
win on overlap. The short directory must
retain its admitted canonical identity, current-user ownership and private
mode before and after execution. Grok's native sandbox is off inside the
required outer guard because nested initialization fails. Codex keeps its
native read-only profile and explicit credential-root denials. These public
routes have no unguarded fallback or provider substitution.

The outer guard permits reads outside the declared credential roots and
network access outside protected Unix socket paths. It is not a global read or
network allowlist. ZCode's native Bash tool does not have Grok's exact-command
permission gate; the supplied read plan is guidance enforced alongside the
bounded filesystem guard. Unrelated readable files and network destinations
remain outside this policy's containment claim. Live policy roots must be valid
UTF-8 with printable characters so Seatbelt and native provider configuration
name the exact admitted paths; non-printable roots fail before launch.

Guard admission inspects credential and writable-root file metadata through
directory descriptors, without following symlinks or reading file contents.
Regular files with existing hardlink aliases fail admission. Links outside the
writable roots are denied, while ordinary source and Git hardlinks remain
supported. Cancellation and the request timeout bound admission. This launch
policy does not contain unrelated processes running as the same user.

## Results and compatibility

Providers propose findings and evidence claims. Mulgae owns identities, semantic validation, coverage, typed failures, atomic publication, and artifact integrity. Validate evidence against the declared source side; committed evidence uses resolved Git objects, live evidence is an observation without a retained-source replay guarantee. Retain report excerpts and selected evidence needed to read a result without archiving the full source tree. PNG, JPEG, and WebP evidence retains existing signature and binary handling.

Keep objective input, selected roles, reports, structured findings, status, inspection, export, cleanup, and attached start/await/cancel. Preflight remains provider-free and describes the target, source access, routes, and limitations. Remove capture-bound request guards and immutable capture claims from new execution; retain the independent expected project binding guard. Version changed public schemas and advertise capabilities explicitly. Old capture-bound requests fail before provider execution.

Remove `--dirty`, `--patch`, `--stdin`, followup, delta, rerun, recovery-provider replay, and compose execution, including CLI/MCP routes, obsolete configuration, schemas, help, and installed-skill source guidance. Preserve ordinary role routing; remove routing fields used only by retired recovery execution. There is no deprecation release or legacy replay path.

Keep existing artifacts unchanged. Read and export ordinary, child, failed, no-change, and composite historical results with their original schema and integrity rules. Retain only the archive readers needed for historical inspection. Do not advertise removed recovery actions. Preserve atomic publication reconciliation without provider replay. Existing cleanup safety and lineage protection remain in force; do not scan or delete arbitrary legacy temporary directories.

## Requirements and acceptance

- [ ] LWR-001: all five source scopes have the specified candidate semantics without source snapshots.
- [ ] LWR-002: neutral process/session cwd, explicit shared-guide injection, and isolated credential/scratch homes work together.
- [ ] LWR-003: all three providers read exact targets, return protocol reports, and cannot mutate source or Git state under the supported review policy.
- [ ] LWR-004: live evidence limits, project binding, typed failures, result integrity, and attached lifecycle remain honest and usable.
- [ ] LWR-005: removed execution surfaces fail explicitly; historical inspection, export, and cleanup remain compatible.
- [ ] LWR-006: capture/replay machinery and its affected assets, configuration, docs, and guidance are removed together at cutover.
- [ ] LWR-007: exact-binary, client, and real ZCode/Grok/Codex evidence certify the integrated change.

EPIC-008 is held for redesign against this execution model. This epic adds no requirements-assessment engine, finding tracker, automatic remediation, alternative provider, or platform. Adoption authorizes planning; implementation, installation, configuration, and release retain their separate authorization boundaries.
