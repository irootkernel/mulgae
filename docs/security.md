# Security model

## Trust model

Mulgae treats the project, target, project context, and provider output as
untrusted. Trusted code owns configuration admission, target capture, execution
policy, schema compilation, identity, evidence verification, state reduction,
and publication.

## Provider isolation

Providers do not receive live access to the project tree. Mulgae captures the
target and materializes a controlled workspace. Subprocesses use adapter-owned
commands against that immutable directory view, isolated output, explicit
credential projection, execution bounds, per-instance serialization,
cancellation, and terminal process-state checks. Prompt packets retain bounded
patch, stdin, and old/new review-target bytes that a workspace tree alone cannot
represent; surrounding project content is read selectively from the sealed
directory view rather than re-embedded for every role.

The workspace is materialized as ordinary read-only files (`0444`) and
directories (`0555`). A single tree appears under `current/`; Git comparisons
appear under `before/` and `after/`. Mulgae revalidates the view through retained
descriptors before and after every invocation. Post-execution drift overrides
provider success, so a provider that mutates the view cannot produce a
publishable result.

Project configuration cannot introduce an executable command.

### Per-family write posture

Write authority is not uniform across families, and it is no longer accurate to
say that no provider ever holds it.

- ZCode review invocations run with `--mode yolo` and the adapter-owned
  denylist `Bash,Edit,NotebookEdit,WebSearch,WebFetch`. `Write` is deliberately
  enabled so ZCode can place its role report at the one absolute path Mulgae
  chose. ZCode qualification is unchanged: plan mode with all tools denied.
- AGY review invocations are unchanged: `--new-project --sandbox --add-dir
  <workspace> --mode plan` in the default safe permission mode. Headless AGY
  auto-denies `write_file` in safe mode, so AGY role reports stay on the stdout
  transport. The dangerous permission bypass remains an explicit opt-in and is
  not used for role output.
- Kimi is unchanged and has no adapter-owned workspace tools; its process
  working directory is still the immutable workspace view.

### Staging boundary

A ZCode review launch receives exactly one write target: a fresh
per-invocation directory Mulgae creates with `0700` under the provider's
disposable namespace scratch area, holding the single Mulgae-chosen filename
`role-report.md`. That directory is outside the sealed workspace view and
outside `.mulgae`. The exact absolute path is stated only by the prompt's last trusted
layer; a staged launch whose packet lacks that layer fails closed before the
process starts, and a staging destination the adapter did not itself choose is
refused.

After the process has fully terminated, the adapter validates the staged file
through the directory and parent descriptors it retained at creation, so no
step re-resolves a path the provider could have replaced. It rejects symbolic
links, files with more than one hard link, non-regular files, a file on another
device, any extra directory entry, ownership or mode drift, staging-directory
identity drift, content that changed while it was read,
invalid UTF-8, embedded NUL, and empty or whitespace-only content. Accepted
bytes remain untrusted provider output and enter the same acceptance pipeline
as stdout bytes; they are then copied into the Mulgae-owned
`role-reports/<role>.md`, and the provider-owned inode is never published.
Staging is removed on every exit path, and a cleanup that cannot be proven
overrides provider success as an artifact failure. Missing or unusable staged
content is an operational invalid-provider-output outcome that may be repaired;
a boundary violation is a security fail-closed outcome that never authorizes
repair or publication.

### ZCode residual risk (owner-accepted)

ZCode exposes no path-scoped write permission, so the `Write` grant above is
not confined to the staging directory by the provider itself. Its tool controls
are name-based: local ZCode 0.16.1 rejects `--allowed-tools` at runtime, so
Mulgae uses an explicit denylist, which can enable or deny `Write` wholesale
but cannot bind it to one directory. Containment is therefore entirely
Mulgae-side: the review workspace is a read-only `0444`/`0555` directory view whose
post-execution drift check overrides provider success; the process runs in a
disposable namespace with projected `HOME`, `TMPDIR`, and scratch; only the
staging directory is ever read back as trusted-path input, and only after full
process termination; and everything read back is validated and copied rather
than published in place. Outside those layers, a stray absolute-path write is
not blocked by Mulgae, and the live project tree is git-managed, so such a
write remains user-detectable rather than silent. This residual risk is an
explicit owner decision recorded against live capability evidence, not an
oversight; it applies to ZCode review invocations only.

## Credentials and secrets

Credentials remain owned by the installed provider. Mulgae projects only the
provider-specific files and environment required by the adapter into a
temporary namespace. That namespace also supplies the disposable `HOME`,
`TMPDIR`, and scratch area holding any per-invocation staging directory, so
staging is removed with the namespace it belongs to and never reaches a
credential or project location. Do not commit credentials, provider homes,
`.mulgae/` artifacts, or exported review bundles.

Runtime diagnostics and exports must not disclose secrets or native paths. A
new diagnostic field is a data-release boundary and requires review.

Review capture does not apply secret-pattern detection to source files,
security fixtures, objectives, or provider packets. A configured provider is
therefore authorized to receive every file in the captured workspace view, including
credential-like placeholders and test data. Use `.mulgaeignore` to exclude
`.env` files, credential files, generated data, or any other path that must not
be transmitted. The immutable v3 `._mulgae_workspace_manifest.json` supplied
in each provider workspace lists the exact transmitted paths, sizes, hashes,
media types, and capture dispositions.

Supported PNG, JPEG, and WebP files are preserved as bounded binary evidence
after extension and signature validation. Changed raster evidence and
configured design references are listed in artist visual metadata. Line-based
evidence readers omit their bodies instead of decoding them as UTF-8. Invalid
raster signatures fail as `unsupported_content` with the affected path.
`.mulgaeignore` and the existing workspace/file byte limits apply to raster
evidence exactly as they do to text files. Git's textual binary-diff marker is
path-only; the reference-only captured archive manifest, its support-indexed
SHA-256 blobs, and the workspace manifest bind the actual raster bytes. Dirty
capture revalidates those bytes before admission.

Source and structured-control limits are centralized and composition-checked:
one source tree is bounded to 10,000 files, 64 MiB total, and 4 MiB per file;
the provider's comparison view permits exactly two maximum trees, up to 20,000
files and 128 MiB total; capture and
other structured publication manifests are bounded to 8 MiB; and fixed-size
storage reads are bounded to 32 MiB. Provider-authored reports are not source
admission metadata and have no fixed report-size ceiling. Exact capture-manifest
feasibility is evaluated before any provider invocation. Workspace limit
failures use `capture_workspace_too_large` and report the bounded stage, member,
counts, limits, and `provider_invoked=false` without exposing source bytes.

For example, a repository may start with:

```gitignore
.env
.env.*
*.pem
*.key
credentials/
```

These entries are examples, not a built-in policy: repository owners remain in
control of the paths shared with their selected providers. Output redaction,
configuration credential admission, bounded workspace views, and provider sandboxing
remain enforced independently of capture admission.

A credential-like provider raw stream may be omitted from private diagnostics,
but that diagnostic drop does not turn an otherwise valid review into a
provider failure. Canonical final reviews and path-authorized run support retain
validated source evidence; unvalidated writes and exported projections continue
to use their existing redaction and secret-rejection boundaries.

## Validation and fail-closed behavior

Provider assistant output is admitted as UTF-8 without a fixed report-size
ceiling. Markdown/free-form role reports are the primary consumable success
form; bounded diagnostic previews and exact structured finding extraction remain
separate. Structured extraction is optional: Mulgae may apply one constrained
repair, then validate that wire with schema checks, trusted-field injection, and
semantic/evidence rules. Prose is not schema-validated as review JSON. External
schema loading is disabled. Mulgae owns trusted identity, evidence verification
state, and publication.

Evidence begins as `claimed`; only Mulgae can mark it verified, stale, invalid,
or unverifiable. Security, configuration, integrity, cancellation, and internal
failures never authorize repair or publication.

Mulgae output remains advisory after every technical check passes.

## Reporting vulnerabilities

Do not open a public issue containing credentials, private source, raw provider
transcripts, or `.mulgae/` artifacts. Share the smallest redacted reproduction
through the repository owner's private security contact.
