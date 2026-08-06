# Security

The project, target, project context, and provider output are untrusted.
Providers do not receive live access to the project tree. Mulgae captures the
target, materializes an isolated read-only workspace, lets adapters grant
selective read access to that sealed snapshot, projects only required provider
credentials, bounds subprocess execution, and keeps stdout and stderr separate.
Snapshot drift detected after execution overrides provider success.

Project configuration cannot introduce executable commands. Supported provider
adapters are compiled into Mulgae.

One provider family is granted bounded write authority. A ZCode review runs
with `Write` enabled so it can place its role report in a fresh per-invocation
staging directory Mulgae creates under a disposable namespace, outside the
snapshot and outside `.mulgae`. Exactly one filename is authorized, and Mulgae
names the absolute path in the last trusted prompt layer. After the process
exits, Mulgae validates that file through retained descriptors, rejecting
symlinks, extra hard links, non-regular files, extra entries, ownership, mode,
or identity drift, oversize content, invalid UTF-8, NUL bytes, and empty or
whitespace-only content. Accepted bytes are copied into
`role-reports/<role>.md`; the provider's own file is never published, and
staging is always removed. Missing or unusable staged content is an ordinary
invalid-output failure; a boundary violation fails closed.

Be aware that ZCode has no path-scoped write permission, so that grant is not
confined to staging by the provider itself. Containment is Mulgae-side: the
read-only snapshot and its drift check, the disposable namespace, staging-only
trusted read-back after full process termination, and validate-then-copy
publication. A stray absolute-path write elsewhere is not blocked by Mulgae; a
git-managed project tree keeps such a write detectable. This residual risk is
an accepted owner decision and applies to ZCode review invocations only. AGY
and Kimi are unchanged: AGY stays in `--sandbox` plan mode with safe
permissions, where headless `write_file` is auto-denied.

Security, configuration, artifact, cancellation, and internal failures do not
authorize fallback or publication. Checksums, safe paths, schema identities,
semantic ownership, and evidence must all agree before a final artifact is
committed.

Do not commit `.mulgae/`, provider credential directories, raw transcripts, or
exported review bundles.

Review capture does not block source code or test fixtures because they look
like credentials. The selected providers receive every path in the bounded
snapshot. Use `.mulgaeignore` to exclude `.env`, `*.pem`, `*.key`, credential
directories, generated data, or any other path that must not be transmitted.
Each provider workspace includes a v3 `._mulgae_workspace_manifest.json`,
which lists the exact transmitted paths, sizes, hashes, media types, and
capture dispositions. PNG, JPEG, and WebP files are preserved byte-for-byte
after extension and signature validation. Changed raster evidence and
configured design references are listed in artist metadata; line-oriented
evidence readers omit their binary bodies instead of decoding them as UTF-8.
Invalid raster signatures are reported as `unsupported_content`.
`.mulgaeignore` and snapshot size limits still apply. Output redaction and
configuration credential checks remain separate security boundaries. The
captured archive and workspace manifest, rather than Git's path-only binary
marker, bind the exact raster bytes; dirty capture revalidates them before use.

Credential-like raw provider streams may be omitted from private diagnostics
without failing an otherwise valid review. Validated final reviews and
path-authorized source evidence remain publishable; generic writes and exports
retain their separate secret-rejection controls.
