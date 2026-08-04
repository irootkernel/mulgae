# Security

The project, target, project context, and provider output are untrusted.
Providers do not receive live access to the project tree. Mulgae captures the
target, materializes an isolated workspace, projects only required provider
credentials, bounds subprocess execution, and keeps stdout and stderr separate.

Project configuration cannot introduce executable commands. Supported provider
adapters are compiled into Mulgae.

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
