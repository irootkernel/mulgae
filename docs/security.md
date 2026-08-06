# Security model

## Trust model

Mulgae treats the project, target, project context, and provider output as
untrusted. Trusted code owns configuration admission, target capture, execution
policy, schema compilation, identity, evidence verification, state reduction,
and publication.

## Provider isolation

Providers do not receive live access to the project tree. Mulgae captures the
target and materializes a controlled workspace. Subprocesses use adapter-owned
read-oriented commands against that immutable snapshot, isolated output,
explicit credential projection, execution bounds, per-instance serialization,
cancellation, and terminal process-state checks. Prompt packets retain bounded
patch, stdin, and old/new review-target bytes that a workspace tree alone cannot
represent; surrounding project content is read selectively from the sealed
snapshot rather than re-embedded for every role.

Project configuration cannot introduce an executable command.

## Credentials and secrets

Credentials remain owned by the installed provider. Mulgae projects only the
provider-specific files and environment required by the adapter into a
temporary namespace. Do not commit credentials, provider homes, `.mulgae/`
artifacts, or exported review bundles.

Runtime diagnostics and exports must not disclose secrets or native paths. A
new diagnostic field is a data-release boundary and requires review.

Review capture does not apply secret-pattern detection to source files,
security fixtures, objectives, or provider packets. A configured provider is
therefore authorized to receive every file in the captured snapshot, including
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
path-only; the captured archive and workspace manifest bind the actual raster
bytes, and dirty capture revalidates those bytes before admission.

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
configuration credential admission, bounded snapshots, and provider sandboxing
remain enforced independently of capture admission.

A credential-like provider raw stream may be omitted from private diagnostics,
but that diagnostic drop does not turn an otherwise valid review into a
provider failure. Canonical final reviews and path-authorized run support retain
validated source evidence; unvalidated writes and exported projections continue
to use their existing redaction and secret-rejection boundaries.

## Validation and fail-closed behavior

Provider assistant output is admitted as bounded UTF-8. Markdown/free-form role
reports are the primary consumable success form. Exact structured finding JSON
remains optional: Mulgae may apply one constrained repair, then validate that
wire with schema checks, trusted-field injection, and semantic/evidence rules.
Prose is not schema-validated as review JSON. External schema loading is
disabled. Mulgae owns trusted identity, evidence verification state, and
publication.

Evidence begins as `claimed`; only Mulgae can mark it verified, stale, invalid,
or unverifiable. Security, configuration, integrity, cancellation, and internal
failures never authorize fallback or publication.

Mulgae output remains advisory after every technical check passes.

## Reporting vulnerabilities

Do not open a public issue containing credentials, private source, raw provider
transcripts, or `.mulgae/` artifacts. Share the smallest redacted reproduction
through the repository owner's private security contact.
