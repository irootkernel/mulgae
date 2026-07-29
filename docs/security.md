# Security model

## Trust model

Mulgae treats the project, target, project context, and provider output as
untrusted. Trusted code owns configuration admission, target capture, execution
policy, schema compilation, identity, evidence verification, state reduction,
and publication.

## Provider isolation

Providers do not receive live access to the project tree. Mulgae captures the
target and materializes a controlled workspace. Subprocesses use adapter-owned
commands, isolated output, explicit credential projection, execution bounds,
per-instance serialization, cancellation, and terminal process-state checks.

Project configuration cannot introduce an executable command.

## Credentials and secrets

Credentials remain owned by the installed provider. Mulgae projects only the
provider-specific files and environment required by the adapter into a
temporary namespace. Do not commit credentials, provider homes, `.mulgae/`
artifacts, or exported review bundles.

Runtime diagnostics and exports must not disclose secrets or native paths. A
new diagnostic field is a data-release boundary and requires review.

## Validation and fail-closed behavior

Provider output must be exactly one JSON value. External schema loading is
disabled. Mulgae validates the provider wire, injects trusted fields, validates
the normalized document, and checks semantic and evidence rules.

Evidence begins as `claimed`; only Mulgae can mark it verified, stale, invalid,
or unverifiable. Security, configuration, integrity, cancellation, and internal
failures never authorize fallback or publication.

Mulgae output remains advisory after every technical check passes.

## Reporting vulnerabilities

Do not open a public issue containing credentials, private source, raw provider
transcripts, or `.mulgae/` artifacts. Share the smallest redacted reproduction
through the repository owner's private security contact.
