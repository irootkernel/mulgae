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
