# Mulgae

Mulgae is a local, multi-provider AI code review CLI. It reads the original workspace, index or resolved Git objects from a neutral
reviewer directory, runs role-specific reviews through configured providers,
verifies evidence, and publishes durable results under `.mulgae/`.

Mulgae roles are functional review lenses.
They are not people, teams, or organizational authorities.
Mulgae reports findings and recommendations only.

## Start

Automatic initialization requires ZCode and Grok and fails closed unless both
are available. Default roles prefer ZCode with Grok as the secondary preference
for core text roles, and ZCode for artist. Existing configured role assignments
are preserved.

```bash
mulgae init
mulgae config
mulgae doctor --output json
mulgae providers --include-unverified
mulgae review --diff origin/main...HEAD \
  --objective "Review this change before merge."
```

Commit the generated `.mulgae/config.yaml` project policy, but keep
`.mulgae/local.yaml` and all runtime artifacts untracked. After cloning a
configured project, run `mulgae init` to create the local file.

Install with:

```bash
go install github.com/irootkernel/mulgae@latest
```

The initial release supports only `darwin/arm64`. Run `mulgae help workflows`
for target and command forms, or `mulgae help security` for trust boundaries.
