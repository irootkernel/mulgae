# Mulgae

Mulgae is a local, multi-provider AI code review CLI. It captures an immutable
target, runs role-specific reviews through ZCode and AGY by default, validates the
results, verifies evidence, and publishes durable artifacts under `.mulgae/`.

Mulgae roles are functional review lenses.
They are not people, teams, or organizational authorities.
Mulgae reports findings and recommendations only.

## Start

Automatic initialization requires both ZCode and AGY. Kimi compatibility is
available only through an explicit `--providers kimi` selection. Codex is
available through an explicit `--providers codex` selection and does not alter
the automatic topology.

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
