# Mulgae

Mulgae is a local, multi-provider AI code review CLI. It captures an immutable
target, runs role-specific reviews through ZCode and AGY by default, validates the
results, verifies evidence, and publishes durable artifacts under `.mulgae/`.

Mulgae roles are functional review lenses.
They are not people, teams, or organizational authorities.
Mulgae reports findings and recommendations only.

## Start

Automatic initialization requires both ZCode and AGY. Kimi compatibility is
available only through an explicit `--providers kimi` selection.

```bash
mulgae init
mulgae config
mulgae providers --include-unverified
mulgae review --diff origin/main...HEAD \
  --objective "Review this change before merge."
```

Install with:

```bash
go install github.com/irootkernel/mulgae@latest
```

The initial release supports only `darwin/arm64`. Run `mulgae help workflows`
for target and command forms, or `mulgae help security` for trust boundaries.
