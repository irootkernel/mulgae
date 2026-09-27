# Mulgae configuration authoring

Load this reference only when a user asks to initialize or change providers,
roles, artist inputs, timeouts, or other supported project configuration.

## Select built-in configuration

Inspect the compiled inventories and current authority before proposing a
change:

```bash
mulgae roles --output json
mulgae providers --include-unverified --output json
mulgae config --mode effective --output json
mulgae config --mode provenance --output json
```

For a new workspace, `mulgae init` selects only compiled provider families and
compiled roles. Mulgae supports ZCode, Grok, and Codex. Automatic provider
selection requires both ZCode and Grok; select a subset explicitly with
`--providers zcode`, `--providers grok`, or `--providers codex`. The compiled
catalog holds seven roles, and bare `mulgae init` enables only the required
`logic` role, so list every intended role explicitly. Examples:

```bash
mulgae init --providers zcode,grok \
  --roles logic,security,maintainability,product,documentation,testing \
  --output json
mulgae init --providers grok --roles logic,security \
  --grok-executable /absolute/path/to/grok \
  --grok-model grok-4.7 --grok-reasoning-effort high --output json
mulgae init --providers codex --roles logic,security --output json
```

New projects that select Grok write `grok-4.7` and `high` when either value is
not supplied explicitly. The two flags override those dimensions independently.
An existing Config v4 file that omits either field continues to use Grok's
provider default for that dimension; initialization and local refresh must not
silently add the generated defaults to it.

Add the seventh role, `artist`, only with `--project-kind ui`; artist inputs
require the artist role. Initialization never overwrites an existing complete
Config v4 pair.

## Change an existing configuration

`<canonical-project-root>/.mulgae/config.yaml` owns shared provider families and
models, roles, artist inputs, timeouts, validation, resources, and CI policy.
Edit it only when the user explicitly authorizes that policy change. The
untracked, mode-`0600` `.mulgae/local.yaml` owns only the native home and
provider executable, ZCode app-bundle, and credential-home paths. Prefer
`mulgae init --refresh-local` over hand-editing ordinary discovered paths. Use
only Config v4 fields demonstrated by current effective configuration, the
paired embedded examples, and `mulgae help config`; Config v1 through v3 are
unsupported.

## Configure several Codex authentication profiles

Named Codex profiles are a YAML-only Config v4 feature. Treat profile IDs as
operator-chosen authentication aliases, not executable names. With explicit
authorization, set the default and any role overrides in shared project policy:

```yaml
# .mulgae/config.yaml
providers:
  codex:
    default_credential_profile: "personal"
roles:
  logic: {enabled: true, primary_provider: "codex"}
  security: {enabled: true, primary_provider: "codex", credential_profile: "work"}
```

Map exactly those aliases, in lexical order, to their private machine-local
`CODEX_HOME` directories:

```yaml
# .mulgae/local.yaml
providers:
  codex:
    executable: "/Users/operator/.local/bin/codex"
    credential_homes:
      - profile: "personal"
        home: "/Users/operator/.codex"
      - profile: "work"
        home: "/Users/operator/.codex-work"
```

Use lowercase kebab-case profile IDs and one common real `codex` executable.
Do not point `executable` at wrappers that rewrite `CODEX_HOME`. The local list
must cover the default plus every role override exactly; unused, missing,
duplicate, or unsorted entries are rejected. A role-level profile is valid only
for a Codex role. Mulgae imports only `auth.json`; model, reasoning, and timeout
remain shared project policy, while Codex config, rules, skills, and plugins are
ignored. Do not authenticate, create homes, or expose their paths without the
user's separate authorization.

After editing, re-read both admitted value and provenance:

```bash
mulgae config --mode effective --output json
mulgae config --mode provenance --output json
mulgae review --stage --preflight --output json
```

The final command is execution-free and confirms current role routing, provider
timeouts, permission mode, and budgets for the selected target. Configuration
changes invalidate an earlier request receipt. Before an authorized review,
obtain a fresh native binding/preflight receipt and use paired execution guards
as described in [SKILL.md](../SKILL.md#bind-the-review-target); do not reuse the
pre-change digest or silently remove a requested guard.

Keep this root-anchored Git policy:

```gitignore
/.mulgae/*
!/.mulgae/config.yaml
```

Commit only `config.yaml`; never commit `local.yaml` or runtime artifacts.

## Authoring boundaries

Project configuration cannot add arbitrary executable commands, provider
families, roles, or prompt layers. Mulgae does not support custom workflow,
manifest, procedure, or task-policy authoring. The repository's
`assets/roles.yaml` is a build-time source for initialization defaults and the
compiled-in role prompts, not a project customization surface and not a
fallback for configured values. Editing it changes neither an installed binary
nor an existing project.
