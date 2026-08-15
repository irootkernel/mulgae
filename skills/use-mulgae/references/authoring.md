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
compiled roles. Automatic provider selection requires ZCode and AGY; Kimi and
Codex must be selected explicitly. The compiled catalog holds seven roles, and
bare `mulgae init` enables only the required `logic` role, so list every
intended role explicitly. Example:

```bash
mulgae init --providers zcode,agy \
  --roles logic,security,maintainability,product,documentation,testing \
  --output json
```

Add the seventh role, `artist`, only with `--project-kind ui`; artist inputs
require the artist role. Initialization never overwrites an existing complete
Config v3 pair.

## Change an existing configuration

`<canonical-project-root>/.mulgae/config.yaml` owns shared provider families and
models, roles, artist inputs, timeouts, validation, resources, and CI policy.
Edit it only when the user explicitly authorizes that policy change. The
untracked, mode-`0600` `.mulgae/local.yaml` owns only the native home and
provider executable, launcher, data-home, and credential-home paths. Prefer
`mulgae init --refresh-local` over hand-editing ordinary discovered paths. Use
only Config v3 fields demonstrated by current effective configuration, the
paired embedded examples, and `mulgae help config`; Config v1 and v2 are
unsupported.

## Configure several Codex authentication profiles

Named Codex profiles are a YAML-only Config v3 feature. Treat profile IDs as
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
timeouts, permission mode, and budgets for the selected target.

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
