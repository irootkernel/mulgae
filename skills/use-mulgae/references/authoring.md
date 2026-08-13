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
compiled roles. Automatic provider selection requires ZCode and AGY; Kimi must
be selected explicitly. The compiled catalog holds seven roles, and bare
`mulgae init` enables only the required `logic` role, so list every intended
role explicitly. Example:

```bash
mulgae init --providers zcode,agy \
  --roles logic,security,maintainability,product,documentation,testing \
  --output json
```

Add the seventh role, `artist`, only with `--project-kind ui`; artist inputs
require the artist role. Initialization never overwrites an existing complete
Config v2 pair.

## Change an existing configuration

`<canonical-project-root>/.mulgae/config.yaml` owns shared provider families and
models, roles, artist inputs, timeouts, validation, resources, and CI policy.
Edit it only when the user explicitly authorizes that policy change. The
untracked, mode-`0600` `.mulgae/local.yaml` owns only the native home and
provider executable, launcher, and data-home paths. Prefer
`mulgae init --refresh-local` over hand-editing those paths. Use only Config v2
fields demonstrated by current effective configuration, the paired embedded
examples, and `mulgae help config`; Config v1 is unsupported.

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
