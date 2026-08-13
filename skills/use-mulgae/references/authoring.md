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
require the artist role. Initialization never overwrites an existing
`.mulgae/config.yaml`.

## Change an existing configuration

The sole runtime authority is `<canonical-project-root>/.mulgae/config.yaml`.
Edit it only when the user explicitly authorizes the specific provider, role,
artist-input, timeout, or policy change. Preserve Config v1 structure and use
only fields demonstrated by the current effective configuration, embedded
example, and `mulgae help config`.

After editing, re-read both admitted value and provenance:

```bash
mulgae config --mode effective --output json
mulgae config --mode provenance --output json
mulgae review --stage --preflight --output json
```

The final command is execution-free and confirms current role routing, provider
timeouts, permission mode, and budgets for the selected target.

## Authoring boundaries

Project configuration cannot add arbitrary executable commands, provider
families, roles, or prompt layers. Mulgae does not support custom workflow,
manifest, procedure, or task-policy authoring. The repository's
`assets/roles.yaml` is a build-time source for initialization defaults and the
compiled-in role prompts, not a project customization surface and not a
fallback for configured values. Editing it changes neither an installed binary
nor an existing project.
