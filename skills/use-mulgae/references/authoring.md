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
compiled roles. Mulgae supports ZCode and Grok. Automatic
selection requires both ZCode and Grok; select a
supported subset explicitly with `--providers FAMILY[,FAMILY...]`. Default core
roles prefer ZCode with Grok as secondary preference, and artist uses ZCode.
Existing policy is preserved.
The compiled catalog holds seven roles, and bare `mulgae init` enables only the required
`logic` role, so list every intended role explicitly. Examples:

```bash
mulgae init --providers zcode,grok \
  --roles logic,security,maintainability,product,documentation,testing \
  --output json
mulgae init --providers grok --roles logic,security \
  --grok-executable /absolute/path/to/grok \
  --grok-model grok-4.7 --grok-reasoning-effort high --output json
```

New projects that select Grok write `grok-4.7` and `high` when either value is
not supplied explicitly. The two flags override those dimensions independently.
An existing Config v5 file that omits either field continues to use Grok's
provider default for that dimension; initialization and local refresh must not
silently add the generated defaults to it.

Add the seventh role, `artist`, only with `--project-kind ui`; artist inputs
require the artist role and ZCode (Grok is text-only). Initialization never
overwrites an existing complete Config v5 pair.

## Change an existing configuration

`<canonical-project-root>/.mulgae/config.yaml` owns shared provider families and
models, roles, artist inputs, timeouts, validation, resources, and CI policy.
Edit it only when the user explicitly authorizes that policy change. The
untracked, mode-`0600` `.mulgae/local.yaml` owns only the native home and
provider executable and ZCode app-bundle paths. Upgrading
Mulgae preserves existing valid Config v5 shared and machine-local files,
including custom provider-role routing, provider timeouts,
Grok/ZCode model and reasoning settings, and UI `artist` inputs, without
running a fresh `mulgae init`. Prefer `mulgae init --refresh-local` over hand-editing
ordinary discovered paths. Use only Config v5 fields demonstrated by current
effective configuration, the paired embedded examples, and `mulgae help config`;
Config v1 through v4 are unsupported. To migrate v4 deliberately, back up the
private file, set both versions to 5 and remove shared
`execution.workspace_access`. No replacement setting or automatic migration
exists.

After editing, re-read both admitted value and provenance:

```bash
mulgae config --mode effective --output json
mulgae config --mode provenance --output json
mulgae review --stage --preflight --output json
```

The final command is execution-free and confirms current role routing, provider
timeouts, permission mode, and budgets for the selected target. Configuration
changes invalidate earlier routing and budget observations. Before an authorized
review, repeat execution-free preflight for the selected source and preserve the
independently established project binding as described in
[SKILL.md](../SKILL.md#bind-the-review-target). Do not silently remove a requested
guard. Current live execution has no request-digest guard.

Keep this root-anchored Git policy:

```gitignore
/.mulgae/*
!/.mulgae/config.yaml
```

Commit only `config.yaml`; never commit `local.yaml` or runtime artifacts.

## Authoring boundaries

Project configuration cannot add arbitrary executable commands, provider
families, roles, prompt layers, or Haepari controller/lock settings. Live review
coordination uses the external `HAEPARI_HOME` Installation (`advisory-lock/v1`)
and its registered capacity-one `mulgae-review` resource. When authoring or
raising provider timeouts or role invocation budgets, ensure the external
`mulgae-review` maximum-hold policy covers the full admitted run budget
(`budget.run_deadline`), preparation, and two minutes of terminal cleanup;
review execution never registers or modifies Haepari resource policy, and policy
changes require separate setup authority. Mulgae does not support custom
workflow, manifest, procedure, or task-policy authoring. The repository's
`assets/roles.yaml` is a build-time source for initialization defaults and the
compiled-in role prompts, not a project customization surface and not a
fallback for configured values. Editing it changes neither an installed binary
nor an existing project.
