# Configuration

Mulgae Config v4 has two configuration authorities:

- `<canonical-project-root>/.mulgae/config.yaml` is the Git-shareable project
  policy.
- `<canonical-project-root>/.mulgae/local.yaml` contains machine-local native
  home and provider paths and must remain mode `0600` and untracked.

`mulgae init` creates both files for a new project. When only the tracked project
file exists after a clone, it creates the local file without changing project
policy and rejects project-policy options.
Earlier versions, including Config v2, are rejected; there is no automatic
migration path.

Config v4 is additive: a release may add an optional project-policy field
without changing the version, and an omitted field keeps its documented
default. A newer Mulgae reads a file written by an older Config v4 release, but
unknown fields are rejected, so an older Mulgae reports `config_yaml_invalid`
for a file a newer one wrote. Since `config.yaml` is shared through Git, keep every collaborator on
a Mulgae at least as new as the release that last wrote it.

To migrate Config v3 manually, change both `version` fields to `4`. In
`local.yaml`, remove ZCode's `node_executable` and `launcher`, then set
`app_bundle` to their canonical containing app bundle, normally
`/Applications/ZCode.app`. The shared file must already be valid Config v4
before `init --refresh-local` can
rebuild the local file.

```text
mulgae init [--project-root PATH] [--name NAME]
  [--providers auto|FAMILY[,FAMILY...]]
  [--roles ROLE[,ROLE...]]
  [--context RELATIVE_PATH]
  [provider-specific overrides]
  [--refresh-local]
  [--output human|json]
```

`FAMILY := zcode | grok | codex`

`--providers auto` discovers ZCode and Grok and fails closed unless both are
available. It assigns every default role to ZCode. Select any supported family
explicitly to choose a different portfolio. Grok accepts a
machine-local `--grok-executable` override and an optional shared-policy
`providers.grok.timeout`. `--grok-model` and `--grok-reasoning-effort` record
optional project-policy values; automatic initialization may also accept these
two flags. Explicit provider selection that excludes Grok rejects either flag,
and `init --refresh-local` rejects them even when the supplied value is empty.
Omitting either dimension independently preserves the provider default.

ZCode uses the standard `/Applications/ZCode.app` bundle by default. An app
installed elsewhere accepts the machine-local `--zcode-app-bundle` override.
Mulgae derives the app-owned Electron runtime, bundled app-server launcher, and
built-in provider configuration from that one canonical absolute bundle path;
it does not require an external Node.js executable.
ZCode reviews import only API-key personal providers from the installed user's
`~/.zcode/cli/config.json`. Desktop and account sign-in state is not projected
into the disposable review home. The selected imported provider and model are
applied before Mulgae sends a review prompt.

Use `mulgae config --mode effective` to inspect the admitted configuration and
`mulgae config --mode provenance` to inspect its source.
`execution.workspace_access` is required and must remain `none`.

`validation.extraction.enabled` admits the Mulgae-owned structured extraction
trailer, which transcribes an accepted free-form role report into exact finding
JSON on the same provider and role. `mulgae init` sets it for new projects; an
existing Config v4 file that omits the block keeps it disabled until you add:

```yaml
validation:
  extraction:
    enabled: true
```

Extraction and repair compete for the same single second invocation, so enabling
it never widens a role path and `resources.role_max_invocations` stays `2`. A
role that already spent that invocation on a retry or a failed repair is not
extracted and remains reports-only.

Use `mulgae init --refresh-local` after provider installations move or the
shared provider family set changes. Refresh atomically replaces only
`.mulgae/local.yaml`; it rejects project-policy options. Mulgae never edits
`.gitignore`. Repositories should use:

```gitignore
/.mulgae/*
!/.mulgae/config.yaml
```

Each configured provider accepts an optional `timeout` duration. The effective
default is `60m`, which is also the admitted maximum; valid values range
inclusively from `1m` through `60m`, so a project may only shorten a provider
window. A shorter timeout also shortens how long Mulgae waits before it stops a
provider that is not making progress.
Default-valued fields are omitted from canonical YAML, while non-default values
such as the following are preserved canonically:

```yaml
providers:
  zcode:
    timeout: "30m"
```

Executable and ZCode app-bundle paths belong only in `local.yaml`.
Provider stdout and stderr have no configuration field or product byte ceiling.

Grok accepts optional project-policy `model` and `reasoning_effort` fields and
a machine-local `executable`. Model values are 1-128 ASCII characters, start
with an alphanumeric character, use only alphanumerics plus `._/-`, and cannot
be absolute or contain `//` or a `..` path segment. Reasoning-effort values are
1-128 ASCII characters, start with an alphanumeric character, and use only
alphanumerics plus `._-`. Mulgae preserves exact spelling and does not maintain
a provider-owned catalog. For example:

```yaml
providers:
  grok:
    model: "grok-4.5"
    reasoning_effort: "high"
```

Codex accepts optional project-policy `model` and `reasoning_effort` fields and
a machine-local `executable`. Valid reasoning efforts are `minimal`, `low`,
`medium`, `high`, and `xhigh`. Omitting model or reasoning effort preserves the
Codex CLI default. For example:

```yaml
providers:
  codex:
    model: "gpt-5.3-codex"
    reasoning_effort: "high"
```

Several authenticated Codex environments can share the same executable and
project model policy. Set `default_credential_profile` in `.mulgae/config.yaml`,
use an optional role-level `credential_profile` override, and list the exact
machine-local homes in `.mulgae/local.yaml`:

```yaml
# project policy
providers:
  codex:
    default_credential_profile: "personal"
roles:
  logic: {enabled: true, primary_provider: "codex"}
  security: {enabled: true, primary_provider: "codex", credential_profile: "work"}
```

```yaml
# local machine paths
providers:
  codex:
    executable: "/Users/operator/.local/bin/codex"
    credential_homes:
      - profile: "personal"
        home: "/Users/operator/.codex"
      - profile: "work"
        home: "/Users/operator/.codex-work"
```

Profile IDs are operator-chosen authentication aliases, not executable names;
they use lowercase kebab-case. The profile list is lexical and must exactly
cover the default and role overrides. Mulgae uses only each home's `auth.json`;
it does not inherit that home's Codex settings or extensions.

`mulgae config --mode effective` reports every configured provider family's
effective timeout. Provenance reports the field as `defaulted` when omitted and
`configured` when a non-default value is present.
`mulgae review --stage --preflight --output json` reports the same effective
timeout on each projected role transmission and proves that the derived role-path and
run budgets can accommodate them, without launching providers.

For UI projects, `roles.artist.inputs.design_spec_globs` are discovery hints,
not file-access rules. Default Git reviews always retain the configured artist;
an added or modified supported image matching a hint becomes primary evidence,
while a review without a matching changed image proceeds from the UI code.
Added images are primary `after` evidence; modified images provide both `before`
and `after`. The artist may inspect any file in the captured workspace when
history or a similar screen is useful.

Initialization installs each Config v4 file atomically and uses an unconditional
project-root durability barrier. The two files cannot commit as one filesystem
transaction: if project policy commits before the local write fails, init
reports `project_committed_local_missing`. Resolve any reported local-path
collision and rerun plain `mulgae init`; it preserves `config.yaml` and creates
only `local.yaml`. An output delivery failure never rolls back a committed
configuration.
