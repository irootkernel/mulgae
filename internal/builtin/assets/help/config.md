# Configuration

Mulgae has one configuration authority:
`<canonical-project-root>/.mulgae/config.yaml`.

`mulgae init` creates that file and never overwrites an existing configuration.
There is no migration or compatibility path from pre-release configuration.

```text
mulgae init [--project-root PATH] [--name NAME]
  [--providers auto|FAMILY[,FAMILY...]]
  [--roles ROLE[,ROLE...]]
  [--context RELATIVE_PATH]
  [provider-specific overrides]
  [--output human|json]
```

`FAMILY := kimi | zcode | agy`

`--providers auto` discovers exactly ZCode and AGY and fails closed unless both
are available. Select Kimi explicitly to create a Kimi-backed compatibility
configuration.

Use `mulgae config --mode effective` to inspect the admitted configuration and
`mulgae config --mode provenance` to inspect its source.
`execution.workspace_access` is required and must remain `none`.

Each configured provider accepts an optional `timeout` duration. The effective
default is `15m`; valid values range inclusively from `1m` through `60m`.
Default-valued fields are omitted from canonical YAML, while non-default values
such as the following are preserved canonically:

```yaml
providers:
  zcode:
    node_executable: "/opt/homebrew/bin/node"
    launcher: "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs"
    timeout: "30m"
```

`mulgae config --mode effective` reports every configured provider family's
effective timeout. Provenance reports the field as `defaulted` when omitted and
`configured` when a non-default value is present.
`mulgae review --stage --preflight --output json` reports the same effective
timeout on each projected role transmission and proves that the derived lane and
run budgets can accommodate them, without launching providers.

AGY's effective `permission_mode` defaults to `safe` for workspace-first
reviews. Mulgae still launches AGY with `--sandbox` and `--add-dir` limited to
the immutable captured workspace view. Headless write/shell requests remain denied
under the default. To opt into AGY's permission bypass, set:

```yaml
providers:
  agy:
    executable: "/opt/homebrew/bin/agy"
    permission_mode: "dangerously-skip-permissions"
```

Effective configuration reports both the selected mode and a warning when
`dangerously-skip-permissions` is selected, because that mode may approve write
or shell tool requests outside Mulgae's read-oriented boundary. Provenance
marks an omitted safe mode as `defaulted` and an explicit mode as `configured`.

Existing Config v1 files that explicitly recorded
`dangerously-skip-permissions` remain canonical byte-for-byte. Older canonical
files that omitted the mode now select the safe default.

For UI projects, `roles.artist.inputs.design_spec_globs` are discovery hints,
not file-access rules. Default Git reviews always retain the configured artist;
an added or modified supported image matching a hint becomes primary evidence,
while a review without a matching changed image proceeds from the UI code.
Added images are primary `after` evidence; modified images provide both `before`
and `after`. The artist may inspect any file in the captured workspace when
history or a similar screen is useful.

Initialization uses atomic installation and an unconditional project-root
durability barrier. An output delivery failure never rolls back a committed
configuration.
