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

Initialization uses atomic installation and an unconditional project-root
durability barrier. An output delivery failure never rolls back a committed
configuration.
