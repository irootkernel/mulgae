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

Use `mulgae config --mode effective` to inspect the admitted configuration and
`mulgae config --mode provenance` to inspect its source.
`execution.workspace_access` is required and must remain `none`.

Initialization uses atomic installation and an unconditional project-root
durability barrier. An output delivery failure never rolls back a committed
configuration.
