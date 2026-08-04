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
timeouts on each projected primary/fallback transmission and proves that the
derived lane and run budgets can accommodate them, without launching providers.

AGY's effective `permission_mode` defaults to
`dangerously-skip-permissions` for headless reviews. The flag does not expand
workspace access: AGY remains sandboxed and receives only Mulgae's bounded
snapshot through `--add-dir`. To opt into AGY's prompt-based policy, set:

```yaml
providers:
  agy:
    executable: "/opt/homebrew/bin/agy"
    permission_mode: "safe"
```

Effective configuration reports both the selected mode and a warning when
`safe` is selected, because headless tool requests may be denied. Provenance
marks an omitted headless mode as `defaulted` and explicit safe mode as
`configured`.

Existing Config v1 files that explicitly recorded
`dangerously-skip-permissions` remain canonical byte-for-byte. Older canonical
files that omitted the former safe default now select the new headless default;
add explicit `permission_mode: "safe"` to retain prompt-based behavior.

Initialization uses atomic installation and an unconditional project-root
durability barrier. An output delivery failure never rolls back a committed
configuration.
