# Configuration

Mulgae Config v3 has two configuration authorities:

- `<canonical-project-root>/.mulgae/config.yaml` is the Git-shareable project
  policy.
- `<canonical-project-root>/.mulgae/local.yaml` contains machine-local native
  home and provider paths and must remain mode `0600` and untracked.

`mulgae init` creates both files for a new project. When only the tracked project
file exists after a clone, it creates the local file without changing project
policy and rejects project-policy options.
Earlier versions, including Config v2, are rejected; there is no automatic
migration path.

```text
mulgae init [--project-root PATH] [--name NAME]
  [--providers auto|FAMILY[,FAMILY...]]
  [--roles ROLE[,ROLE...]]
  [--context RELATIVE_PATH]
  [provider-specific overrides]
  [--refresh-local]
  [--output human|json]
```

`FAMILY := kimi | zcode | agy`

`--providers auto` discovers exactly ZCode and AGY and fails closed unless both
are available. Select Kimi explicitly to create a Kimi-backed compatibility
configuration.

Use `mulgae config --mode effective` to inspect the admitted configuration and
`mulgae config --mode provenance` to inspect its source.
`execution.workspace_access` is required and must remain `none`.

Use `mulgae init --refresh-local` after provider installations move or the
shared provider family set changes. Refresh atomically replaces only
`.mulgae/local.yaml`; it rejects project-policy options. Mulgae never edits
`.gitignore`. Repositories should use:

```gitignore
/.mulgae/*
!/.mulgae/config.yaml
```

Each configured provider accepts an optional `timeout` duration. The effective
default is `15m`; valid values range inclusively from `1m` through `60m`.
Default-valued fields are omitted from canonical YAML, while non-default values
such as the following are preserved canonically:

```yaml
providers:
  zcode:
    timeout: "30m"
```

Executable and launcher paths belong only in `local.yaml`.
Provider stdout and stderr have no configuration field or product byte ceiling.

`mulgae config --mode effective` reports every configured provider family's
effective timeout. Provenance reports the field as `defaulted` when omitted and
`configured` when a non-default value is present.
`mulgae review --stage --preflight --output json` reports the same effective
timeout on each projected role transmission and proves that the derived role-path and
run budgets can accommodate them, without launching providers.

AGY's effective `permission_mode` defaults to `safe` for workspace-first
reviews. Mulgae still launches AGY with `--sandbox` and `--add-dir` limited to
the immutable captured workspace view. Headless write/shell requests remain denied
under the default. To opt into AGY's permission bypass, set:

```yaml
providers:
  agy:
    permission_mode: "dangerously-skip-permissions"
```

Effective configuration reports both the selected mode and a warning when
`dangerously-skip-permissions` is selected, because that mode may approve write
or shell tool requests outside Mulgae's read-oriented boundary. Provenance
marks an omitted safe mode as `defaulted` and an explicit mode as `configured`.

Config v3 files that omit the mode select the safe default.

For UI projects, `roles.artist.inputs.design_spec_globs` are discovery hints,
not file-access rules. Default Git reviews always retain the configured artist;
an added or modified supported image matching a hint becomes primary evidence,
while a review without a matching changed image proceeds from the UI code.
Added images are primary `after` evidence; modified images provide both `before`
and `after`. The artist may inspect any file in the captured workspace when
history or a similar screen is useful.

Initialization installs each Config v3 file atomically and uses an unconditional
project-root durability barrier. The two files cannot commit as one filesystem
transaction: if project policy commits before the local write fails, init
reports `project_committed_local_missing`. Resolve any reported local-path
collision and rerun plain `mulgae init`; it preserves `config.yaml` and creates
only `local.yaml`. An output delivery failure never rolls back a committed
configuration.
