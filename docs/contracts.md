# Contracts and artifacts

## Versioning

The public contract surface starts at v1. Configuration uses `version: 1`;
machine documents use identifiers such as `mulgae-run-manifest.v1`; prompts and
role definitions also carry v1 identities.

The initial release is a clean break from the pre-release prototype. Mulgae
does not read old command names, paths, environment variables, or schema
versions.

## Configuration

There is one configuration authority:

```text
<canonical-project-root>/.mulgae/config.yaml
```

`mulgae init` creates it without overwriting an existing file. Configuration
selects provider paths and models, role assignments, validation policy,
resource ceilings, and CI thresholds. It cannot add arbitrary provider
commands. Use `mulgae config --mode effective` for the admitted value and
`mulgae config --mode provenance` for its source.

See the complete
[`local-config.yaml`](../internal/builtin/assets/examples/local-config.yaml)
example.

## Embedded v1 contracts

Schemas use JSON Schema Draft 2020-12 and live in
[`internal/builtin/assets/schemas`](../internal/builtin/assets/schemas).
The catalog contains one current schema/example pair for command and doctor
results, provider/platform evidence, provider review values, repair and
validation values, run/final artifacts, clean/export values, and the embedded
file catalog.

Schema validation is necessary but not sufficient. Services also enforce
trusted field ownership, identity relationships, state transitions, path
locality, evidence freshness, and publication cardinality.

## Field ownership

Providers may propose finding content and evidence claims, but do not assign:

- session, run, attempt, review, or finding identities;
- target or source identity;
- provider/role identity;
- verification state;
- final content, coverage, publication, or CI outcomes.

Mulgae injects or derives those fields after validation. A constrained repair
may change only explicitly allowed provider-owned paths.

## Artifact layout

```text
.mulgae/
  s_<uuidv7>/
    r_<uuidv7>/
      manifest.json
      runtime.jsonl
      attempts/
      validation/
      review_<uuidv7>.json
```

`manifest.json` is the run index and integrity record. A completed run has at
most one top-level final review. Failed or repaired candidates remain beneath
`attempts/`.

`review`, `followup`, `delta`, and `rerun` create distinct runs. They
respectively start a review, check one prior finding, review a delta, or repeat
a selected attempt.

## Output and exits

`mulgae version --json` returns exactly `name` and `version`. Workflow commands
use `--output json` and return a `mulgae-command-result.v1` envelope. Process
exits:

| Exit | Meaning |
|---:|---|
| 0 | success |
| 1 | policy outcome |
| 2 | invalid usage or configuration |
| 4 | provider or readiness unavailable |
| 7 | artifact or integrity failure |
| 8 | security policy failure |
| 9 | cancellation |
| 10 | internal failure |

CI decisions derive from committed artifacts. Provider output or an uncommitted
candidate has no CI authority.
