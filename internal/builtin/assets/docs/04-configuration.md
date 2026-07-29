# Project-local configuration

Mulgae has one configuration authority: `<canonical-project-root>/.mulgae/config.yaml`.
It does not search a home directory, XDG directory, repository proposal, embedded
default, environment variable, or compatibility filename. The file is local
operator state and must never be tracked by Git.
There is no migration or compatibility path from `.mulgae.yaml`, `.mulgae.yml`, a
home-directory configuration, or an XDG configuration.

## Admission

The project root is a no-symlink, effective-user-owned directory with mode
`0700`, `0750`, or `0755`. `.mulgae` is mode `0700`; `config.yaml` is a single-link
regular file at mode `0600`. Descriptor traversal is no-follow and the accepted
file is bounded to 1 MiB.

`help` is outside this admission path because it renders only embedded documentation and reads no project configuration. Init, config, doctor, qualification, and provider execution retain their required locality barriers.

Admission also binds an immutable locality context containing the repository and
root identity, checkout HEAD and tree, every index stage, applicable target
commits, the config descriptor and digest, and the parsed target decision. A
tracked or committed `.mulgae/` path, an unmerged index, or a complete unified diff
that changes `.mulgae/` rejects admission. The proof is revalidated before decode,
provider qualification, and provider execution.

An exact `.mulgae/config.yaml` target reports `target_private_config_forbidden`; `.mulgae` itself and every other descendant report `target_private_namespace_forbidden`. Both are reason-only security failures at exit `8`. Prose and malformed patch-like input do not trigger either reason.

## Canonical YAML v2

The document has `version: 2` and the sections `project`, `native_user`,
`providers`, `execution`, `roles`, `review`, `validation`, `resources`, and
`ci`. `providers` contains any nonempty subset of `kimi`, `zcode`, and `agy`.
Provider commands are family-specific fields; generic argv, environment, shell,
and credential fields do not exist. `execution.workspace_access` is required and
may only be `none` or `readonly_snapshot`; omission is rejected. `mulgae init`
explicitly writes `none` into every newly created configuration.

Each role contains `enabled`, `primary_provider`, and, except for a
singleton provider configuration, `fallback_provider`. Both provider values are
family IDs from the configured nonempty subset. They must differ. Version 1 is
rejected without migration or compatibility fallback.

`project.kind` is `non_ui` when omitted and may be explicitly set to `ui`.
The enabled project set contains one to seven roles and must include `logic`.
Disabled roles retain deterministic provider assignments so the
document shape remains fixed, but they are not qualified, scheduled, budgeted,
or selected by a default review. Every `review.required_roles` member must be
enabled, and the required-role set must include `logic`; other enabled roles may
also be required. New projects enable only `logic` unless `mulgae init --roles`
selects more roles. UI projects may additionally enable `artist`, but do not do
so automatically. Config v2 retains the field names `inputs.task_path` and
`inputs.design_spec_globs` as project defaults for one UTF-8 artist brief and
bounded PNG/JPEG/WebP visual references. The configured filename is not fixed;
new UI init writes `ux-ui-info.md` unless `--artist-brief` selects a different
project-relative file. Artist is assigned only to AGY then ZCode; Kimi is not
an artist-capable fallback.

With all three families, init writes `logic=kimi/zcode`,
`documentation=agy/zcode`, and
`security|maintainability|product|testing=zcode/agy`, where each pair is
`primary/fallback`. For subsets it selects the first two configured families
from `kimi,zcode,agy` for logic, `agy,zcode,kimi` for documentation, and
`zcode,agy,kimi` for the other roles. A singleton uses the sole family as
primary and has no fallback.

Artist activation is declaration-only: filenames and framework detection never
turn it on. For `mulgae review`, `--artist-brief` and
`--artist-design-specs` independently override the corresponding Config v2
fallback. A selected artist review fails before provider execution when its
resolved brief is missing, empty, or invalid, or when its resolved globs match
no supported visual. A review that does not select artist does not resolve,
capture, or prompt with these inputs.

Parsing is strict: one UTF-8 YAML document, exact keys, no aliases, tags, merges,
duplicates, nulls, placeholders, controls, or unknown fields. Canonical output
uses LF, two-space indentation, quoted strings, and fixed family, role, and
severity order. Persisted paths are canonical absolute no-symlink paths.

Admission runs bounded structural parsing, then the deterministic credential
scan, then exact-key/known-field and typed semantic validation. The scanner
ASCII-lowercases keys and folds runs of `-`, `_`, `.`, and ASCII space to `_`,
so a secret-like noncanonical key is rejected with the credential reason before
ordinary unknown-key rejection. Explicit empty strings, Unicode control
characters, and nonempty `${...}` placeholders are invalid. Only fields
explicitly defined as optional receive code-fixed defaults;
`execution.workspace_access` is not optional.

Credential-like keys and deterministic credential value forms are rejected
before an accepted digest or provenance is produced. Diagnostics expose only
the reason code, never the key, value, path, digest, or source bytes.
PEM detection covers PKCS#8, encrypted, RSA, DSA, EC, OpenSSH, and other
canonical `BEGIN ... PRIVATE KEY` headers rather than a fixed algorithm list.

`mulgae config` also admits the configured native account before returning an
effective or provenance digest. An unavailable account or a configured home
that does not match the effective installed account is readiness exit `4`.
An unsafe native-home descriptor or identity drift is security exit `8`.
A pure native-home observation cancellation is exit `9`; it exposes no
accepted digest and does not weaken an independently observed security failure.

## Init and runtime

`mulgae init` discovers or accepts an explicit provider subset, renders and
round-trips canonical bytes, then creates `.mulgae/config.yaml` exactly once. It
uses an unconditional project-root durability barrier, a same-directory 0600
temporary file, no-replace installation, a `.mulgae` durability barrier, and final
identity, byte, and locality re-attestation. Installed-but-unconfirmed bytes are
retained and reported truthfully; output delivery failure never rolls back a
committed config.

Kimi defaults to `kimi-code/kimi-for-coding` and projects only its two allowed native files.
ZCode binds the configured Node executable identity and the bundled readable
CJS launcher identity; the launcher is descriptor-hashed but does not require
execute permission. ZCode projects only its native CLI config into the distinct
`zcode-{role}` namespace for each configured ZCode route; no additional
configuration field or second native credential source is required. AGY uses the effective OS account home and an explicit
`safe` or `dangerously-skip-permissions` mode; omission is `safe`. Mulgae never
persists credentials or copies provider state back. Runtime review uses only
the absolute executable, launcher, and Kimi data-home paths admitted from this
file; ambient PATH, `XDG_CONFIG_HOME`, and `KIMI_CODE_HOME` cannot override or
invalidate an admitted runtime configuration.
