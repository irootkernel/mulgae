# Configuration

## 1. Configuration Layers

KAR resolves configuration through a fail-closed trust reducer:

```text
B (built-in trusted baseline) → G (global user configuration) → P (trusted-base project proposal) → CLI
```

`P` is read from the configured trusted base snapshot, never the unreviewed target head. The whole project proposal is validated before any of its fields merge; a mixed strengthen-and-weaken proposal is rejected atomically with exit `2`. CLI is run-local and cannot change persisted policy.

Default files:

```text
Global:  $XDG_CONFIG_HOME/kar/config.yaml
Fallback: ~/.config/kar/config.yaml
Project: .kar.yaml
```

The resolved, redacted configuration is stored in every run.

## 2. Ownership by Layer

| Concern | Built-in trusted baseline | Global user config | Trusted-base project proposal | CLI |
|---|---:|---:|---:|---:|
| Domain schemas and six role definitions | Yes | No | No | No |
| Provider executable, argv, account/profile | Adapter defaults | Yes | No | Dangerous explicit provider command only |
| Provider credentials | No | No secrets stored | No | Environment or provider CLI |
| Project context path | No | No | Declarative in-project selection only | One-run selection |
| CI policy | Safe default | Strengthen only | Strengthen only | Dangerous weakening only |
| Provider instance declarations | Optional | Yes | Reference only | Temporary explicit instance only |
| Required-role floor | `logic`, `security` | Add only | Add only | Never weaken |
| Role assignment inputs | Built-in hard constraints | Eligible provider tuples only | Add required roles only | Run-local selection only |
| Request-change threshold | `high` | Strengthen only | Strengthen only | Dangerous weakening only |
| Output/time/concurrency limits | Trusted ceilings | Reduce only | Reduce only | Dangerous increase only |
| Workspace access | `none` | Trusted explicit expansion | Intersect/reduce only | Dangerous explicit expansion only |
| Shell execution | Disabled | Explicit opt-in only | Never | Dangerous one-run opt-in only |

## 3. Provider Instance and Role Inputs

A provider instance declares a local executable, account/profile, approved limits, and a concurrency key. For G0 contract evidence, the only provider families are `kimi`, `zcode`, and `agy`. `codex` and `claude` are absent from the G0 provider inventory, assignment fixtures, and defaults.

```yaml
providers:
  kimi-work:
    driver: kimi
    bin: kimi
    concurrency_key: kimi-work

  zcode-work:
    driver: zcode
    bin: zcode
    concurrency_key: zcode-work
```

`kar init` preserves each configured intended provider ID with `status: unverified` when no supporting probe evidence exists. It must not silently remove, disable, or replace it; `kar doctor` determines readiness.

The lane serialization key is `concurrency_key`, not the driver name. Input is Unicode NFC, then ASCII-lowercased; non-ASCII is rejected and the normalized result must match `[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?`. Equal normalized keys share exactly one lane.

Roles are fixed as `logic`, `security`, `maintainability`, `product`, `documentation`, and `testing`. `logic` and `security` are the non-removable required floor. The effective required set is:

```text
required_floor = {logic, security}
effective_required = required_floor ∪ global_required ∪ valid_project_additions
```

Only provider tuples with complete base and role-fit PASS evidence enter the deterministic assignment reducer. Configuration does not authorize an ad hoc mapping or substitute an unverified provider; the built-in exhaustive lexical reducer freezes exactly six rows after evidence.

## 4. Project Configuration Trust

Project configuration is repository-controlled and must be treated as limited-trust input.

Default restrictions:

- project configuration cannot define `bin`, `args`, `command`, `shell`, arbitrary environment variables, or provider-family substitutions;
- it cannot disable logic, security, output-schema validation, evidence verification, CI enforcement, or the required floor;
- it cannot move `request_changes_on` right toward a weaker threshold, relax incomplete/degraded enforcement, increase a limit, or expand workspace access;
- it may add required roles, lower the request-changes threshold, union failure restrictions, OR enforcement booleans, reduce limits, and intersect workspace access;
- it cannot load prompt files through symlinks that escape the trusted root or add absolute paths outside the project root;
- unknown keys and duplicate YAML keys are rejected.

Project prompt overrides are disabled by default. When globally enabled, every asset is read from the trusted base snapshot. A proposal that contains both an allowed strengthening and any prohibited weakening is rejected as a whole; no per-field partial merge is allowed.

Recommended policy:

```yaml
trust:
  project_config: declarative_only
  project_prompt_overrides: false
  project_prompt_source: target_base
  allow_project_provider_commands: false
  allow_project_shell: false
```

## 5. Merge and trust rules

Maps merge by key, scalars replace only when the replacement passes the trust reducer, and lists replace unless a field explicitly declares set-union behavior. Unsafe conflicts fail closed.

The project layer is strengthening-only. Its allowed operations are exactly: union required roles and failure restrictions; OR enforcement booleans; choose a severity threshold no weaker than the global effective threshold; choose numeric limits no greater than the global effective limits; and intersect workspace access. No project setting may alter provider command execution, shell policy, trusted templates, or the floor.

Dangerous CLI flags never weaken the trusted policy. They create a tainted, non-proof execution selection only:

| Flag family | Required record |
|---|---|
| `--dangerously-skip-required-role=<role>` | selected role omitted; `coverage_status=incomplete`, `tainted=true`, `ci_proof_eligible=false` |
| `--dangerously-raise-request-changes-threshold=<critical\|blocker>` | requested/effective threshold, source, acceptance, taint, and non-proof reason |
| `--dangerously-allow-degraded`, `--dangerously-allow-incomplete` | requested/effective policy, taint, and non-proof reason |
| `--dangerously-increase-limit=<field>:<value>` | requested/effective limits, source, acceptance, taint, and non-proof reason |
| `--dangerously-expand-workspace=<mode>`, `--dangerously-use-provider=<id>`, `--dangerously-provider-command=<JSON-array>`, `--dangerously-enable-shell` | requested/effective value, source, acceptance, taint, and non-proof reason |

CI rejects every weakening flag before the run with exit `2`. Global configuration can reduce its own policy only through the explicitly configured trusted posture; it cannot circumvent the built-in required floor.

## 6. Strict Parsing

Configuration loaders must:

1. reject duplicate mapping keys;
2. reject unknown fields by default;
3. validate enums and numeric ranges;
4. normalize and validate paths;
5. reject path traversal and symlink escape;
6. reject embedded secrets in known sensitive fields;
7. emit source location and layer in diagnostics;
8. write only redacted resolved configuration to artifacts.

## 7. Environment Resolution

Resolution order for provider binaries:

1. one-run CLI override;
2. global provider instance `bin`;
3. adapter default command name;
4. `exec.LookPath` using the resolved PATH.

Runtime values:

```text
HOME = CLI override -> global runtime.home -> os.UserHomeDir()
PATH = global inherit/prepend/append policy
PWD  = isolated attempt workspace by default
```

The real project root is not the default child process working directory.

Only allowlisted environment keys are passed. Secret values are never written to `command.json` or `env.json`.

## 8. Shell Policy

Direct argv is mandatory by default.

```yaml
providers:
  kimi-safe:
    driver: kimi
    bin: /usr/local/bin/kimi
    args: ["--print-json"]
```

Shell execution requires a global or explicit one-run opt-in and must produce a high-visibility warning. Project config can never enable it.

```yaml
providers:
  agy-shell:
    driver: agy
    shell:
      enabled: true
      command: "source ~/.company/env && agy --json"
```

Shell mode is excluded from the default supported posture because quoting, startup files, environment expansion, and command injection reduce reproducibility and safety.

## 9. Recommended Configuration

See:

- [Global configuration example](../examples/global-config.yaml)
- [Project configuration example](../examples/project-config.yaml)

The examples use only declarative project settings and keep executable provider details in the global file.

## 10. Configuration Artifact

Every run stores:

```text
resolved-config.yaml
config-sources.json
```

`config-sources.json` records each effective value's source layer without exposing secret values. This makes a review reproducible and explains why a provider, role, timeout, or policy was selected.
