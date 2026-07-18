# Security and Trust Model

## 1. Threat Model

KAR processes repository-controlled files, arbitrary diffs, user objectives, prior AI output, and local provider executables. Any of these may be malformed, adversarial, compromised, or unexpectedly sensitive.

Primary threats:

- prompt injection inside reviewed content;
- project config introducing arbitrary commands;
- provider process reading or mutating local files;
- secret transmission or secret output;
- path traversal and symlink escape;
- untrusted evidence references;
- shell injection;
- malicious or compromised provider binary;
- concurrent provider state corruption;
- artifact tampering;
- CI using an incomplete review as if it were complete.

## 2. Trust Hierarchy

| Source | Trust level | Allowed authority |
|---|---|---|
| Built-in domain rules and schemas | Highest | Define invariants and validation |
| Global user configuration | Trusted local policy | Define provider executables and bounded overrides |
| CLI flags | Trusted one-run policy | Select and narrow behavior, explicit dangerous opt-ins |
| Project configuration | Limited trust | Declarative project and assignment settings only |
| Project context and prompt assets | Untrusted by default | Context only unless globally authorized |
| Review target | Untrusted | Data only |
| Prior provider output | Untrusted | Claims and context only |
| Current provider output | Untrusted | Claims pending validation |

A lower-trust source cannot weaken a higher-trust restriction.
### Deterministic Trust Reducer

`required_floor={logic,security}`. `additional_required` is `global_required ∪ valid_project_additions`, and `effective_required=required_floor ∪ additional_required`. `execution_selection` is run-local and cannot redefine policy. Merge is exactly built-in policy (B) → global user policy (G) → project proposal (P, checked against the trusted base as one atomic proposal) → CLI.

A project may only strengthen: move the request-changes threshold left in `low < medium < high < critical < blocker`, union required roles and failure sets, OR enforcement flags, lower limits, and intersect workspace access. It cannot disable logic or security, relax degraded/incomplete enforcement, raise the threshold, expand workspace, enable shell, or define provider commands. A mixed strengthening/weakening proposal is rejected as a whole with exit `2`; no subset is applied.

Interactive dangerous flags record requested value, effective value, source, acceptance, `tainted=true`, `ci_proof_eligible=false`, and a reason. `--dangerously-skip-required-role=<role>` preserves the policy requirement but omits execution selection, yielding `coverage_status=incomplete`. `--dangerously-raise-request-changes-threshold=<critical|blocker>` records the request but leaves the trusted effective CI threshold unchanged. The same recording applies to `--dangerously-allow-degraded`, `--dangerously-allow-incomplete`, `--dangerously-increase-limit=<field>:<value>`, `--dangerously-expand-workspace=<mode>`, `--dangerously-use-provider=<id>`, `--dangerously-provider-command=<JSON-array>`, and `--dangerously-enable-shell`.

CI rejects every weakening flag before execution with exit `2`. In CI, `effective_required` must be a subset of `execution_selection`; a valid finding rejected by trusted policy is exit `1`, not a configuration error.

## 3. Provider Execution Boundary

Default:

```text
workspace_access = none
cwd = isolated attempt workspace
```

The provider receives captured target bytes, not the live project directory. This limits accidental mutation and broad local file discovery, but it does not make an arbitrary executable safe.

Optional `readonly_snapshot` should use OS-supported read-only mounts, permissions, or sandbox primitives where available. A copied directory with writable permissions is not read-only isolation.

`project` access is a dangerous opt-in and must be visible in command output and artifacts.

## 4. Mutation Detection

KAR may capture repository state before and after execution, especially for `project` mode. This is an anomaly detector, not an isolation mechanism.

It cannot prevent:

- reading secrets;
- network exfiltration;
- writes outside the repository;
- changes to ignored files unless explicitly monitored;
- confusion with simultaneous user edits.

Security documentation and help must not describe mutation detection as a sandbox.

## 5. Executable Configuration

Default rules:

- provider binary and arguments exist only in global config, built-in adapter profiles, or explicit CLI overrides;
- project config cannot define a command or shell;
- shell mode is disabled;
- provider binary paths are resolved without project-controlled PATH entries by default;
- adapter version compatibility is checked before execution;
- resolved executable path and optional file hash are recorded.

A file hash is provenance, not a trust guarantee. Package signing or OS trust policy may be added separately.

## 6. Prompt Injection Boundary

Trusted prompt layers state that all project and target content is data. Delimiters, content hashes, and role-specific instructions improve clarity, but prompt framing alone is not a formal security boundary.

Defense in depth includes:

- no provider tool access by default;
- no live project filesystem access by default;
- strict JSON-only output;
- deterministic validation;
- evidence verification;
- restricted project prompt overrides;
- explicit objective linting.

## 7. Secrets and Environment

KAR must not store API keys in project or global YAML examples. Provider CLIs own authentication.

Environment rules:

- explicit allowlist;
- known secret values omitted from artifacts;
- keys may be recorded with `present: true` and a redacted marker;
- no full environment dump;
- no secret value in command-line arguments when a safer transport exists;
- preflight detection may block obvious secrets in review targets according to policy.

A provider may transmit the prompt and target to a remote service. `kar doctor security` and help must state this clearly. Users must select providers appropriate for their data policy.

## 8. Shared Scan-Before-Write

`kar-secure-writer/v1` is mandatory before every newly persisted untrusted copy:

```text
provider stdout and stderr
external logs
project context
captured target copies
prior provider output, finding, and report
prompt stdin and blobs
repair requests and results
export members
provider/platform raw and derived evidence
diagnostics containing provider or user bytes
```

The writer creates `0700` parent directories and `0600` files, opens only beneath an approved root with `openat`, no-follow, and an exclusive temporary name, streams through the configured cap and credential/token scanner before durable write, and rejects path or symlink escape. Existing immutable source bytes are referenced rather than copied; copying them invokes this writer.
For G008 export, this is the implemented secure export boundary: export members pass through the writer into a new package, redaction is mandatory, and the package remains separate from immutable source bytes. A successful export neither publishes a review nor authorizes release, approval, or any authority mutation.

On a secret match or scan overflow, KAR terminates the producer, zeros and drops the buffer, unlinks the temporary file before rename, and writes only drop metadata: channel, detector, count, and source IDs. It persists no content, substring, or hash of the blocked bytes. Repair, fallback, and publication are forbidden; the result is a security failure (exit `8`).

Only a clean stream may write the temporary file, fsync it, rename it, and fsync its directory. Raw immutable evidence, normalized internal artifacts, and redacted human/export views are distinct only after this boundary; `redact_surface` never authorizes preserving detected credentials in an untrusted durable raw copy.
The export destination is a safe relative `--output-path`; `--output` selects only human or JSON command-result rendering and cannot select an unredacted export mode.

## 9. Path Safety

All artifact and project-relative paths must:

- be normalized;
- remain beneath the expected root;
- reject absolute paths when a relative path is required;
- reject `..` traversal;
- reject symlink escape;
- avoid following untrusted symlinks during cleanup or export;
- use no user-controlled path component without strict validation.

Evidence paths are logical target paths, not direct host filesystem paths.

## 10. Failure Containment

`security_policy_violation`, source mutation, `configuration_violation`, `artifact_failure`, `user_cancelled`, `kar_internal_error`, and a valid finding all have `fallback=forbidden`. Secret exposure, mutation in live-project mode, and sandbox-escape indicators cancel the run by default; secret and mutation also forbid repair and publication and return exit `8`.

`timeout`, `auth`, `quota`, and `rate_limit` are operational failures with `repair=none` and `fallback=allowed`. If an eligible configured fallback exists, it may be scheduled; otherwise the role is exhausted. Invalid JSON, AI-owned missing values, and invalid or unverifiable evidence claims may use exactly one bounded repair before eligible fallback. These rules do not make fallback success or publication automatic.

Artifact corruption, schema/hash mismatch, stale clean-plan apply, and publication ambiguity are artifact failures (exit `7`). Cancellation is exit `9`; an internal invariant failure is exit `10`. Required exhaustion preserves valid content and produces `coverage_status=incomplete`; optional exhaustion may produce `coverage_status=degraded`, with trusted CI policy deciding pass or fail for the latter.

## 11. Artifact Integrity

Protection mechanisms:

- restrictive permissions;
- atomic publication;
- SHA-256 in the run manifest;
- immutable completed runs;
- schema versioning;
- final artifact validation after serialization;
- optional future signing outside v0.1.

KAR must report a hash mismatch as artifact corruption. It must not silently regenerate a missing or altered final review from normalized summaries.

## 12. CI Trusted-Base Posture

Recommended CI defaults are:

```yaml
execution:
  workspace_access: none
  shell: false

trust:
  project_config: declarative_only
  project_prompt_overrides: false

ci:
  degraded_review_fails: true
  incomplete_review_fails: true
```

CI resolves the trusted base before project configuration and applies the deterministic reducer above. A repository pull request cannot change the provider command used to review itself, disable the required floor, loosen severity or coverage enforcement, expand workspace, enable shell, or accept a weakening CLI flag. KAR and provider adapter versions are pinned. A project may add requirements or otherwise strengthen policy, but cannot turn an untrusted proposal into a CI proof.

The resulting `ci_decision` is exactly `pass` or `fail` with trusted-policy reason codes. It is a projection of validated content and coverage, not a mutation of `content_verdict`, `coverage_status`, or `publication_status`.

## 13. Security Limitations

v0.1 should state these limitations explicitly:

- KAR cannot guarantee the behavior of an arbitrary provider executable.
- Network isolation depends on the operating system, container, or external sandbox.
- Prompt injection mitigations reduce risk but do not mathematically guarantee model behavior.
- Secret detection is incomplete and may produce false positives or false negatives.
- Read-only snapshot guarantees depend on the selected platform implementation.
