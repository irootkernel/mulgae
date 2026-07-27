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
Production root `kar review` is currently reopened under `REOPENED_PRODUCTION_REVIEW_INCOMPLETE`; composition is present, but this normative security policy does not claim production verification or closure. Full current authority gates and three family-distinct normal P2 receipts remain pending.

## 2. Trust Hierarchy

| Source | Trust level | Allowed authority |
|---|---|---|
| Built-in domain rules and schemas | Highest | Define invariants and validation |
| `.kar/config.yaml` | Sole operator-local configuration authority after locality admission | Define the configured provider subset and bounded policy |
| CLI flags | Trusted one-run policy | Select and narrow behavior, explicit dangerous opt-ins |
| Project configuration | Limited trust | Declarative project and assignment settings only |
| Project context and prompt assets | Untrusted by default | Context only; local config cannot grant prompt authority |
| Review target | Untrusted | Data only |
| Prior provider output | Untrusted | Claims and context only |
| Current provider output | Untrusted | Claims pending validation |

A lower-trust source cannot weaken a higher-trust restriction.

### Deterministic Authority Admission

`required_floor={logic}` remains code-fixed. `.kar/config.yaml` is admitted as one complete, project-local operator document; there is no global/project reducer, repository-owned proposal, or partial merge. Semantic validation rejects any document that violates code-fixed role, workspace, provider-family, execution, or resource bounds. The document may require additional enabled roles but may not remove logic from either the enabled or required set. Run-local CLI selection may narrow an operation but cannot redefine those invariants. A valid finding rejected by the admitted CI policy is exit `1`, not a configuration error.

## 3. Provider Execution Boundary

Default:

```text
workspace_access = none
cwd = isolated attempt workspace
```

The provider receives captured target bytes, not the live project directory. Kimi and ZCode receive isolated `HOME` directories with credential projection. On macOS, AGY alone receives an explicitly captured installed-user native `HOME`, inode-revalidated immediately before spawn, because its authentication is bound to that Keychain context. This authentication context is not workspace access: AGY's descriptor-bound CWD remains the immutable review snapshot, while KAR owns its XDG, cache, temporary, and scratch namespaces. KAR must not use a synthetic AGY `HOME` or copy OAuth or installation files into one. KAR's own setup, policy, and cleanup paths never write, overwrite, zero, or unlink the user's AGY authentication or settings files; normal provider-owned Keychain/profile refresh during AGY execution is not claimed as KAR-owned state. Native `@file` transport refers only to immutable captured material.

Optional `readonly_snapshot` should use OS-supported read-only mounts, permissions, or sandbox primitives where available. A copied directory with writable permissions is not read-only isolation.

`project` is a rejected legacy/unsafe workspace value, not an opt-in. The closed
workspace set is `none|readonly_snapshot`, and neither value authorizes live-root
or user-`HOME` access. AGY's captured native authentication context remains the
narrow exception described above and is not workspace access.
AGY policy is not installed through a user `settings.json`. The enforceable macOS AGY controls are `--sandbox`, the exact immutable-snapshot `--add-dir`, `--mode plan`, bounded time and output, and post-output process-group `SIGTERM` followed by `SIGKILL` when required. These controls do not make the native authentication context a sandbox, authorize user-home mutation, or establish production verification or closure.

## 4. Mutation Detection

KAR may capture repository state before and after execution to detect source
mutation. This is an anomaly detector, not an isolation mechanism or a dormant
`project` mode.

It cannot prevent:

- reading secrets;
- network exfiltration;
- writes outside the repository;
- changes to ignored files unless explicitly monitored;
- confusion with simultaneous user edits.

Security documentation and help must not describe mutation detection as a sandbox.

## 5. Executable Configuration

Default rules:

- provider executables exist only in the admitted local family-specific configuration;
- local config cannot define generic arguments, environment, a command, or a shell;
- shell mode is disabled;
- provider binary paths are resolved without project-controlled PATH entries by default;
- adapter version compatibility is checked before execution;
- resolved executable path and optional file hash are recorded.

A file hash, executable path, and adapter profile are diagnostic provenance, not a trust guarantee or a pin to a historical executable. Provider admission still requires an allowlisted family, the applicable minimum version, and current capability and security PASS; a newer version is allowed after that PASS. Package signing or OS trust policy may be added separately.

## 6. Prompt Injection Boundary

Trusted prompt layers state that all project and target content is data. Delimiters, content hashes, and role-specific instructions improve clarity, but prompt framing alone is not a formal security boundary.

Defense in depth includes:

- no provider tool access by default;
- no live project filesystem access;
- strict JSON-only output;
- deterministic validation;
- evidence verification;
- restricted project prompt overrides;
- explicit objective linting.

## 7. Secrets and Environment

KAR must not store API keys in local YAML or examples. Provider CLIs own authentication.

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

`security_policy_violation`, source mutation, `configuration_violation`, `artifact_failure`, `user_cancelled`, `kar_internal_error`, and a valid finding all have `fallback=forbidden`. Secret exposure, detected source mutation, and sandbox-escape indicators cancel the run by default; secret and mutation also forbid repair and publication and return exit `8`.

`timeout`, `auth`, `quota`, and `rate_limit` are operational failures with `repair=none` and `fallback=allowed`. If an eligible configured fallback exists, it may be scheduled; otherwise the role is exhausted. Invalid JSON, AI-owned missing values, and invalid or unverifiable evidence claims may use exactly one bounded repair before eligible fallback. These rules do not make fallback success or publication automatic.

Artifact corruption, schema/hash mismatch, stale clean-plan apply, and publication ambiguity are artifact failures (exit `7`). Cancellation is exit `9`; an internal invariant failure is exit `10`. Exhaustion of any selected lane preserves valid content, fails the run, and produces `coverage_status=incomplete` at exit `4` unless a higher-priority failure applies. Degraded coverage is limited to valid policy-permitted results.

Terminal cleanup never discards an initiating failure. Provider namespace drain and workspace release or abort retain their bounded terminal evidence and retry rules. The production composition then attempts deletion of both KAR-owned private namespace and workspace roots even when one deletion fails. A deletion failure is joined with any initiating error, classified as `artifact_failure`, and projects exit `7`; it cannot be reported as a successful root or child workflow.

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

## 12. CI Project-Local Authority Posture

CI checks out the target first, then provisions `.kar/config.yaml` as private untracked operator state through `kar init` or an equivalent secure installation step. The file records absolute provider identities for that CI machine, explicitly records the required `workspace_access: none`, and remains outside repository control. KAR re-attests the root, `.kar`, configuration, checkout, index, and applicable commits across admission and execution boundaries. Repository content cannot supply a fallback configuration, select a provider command, disable the required role floor, or expand workspace access. KAR and provider adapter versions remain pinned by the CI environment.

The resulting `ci_decision` is exactly `pass` or `fail` with admitted-policy reason codes. It is a projection of validated content and coverage, not a mutation of `content_verdict`, `coverage_status`, or `publication_status`.

## 13. Security Limitations

v0.1 should state these limitations explicitly:

- KAR cannot guarantee the behavior of an arbitrary provider executable.
- Network isolation depends on the operating system, container, or external sandbox.
- Prompt injection mitigations reduce risk but do not mathematically guarantee model behavior.
- Secret detection is incomplete and may produce false positives or false negatives.
- Read-only snapshot guarantees depend on the selected platform implementation.

## 13. Runtime Diagnostic Security Boundary

Runtime diagnostics may contain provider or user bytes only in separately bounded raw artifacts. Every such byte crosses the existing scan-before-write boundary before installation. A secret match or scan overflow terminates the producer, zeros and drops buffered content, removes the temporary file, and persists only bounded channel, detector, count, and source-ID metadata; no rejected content, substring, or hash is retained.

Structured runtime events accept only closed codes, validated identifiers, numeric facts, UTC/elapsed ordering data, and installed safe relative references. Free-form provider errors, credentials, paths, prompts, source bytes, raw streams, and Go locations are forbidden. Security rejection preserves exit `8` semantics and prohibits repair, fallback, and publication. Diagnostic persistence failure fails closed before spawn or becomes a typed artifact failure after execution begins; it cannot be hidden by a provider failure.
