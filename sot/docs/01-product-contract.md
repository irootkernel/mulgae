# Product Contract

## 1. Purpose

KAR makes evidence-backed AI review portable across repositories and organizations. A user installs one binary, configures local provider instances, selects functional review roles, and receives both a human-readable report and a stable machine-readable artifact.

The product is designed for local development, CI, pre-merge checks, remediation verification, and review provenance. It is not a substitute for code ownership, legal approval, security authorization, or release governance.

## 1.1 SOT 1.13.0 Contract and Implementation Status

This document preserves the historical G0–G010 record and defines the current G011 release contract. Decision readiness is `READY`; implementation is `RELEASE_READY` after the exact final committed tree passed the sole `make test` gate. Ordinary provider support is limited to the allowlisted `kimi`, `zcode`, and `agy` families and requires current runtime capability and security admission. AGY's minimum version is 1.1.4. Executable path, SHA-256, and adapter profile are diagnostic provenance only; they do not pin authorization to one historical executable.

The current decisions keep `darwin-arm64` as the sole supported native platform, preserve six core roles plus the UI-only artist role, keep outcomes independent, and require deterministic retention, fail-closed trust and assignment, and byte- and identity-bound prompt/evidence provenance.

The G0 approval contract remains a one-way, session-bound sequence. G001 completed it before product implementation. G008 through G010 receipts and live workflow timings are historical evidence rather than current release predicates. Historical qualification evidence does not constrain ordinary family support to a recorded version or SHA-256, broaden support beyond the allowlisted families, or make a future platform release-eligible. G011 closure requires deterministic product acceptance plus one non-skipping live capability certification for each supported provider family through `make test`. No release asset is authorized by technical readiness alone.
## 2. Primary User Outcomes

A successful KAR run gives the user:

- an immutable record of the reviewed target;
- exact prompt provenance for every provider attempt;
- structured and validated findings;
- verified evidence references into the reviewed target;
- clear role and provider coverage;
- explicit degradation and failure information;
- a durable final artifact at `.kar/{session_id}/{run_id}/review_{uuidv7}.json`;
- built-in help sufficient to operate the product without external skills or private context.
- four independent outcome axes: content, coverage, publication, and CI; and
- an explicit G0 readiness posture that never treats missing provider or platform evidence as support.

## 3. Product Boundary

### KAR owns

- CLI UX and embedded help;
- layered configuration and trust policy;
- provider discovery and readiness checks;
- immutable target capture;
- prompt packet compilation;
- provider lane coordination;
- process execution, timeout, cancellation, and output limits;
- raw output and provenance capture;
- structured output parsing and validation;
- bounded, constrained repair of missing AI-owned values;
- evidence verification;
- finding normalization and aggregation;
- human and JSON report rendering;
- session, run, role task, attempt, validation, and review artifacts;
- CI exit policy.

### KAR does not own

- provider credentials or account provisioning;
- organizational approval or waiver authority;
- merge, deploy, release, or runtime activation authority;
- arbitrary code modification by AI providers;
- execution of project tests unless a future, separately specified feature is introduced;
- live provider network privacy guarantees beyond the configured provider and local sandbox capabilities;
- external workflow systems.

## 4. Functional Role Model

Roles are review lenses. They are not people, teams, colors, or authorities.

| Role | Responsibility | Representative questions |
|---|---|---|
| `logic` | Correctness and internal consistency | Are state transitions valid? Are edge cases and failure paths handled? |
| `security` | Security and safety | Can untrusted input cross an authorization, path, process, secret, or network boundary unsafely? |
| `maintainability` | Long-term design quality | Are responsibilities, APIs, configuration, and extension points coherent? |
| `product` | User and operator value | Are defaults, workflows, errors, recovery paths, and onboarding understandable? |
| `documentation` | Help and traceability | Do help, README, examples, schemas, and implementation behavior agree? |
| `testing` | Verification quality | Are important behaviors, failures, concurrency, and regressions covered? |

Required help statement:

```text
KAR roles are functional review lenses.
They are not people, teams, or organizational authorities.
KAR reports findings and recommendations only.
```

## 5. v0.1 Scope

The v0.1 product includes:

1. `kar init`, `doctor`, `review`, `followup`, `delta`, `rerun`, `status`, `report`, `findings`, `excerpt`, `providers`, `config`, `prompt`, `schema`, `clean`, `export`, and `help`, with the command contracts in [CLI Workflows](03-cli-workflows.md).
2. Exactly these built-in functional roles: `logic`, `security`, `maintainability`, `product`, `documentation`, and `testing`.
3. G0 contract probes for provider families `kimi`, `zcode`, and `agy` only; an intended but unprobed provider is `unverified`, not silently disabled or substituted.
4. One active attempt per normalized concurrency key, with parallelism across independent keys.
5. JSON-only provider output.
6. Schema, semantic, and evidence validation.
7. One bounded repair attempt by default.
8. Immutable session and run lineage.
9. Atomic artifact publication under `.kar/`.
10. Human-readable reports and CI policy.

## 6. Explicit Non-Goals for v0.1

- Autonomous source editing.
- Automatic acceptance or merge approval.
- G0 product implementation, provider/platform PASS assertions, authority promotion, or `g0_complete`.
- Automatic result shopping across providers after a valid negative review.
- Full multi-provider consensus.
- Arbitrary executable project configuration.
- Arbitrary shell provider commands by default.
- Silent truncation of review targets or provider output.
- Silent repair of semantic contradictions.
- Mutation guard presented as a security sandbox.

## 7. Product Invariants

The following statements are normative:

```text
A valid negative review is a review result, not a provider failure.
```

```text
A final review artifact is published only after all required validation stages pass.
```

```text
System-owned metadata is generated by KAR and is never requested from an AI provider.
```

```text
Every completed run is immutable. Followup, delta, and rerun create new runs.
```

```text
Provider output is an untrusted claim until KAR validates structure and evidence.
```

```text
Ordinary provider support is limited to the allowlisted `kimi`, `zcode`, and `agy` families and requires the applicable minimum version plus current successful runtime capability and security admission. A newer version is allowed after that PASS. Executable path, SHA-256, and adapter profile are diagnostic provenance, not support authorization; KAR does not substitute provider families automatically.
```
A review result serializes four independent axes. A high finding alongside a failed required role, for example, remains `content_verdict=request_changes` and `coverage_status=incomplete`; neither axis overwrites the other.

| Axis | Values | Meaning |
|---|---|---|
| `content_verdict` | `no_findings`, `findings_present`, `request_changes` | Normalized review content only |
| `coverage_status` | `complete`, `degraded`, `incomplete` | Required/selected role coverage only |
| `publication_status` | `not_published`, `staged`, `installed`, `committed`, `corrupt` | Durable publication state only |
| `ci_decision` | `pass`, `fail` | Policy projection with recorded reasons only |

A valid `request_changes` result is not a provider failure. Valid content is retained when coverage is degraded or incomplete; the independently computed CI outcome and typed exit communicate enforcement.

## 8. Quality Attributes

| Attribute | Required property |
|---|---|
| Auditability | Every attempt, prompt layer, output, repair, and validation decision is retained |
| Determinism | Given the same captured inputs, normalization and policy evaluation are deterministic |
| Safety | Executable configuration is restricted and workspace access is minimized |
| Portability | The configuration contract is portable, while each machine's operator-local file records its admitted absolute provider paths and native home identity |
| Diagnosability | Failures identify stage, provider, role, attempt, and recovery path |
| Extensibility | Drivers, roles, schemas, and report formats are adapters around a stable domain model |
| CI suitability | Machine-readable results and exit behavior are explicit and versioned |
