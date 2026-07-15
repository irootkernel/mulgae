# JSON Schema Contracts

All schemas use JSON Schema Draft 2020-12 and declare a canonical `$id`; new G0 schemas use `https://kar.local/schemas/<filename>.schema.json`, while released v1 schemas retain their immutable identity.

## Contracts

| Schema | Valid example | Producer | Consumer |
|---|---|---|---|
| `kar-provider-review-output.v1` | `../examples/provider-review-output.valid.json` | Review, delta, or rerun provider | KAR validation pipeline |
| `kar-provider-followup-output.v1` | `../examples/provider-followup-output.valid.json` | Followup provider | KAR validation pipeline |
| `kar-validation-result.v1` | `../examples/validation-result.valid.json` | KAR validator | Artifacts, diagnostics, tests |
| `kar-repair-request.v1` | `../examples/repair-request.json` | KAR | Same provider repair invocation |
| `kar-repair-patch.v1` | `../examples/repair-patch.json` | Provider repair invocation | KAR constrained patch applicator |
| `kar-review-artifact.v1` | `../examples/review-artifact.valid.json` | KAR publisher | Existing v1 readers |
| `kar-run-manifest.v1` | `../examples/run-manifest.valid.json` | KAR artifact store | Existing v1 readers |
| `kar-clean-plan.v1` | `../examples/clean-plan.v1.valid.json` | KAR cleanup planner | Clean apply and explain |
| `kar-command-result.v1` | `../examples/command-result.v1.valid.json` | KAR command envelope | CLI, CI, and automation |
| `kar-doctor-result.v1` | `../examples/doctor-result.v1.valid.json` | KAR doctor | CLI, CI, and readiness gates |
| `kar-export-manifest.v1` | `../examples/export-manifest.v1.valid.json` | KAR exporter | Export verifier and consumer |
| `kar-g0-file-catalog.v1` | `../examples/g0-file-catalog.v1.valid.json` | G0 catalog generator | Integrity and promotion validation |
| `kar-platform-contract-evidence.v1` | `../examples/platform-contract-evidence.v1.valid.json` | Platform probe | Doctor and G0 readiness validation |
| `kar-platform-contract-evidence.v2` | `../examples/platform-contract-evidence.v2.valid.json` | Platform probe | G0 readiness ingress authority |
| `kar-prompt-manifest.v1` | `../examples/prompt-manifest.v1.valid.json` | Prompt composer | Replay, audit, and invocation validation |
| `kar-provider-contract-evidence.v1` | `../examples/provider-contract-evidence.v1.valid.json` | Provider probe | Doctor and G0 readiness validation |
| `kar-provider-contract-evidence.v2` | `../examples/provider-contract-evidence.v2.valid.json` | Provider probe | G0 readiness ingress authority |
| `kar-provider-followup-output.v2` | `../examples/provider-followup-output.v2.valid.json` | KAR-normalized followup provider result | KAR validation pipeline |
| `kar-provider-review-output.v2` | `../examples/provider-review-output.v2.valid.json` | KAR-normalized review/delta/rerun provider result | KAR validation pipeline |
| `kar-review-artifact.v2` | `../examples/review-artifact.v2.valid.json` | KAR publisher | CLI, CI, reporting, and external consumers |
| `kar-run-manifest.v2` | `../examples/run-manifest.v2.valid.json` | KAR artifact store | CLI, recovery, integrity, and publication validation |
| `kar-validation-receipt.v1` | `../examples/validation-receipt.v1.valid.json` | KAR validator | G0 receipts, diagnostics, and tests |
| `kar-validation-result.v2` | `../examples/validation-result.v2.valid.json` | KAR validator | Artifacts, diagnostics, and tests |

The sixteen G0 contract pairs above are additive. The seven existing v1 schema/example pairs remain immutable; `kar-platform-contract-evidence.v1` and `kar-provider-contract-evidence.v1` are compatibility-only and are not readiness-ingress authorities. The explicit `kar-platform-contract-evidence.v2` and `kar-provider-contract-evidence.v2` `$id` values are the only provider/platform readiness-ingress authorities.

The initial v2 examples are schema-valid UNVERIFIED fixtures, not PASS evidence: the required `darwin-arm64` platform row is all `NOT_RUN`, and the examples themselves grant no support, readiness, or implementation authority. G001 completion is established by executed receipts and the authority chain, never by these example bytes.

## JSON Schema Is Not the Whole Validator

JSON Schema is the structural gate. It validates the declared Draft 2020-12 dialect and canonical `$id`, object/array shape, primitive types, enums, required members, local cardinality constraints, and closed objects. A schema-valid document is not automatically trusted, complete, publishable, or eligible for CI proof.

The semantic validator runs after schema validation and must reject, at minimum:

- duplicate YAML keys, unknown configuration fields, empty or placeholder values, and invalid UUID version 7 identities;
- non-NFC, absolute, traversing, escaping, symlinked, or non-regular artifact paths;
- invalid byte counts, UTF-8/line ranges, domain-separated hashes, content-addressed references, and source/current evidence quotes;
- cross-document identity, parent/child, role, attempt, provider, target, finding, and manifest-reference mismatches;
- inconsistent coverage, content, CI, failure, repair, fallback, resolution, summary, and limitation projections;
- role assignments that violate the logic/security required floor, distinct-lane constraints, intended-provider readiness, or invocation, output, lane-deadline, and run-deadline caps;
- project configuration proposals that weaken the trusted base: required roles, request-changes threshold, degraded or incomplete enforcement, workspace boundary, shell policy, provider command policy, or resource caps;
- provider/platform probe evidence that is incomplete, stale, unverified, secret-bearing, or inconsistent with the configured profile;
- publication without one matching immutable manifest, lineage edge, and composite epoch record, or any staged/final/hash/path multiplicity or mismatch;
- cleanup plans whose store epoch, protected closure, ordered actions, byte accounting, or apply-plan hash no longer match; and
- command, doctor, export, prompt, repair, and validation receipts whose operation, typed exit, capability, wire identity, or referenced bytes are not valid for the requested action.

Schema validation therefore precedes semantic validation; it never replaces filesystem checks, cryptographic verification, secure scan-before-write handling, deterministic reducers, or evidence collection.

## Versioning

A released schema version is immutable. Breaking changes create a new version. Readers may support multiple versions, but writers emit one explicit configured version and consumers select it by canonical `$id`.

## Examples

The `../examples/` directory contains one valid example for every indexed schema. CI validates each example against its declared schema and then runs its semantic fixtures; an example is not evidence that a provider or platform contract has passed.