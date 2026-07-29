# JSON Schema Contracts

Mulgae exposes one version of each JSON contract. Every schema uses JSON Schema
Draft 2020-12 and a canonical
`https://mulgae.local/schemas/<filename>.schema.json` identifier.

## Contracts

| Schema | Valid example |
|---|---|
| `mulgae-clean-plan.v1` | `../examples/clean-plan.v1.valid.json` |
| `mulgae-command-result.v1` | `../examples/command-result.v1.valid.json` |
| `mulgae-doctor-result.v1` | `../examples/doctor-result.v1.valid.json` |
| `mulgae-export-manifest.v1` | `../examples/export-manifest.v1.valid.json` |
| `mulgae-file-catalog.v1` | `../examples/file-catalog.v1.valid.json` |
| `mulgae-platform-contract-evidence.v1` | `../examples/platform-contract-evidence.v1.valid.json` |
| `mulgae-provider-contract-evidence.v1` | `../examples/provider-contract-evidence.v1.valid.json` |
| `mulgae-provider-followup-output.v1` | `../examples/provider-followup-output.v1.valid.json` |
| `mulgae-provider-review-output.v1` | `../examples/provider-review-output.v1.valid.json` |
| `mulgae-provider-review-wire.v1` | `../examples/provider-review-wire.v1.valid.json` |
| `mulgae-repair-patch.v1` | `../examples/repair-patch.json` |
| `mulgae-repair-request.v1` | `../examples/repair-request.json` |
| `mulgae-review-artifact.v1` | `../examples/review-artifact.v1.valid.json` |
| `mulgae-run-manifest.v1` | `../examples/run-manifest.v1.valid.json` |
| `mulgae-validation-receipt.v1` | `../examples/validation-receipt.v1.valid.json` |
| `mulgae-validation-result.v1` | `../examples/validation-result.v1.valid.json` |

Examples are structural fixtures, not evidence that a provider or platform
contract has passed. Semantic validation, filesystem checks, cryptographic
verification, and fail-closed readiness checks still apply after schema
validation.

Breaking changes require a future schema version. This release neither embeds
nor accepts a compatibility schema for a superseded Mulgae contract.
