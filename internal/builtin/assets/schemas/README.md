# JSON Schema Contracts

Mulgae selects the documented contract version for each source kind and retains
predecessors for backward reads. Every schema uses JSON Schema
Draft 2020-12 and a canonical
`https://mulgae.local/schemas/<filename>.schema.json` identifier.

## Contracts

| Schema | Valid example |
|---|---|
| `mulgae-command-result.v12` | `../examples/command-result.v12.valid.json` |
| `mulgae-command-result.v11` | `../examples/command-result.v11.valid.json` |
| `mulgae-command-result.v9` | `../examples/command-result.v9.valid.json` |
| `mulgae-command-result.v10` | `../examples/command-result.v10.valid.json` |
| `mulgae-command-result.v8` | `../examples/command-result.v8.valid.json` |
| `mulgae-command-result.v7` | `../examples/command-result.v7.valid.json` |
| `mulgae-run-recovery.v1` | `../examples/run-recovery.v1.valid.json` |
| `mulgae-review-artifact.v2` | `../examples/review-artifact.v2.valid.json` |
| `mulgae-run-manifest.v2` | `../examples/run-manifest.v2.valid.json` |
| `mulgae-composite-review-artifact.v2` | `../examples/composite-review-artifact.v2.valid.json` |
| `mulgae-composite-run-manifest.v2` | `../examples/composite-run-manifest.v2.valid.json` |
| `mulgae-clean-plan.v1` | `../examples/clean-plan.v1.valid.json` |
| `mulgae-composite-review-artifact.v1` | `../examples/composite-review-artifact.v1.valid.json` |
| `mulgae-composite-run-manifest.v1` | `../examples/composite-run-manifest.v1.valid.json` |
| `mulgae-command-result.v5` | `../examples/command-result.v5.valid.json` |
| `mulgae-command-result.v6` | `../examples/command-result.v6.valid.json` |
| `mulgae-doctor-result.v3` | `../examples/doctor-result.v3.valid.json` |
| `mulgae-doctor-result.v4` | `../examples/doctor-result.v4.valid.json` |
| `mulgae-doctor-result.v5` | `../examples/doctor-result.v5.valid.json` |
| `mulgae-doctor-result.v2` | `../examples/doctor-result.v2.valid.json` |
| `mulgae-export-manifest.v1` | `../examples/export-manifest.v1.valid.json` |
| `mulgae-file-catalog.v1` | `../examples/file-catalog.v1.valid.json` |
| `mulgae-mcp-tool-result.v1` | `../examples/mcp-tool-result.v1.valid.json` |
| `mulgae-platform-contract-evidence.v1` | `../examples/platform-contract-evidence.v1.valid.json` |
| `mulgae-provider-contract-evidence.v3` | `../examples/provider-contract-evidence.v3.valid.json` |
| `mulgae-provider-contract-evidence.v4` | `../examples/provider-contract-evidence.v4.valid.json` |
| `mulgae-provider-contract-evidence.v2` | `../examples/provider-contract-evidence.v2.valid.json` |
| `mulgae-provider-heartbeat-result.v2` | `../examples/provider-heartbeat-result.v2.valid.json` |
| `mulgae-provider-heartbeat-result.v3` | `../examples/provider-heartbeat-result.v3.valid.json` |
| `mulgae-provider-heartbeat-result.v1` | `../examples/provider-heartbeat-result.v1.valid.json` |
| `mulgae-provider-followup-output.v1` | `../examples/provider-followup-output.v1.valid.json` |
| `mulgae-provider-review-output.v1` | `../examples/provider-review-output.v1.valid.json` |
| `mulgae-provider-review-wire.v1` | `../examples/provider-review-wire.v1.valid.json` |
| `mulgae-repair-patch.v1` | `../examples/repair-patch.json` |
| `mulgae-repair-request.v1` | `../examples/repair-request.json` |
| `mulgae-review-artifact.v1` | `../examples/review-artifact.v1.valid.json` |
| `mulgae-review-preflight.v4` | `../examples/review-preflight.v4.valid.json` |
| `mulgae-review-preflight.v5` | `../examples/review-preflight.v5.valid.json` |
| `mulgae-review-preflight.v3` | `../examples/review-preflight.v3.valid.json` |
| `mulgae-run-manifest.v1` | `../examples/run-manifest.v1.valid.json` |
| `mulgae-validation-receipt.v1` | `../examples/validation-receipt.v1.valid.json` |
| `mulgae-validation-result.v1` | `../examples/validation-result.v1.valid.json` |

Examples are structural fixtures, not evidence that a provider or platform
contract has passed. Semantic validation, filesystem checks, cryptographic
verification, and fail-closed readiness checks still apply after schema
validation.

Breaking changes require a future schema version. Command-result v5 through v10
schemas remain available for explicit backward reads while commands emit v11.
Published review, run-manifest, and composite v1 contracts remain readable
alongside the v2 contracts for recovery-derived artifacts.
