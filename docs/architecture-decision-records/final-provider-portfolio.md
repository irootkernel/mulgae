# Final provider portfolio

Status: Accepted

Roadmap: [EPIC-004](../roadmap/README.md#epic-004-zcode-first-review-with-grok-recovery),
[EPIC-017](../roadmap/README.md#epic-017-herdr-core-isolated-terminal-runtime-and-grok-migration)

## Decision

The canonical inventory is ZCode and Grok. Automatic initialization requires
ZCode and Grok and fails closed unless both are available. `assets/roles.yaml`
places ZCode first for all core roles with Grok as the secondary preference, and
ZCode alone for artist. Configured assignments are never recomputed from those
defaults. Grok remains an operator-selected text route running through the
isolated `herdr-core` terminal runtime (`1.0.89+`).

Provider failure never causes automatic substitution. Each role still runs on
the provider selected by project policy, and the operator decides whether to
configure and run a replacement.

Retired provider families (`kimi`, `cursor`, `codex`, `agy`) have no executable,
discovery, credential, qualification, transport, help, or release-test path.
Configuration that names one fails with `config_provider_retired`. Public
artifact reads inspect direct and transitive provider lineage and fail with
`retired_provider_artifact`. Cleanup may inspect and delete those artifacts
without exposing their content. Kimi, Cursor, Codex, and AGY remain retired in
every era, including transitive lineage. Codex remains supported only as an
external MCP client (`make test-mcp-clients`, `make test-mcp-requirements-clients`),
not as a Mulgae review provider.

## Verification boundary

The complete release gate requires live ZCode certification (`make test-e2e`).
Grok (`make test-grok`) and `herdr-core` (`make test-herdr`) retain their
standalone exact-candidate live gates and deterministic coverage in the
mandatory non-live gates.

## Consequences

Current command-result v25, doctor v9, heartbeat v6 and preflight v13 reflect
the two-family portfolio (`zcode`, `grok`) and reject `kimi`, `cursor`, `codex`,
and `agy`. Codex-only credential profile mechanics (`default_credential_profile`,
`credential_homes`, `roles.*.credential_profile`, and `heartbeat --credential-profile`)
are removed from the current contract. Older contract assets retain their
original bytes and meanings. Provider-evidence v4 remains a frozen historical
contract. Historical Git records preserve the retired implementations and
planning detail; current documentation describes only the supported portfolio
and the typed retirement boundary.
