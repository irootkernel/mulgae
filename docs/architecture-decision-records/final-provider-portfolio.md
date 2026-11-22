# Final provider portfolio

Status: Accepted

Roadmap: [EPIC-004](../roadmap/README.md#epic-004-zcode-first-review-with-grok-recovery),
[EPIC-011](../roadmap/README.md#epic-011-agy-stream-json-review-provider)

## Decision

The canonical inventory is ZCode, Grok, Codex, AGY. Automatic
initialization requires ZCode and Grok and includes AGY when installed.
`assets/roles.yaml` places AGY first for documentation and ZCode first for the
remaining roles. Configured assignments are never recomputed from those defaults.
Grok remains an operator-selected text route. Codex can use separate credential
profiles. AGY uses one default Gemini account; multiple-account support is
deferred. Its transport and isolation decision is recorded in
[AGY stream-JSON transport](agy-stream-json-transport.md).

Provider failure never causes automatic substitution. Each role still runs on
the provider selected by project policy, and the operator decides whether to
configure and run a replacement.

Retired provider families have no executable, discovery, credential,
qualification, transport, help, or release-test path. Configuration that names
one fails with `config_provider_retired`. Public artifact reads inspect direct
and transitive provider lineage and fail with `retired_provider_artifact`.
Cleanup may inspect and delete those artifacts without exposing their content.
AGY's readmission exempts only validated current live-source artifact/manifest
v3/v4 publications. Their source metadata, target and support must agree. An old
artifact carrying the same version token alone is insufficient. Captured,
composite and recovery AGY history remains retired; Kimi and Cursor remain
retired in every era, including transitive lineage.

## Verification boundary

The complete release gate requires live ZCode certification (`make test-e2e`).
Grok (`make test-grok`), AGY (`make test-agy`), and primary-account Codex
(`MULGAE_E2E_OPT_IN=1 make test-e2e-opt-in` with `MULGAE_E2E_CODEX_PRIMARY_HOME`)
retain their standalone exact-candidate live gates and deterministic coverage in
the mandatory non-live gates.

## Consequences

Current command-result v24, doctor v8, heartbeat v5 and preflight v12 reflect
the four-family portfolio (`zcode`, `grok`, `codex`, `agy`) and reject `cursor`.
Older contract assets retain their original bytes and meanings. Provider-evidence
v4 remains a frozen historical contract: no production evidence
reader or AGY certificate producer exists, so AGY is unverified there.
Historical Git records preserve the retired implementations and planning
detail; current documentation describes only the supported portfolio and the
typed retirement boundary.
