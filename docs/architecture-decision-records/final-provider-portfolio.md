# Final provider portfolio

Status: Accepted

Roadmap: [EPIC-004](../roadmap/README.md#epic-004-zcode-first-review-with-grok-recovery),
[EPIC-011](../roadmap/README.md#epic-011-agy-stream-json-review-provider)

## Decision

The canonical inventory is ZCode, Grok, Codex, Cursor, AGY. Automatic
initialization requires ZCode and Grok and includes AGY when installed.
`assets/roles.yaml` places AGY first for documentation and ZCode first for the
remaining roles. Cursor remains explicit and outside the default preference
lists. Configured assignments are never recomputed from those defaults.
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
v3 publications. Their source metadata, target and support must agree. An old
artifact carrying the same version token alone is insufficient. Captured,
composite and recovery AGY history remains retired; Kimi remains retired in
every era, including transitive lineage.

## Verification boundary

The complete release gate requires live ZCode and Grok certification. Codex
keeps deterministic coverage in the mandatory non-live gates. Its live primary
and secondary credential-profile scenario remains opt-in through
`MULGAE_E2E_OPT_IN=1 make test-e2e-opt-in`.
AGY has a separate `make test-agy` single-account exact-candidate gate. It does
not add another account to the mandatory mixed-provider gate.

## Consequences

Current command-result v21, doctor v7, heartbeat v4 and preflight v9 admit AGY.
Older contract assets retain their original bytes and meanings. Provider-evidence
v4 remains the historical three-provider contract: no production evidence
reader or AGY certificate producer exists, so AGY is unverified there.
Historical Git records preserve the retired implementations and planning
detail; current documentation describes only the supported portfolio and the
typed retirement boundary.
