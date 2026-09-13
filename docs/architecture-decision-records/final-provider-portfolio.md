# Final provider portfolio

Status: Accepted

Roadmap: [EPIC-004](../roadmap/README.md#epic-004-zcode-first-review-with-grok-recovery)

## Decision

Mulgae supports ZCode, Grok, and Codex in that canonical order. Automatic
initialization requires ZCode and Grok, configures both, and assigns every
default role to ZCode. Grok is an operator-selected recovery route for text
roles. Codex remains available through explicit configuration and can use
separate credential profiles.

Provider failure never causes automatic substitution. Each role still runs on
the provider selected by project policy, and the operator decides whether to
configure and run a replacement.

The removed provider families have no executable, discovery, credential,
qualification, transport, help, or release-test path. Configuration that names
one fails with `config_provider_retired`. Public artifact reads inspect direct
and transitive provider lineage and fail with `retired_provider_artifact`.
Cleanup may inspect and delete those artifacts without exposing their content.

## Verification boundary

The complete release gate requires live ZCode and Grok certification. Codex
keeps deterministic coverage in the mandatory non-live gates. Its live primary
and secondary credential-profile scenario remains opt-in through
`MULGAE_E2E_OPT_IN=1 make test-e2e-opt-in`.

## Consequences

Versioned command, doctor, provider-evidence, heartbeat, and preflight contracts
publish new versions for the three-provider portfolio. Older contract assets
remain available only where backward reading is part of the public contract.
Historical Git records preserve the retired implementations and planning
detail; current documentation describes only the supported portfolio and the
typed retirement boundary.
