# Superseded Authority Ledger

This ledger prevents historical terminology from being mistaken for current
runtime authority. Current behavior is defined by the project-local contract in
[Configuration](04-configuration.md) and the accepted decisions in
[Decision Log](14-decision-log.md).

| Superseded term or artifact | Current rule |
|---|---|
| Global, home, or XDG configuration | Never read. `<canonical-project-root>/.kar/config.yaml` is the sole configuration authority. |
| `global-config.yaml`, `project-config.yaml`, `trusted_base`, and trusted project strengthening | Removed from current configuration and emitted v2 review artifacts. Policy source is `project_local`; code-fixed floors remain invariants, not another configuration layer. |
| Versioned `.kar/context.md` or `.kar/prompts/` | Forbidden as authority. The entire `.kar/` namespace is private operator and runtime state and should be ignored by Git. |
| All three provider families required for runtime readiness | Historical G0 qualification evidence only. Current configuration accepts any nonempty subset; a complete singleton is degraded at exit 0, and omitted families are `not_configured`. |
| Inferred AGY permission escalation | Removed. Omission means `safe`; dangerous mode requires the exact explicit operator value `dangerously-skip-permissions`. |
| Help locality admission | Not required. Help reads embedded documentation only and remains available without a repository or configuration. |

Historical evidence remains append-only evidence about its recorded run. It
does not restore a superseded runtime lookup, policy reducer, or readiness gate.
