# Mulgae contributor documentation

This directory explains the product boundary and implementation choices that
contributors need to preserve. User installation and the common command flow
live in the repository [README](../README.md); JSON Schema files and valid
examples live with the embedded runtime assets.

## Document map

| Document | Purpose |
|---|---|
| [Project goals](goals.md) | Why Mulgae exists, what it promises, and what is out of scope |
| [Architecture](architecture.md) | Package boundaries, runtime flow, and dependency direction |
| [Contracts](contracts.md) | Configuration, schemas, prompts, artifacts, versioning, and exits |
| [Security](security.md) | Trust boundaries, isolation, evidence, and secret handling |
| [Development](development.md) | Local setup, test gates, asset changes, and release preparation |

## Sources of truth

The implementation is authoritative for runtime behavior:

- `internal/app` owns use cases and application policy.
- `internal/domain` owns immutable domain values and state transitions.
- `internal/ports` owns inward-facing interfaces.
- `internal/adapters` owns operating-system, Git, provider, schema, and
  filesystem integration.
- `internal/composition` owns executable bootstrap and concrete production
  wiring.
- `internal/builtin/assets` owns embedded versioned runtime contracts.
- `internal/entrypoint/mulgae` owns CLI grammar and result projection.
- `internal/entrypoint/mcp` owns attached MCP grammar, transport, and result
  projection.

Contributor documents explain these boundaries but do not create a parallel
runtime contract. When behavior changes, update code, tests, embedded contracts,
and the relevant document in the same change.
