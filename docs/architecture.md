# Architecture

## Dependency direction

Mulgae follows a domain-first, ports-and-adapters design:

```text
main
  -> internal/composition
      -> internal/entrypoint/mulgae
      -> internal/app/*
      -> internal/adapters/*
      -> internal/builtin

internal/entrypoint/mulgae -> internal/app/* -> internal/domain
                                             -> internal/ports
internal/adapters/* --------------------------> internal/ports
```

The domain and application packages do not depend on CLI parsing, provider
process details, or concrete storage. Adapters implement ports;
`internal/composition` wires concrete implementations into the application,
and the root `main.go` delegates process execution to that package. Architecture
tests enforce this direction and keep every other Go file out of the repository
root.

## Package map

| Area | Responsibility |
|---|---|
| `main.go` | Darwin/arm64 process shim and release linker variables |
| `internal/composition` | Executable bootstrap, build identity, and production graph |
| `internal/entrypoint/mulgae` | CLI grammar, dispatch, output, selector resolution |
| `internal/app/reviewrun` | Target capture, planning, qualification, prompts, orchestration |
| `internal/app/review` | Assignments, coordination, aggregation, results |
| `internal/app/validation` | Wire parsing, trusted-field injection, checks, repair |
| `internal/app/publication` | Manifests, attempts, final artifacts, recovery, integrity |
| `internal/app/{followup,delta,rerun}` | Child-run lineage and specialized reviews |
| `internal/app/childrun` | Child-run execution and publication engine |
| `internal/app/{query,report,clean,export}` | Inspection and artifact lifecycle |
| `internal/domain` | IDs, findings, failures, states, roles, immutable values |
| `internal/ports` | Interfaces and safe values crossing application boundaries |
| `internal/adapters/providercli` | Provider profiles, qualification, credentials, invocation |
| `internal/adapters/workspace` | Isolated directory views and descriptor-bound workspaces |
| `internal/adapters/filesystem` | Secure project-local storage and publication |
| `internal/adapters/jsonschema` | Offline Draft 2020-12 validation |
| `internal/builtin` | Embedded schemas, prompts, examples, and help |
| `assets` | Repository-root human-authored role document, embedded into the binary |
| `internal/roles` | Role document schema, parsing, and whole-catalog validation |
| `internal/app/roleassets` | Single application-layer reader of the role document |
| `skills` | Optional, source-distributed AI-agent operating guidance; not a runtime authority or embedded binary asset |
| `test/e2e` | Black-box binary integration, artist fixture, and live-provider E2E tests |

## Role catalog

`assets/roles.yaml` is the one human-authored source for the fixed review roles.
It carries each role's review guidance, its ordered `provider_preferences`, and
the artist input defaults. `go:embed` patterns cannot escape their own package
directory, so the root `assets` package embeds the document and `internal/builtin`
overlays it into the contract catalog under the same checksum inventory as every
embedded file.

The document is a generation-time authority only. `mulgae init` derives the
default provider assignment it writes into a new project from the preference
order intersected with the providers it configured. Nothing resolves a
configured value from embedded bytes, and the policy in `.mulgae/config.yaml`
is never re-derived after init. Machine paths are independently admitted from
the untracked `.mulgae/local.yaml` authority.

## Review flow

1. The entrypoint parses one canonical command request.
2. Project-local configuration is admitted against platform and locality rules.
3. The requested target is captured immutably.
4. The planner selects roles and each role's configured provider.
5. Mulgae composes trusted prompt layers and one capture-owned immutable
   directory view shared by every role in the run. A single tree is available
   under `current/`; a Git comparison exposes both `before/` and `after/`.
6. Provider executions run independently within the explicit
   `max_active_lanes` process capacity, with adapter-owned tool boundaries and
   per-invocation process isolation against that shared directory view.
7. The provider result arrives on the transport declared for that route: a
   Mulgae-owned staged file the adapter validates and reads back after the
   process terminates, or process stdout.
8. UTF-8 provider output becomes Mulgae-owned free-form role reports without a
   fixed report-size ceiling; bounded previews remain private diagnostics;
   optional exact JSON may be structured-extracted and normalized with
   Mulgae-owned identity/state. Prose is not treated as a schema document.
9. One constrained repair on the same provider occurs only when an explicit
   transition authorizes it. A role never moves to another provider: a failed
   role is reported with its typed reason while peer roles continue.
10. Evidence for structured findings is checked against the captured target.
11. Publication atomically commits the manifest, role reports, and at most one
    final review, recording the transport that carried each accepted role
    report. Captured content is retained as a reference-only manifest plus
    deduplicated SHA-256 blobs for immutable child-run reconstruction.

## Concurrency, cancellation, and storage

Application routes, budgets, runtime definitions, and process requests identify
providers directly; they contain no concurrency or scheduling key. Each run
owns a registry and one temporary namespace generation per provider instance,
so independent runs can invoke the same configured provider concurrently. A run
cannot register one provider instance twice, and
an impossible concurrent reuse of one instance within the same registry fails
immediately as an internal invariant instead of waiting. The coordinator
enforces the process-local `max_active_lanes` capacity plus per-role and per-run
invocation ceilings, and schedules repair only after the initial wave is
committed. There is no user-global capacity authority: provider-side
concurrency or rate limits remain provider outcomes, and operators choose the
number of Mulgae processes they run.

Role-path deadlines are calculated from initial-to-repair dependencies and the
process capacity. Before an invocation starts, the runtime still requires
enough enclosing budget for the provider's complete configured timeout window;
removing provider locks does not weaken that check. Provider-observed timeouts
remain distinct from an enclosing deadline exhausted before provider start.

Project-local publication retains a context-aware filesystem lock because it
mutates shared durable state. It serializes publication to one project across
processes without coordinating provider execution or different project roots.
Cancellation propagates to subprocesses and terminal publication. When
cancellation is observed together with a protected artifact, security, or
internal failure, canonical failure precedence preserves the protected failure
instead of projecting the operation as cancellation.

`.mulgae/config.yaml` contains Git-shareable policy. `.mulgae/local.yaml`
contains private machine paths, while the remaining `.mulgae/` tree contains
durable review state. Temporary provider workspaces and namespaces live outside
the project and are removed after use.

Runtime assets are ordinary files under `internal/builtin/assets`, included with
`go:embed`. `CHECKSUMS.sha256` is generated from those files and validated
before the catalog serves any asset.
