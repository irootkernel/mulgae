# Development and release workflow

## Requirements

- macOS on Apple silicon for the complete release gate
- Go 1.26.6 or newer
- Git
- authenticated ZCode, AGY, and Codex installations for the mandatory live tests
- an authenticated Kimi installation only for the opt-in compatibility test
- two distinct authenticated Codex homes plus an authenticated Kimi data home
  only for the opt-in mixed-profile E2E

## Local checks

The complete gate is:

```bash
make test
```

It runs generators and static checks, serialized race-instrumented unit tests,
serialized race-instrumented integration tests, an exact-binary production
workflow, and independent live capability certification for ZCode, AGY, and
Codex. It then invokes the opt-in mixed-profile target, which reports a stable
skip unless `MULGAE_E2E_OPT_IN=1` is present.

Smaller targets are available while iterating:

```bash
make test-prepare
make test-unit
make test-int
make test-e2e
make test-e2e-opt-in
make test-kimi
make test-mcp-clients
```

`make test-kimi` is an opt-in compatibility check and is not part of
`make test`. Do not call a change release-ready when the mandatory
ZCode/AGY/Codex live gate was skipped.

`make test-e2e-opt-in` is called after `make test-e2e`, but performs no provider
discovery or execution unless `MULGAE_E2E_OPT_IN=1`. When enabled it runs one
three-role exact-binary review: Kimi owns `logic`, Codex profile `primary` owns
`security`, and Codex profile `secondary` owns `documentation`. Supply the two
distinct credential roots and Kimi data root explicitly; profile names are test
aliases and do not prescribe directory names:

```bash
MULGAE_E2E_OPT_IN=1 \
MULGAE_E2E_CODEX_PRIMARY_HOME=/absolute/path/to/primary-codex-home \
MULGAE_E2E_CODEX_SECONDARY_HOME=/absolute/path/to/secondary-codex-home \
MULGAE_E2E_KIMI_DATA_HOME=/absolute/path/to/kimi-data-home \
make test-e2e-opt-in
```

Override executable discovery with `MULGAE_E2E_CODEX_EXECUTABLE` and
`MULGAE_E2E_KIMI_EXECUTABLE`. Once enabled, missing credentials, qualification
failure, invalid provider output, wrong role routing, publication failure, or
credential mutation fails the target; the Go test never converts these states
to a skip. This optional result does not replace mandatory ZCode/AGY/Codex
certification or the separate `make test-kimi` capability check.

`make test-mcp-clients` is an opt-in local compatibility check and is not part
of `make test`. It builds the exact current Mulgae binary, isolates client
configuration in temporary directories, verifies that installed Codex can
initialize Mulgae as a required MCP server, and verifies that installed Claude
Code reports the server as connected. Override their absolute paths with
`MULGAE_MCP_CODEX_BINARY` and `MULGAE_MCP_CLAUDE_BINARY`. The installed-client
check does not expose or assert either client's discovered tool catalog. It also
does not invoke a model or provider, mutate user client configuration, or prove
a live review; deterministic MCP tests cover tool discovery, calls, resources,
progress, and cancellation.

### Optional Gaori evidence compression

Gaori can wrap long or noisy local test commands so coding agents and developers
can inspect bounded summaries before opening complete logs. It does not replace
the Make targets above or change their pass/fail result.

Use the locally installed Gaori without enforcing a specific version. Portable
configuration lives in the tracked `.gaori/tester.yaml`; evidence and
machine-local state remain ignored below `.gaori/`. The repository configuration
defines these commands:

| Command ID | Wrapped command | Parser | Tags | Timeout |
|---|---|---|---|---:|
| `prepare` | `make test-prepare` | `generic` | `go`, `static` | 3,600s |
| `unit` | `make test-unit` | `go-test` | `go`, `unit` | 6,000s |
| `integration` | `make test-int` | `go-test` | `go`, `integration` | 6,000s |
| `release` | `make test-release` | `generic` | `go`, `release` | 1,800s |
| `e2e` | `make test-e2e` | `go-test` | `go`, `e2e`, `live` | 11,400s |
| `e2e-opt-in` | `make test-e2e-opt-in` | `go-test` | `go`, `e2e`, `live`, `kimi`, `codex`, `multi-profile` | 7,200s |
| `kimi` | `make test-kimi` | `go-test` | `go`, `e2e`, `live`, `kimi` | 6,000s |
| `full` | `make test` | `generic` | `go`, `full`, `live` | 28,800s |

Use argv arrays for the wrapped commands and configure these RE2 redaction
patterns for derived evidence:

```yaml
redaction:
  patterns:
    - name: credential-assignment
      regex: '(?i)\b(authorization|api[_-]?key|token|secret|password)=\S+'
      replace: '$1=<redacted>'
    - name: bearer-token
      regex: '(?i)(Bearer)\s+\S+'
      replace: '$1 <redacted>'
```

Run a configured command from the repository root, for example:

```bash
gaori run unit
```

For a focused Go test that is not configured, select the parser explicitly:

```bash
gaori run --parser go-test --tag go --tag unit -- \
  go test -count=1 ./internal/app/reviewrun -run '^TestQualifiedPlanner'
```

Gaori emits no running heartbeat. A long period without console output can be
normal for the serialized race and live-provider targets. After a pass, use the
compact status and do not open logs by default. After a failure, inspect the
Markdown summary, structured summary, and bounded excerpts in that order. Open
only the necessary portion of the raw log when extraction is insufficient or
degraded: raw logs are preserved without redaction and may contain secrets.

If Gaori is unavailable, run the corresponding Make target directly and report
that evidence compression was unavailable. Never skip a required check because
its optional wrapper is unavailable.

## Changing embedded assets

Runtime assets live in `internal/builtin/assets` and are embedded directly.
There is no `assets.zip` build product. The role document is the one exception
to the location: `assets/roles.yaml` sits at the repository root so the tunable
role defaults are discoverable, and is embedded by the root `assets` package
because a `go:embed` pattern cannot escape its own package directory.

```bash
go generate ./internal/app/init
go generate ./internal/builtin
```

The first generator maintains init schema sections and golden data. The second
validates the role document and regenerates `CHECKSUMS.sha256`, which covers the
embedded tree *and* the root role document. The order matters: the first writes
into the tree the second checksums. Running both twice must leave the worktree
unchanged. Every schema needs exactly one paired valid example, plus semantic
tests in the owning application package.

## Contribution checklist

- Keep dependency direction intact; external behavior belongs behind a port.
- Preserve project-local and provider isolation boundaries.
- For provider-concurrency changes, prove overlap with separate coordinators
  and registries and with two release-binary processes sharing the applicable
  runtime environment. Cover both legacy runtime-root discovery branches when
  proving that the removed global filesystem namespace is not recreated.
- Keep publication tests separate from provider-execution concurrency: prove
  different project roots publish independently and a same-root filesystem-lock
  waiter honors cancellation or deadline without mutating committed artifacts.
- Preserve canonical failure precedence in cancellation tests; test pure
  cancellation independently from cancellation joined with artifact, security,
  or internal failures.
- Add negative fail-closed tests, not only success tests.
- Update affected versioned contracts and docs with user-visible behavior.
- Keep unrelated changes out of the commit.
- Run the complete gate before release.

## Manual release

The repository intentionally has no GitHub Actions release workflow:

1. start from a clean commit on `main`;
2. run `make test`;
3. verify module installation in a temporary `GOBIN`;
4. verify `mulgae version`, `mulgae --help`, and project initialization;
5. tag the exact verified commit;
6. push the commit and tag as a separate explicit operation.

Never tag a dirty tree or a different commit from the one exercised by the
release gate.
