# Development and release workflow

## Requirements

- macOS on Apple silicon for the complete release gate
- Go 1.26 or newer
- Git
- authenticated ZCode and AGY installations for the mandatory live tests
- an authenticated Kimi installation only for the opt-in compatibility test

## Local checks

The complete gate is:

```bash
make test
```

It runs generators and static checks, serialized race-instrumented unit tests,
serialized race-instrumented integration tests, an exact-binary production
workflow, and independent live capability certification for ZCode and AGY.

Smaller targets are available while iterating:

```bash
make test-prepare
make test-unit
make test-int
make test-e2e
make test-kimi
```

`make test-kimi` is an opt-in compatibility check and is not part of
`make test`. Do not call a change release-ready when the mandatory ZCode/AGY
live gate was skipped.

### Optional Gaori evidence compression

Gaori can wrap long or noisy local test commands so coding agents and developers
can inspect bounded summaries before opening complete logs. It does not replace
the Make targets above or change their pass/fail result.

Install and verify the pinned version explicitly:

```bash
go install github.com/irootkernel/gaori@v0.1.8
gaori --version
```

The version command must report `gaori v0.1.8`. Local Gaori configuration and
evidence live below the ignored `.gaori/` directory. Provision
`.gaori/tester.yaml` with these commands:

| Command ID | Wrapped command | Parser | Tags | Timeout |
|---|---|---|---|---:|
| `prepare` | `make test-prepare` | `generic` | `go`, `static` | 3,600s |
| `unit` | `make test-unit` | `go-test` | `go`, `unit` | 6,000s |
| `integration` | `make test-int` | `go-test` | `go`, `integration` | 6,000s |
| `release` | `make test-release` | `generic` | `go`, `release` | 1,800s |
| `e2e` | `make test-e2e` | `go-test` | `go`, `e2e`, `live` | 11,400s |
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

If Gaori or the pinned version is unavailable, run the corresponding Make
target directly and report that evidence compression was unavailable. Never
skip a required check because its optional wrapper is unavailable.

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
- Add negative fail-closed tests, not only success tests.
- Update v1 contracts and docs with user-visible behavior.
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
