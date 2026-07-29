# Development and release workflow

## Requirements

- macOS on Apple silicon for the complete release gate
- Go 1.26 or newer
- Git
- authenticated Kimi, ZCode, and AGY installations for live tests

## Local checks

The complete gate is:

```bash
make test
```

It runs generators and static checks, serialized race-instrumented unit tests,
serialized race-instrumented integration tests, an exact-binary production
workflow, and independent live capability certification for all providers.

Smaller targets are available while iterating:

```bash
make test-prepare
make test-unit
make test-int
make test-e2e
```

Do not call a change release-ready when the live gate was skipped.

## Changing embedded assets

Runtime assets live in `internal/builtin/assets` and are embedded directly.
There is no `assets.zip` build product.

```bash
go generate ./internal/app/init
go generate ./internal/builtin
```

The first generator maintains init schema sections and golden data. The second
regenerates `CHECKSUMS.sha256`. Running both twice must leave the worktree
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
