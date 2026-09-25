# Implementation and release guidance

## Requirements

- macOS on Apple silicon for the complete release gate
- Go 1.27.1 or newer
- Git
- a ZCode app bundle with a current Z.AI Individual Coding Plan connection,
  plus an authenticated Grok installation, for the mandatory live tests
- two distinct authenticated Codex homes only for the opt-in profile E2E

Codex provider execution requires CLI 0.154.0 or newer for the app-server
route. The separate Codex MCP-client compatibility check retains its own
minimum version.

Grok provider execution requires CLI 1.0.34 or newer. Version 1.0.40 is the
latest release verified for the exact ACP model and reasoning-effort selection
contract; later versions remain eligible but require current qualification.

ZCode app 3.12.3 is the minimum and currently verified app release for the app-owned
Electron plus bundled `zcode.cjs app-server --stdio` route. That bundle's
launcher reports protocol version 0.16.5; provider qualification observes that
launcher value, so its minimum and verified-latest guidance remain 0.16.5.
App releases above 3.12.3 and launcher protocol releases above 0.16.5 remain
eligible as `newer_than_verified`; the two version axes are never substituted.

## Local checks

The complete gate is:

```bash
make test
```

It runs generators and static checks, serialized race-instrumented unit tests,
serialized race-instrumented integration tests, one exact-binary two-role live
review, and independent live capability certification for ZCode and Grok. The
live review routes `logic` to ZCode and `security` to Grok concurrently, accepts
one Markdown report from each provider without repair or structured extraction,
and requires Mulgae to publish one complete reports-only review. Each role must
reproduce a fresh marker stored only in its captured source file, never the
objective, so a report that merely claims it could not read the target does not
certify workspace access. The complete gate then invokes the opt-in Codex
profile target, which reports a stable skip unless `MULGAE_E2E_OPT_IN=1` is
present.
Independent live capability certification failures preserve the exact request,
nonempty version/capability stdout and stderr, and process exit metadata in a
private `mulgae-capability-failure-<family>-*` temporary directory. The failure
log prints that directory; the secure writer drops credential-bearing streams.
These diagnostics survive fixture cleanup and are local evidence, not published
review artifacts. `launches=2` means version plus capability, not two retries.
Inspect this evidence before attributing a binding mismatch to provider load or
to a Mulgae decoder defect; successful reruns alone do not establish stability.
The mandatory `make test-e2e` capability filter also runs the offline checks for
private evidence permissions, credential screening, and failure guidance.

Smaller targets are available while iterating:

```bash
make test-prepare
make test-unit
make test-int
make test-release
make test-e2e
make test-e2e-opt-in
make test-grok
make test-mcp-clients
```

`make test-release` first installs the production binary with only the public
version and revision link flags and checks that exact installed artifact through
`internal/releasecheck`. It separately builds an isolated recovery-scenario
fixture with the test-only native-home override. The fixture exercises recovery
without reading the operator's real home; it is not the installed release
artifact and does not replace the releasecheck evidence.

`make test-grok` builds the exact current release binary and runs one authorized
Grok review through ACP v1. It uses `MULGAE_E2E_GROK_EXECUTABLE` when set and
otherwise discovers `grok` on `PATH`. The target requires an already
authenticated installation, does not modify native Grok configuration, and is
an optional standalone provider diagnostic; the mandatory `make test-e2e` gate
already exercises Grok through the mixed-provider review.

`make test-e2e-opt-in` is called after `make test-e2e`, but performs no provider
discovery or execution unless `MULGAE_E2E_OPT_IN=1`. When enabled it runs one
three-role exact-binary review: Codex profile `primary` owns `logic` and
`security`, while profile `secondary` owns `documentation`. Supply the two
distinct credential roots explicitly; profile names are test aliases and do
not prescribe directory names:

```bash
MULGAE_E2E_OPT_IN=1 \
MULGAE_E2E_CODEX_PRIMARY_HOME=/absolute/path/to/primary-codex-home \
MULGAE_E2E_CODEX_SECONDARY_HOME=/absolute/path/to/secondary-codex-home \
make test-e2e-opt-in
```

Override executable discovery with `MULGAE_E2E_CODEX_EXECUTABLE`. Once enabled,
missing credentials, qualification
failure, invalid provider output, wrong role routing, publication failure, or
credential mutation fails the target; the Go test never converts these states
to a skip. This optional result does not replace mandatory ZCode/Grok
certification.

`make test-mcp-clients` is an opt-in local compatibility check and is not part
of `make test`. It builds the exact current Mulgae binary, isolates client
configuration in temporary directories, verifies that installed Codex can
initialize Mulgae as a required MCP server, validates the observable Codex
`mcp get mulgae --json` fields, and verifies that installed Claude Code reports
the server as connected. The Codex check preserves an absent `required` field
as unobserved rather than interpreting it as `false`. Override client paths with
`MULGAE_MCP_CODEX_BINARY` and `MULGAE_MCP_CLAUDE_BINARY`. The installed-client
check does not expose or assert either client's discovered tool catalog. It also
does not invoke a model or provider, mutate user client configuration, or prove
a live review; deterministic MCP tests cover tool discovery, calls, resources,
progress, and cancellation.

Release evidence for the lifecycle workflow additionally requires separately
authorized, exact-client model runs against an isolated or read-only project
target. Each supported client must discover all three lifecycle tools, call one
`start_review`, keep one `await_review` pending through a meaningfully long live
review, and inspect the exact terminal run. The client event stream must show no
assistant/model message or second tool call between the await start and its
terminal result. Host-rendered progress events are permitted observation and do
not count as model turns. Record client versions, target SHA-256, invocation and
run identities, elapsed await behavior, publication/coverage state, and finding
count without committing client transcripts or `.mulgae/` artifacts.

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
| `e2e-opt-in` | `make test-e2e-opt-in` | `go-test` | `go`, `e2e`, `live`, `codex`, `multi-profile` | 7,200s |
| `grok` | `make test-grok` | `go-test` | `go`, `e2e`, `live`, `grok` | 6,000s |
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

The checksum generator follows the `go:embed assets` directory rule: files and
directories whose names start with `.` or `_` are excluded at every depth.
Excluded directories are not traversed, so local tool state inside them cannot
enter the checksum inventory. Included assets must remain regular files; symbolic
links and other non-regular entries are rejected.

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
2. replace the current changelog section's `Unreleased` marker with the release
   date;
3. commit the release metadata and require a clean candidate on `main`;
4. run `make test` against that exact candidate;
5. verify module installation in a temporary `GOBIN`;
6. verify `mulgae version`, `mulgae --help`, and project initialization;
7. tag the exact verified commit;
8. push the commit and tag as a separate explicit operation;
9. create and publish the GitHub Release for that exact tag as a separate
   explicit operation, using the settled changelog entries;
10. after verifying the hosted Release, immediately open the next planned
    release cycle in a separate change by advancing `RELEASE_VERSION` and its
    architecture assertion and prepending an empty `Unreleased` changelog
    section.

During development, record concise user-visible outcomes under `Added`,
`Changed`, or `Fixed` in the current `Unreleased` section.

Never tag a dirty tree or a different commit from the one exercised by the
release gate.
