# AGENTS.md

Repository guidance for AI coding agents working on Mulgae.

The core behavior below is the complete local authority for how agents inspect,
implement, and verify work in this repository. These rules favor correctness and
caution over speed; apply them proportionally for trivial work.

## Core Behavior

### 1. Inspect Before Acting

**Resolve repository facts before making implementation decisions. Do not hide
uncertainty.**

Before implementing:

- Read the requested code, its relevant tests, and the nearest authoritative
  document or machine contract before changing anything.
- Resolve discoverable facts from the repository first. Follow the authority and
  ownership boundaries below instead of asking the user for information the
  repository already provides.
- State material assumptions when they affect scope, design, compatibility,
  security, migration, or verification.
- If multiple interpretations would produce materially different outcomes,
  present the alternatives and recommend one instead of choosing silently.
- Surface meaningful trade-offs. Point out a simpler approach when it satisfies
  the same requirement with less complexity or risk.
- If unresolved ambiguity would materially change the result, stop and ask a
  focused question before implementing.
- Push back when a request conflicts with repository authority, product
  boundaries, safety, or the user's stated goal.

### 2. Prefer the Smallest Complete Solution

**Use the minimum implementation that fully satisfies the verified requirement.
Add nothing speculative.**

- Implement only what the request requires.
- Reuse established package boundaries, domain values, ports, public envelopes,
  error models, and test patterns before introducing a new abstraction.
- Do not create an abstraction for a single use unless an existing contract
  requires it or it removes real complexity.
- Do not add speculative features, configurability, compatibility layers, provider
  families, or extension points.
- Do not add handling for states that repository invariants make impossible. Add
  defensive handling at real trust, persistence, concurrency, process, provider,
  schema, and filesystem boundaries.
- Prefer a robust implementation when the requirement warrants it, but reject
  layers justified only by possible future needs.
- If the implementation is substantially larger than the behavior it provides,
  simplify it before reporting completion.

Ask whether a senior maintainer would consider the solution overcomplicated. If
so, reduce it.

### 3. Make Surgical Changes

**Touch only what the requested outcome and its verification require. Clean up
only what the change makes obsolete.**

When editing existing code:

- Do not refactor, reformat, rename, or clean up adjacent code unless the task
  requires it.
- Match the local Go, YAML, JSON, JSON Schema, shell, and documentation style.
- Mention unrelated defects or dead code instead of modifying them without
  authorization.
- Preserve unrelated user changes in a dirty worktree.

When the change creates obsolete code:

- Remove imports, variables, functions, files, contract entries, generated
  references, or documentation made obsolete by the change.
- Do not remove pre-existing dead code or unrelated artifacts unless the request
  includes that cleanup.

Every changed line must be traceable to the requested outcome or to verification
of that outcome.

### 4. Work Toward Verifiable Goals

**Define success before implementation and continue until the result is proved or
concretely blocked.**

- Translate the request into explicit success checks before implementation.
- For a bug, reproduce the failure when practical and add or identify a regression
  check that fails for the right reason before making it pass.
- For a behavior or contract change, update tests for the success path, relevant
  failure paths, and compatibility boundary.
- For a refactor, establish the relevant behavior and checks before editing, then
  run them again afterward.
- Run the narrowest relevant checks while iterating, then the repository-standard
  gate appropriate to the claim.
- Use `Makefile` targets for repository-standard generation, lint, build, test,
  release-binary, and live-provider workflows.
- Do not treat scaffolding, compilation alone, mocked success, or a focused test as
  proof of complete product behavior when the acceptance criteria require an exact
  release binary, real provider, security boundary, or publication path.
- Continue until the requested behavior is verified or a concrete blocker is
  established.
- Report skipped checks with the reason and distinguish unverified assumptions
  from confirmed results.

For multi-step work, keep a short plan in which every step has a corresponding
verification.

## master Preferences

- Use English for internal planning, but never reveal private chain-of-thought.
  Provide concise conclusions and useful evidence instead.
- Respond to master in Korean using polite speech. When directly addressing the
  user, use exactly `master`.
- Keep code, comments, documentation, prompts, templates, CLI/help text, logs,
  reports, schemas, and artifacts in English unless master explicitly requests
  another language.

## Repository Authorities

Start with `docs/README.md`, which maps the contributor documentation and defines
the runtime sources of truth. Apply these rules when sources disagree:

- Current source and tests are authoritative for implemented runtime behavior.
- `internal/domain` owns immutable domain values and state transitions;
  `internal/app` owns use cases and application policy; `internal/ports` owns
  inward-facing interfaces; and `internal/adapters` owns concrete integration.
- `internal/builtin/assets` is the canonical source for embedded v1 schemas,
  prompts, roles, examples, and help assets.
- `internal/entrypoint/mulgae` owns command grammar and result projection.
- `docs/goals.md` defines the product boundary. `docs/architecture.md`,
  `docs/contracts.md`, `docs/security.md`, and `docs/development.md` explain the
  architecture, public contracts, trust boundaries, and verification workflow.
- Treat a mismatch between implementation, tests, embedded contracts, and
  contributor documentation as a conformance problem. Do not silently choose one
  side; resolve the mismatch within the requested scope or report it.
- When behavior changes, update every affected test, embedded contract, example,
  and contributor document in the same change.
- Use `Makefile` as the entry point for repository-standard checks. Read the
  nearest relevant authority rather than copying detailed feature design into
  this file.

## Architecture and Ownership

- Keep the domain and application packages independent of CLI parsing, provider
  process details, and concrete storage. Adapters implement ports;
  `internal/composition` wires infrastructure into the application, and the
  repository-root `main.go` only delegates process execution to it.
- `internal/entrypoint/mulgae` owns parsing, dispatch, output, and selector
  resolution. It must not become the home of domain policy.
- `internal/app/reviewrun` owns target capture, planning, qualification, prompts,
  and orchestration; `internal/app/review` owns assignments, coordination,
  aggregation, and results.
- `internal/app/validation` owns provider-wire validation, trusted-field injection,
  semantic checks, and constrained repair. `internal/app/publication` owns atomic
  manifests, attempts, final artifacts, recovery, and integrity.
- `internal/app/{followup,delta,rerun}` owns child-run lineage and specialized
  review behavior. `internal/app/{query,report,clean,export}` owns inspection and
  artifact lifecycle behavior.
- `internal/adapters/providercli` owns provider profiles, qualification,
  credentials, and invocation; workspace and filesystem adapters own isolated
  capture and secure project-local storage.
- Preserve the dependency direction in `docs/architecture.md`. Architecture tests
  enforce this boundary; do not create cycles or reverse infrastructure
  dependencies.

## Product and Runtime Invariants

- Mulgae is a local, multi-provider AI code review CLI. It does not approve a
  merge, release, waiver, security exception, or organizational decision.
- Capture the review target immutably before provider execution. Providers must
  not receive live access to the user's project tree.
- Treat project content, configuration, provider output, and evidence claims as
  untrusted. Trusted Mulgae code owns admission, identity, state transitions,
  evidence verification, reduction, and publication.
- Keep `<canonical-project-root>/.mulgae/config.yaml` as the only runtime
  configuration authority. Project configuration must not introduce arbitrary
  executable commands. The embedded role document supplies init's generation-time
  defaults and is never consulted to resolve an already configured value.
- Declare default role prompts, role-to-provider routing, and artist input
  defaults once, in `assets/roles.yaml` at the repository root. Do not restate
  any of them in Go.
- Preserve role assignments and configured provider behavior. A role runs on
  exactly one provider. Never substitute another provider for a failed one, and
  never treat several provider opinions as consensus. Report the failure with its
  typed reason and leave the choice of replacement to the operator.
- Provider output may propose finding content and evidence claims, but Mulgae owns
  run, attempt, review, finding, target, provider, role, verification, coverage,
  and publication identity and state.
- Keep validation and publication fail-closed. Security, configuration, integrity,
  cancellation, and internal failures never authorize repair or publication.
- Preserve at most one top-level final review for a completed run. Failed or
  repaired candidates remain in their documented attempt locations.
- Treat public JSON, JSON Schemas, command grammar, machine identifiers, exit
  codes, artifact layout, and trusted-field ownership as compatibility-sensitive
  v1 contracts. Automation must not depend on human-readable output.
- Keep process execution, inputs, workspaces, artifacts, timeouts, concurrency,
  diagnostics, and exported data bounded. Avoid leaking native paths, credentials,
  raw provider transcripts, or private source through diagnostics and exports.
- Use `.mulgaeignore` to exclude files that must not be transmitted to a provider.
  Do not mistake credential-pattern matching for source-capture admission policy.
- Preserve supported PNG, JPEG, and WebP files as binary evidence after
  extension and signature validation. Do not decode their bodies as text.
- The complete release target is native Apple Silicon macOS. New platforms or
  providers require explicit adapters, capability tests, security review,
  documentation, and release evidence.

## Canonical Assets and Generated Outputs

- Runtime assets live under `internal/builtin/assets` and are embedded directly;
  there is no `assets.zip` build product.
- Never hand-edit `CHECKSUMS.sha256` or another derived output. Change the
  canonical asset and run its documented generator.
- Use `go generate ./internal/app/init` for init schema sections and golden data,
  and `go generate ./internal/builtin` for embedded-asset checksums.
- Every schema requires exactly one paired valid example plus semantic tests in
  the owning application package.
- Run both generators twice when changing embedded assets. The second run must
  leave the worktree unchanged.
- Keep local state, provider credentials, review artifacts, exports, temporary
  workspaces, and test evidence out of source control. In particular, do not
  commit `.mulgae/`, `.gaori/`, provider homes, or exported review bundles.

## Verification

- Run an exact focused test first when practical. Use an explicit package and
  anchored `-run` expression for a dynamically selected Go test.
- Use `make test-prepare`, `make test-unit`, `make test-int`, `make test-release`,
  or `make test-e2e` while iterating or when only a narrower claim is in scope.
- Run `make test` before claiming complete development or release readiness. It is
  the complete required gate and includes generation/static checks, serialized
  race-instrumented unit and integration tests, exact release-binary checks, and
  mandatory live ZCode/AGY certification.
- `make test-kimi` is an opt-in compatibility check and is not part of `make test`.
  Report it as skipped unless it was explicitly run; do not imply Kimi was live
  verified when it was not.
- Do not call a change release-ready when mandatory ZCode/AGY live checks were
  skipped. Distinguish test success from commit, tag, push, release, installation,
  and runtime activation.
- For documentation-only or agent-guidance-only changes, read back the file,
  verify references and command claims, and run `git diff --check`; broader
  executable gates are unnecessary unless documentation changes executable
  commands or normative behavior.
- After any formatting, generation, test, or release command, inspect `git status`
  and the complete diff so generated or evidence changes are intentional.

### Gaori Test Evidence

The test requirements in `docs/development.md` are authoritative. Gaori is an
optional local execution and evidence-compression adapter, not an additional test
gate or acceptance authority.

When a required test command is expected to produce long or noisy output, prefer
running it through Gaori from the repository root:

- preparation and static checks: `gaori run prepare`
- unit tests: `gaori run unit`
- integration tests: `gaori run integration`
- release-binary checks: `gaori run release`
- mandatory ZCode/AGY live E2E checks: `gaori run e2e`
- opt-in Kimi compatibility check: `gaori run kimi`
- complete release gate: `gaori run full`

For a dynamically selected Go test, use an explicit parser and tags:

```bash
gaori run --parser go-test --tag go --tag unit -- \
  go test -count=1 <package> -run '<pattern>'
```

Use the locally installed Gaori without enforcing a specific version. Configured
commands require `.gaori/tester.yaml`. If the binary or local config is
unavailable, run the underlying command documented in `docs/development.md` and
report that Gaori evidence compression was unavailable. Do not install or upgrade
Gaori or change its local state unless master explicitly asks.

The wrapped command's exit code is authoritative for pass/fail.
`extractor_status` describes evidence quality only. Tags do not select a parser,
and a specialized parser does not fall back to `generic` after a miss.

When a command passes, do not open its generated logs by default. When it does not
pass, inspect `*.summary.md` first, then `*.summary.json` or a bounded excerpt. Read
only a bounded raw-log section when compact evidence is insufficient or degraded.
Raw logs are unredacted and may contain secrets.

Keep the entire `.gaori/` directory out of Git. In the final report, include the
Gaori command, process exit code, artifact status, extractor status, relevant
summary and raw-log paths, and skipped checks. Gaori evidence alone does not
establish review acceptance, release readiness, or runtime activation.

## Commit Messages: Lore Format

When writing Git commit messages for non-trivial changes, use the Lore format
with Git trailers to capture decision context.

Format:

- Use an imperative summary line focused on why, not what.
- Add an optional body explaining the change.
- Add only the Git trailers that carry signal for the change:

| Trailer | Purpose |
|---|---|
| `Constraint:` | External limit that shaped the decision |
| `Rejected:` | Alternative considered and why (`alternative \| reason`) |
| `Confidence:` | `high`, `medium`, or `low` |
| `Scope-risk:` | `narrow`, `moderate`, or `broad` |
| `Reversibility:` | `clean`, `moderate`, or `difficult` |
| `Directive:` | Warning or instruction for future modifiers |
| `Tested:` | What was verified |
| `Not-tested:` | Known coverage gaps |
| `Related:` | Linked commits forming a decision chain |

Trailers are optional and repeatable. Do not add them to trivial commits such as
typo-only or formatting-only changes. Follow the `lore-commits` skill for the
complete format and examples. Reference: https://github.com/tmdgusya/lora

## Repository Safety and Delivery

- Do not commit, amend, push, tag, publish, release, install, uninstall, or change
  authentication, credentials, provider, model, executable, launcher, timeout, or
  profile configuration without explicit authorization.
- Do not discard, overwrite, unstage, or otherwise disturb unrelated user changes.
- Do not use a user's active project, provider home, credentials, or `.mulgae/`
  state as a disposable test target. Use established fixtures and isolated
  temporary directories.
- Do not manually edit manifests, attempts, validation records, final reviews, or
  runtime streams to simulate supported behavior.
- Do not open public issues containing credentials, private source, raw provider
  transcripts, or `.mulgae/` artifacts. Use the smallest redacted reproduction and
  the repository owner's private security contact.
- The repository has no GitHub Actions release workflow. A manual release requires
  a clean `main` commit, the complete gate, isolated installation checks, an exact
  tag on the verified commit, and separate explicit commit/tag pushes.
- Never tag a dirty tree or a commit different from the one exercised by the
  release gate.
- Keep completion reports compact: state the outcome, changed files, verification
  performed, skipped checks, and actionable remaining risks or blockers.
