# AGENTS.md

Repository guidance for AI coding agents working on Mulgae.

The core behavior below is the complete local authority for how agents inspect,
implement, and verify work in this repository. These rules favor correctness and
caution over speed; apply them proportionally for trivial work.

## Core Behavior

### 1. Lead with Conclusions

- State the result or current finding first, followed by useful evidence and
  material limits.
- Do not repeatedly restate requirements or narrate routine work.

### 2. Reuse Verified Information

- Read the requested code, its relevant tests, and the nearest authoritative
  document or machine contract before changing anything.
- Resolve discoverable facts from the repository before asking master. Reuse
  established facts instead of reading or searching for them again; recheck only
  affected information when state changes, evidence conflicts, or missing context
  makes it unreliable.
- State material assumptions when they affect scope, design, compatibility,
  security, migration, or verification.
- If multiple interpretations would produce materially different outcomes,
  present the alternatives and recommend one. Surface meaningful trade-offs and
  point out a simpler approach when it satisfies the same requirement with less
  complexity or risk.
- Ask a focused question when unresolved ambiguity would materially change the
  result. Push back when a request conflicts with repository authority, product
  boundaries, safety, or master's stated goal.

### 3. Act on Sufficient Evidence

- Stop investigating once the evidence supports action. When the root cause is
  established, implement the smallest complete, durable solution within the
  authorized scope.
- Weigh correctness, performance, maintainability, and structural fit rather than
  diff size alone. If a broader ideal design exceeds scope, complete a bounded
  step that satisfies the current acceptance criteria and preserves a clear path
  forward.
- Reuse established package boundaries, domain values, ports, public envelopes,
  error models, and test patterns. Avoid speculative features, abstractions,
  configurability, compatibility layers, provider families, extension points,
  and handling for states repository invariants make impossible. Add defensive
  handling at real trust, persistence, concurrency, process, provider, schema,
  and filesystem boundaries.
- If the implementation is substantially larger than the behavior it provides,
  simplify it. Ask whether a senior maintainer would consider the solution
  overcomplicated and reduce it if so.
- Touch only what the outcome and its verification require. Do not refactor,
  reformat, rename, or clean up adjacent code without authorization. Match local
  Go, YAML, JSON, JSON Schema, shell, and documentation style, preserve unrelated
  user work, and mention unrelated defects instead of modifying them.
- Remove only imports, variables, functions, files, contract entries, generated
  references, documentation, or other artifacts made obsolete by the change.
  Every changed line must be traceable to the requested outcome or its
  verification.
- Record only independent remaining work in the canonical deferred-feedback
  owner. If none exists, propose the entry and obtain approval before creating
  one. Promote epic-sized work to a TODO candidate or roadmap unit; never defer
  work required for current correctness or acceptance.

### 4. Carry Authorization Forward

- Continue already approved work without asking for confirmation again. Ask only
  when a material change exceeds that authorization or an applicable rule
  requires a distinct approval.
- Preserve the separate boundaries between implementation, installation,
  staging, commits, pushes, tags, publication, release, and activation.
- Re-read affected state before acting on an approved proposal. If a target or
  material prerequisite changed, stop and reconcile the approval against the
  new snapshot.

### 5. Verify in Proportion to Risk

- Define success checks before implementation. For multi-step work, keep a short
  plan in which every step has a corresponding verification.
- For a bug, reproduce the failure when practical and add or identify a regression
  check that fails for the right reason before making it pass. For a behavior or
  contract change, cover the success path, relevant failure paths, and
  compatibility boundary. For a refactor, establish the relevant behavior before
  editing and verify it again afterward.
- Run the narrowest relevant checks while iterating, then the repository-standard
  gate appropriate to the claim. Use `Makefile` targets for standard generation,
  lint, build, test, release-binary, and live-provider workflows.
- Do not add tests merely to appear rigorous or use prose matching as a substitute
  for behavior verification. Do not treat scaffolding, compilation alone, mocked
  success, or a focused test as complete product proof when acceptance requires
  an exact release binary, real provider, security boundary, or publication path.
- Broaden or repeat checks when changes, failures, or unresolved concerns justify
  it. Report skipped checks with the reason and distinguish unverified
  assumptions from confirmed results.

### 6. Finish When Complete

- Continue until the requested deliverables and required verification are
  complete or a concrete blocker prevents progress.
- Once material constraints are resolved or clearly reported, provide the handoff
  and stop. Report the result, necessary evidence, skipped checks and their
  reasons, and remaining actionable uncertainty without opening unrelated work.

### 7. Delegate Selectively

- Use a sub-agent only for an independent task when the expected benefit outweighs
  coordination cost.
- Honor explicitly required independent reviews and restrictions on delegation.
  Keep tightly coupled work local.

## Master Preferences

- Use English for internal planning, but never reveal private chain-of-thought.
  Provide concise conclusions and useful evidence instead.
- Respond to master in Korean using polite speech. When directly addressing the
  user, use exactly `master`.
- Keep code, comments, documentation, prompts, templates, CLI/help text, logs,
  reports, schemas, and artifacts in English unless master explicitly requests
  another language.

## Aquarium Development Guide

- Use `$aquarium:task-handler` for one named roadmap task.
- Use `$aquarium:epic-handler` to implement one roadmap epic as sequential task goals.
- Use `$aquarium:epic-validator` to cold-validate and remediate one completed roadmap epic.
- Use `$aquarium:dev-setup-global` to diagnose, install, or update user-global
  development tools, paired skills, services, and global MCP state.
- Use `$aquarium:dev-setup` to diagnose or configure repository-local tooling and
  operating guidance.
- Use `$aquarium:docs-setup` to audit, establish, adopt, or migrate canonical
  documentation structure and roadmap IDs.
- Use `$aquarium:test-setup` to audit or configure the common Make or Bun testing
  contract and evidence-backed legacy waivers.
- Use `$aquarium:release-handler` for one stable release lifecycle and
  `$aquarium:release-qa` for exact committed-candidate scenario verification.
- Use `$aquarium:new-project`, `$aquarium:new-feature`, or `$aquarium:refactor`
  for explicitly requested Ouroboros-assisted design workflows.
- Use `$aquarium:war-room` for difficult-bug diagnosis that stops at an approved
  task, epic, or incomplete-investigation proposal.
- Use `$use-mulgae` for an authorized Mulgae review, run inspection, finding
  follow-up, configuration diagnosis, cleanup plan, or recovery.
- Use `$use-gaori` when a selected long or noisy check is routed through Gaori
  or existing Gaori evidence must be inspected. Use `$use-gaori-status` for
  Gaori-calculated duration, outcome history, or detailed timing explanations.
- Use `$use-sanho` at an authorized commit or push boundary in a
  Sanho-managed repository, or for an explicitly requested Sanho operation.
- Let `$aquarium:task-handler`, `$aquarium:epic-handler`, and
  `$aquarium:epic-validator` use Podway by default unless the current user opts
  out before the first managed-session mutation; Aquarium workflow skills retain
  their stricter roadmap, ownership, and approval rules.
- Use `$use-podway` directly for an explicitly requested Procedure v2 session
  lifecycle, goal, diagnosis, recovery, cancellation, or current-session discard
  flow. Keep each handler opt-out local to its current task, epic, or validation
  request. Procedure authoring requires the separate maintainer skill and is not
  provided by `$use-podway`.
- Use `$lore-commits` for non-trivial commit messages and `$lore-query` to inspect
  recorded decision context.
- Use the separately installed upstream `$deslop` skill for task-owned cleanup
  when an Aquarium workflow requests it.
- Use the separately installed upstream `$humanizer` skill once as the final prose
  pass for English human-authored documentation. Preserve meaning, facts, code,
  commands, identifiers, URLs, citations, quotes, legal text, and generated
  content; fail closed with the unchanged draft when validation fails.
- Keep `.mulgae/**`, `.gaori/runs/**`, and `.podway/runtime/**` as local runtime
  evidence. Do not cite their paths or identities as durable tracked evidence;
  use a reviewed `aquarium.promoted-evidence/v1` package under
  `evidence/aquarium/` only when a downstream consumer requires retention.
- Repository-specific rules below override defaults from the referenced skills.

## Project Configuration

- Aquarium release notes: CHANGELOG.md

### Repository Index and Authorities

#### Repository Authorities

Start with `docs/README.md`, which maps the contributor documentation and defines
the runtime sources of truth. Apply these rules when sources disagree:

- Current source and tests are authoritative for implemented runtime behavior.
- `internal/domain` owns immutable domain values and state transitions;
  `internal/app` owns use cases and application policy; `internal/ports` owns
  inward-facing interfaces; and `internal/adapters` owns concrete integration.
- `internal/builtin/assets` is the canonical source for embedded v1 schemas,
  prompts, roles, examples, and help assets.
- `internal/entrypoint/mulgae` owns command grammar and result projection.
- `docs/specs/goals.md` defines the product boundary.
  `docs/architecture/README.md`, `docs/specs/contracts.md`,
  `docs/specs/security.md`, and `docs/implementation-tips/README.md` explain the
  architecture, public contracts, trust boundaries, and verification workflow.
- Treat a mismatch between implementation, tests, embedded contracts, and
  contributor documentation as a conformance problem. Do not silently choose one
  side; resolve the mismatch within the requested scope or report it.
- When behavior changes, update every affected test, embedded contract, example,
  and contributor document in the same change.
- Use `Makefile` as the entry point for repository-standard checks. Read the
  nearest relevant authority rather than copying detailed feature design into
  this file.

#### Architecture and Ownership

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
- Preserve the dependency direction in `docs/architecture/README.md`.
  Architecture tests enforce this boundary; do not create cycles or reverse
  infrastructure dependencies.

#### Product and Runtime Invariants

- Mulgae is a local, multi-provider AI code review CLI. It does not approve a
  merge, release, waiver, security exception, or organizational decision.
- Capture the review target immutably before provider execution. Providers must
  not receive live access to the user's project tree.
- Treat project content, configuration, provider output, and evidence claims as
  untrusted. Trusted Mulgae code owns admission, identity, state transitions,
  evidence verification, reduction, and publication.
- Keep `<canonical-project-root>/.mulgae/config.yaml` as the Git-shareable
  project-policy authority and `<canonical-project-root>/.mulgae/local.yaml` as
  the mode-`0600`, untracked machine-path authority. Project configuration must
  not introduce arbitrary executable commands. The embedded role document
  supplies init's generation-time defaults and is never consulted to resolve an
  already configured value.
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
  versioned contracts. Automation must not depend on human-readable output.
- Keep process lifetimes, configuration and transport inputs, workspaces,
  structured artifacts, concurrency, diagnostics metadata, and exported data
  bounded. Provider content is deliberately unbounded: source capture, prompt
  payloads, role reports, and complete provider stdout and stderr carry no
  product byte ceiling. Do not add one. Avoid leaking native paths,
  credentials, raw provider transcripts, or private source through public
  diagnostics and exports.
- Use `.mulgaeignore` to exclude files that must not be transmitted to a provider.
  Do not mistake credential-pattern matching for source-capture admission policy.
- Preserve supported PNG, JPEG, and WebP files as binary evidence after
  extension and signature validation. Do not decode their bodies as text.
- The complete release target is native Apple Silicon macOS. New platforms or
  providers require explicit adapters, capability tests, security review,
  documentation, and release evidence.

#### Canonical Assets and Generated Outputs

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
  workspaces, and test evidence out of source control. The only trackable
  development-tool state is `.mulgae/config.yaml`, `.gaori/tester.yaml`,
  `.gaori/tester/rules/*.yaml`, `.podway/config.yaml`, `.podway/.gitignore`, and
  `.podway/procedures/*.yaml`. Never commit `.mulgae/local.yaml`, any other
  `.mulgae/**` path, `.gaori/toolchain.yaml`, `.gaori/rule-proposals/`,
  `.gaori/runs/`, any other Gaori runtime or evidence path, `.podway/runtime/`,
  provider homes, or exported review bundles.

### Commit Messages

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

### Project-Specific Operating Rules

#### Verification

- Run an exact focused test first when practical. Use an explicit package and
  anchored `-run` expression for a dynamically selected Go test.
- Use `make test-prepare`, `make test-unit`, `make test-int`, `make test-release`,
  `make test-e2e`, or `make test-e2e-opt-in` while iterating or when only a
  narrower claim is in scope.
- Run `make test` before claiming complete development or release readiness. It is
  the complete required gate and includes generation/static checks, serialized
  race-instrumented unit and integration tests, exact release-binary checks, and
  mandatory live ZCode/Codex certification.
- A patch-only release may use a reduced exact-commit gate when master explicitly
  states that `make test` has already passed, accepts responsibility for relying
  on that result, and explicitly requests release after only a patch-version
  increment. Treat master's statement as the authoritative verification waiver;
  do not require prior artifacts, reconstruct the earlier run, or rerun
  `make test`. The diff since the user-accepted result must be limited to the
  release-version declaration, its matching test assertion, release notes, and
  release-procedure documentation or agent guidance; it must not change runtime
  behavior, schemas, embedded assets, dependencies, build inputs, provider
  policy, or tool configuration. In that case run `make test-prepare`,
  `make test-unit`, and `make test-int`, then build the exact commit into an
  isolated temporary `GOBIN` and verify both `mulgae version` and
  `mulgae version --json` report the new version. The public version result does
  not expose the build revision. Report that master waived a repeated full gate
  and that release-binary and live E2E targets were not rerun. If any condition
  is not satisfied, run `make test`.
- `make test` calls `make test-e2e-opt-in` after the mandatory E2E target. It
  reports a stable skip unless `MULGAE_E2E_OPT_IN=1`; the default complete gate
  therefore does not require Kimi or a second Codex credential home.
- When enabled, `make test-e2e-opt-in` requires explicit primary and secondary
  Codex homes plus a Kimi data home and runs exactly three roles: Kimi logic,
  Codex-primary security, and Codex-secondary documentation. Missing or unsafe
  prerequisites and provider failures fail the target; do not downgrade them to
  skips or substitute another provider.
- `make test-kimi` is an opt-in compatibility check and is not part of `make test`.
  Report it as skipped unless it was explicitly run; do not imply Kimi was live
  verified when it was not.
- Do not call a change release-ready when mandatory ZCode/Codex live checks were
  skipped, except under the explicit patch-only release rule above with the
  user's full-gate waiver recorded. Distinguish test success from commit, tag,
  push, release, installation, and runtime activation.
- For documentation-only or agent-guidance-only changes, read back the file,
  verify references and command claims, and run `git diff --check`; broader
  executable gates are unnecessary unless documentation changes executable
  commands or normative behavior.
- After any formatting, generation, test, or release command, inspect `git status`
  and the complete diff so generated or evidence changes are intentional.

##### Gaori Test Evidence

The standard test and release requirements in
`docs/implementation-tips/README.md` are authoritative for the normal workflow.
The explicit patch-only waiver above is an agent-specific override when master
supplies the required authorization.
Gaori is an optional local execution and evidence-compression adapter, not an
additional test gate or acceptance authority.

When a required test command is expected to produce long or noisy output, prefer
running it through Gaori from the repository root:

- preparation and static checks: `gaori run prepare`
- unit tests: `gaori run unit`
- integration tests: `gaori run integration`
- release-binary checks: `gaori run release`
- mandatory ZCode/Codex live E2E checks: `gaori run e2e`
- opt-in Kimi/two-profile Codex E2E: `gaori run e2e-opt-in`
- opt-in Kimi compatibility check: `gaori run kimi`
- complete release gate: `gaori run full`

For a dynamically selected Go test, use an explicit parser and tags:

```bash
gaori run --parser go-test --tag go --tag unit -- \
  go test -count=1 <package> -run '<pattern>'
```

Use the locally installed Gaori without enforcing a specific version. Configured
commands require `.gaori/tester.yaml`. If the binary or local config is
unavailable, run the underlying command documented in
`docs/implementation-tips/README.md` and report that Gaori evidence compression
was unavailable. Do not install or upgrade Gaori or change its local state unless
master explicitly asks.

The wrapped command's exit code is authoritative for pass/fail.
`extractor_status` describes evidence quality only. Tags do not select a parser,
and a specialized parser does not fall back to `generic` after a miss.

Follow `$use-gaori` for evidence inspection. Raw logs are unredacted and may
contain secrets. Keep portable `.gaori/tester.yaml` and specifically reviewed
active rule YAML trackable; keep every other `.gaori/` path local and ignored.
Active rule YAML is executable extraction policy and requires specific intent
and review. In the final report, include the Gaori command, process exit code,
artifact status, extractor status, relevant summary and raw-log paths, and
skipped checks. Gaori evidence alone does not establish review acceptance,
release readiness, or runtime activation.

#### Repository Safety and Delivery

- Treat `.podway/procedures/aquarium-*-v2.yaml` as the repository-local
  workflow evidence and routing authority.
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
  a clean `main` commit, the complete gate or the explicit patch-only reduced
  gate, the applicable isolated installation/version checks, an exact tag on the
  verified commit, and separate explicit commit/tag pushes.
- Never tag a dirty tree or a commit different from the one exercised by the
  applicable release gate.
- Keep completion reports compact: state the outcome, changed files, verification
  performed, skipped checks, and actionable remaining risks or blockers.
