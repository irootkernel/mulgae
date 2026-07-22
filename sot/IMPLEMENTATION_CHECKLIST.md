# KAR Implementation Status Checklist

**Status date:** 2026-07-22

SOT 1.10.0 preserves historical G001–G009 evidence and opens G010 as the current implementation ledger. G010 is **IMPLEMENTATION_IN_PROGRESS**: no unchecked item below may be treated as delivered, and `RELEASE_READY` may be recorded only after the exact final-tree `make test` succeeds. Historical evidence and `.gjc/` remain append-only.

## Goal Completion Snapshot

| Goal | Delivered scope | Status | Repository marker |
|---|---|---|---|
| G001 | Authority promotion, post-verification, `g0_complete`, support derivation | **HISTORICAL — COMPLETE** | `1439c3d` |
| G002 | Domain and ports foundation | **HISTORICAL — COMPLETE** | `64ac360` |
| G003 | Trusted adapters, embedded contracts, foundation CLI | **HISTORICAL — COMPLETE** | `905030c` |
| G004 | Prompt validation, bounded repair, fake review slice | **HISTORICAL — COMPLETE** | `f8eaa89` |
| G005 | Coordinator lanes, direct process runtime, evidence, independent outcome axes | **HISTORICAL — COMPLETE** | `da1939f` |
| G006 | Publication recovery, reporting, query commands | **HISTORICAL — COMPLETE** | `feat(g006)` |
| G007 | Provider adapters for supported families `kimi`, `zcode`, and `agy` | **HISTORICAL — COMPLETE** | `feat(g007)` |
| G008 | Fake/offline root/followup/delta/rerun lineage and P2 publication proof; not production root review | **HISTORICAL — COMPLETE** | `feat(g008)` |
| G009 | Historical integrated v0.1 gate; no release publication | **REOPENED_PRODUCTION_REVIEW_INCOMPLETE** | **HISTORICAL_GATE_PASS_NON_PRODUCTION** |
| G010 | Config v2 assignments, configured fallback, production child workflows, and real-provider release gate | **IMPLEMENTATION_IN_PROGRESS** | `g010` |

The checked historical items below preserve G001–G009 evidence and do not establish G010 completion. Only the dedicated G010 section describes current work, and its unchecked items keep the implementation in progress.

## G0 Contract-Freeze Preconditions

- [x] Record a valid session-bound Gate A approval before creating G0 evidence or a candidate.
- [x] Produce and validate the 85-path catalog and 84-regular-file checksum payload; `CHECKSUMS.sha256` remains self-excluded.
- [x] Complete the exact 17 G0 validator receipts: p0, schema, trace, marker, trust, command, publication, prompt, evidence, cleanup, assignment, canonical-argv, failure, integrity, authority, checksums-generate, and checksums-verify.
- [x] Obtain complete PASS evidence for `darwin-arm64`: native/local-POSIX plus all 11 platform probes.
- [x] Historical G0 only: obtain provider readiness as all three families in runtime order `kimi`, `zcode`, `agy` × all 16 probes (**48 PASS**), three secure-writer indexes (**3 PASS**), and a live assignment receipt (**PASS**) before the recorded authority promotion. Current runtime readiness evaluates the configured nonempty subset.
- [x] Retain `linux-amd64`, `linux-arm64`, and `darwin-amd64` only as `intended_future`, non-blocking, unsupported, and release-ineligible inventory; they are not required G0 execution or release targets.
- [x] Treat provider/platform evidence v1 as byte-identical compatibility-only input; only v2 may enter readiness.
- [x] Post-verify the promoted authority candidate and record `g0_complete`.
- [x] Record the separate session-bound implementation approval before starting any item below.

- [x] Validate the v2 four-axis contract (`content_verdict`, `coverage_status`, `publication_status`, `ci_decision` with reasons) without collapsing one axis into another.
- [x] Validate separate source and current evidence identities; source evidence must never become current verified evidence.
- [x] Validate the deterministic six-role/provider assignment reducer, the code-fixed required floor, admitted project-local additions, and run-local non-weakening CLI selection.
- [x] Validate the four canonical provider/platform argv arrays, their domain-separated hashes, and bundle hash before any probe; legacy `--evidence-root` and `--index` are rejected.
- [x] Validate `timeout`, `auth`, `quota`, and `rate_limit` as `repair=none` and `fallback=allowed`; preserve the distinct exhausted-role projections.
- [x] Validate the publication classifier precedence and all ten named cross-boundary fixtures; persist a journal hint but serialize publication only from durable derived state.
- [x] Validate the 84-file payload root with the `KAR-SOT-PAYLOAD-ROOT/1` domain, UTF-8 bytewise path sort, NUL, raw 32-byte digest, and LF grammar.

## P0 Contracts

- [x] Implement separate domain states for run, role task, attempt, parse, validation, evidence, verdict, and finding lifecycle. See [Domain and State Model](docs/02-domain-and-state-model.md).
- [x] Implement canonical UUIDv7 ID types and prefix validation.
- [x] Implement `.kar/{session_id}/{run_id}/review_{uuidv7}.json` as the only final publication path. See [Artifacts](docs/08-artifacts-lineage-and-storage.md).
- [x] Enforce at most one final review per run.
- [x] Record final file SHA-256 in `manifest.json`.
- [x] Keep completed runs immutable.
- [x] Reject project-controlled executable provider configuration. See [Configuration](docs/04-configuration.md).
- [x] Default provider workspace access to `none`. See [Security](docs/09-security-and-trust.md).
- [x] Implement a central coordinator for dynamic fallback and terminal state.
- [x] Ensure valid findings never trigger fallback.
- [x] Ensure security, cancellation, configuration, artifact, and internal failures never trigger fallback.

## Provider Output and Repair

- [x] Require JSON-only provider output.
- [x] Validate provider output against versioned schemas.
- [x] Apply meaningful-value checks in addition to key presence.
- [x] Separate AI-owned and KAR-owned mandatory fields. See [Field Ownership Matrix](docs/16-field-ownership-matrix.md).
- [x] Implement one constrained repair attempt by default.
- [x] Support `reformat_only` and `fill_missing_fields` repair modes.
- [x] Restrict patch paths to explicit `allowed_paths`.
- [x] Prohibit overwrite of existing meaningful values.
- [x] Preserve all raw and repaired outputs as immutable attempt artifacts.
- [x] Run complete schema, semantic, and evidence validation after repair.

## Target and Evidence

- [x] Resolve Git refs to immutable object IDs at capture time.
- [x] Record staged, unstaged, and untracked scope explicitly.
- [x] Implement target content SHA-256.
- [x] Verify evidence path, side, lines, and quote against captured target.
- [x] Require verified evidence for configured high severities.
- [x] Generate excerpts inside KAR after verification.

## Runtime

- [x] Use direct argv by default.
- [x] Pass only allowlisted environment values.
- [x] Separate stdout result bytes from stderr diagnostics.
- [x] Enforce output and timeout limits.
- [x] Kill complete process groups on cancellation.
- [x] Serialize attempts by concurrency key.
- [x] Add cross-process lane locking where supported.
- [x] Implement fake providers before live adapters.
- [ ] G010 macOS AGY native-auth boundary: use only the captured and inode-revalidated installed-user `HOME`/Keychain context for AGY authentication; do not create a synthetic AGY `HOME`, project credentials, or copy OAuth or installation files. KAR's namespace setup, policy, and cleanup paths must not write, overwrite, zero, or unlink user AGY authentication/settings files; normal provider-owned Keychain/profile refresh may still occur during AGY execution. Preserve the descriptor-bound immutable review CWD and KAR-owned XDG/cache/temp/scratch namespaces; enforce `--sandbox`, exact immutable-snapshot `--add-dir`, `--mode plan`, bounded time/output, and post-output `SIGTERM`/`SIGKILL`. AGY's minimum version is 1.1.4. Check this only after the non-skipping G010 AGY E2E passes.

## Artifacts

- [x] Use secure directory and file permissions.
- [x] Use atomic replacement for mutable run status and publication journal files; install the committed manifest immutably with no replacement.
- [x] Use write, validate, fsync, and atomic rename for final review publication.
- [x] Detect hash mismatch and multiple final files as corruption.
- [x] Add safe retention/tombstone cleanup and redacted secure export paths.

## CLI and CI

- [x] Implement distinct review, followup, delta, and rerun application services with immutable child-workflow lineage.
- [x] Make followup, delta, and rerun create child runs, never mutate the source run.
- [x] Keep review verdict separate from CI decision.
- [x] Implement documented exit-code precedence.
- [x] Add all required help topics and golden tests.
- [x] Cover all seven init provider subsets and canonical family order in CLI E2E tests.
- [x] Emit the rejected init request/result envelope for unambiguous invalid JSON requests.
- [x] Admit the installed native account before `kar config` exposes an accepted digest.
- [x] Prove committed init bytes survive stdout short-write and closed-pipe delivery failure.
- [x] Census embedded help for sole-source, subset, workspace, AGY, durability, transport, and no-migration requirements.
- [x] Preserve native-home observation cancellation as exit 9 for init/config/doctor without weakening security precedence.
- [x] Cover auto discovery with zero through three providers in human and JSON CLI E2E tests.
- [x] Exercise new/existing root-barrier failure, retry, and installed-unconfirmed directory-sync projections at the CLI boundary.
- [x] Ensure product text never implies approval authority.

## Historical G009 Integrated v0.1 Gate Evidence

- [x] Historical: retain the exact 17 load-bearing command registry/binary golden and the truthful schema-list v1 rejection.
- [x] Historical: validate all 25 schema/example pairs and assets.
- [x] Historical: retain fake/offline canonical lineage evidence from the four-workflow end-to-end execution; this is not production root-review proof.
- [x] Historical: retain subprocess crash proof and the full domain, security, publication, cancellation, and fallback suites.
- [x] Historical: full `go test`, `go vet`, and race verification passed with zero recorded P0 blockers.
- [x] Retain the controlled Kimi historical qualification receipt for the recorded G009 run: `kimi/local-default/0.23.6/50c3582a1beeba081271193b74efc39c51b3a0a16b4bf32b754b9482a86a314a/kimi-default`, its append-only ledger receipt, and the byte-identical repository copies indexed by `artifacts/historical/g009/manifest.json`; receipt SHA-256 `1227711091fc94aff32dfed18d34f009da7404862b1eb63d99a2313a30c2be27`, raw-output SHA-256 `435639659d6ec453a8271d9a82787e11d4aa1be0450b981b0aab040966172141`. This is not a current support boundary.
- [x] Preserve the append-only provider attempt history: two later 2026-07-18 retries each ended after approximately 30.15 seconds with `status=timeout`, `termination=timed_out`, and `diagnostic=process_timeout`; retain those ledger events without replacing the earlier PASS.
- [x] Keep G0 provider-family evidence for `kimi`, `zcode`, and `agy` separate from current support. Support those families by runtime capability contract without version, executable path, SHA, or profile allowlisting; retain those fields as diagnostic provenance, produce actionable typed capability diagnostics, explicitly block known incompatibilities only, reject unlisted families, and do not automatically substitute providers. Keep `darwin-arm64` as the sole supported platform.
- [x] Historical integrated-gate classification: **HISTORICAL_GATE_PASS_NON_PRODUCTION**. Production `kar review` composition is wired, but the current status remains **REOPENED_PRODUCTION_REVIEW_INCOMPLETE** until full current qualification/security/P2 provenance and three family-distinct non-SKIP normal P2 receipts are verified. No release assets were authorized or created, and release publication remains subject to separate approval.

## G010 Config-driven Multi-provider Production Gate

### Contract and configuration

- [x] Freeze SOT 1.10.0 with G010 status `IMPLEMENTATION_IN_PROGRESS`, the six-role primary/fallback matrix, workflow-specific fallback scope, and the exact `make test` release gate.
- [x] Implement canonical Config v2 and reject Config v1 without migration or compatibility fallback. Evidence: `TestConfigV2RoleAssignmentsAndV1Rejection`.
- [x] Require every role primary to reference a configured `kimi`, `zcode`, or `agy` family; require a distinct configured fallback whenever two or more families are configured; permit fallback omission only for a singleton. Evidence: config semantic validation and seven-subset round trips.
- [x] Generate the canonical all-family matrix: `logic=kimi/zcode`, `documentation=agy/zcode`, and `security|maintainability|product|testing=zcode/agy`; deterministically reduce the same role preference order for provider subsets. Evidence: `TestInitializeProjectSupportsAllSevenSelectedSubsets`.
- [x] Expose only redacted role-family assignments through `kar config` and retain strict credential rejection. Evidence: `TestRedactionOmitsExecutableAndNativePaths` and adapter credential tests.

### Planning, fallback, and reporting

- [ ] Resolve configured family assignments to current qualified provider routes exactly; reject an absent or unqualified configured primary/fallback instead of silently substituting another family.
- [ ] Preserve the primary result without invoking fallback when primary execution produces valid output, including a valid finding.
- [ ] Schedule configured fallback only for `unavailable`, `timeout`, `authentication`, `quota`, `rate_limit`, or invalid output after its single constrained repair is exhausted.
- [ ] Forbid fallback for security-policy, configuration, artifact, cancellation, internal, mutation, and valid-finding outcomes.
- [ ] Preserve primary failure attempts and fallback attempts, and report the successful fallback role as `selected_via=fallback` with matching P2 lineage and exit projection.

### Production workflows

- [ ] Run production `review`, `delta`, and recomposed `rerun` through current Config v2 primary/fallback assignments.
- [ ] Run `followup` exactly once with the source finding provider; do not apply configured fallback to this source-bound workflow.
- [ ] Run exact `rerun` exactly once with the source attempt provider; do not apply configured fallback to exact replay.
- [ ] Revalidate configuration, provider authority, immutable target, prompt, and credential namespace per CLI process and clean KAR-owned temporary state on every terminal path.

### Test and release gate

- [ ] Classify fake-provider workflow tests as integration tests, never E2E tests.
- [ ] Run `test-unit` and `test-int` independently with `-race -count=1`.
- [ ] Build one current KAR candidate and run non-skipping E2E against the actual Kimi, ZCode, and AGY binaries and native authentication.
- [ ] Exercise Config v2 init/config/doctor, six-role review, followup, three-family delta, exact rerun, and recomposed rerun with schema-valid P2, lineage, assignment, and exit/artifact consistency assertions.
- [ ] Fail E2E when any required binary, launcher, native authentication, qualification, invocation, or publication step is unavailable; do not convert absence to skip.
- [ ] Make `make test` execute exactly `test-prepare`, `test-unit`, `test-int`, and `test-e2e` in order; define no separate offline, race, release, or retained-receipt gate.
- [ ] Preserve the 85-path/84-payload catalog, 25 schema/example pairs, checksum grammar, and generated embedded catalog after every SOT update.
- [ ] Run `make test` on the exact final SOT tree and record `RELEASE_READY` only after it succeeds.
