# KAR Implementation Status Checklist

**Status date:** 2026-07-18

SOT 1.5.0 records the authorized implementation boundary after `g0_complete`: G001 through G008 are complete; G009 remains pending and unauthorized until its own execution and release gates are opened.

## Goal Completion Snapshot

| Goal | Delivered scope | Status | Repository marker |
|---|---|---|---|
| G001 | Authority promotion, post-verification, `g0_complete`, support derivation | **COMPLETE** | `1439c3d` |
| G002 | Domain and ports foundation | **COMPLETE** | `64ac360` |
| G003 | Trusted adapters, embedded contracts, foundation CLI | **COMPLETE** | `905030c` |
| G004 | Prompt validation, bounded repair, fake review slice | **COMPLETE** | `f8eaa89` |
| G005 | Coordinator lanes, direct process runtime, evidence, outcome axes | **COMPLETE** | `da1939f` |
| G006 | Publication recovery, reporting, query commands | **COMPLETE** | `feat(g006)` |
| G007 | Opt-in evidence-gated provider adapters for exactly `kimi`, `zcode`, and `agy` | **COMPLETE** | `feat(g007)` |
| G008 | Immutable root/followup/delta/rerun lineage and P2 publication; runtime attempt/target/prompt artifacts; retention/tombstone cleanup; redacted secure export | **COMPLETE** | `feat(g008)` |
| G009 | Release assets and integrated v0.1 release gate | **PENDING AND UNAUTHORIZED** | — |

A checked item below is covered by the recorded completed G001–G008 boundary. G009 work remains unchecked and unauthorized until its own execution gate opens.

## G0 Contract-Freeze Preconditions

- [x] Record a valid session-bound Gate A approval before creating G0 evidence or a candidate.
- [x] Produce and validate the 71-path catalog and 70-regular-file checksum payload; `CHECKSUMS.sha256` remains self-excluded.
- [x] Complete the exact 17 G0 validator receipts: p0, schema, trace, marker, trust, command, publication, prompt, evidence, cleanup, assignment, canonical-argv, failure, integrity, authority, checksums-generate, and checksums-verify.
- [x] Obtain complete PASS evidence for `darwin-arm64`: native/local-POSIX plus all 11 platform probes.
- [x] Obtain provider readiness as all three families in runtime order `kimi`, `zcode`, `agy` × all 16 probes (**48 PASS**), three secure-writer indexes (**3 PASS**), and a live assignment receipt (**PASS**), before changing External Contract Readiness from `UNVERIFIED`.
- [x] Retain `linux-amd64`, `linux-arm64`, and `darwin-amd64` only as `intended_future`, non-blocking, unsupported, and release-ineligible inventory; they are not required G0 execution or release targets.
- [x] Treat provider/platform evidence v1 as byte-identical compatibility-only input; only v2 may enter readiness.
- [x] Post-verify the promoted authority candidate and record `g0_complete`.
- [x] Record the separate session-bound implementation approval before starting any item below.

- [x] Validate the v2 four-axis contract (`content_verdict`, `coverage_status`, `publication_status`, `ci_decision` with reasons) without collapsing one axis into another.
- [x] Validate separate source and current evidence identities; source evidence must never become current verified evidence.
- [x] Validate the deterministic six-role/provider assignment reducer, required floor, trusted project strengthening, and run-local non-weakening CLI selection.
- [x] Validate the four canonical provider/platform argv arrays, their domain-separated hashes, and bundle hash before any probe; legacy `--evidence-root` and `--index` are rejected.
- [x] Validate `timeout`, `auth`, `quota`, and `rate_limit` as `repair=none` and `fallback=allowed`; preserve the distinct exhausted-role projections.
- [x] Validate the publication classifier precedence and all ten named cross-boundary fixtures; persist a journal hint but serialize publication only from durable derived state.
- [x] Validate the 70-file payload root with the `KAR-SOT-PAYLOAD-ROOT/1` domain, UTF-8 bytewise path sort, NUL, raw 32-byte digest, and LF grammar.

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
- [x] Ensure product text never implies approval authority.

## G008 Completion Evidence and G009 Release Gate

- [x] All JSON examples pass their schemas.
- [x] Race detector passes coordinator and lane tests.
- [x] Crash tests show no partial final artifact.
- [x] Security tests show no fallback after security violation.
- [x] Retain real composed P2 end-to-end evidence covering root review, followup, delta, and rerun through injected provider authority; production standalone operation without canonical recorded provider/evidence authority remains fail-closed with schema-valid typed failures under G007's opt-in authority rules.
- [x] Complete the G007 opt-in live provider/version adapter contract item for exactly the authority-gated `kimi`, `zcode`, and `agy` adapters: direct noninteractive profiles, strict output isolation, process bounds/cancellation, tuple/base-argv evidence binding, strict unlisted-family rejection, provider CLI reporting, offline standard tests, and a controlled live exact Kimi tuple PASS for `local-default` 0.23.6 with binary SHA-256 `50c358...`; standalone absence of evidence remains `UNVERIFIED`, and all unavailable, failed, or inconclusive tuples remain unsupported.
- [x] No P0 issue remains in trust, cancellation, fallback, evidence, or publication through the G008 boundary.
- [x] Retain final full `go test`, `go vet`, race, checksums/generation/diff, cleaner, executor QA, and final architect-review receipts for G008. This completion does not authorize G009 or release.
