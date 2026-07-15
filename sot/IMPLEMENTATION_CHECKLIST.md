# KAR Conditional Implementation Checklist

This is a post-G0 development handoff index, not product implementation authorization. SOT 1.1.0 is Decision **READY**, Implementation **CONDITIONAL**, and External Contract **UNVERIFIED**. No product code, actual product/release CI job, or release asset may begin until `g0_complete` and a separate session-bound implementation approval exist.

## G0 Contract-Freeze Preconditions

- [ ] Record a valid session-bound Gate A approval before creating G0 evidence or a candidate.
- [ ] Produce and validate the 71-path catalog and 70-regular-file checksum payload; `CHECKSUMS.sha256` remains self-excluded.
- [ ] Complete the exact 17 G0 validator receipts: p0, schema, trace, marker, trust, command, publication, prompt, evidence, cleanup, assignment, canonical-argv, failure, integrity, authority, checksums-generate, and checksums-verify.
- [ ] Obtain complete PASS evidence for `darwin-arm64`: native/local-POSIX plus all 11 platform probes.
- [ ] Obtain provider readiness as all three families in runtime order `kimi`, `zcode`, `agy` × all 16 probes (**48 PASS**), three secure-writer indexes (**3 PASS**), and a live assignment receipt (**PASS**), before changing External Contract Readiness from `UNVERIFIED`.
- [ ] Retain `linux-amd64`, `linux-arm64`, and `darwin-amd64` only as `intended_future`, non-blocking, unsupported, and release-ineligible inventory; they are not required G0 execution or release targets.
- [ ] Treat provider/platform evidence v1 as byte-identical compatibility-only input; only v2 may enter readiness.
- [ ] Post-verify the promoted authority candidate and record `g0_complete`.
- [ ] Record the separate session-bound implementation approval before starting any item below.

- [ ] Validate the v2 four-axis contract (`content_verdict`, `coverage_status`, `publication_status`, `ci_decision` with reasons) without collapsing one axis into another.
- [ ] Validate separate source and current evidence identities; source evidence must never become current verified evidence.
- [ ] Validate the deterministic six-role/provider assignment reducer, required floor, trusted project strengthening, and run-local non-weakening CLI selection.
- [ ] Validate the four canonical provider/platform argv arrays, their domain-separated hashes, and bundle hash before any probe; legacy `--evidence-root` and `--index` are rejected.
- [ ] Validate `timeout`, `auth`, `quota`, and `rate_limit` as `repair=none` and `fallback=allowed`; preserve the distinct exhausted-role projections.
- [ ] Validate the publication classifier precedence and all ten named cross-boundary fixtures; persist a journal hint but serialize publication only from durable derived state.
- [ ] Validate the 70-file payload root with the `KAR-SOT-PAYLOAD-ROOT/1` domain, UTF-8 bytewise path sort, NUL, raw 32-byte digest, and LF grammar.

## P0 Contracts

- [ ] Implement separate domain states for run, role task, attempt, parse, validation, evidence, verdict, and finding lifecycle. See [Domain and State Model](docs/02-domain-and-state-model.md).
- [ ] Implement canonical UUIDv7 ID types and prefix validation.
- [ ] Implement `.kar/{session_id}/{run_id}/review_{uuidv7}.json` as the only final publication path. See [Artifacts](docs/08-artifacts-lineage-and-storage.md).
- [ ] Enforce at most one final review per run.
- [ ] Record final file SHA-256 in `manifest.json`.
- [ ] Keep completed runs immutable.
- [ ] Reject project-controlled executable provider configuration. See [Configuration](docs/04-configuration.md).
- [ ] Default provider workspace access to `none`. See [Security](docs/09-security-and-trust.md).
- [ ] Implement a central coordinator for dynamic fallback and terminal state.
- [ ] Ensure valid findings never trigger fallback.
- [ ] Ensure security, cancellation, configuration, artifact, and internal failures never trigger fallback.

## Provider Output and Repair

- [ ] Require JSON-only provider output.
- [ ] Validate provider output against versioned schemas.
- [ ] Apply meaningful-value checks in addition to key presence.
- [ ] Separate AI-owned and KAR-owned mandatory fields. See [Field Ownership Matrix](docs/16-field-ownership-matrix.md).
- [ ] Implement one constrained repair attempt by default.
- [ ] Support `reformat_only` and `fill_missing_fields` repair modes.
- [ ] Restrict patch paths to explicit `allowed_paths`.
- [ ] Prohibit overwrite of existing meaningful values.
- [ ] Preserve all raw and repaired outputs as immutable attempt artifacts.
- [ ] Run complete schema, semantic, and evidence validation after repair.

## Target and Evidence

- [ ] Resolve Git refs to immutable object IDs at capture time.
- [ ] Record staged, unstaged, and untracked scope explicitly.
- [ ] Implement target content SHA-256.
- [ ] Verify evidence path, side, lines, and quote against captured target.
- [ ] Require verified evidence for configured high severities.
- [ ] Generate excerpts inside KAR after verification.

## Runtime

- [ ] Use direct argv by default.
- [ ] Pass only allowlisted environment values.
- [ ] Separate stdout result bytes from stderr diagnostics.
- [ ] Enforce output and timeout limits.
- [ ] Kill complete process groups on cancellation.
- [ ] Serialize attempts by concurrency key.
- [ ] Add cross-process lane locking where supported.
- [ ] Implement fake providers before live adapters.

## Artifacts

- [ ] Use secure directory and file permissions.
- [ ] Use atomic replacement for mutable run status and manifest files.
- [ ] Use write, validate, fsync, and atomic rename for final review publication.
- [ ] Detect hash mismatch and multiple final files as corruption.
- [ ] Add safe cleanup and redacted export paths.

## CLI and CI

- [ ] Implement distinct review, followup, delta, and rerun application services.
- [ ] Make rerun create a child run, not mutate the source run.
- [ ] Keep review verdict separate from CI decision.
- [ ] Implement documented exit-code precedence.
- [ ] Add all required help topics and golden tests.
- [ ] Ensure product text never implies approval authority.

## Release Gate

- [ ] All JSON examples pass their schemas.
- [ ] Race detector passes coordinator and lane tests.
- [ ] Crash tests show no partial final artifact.
- [ ] Security tests show no fallback after security violation.
- [ ] Fake-provider end-to-end tests cover all four run types.
- [ ] At least one provider/version adapter contract passes in an opt-in environment.
- [ ] No P0 issue remains in trust, cancellation, fallback, evidence, or publication.
