# Artifacts, Lineage, and Storage

## 1. Canonical Root

KAR uses a standalone project-local root:

```text
.kar/
```

The canonical final artifact path is:

```text
.kar/{session_id}/{run_id}/review_{uuidv7}.json
```

There is no intermediate `runs/` directory in the canonical path.

## 2. Canonical Tree

```text
.kar/
  config.yaml
  cache/

  s_<session-uuidv7>/
    session.json

    r_<run-uuidv7>/
      manifest.json
      status.json
      request.json
      resolved-config.yaml
      config-sources.json
      target/
        target-manifest.json
        review-target.patch
        untracked-manifest.json
      prompt-summary.json
      aggregation.json
      report.md
      findings.json

      attempts/
        a_<attempt-uuidv7>/
          status.json
          candidate.initial.json
          candidate.repaired.001.json
          invocations/
            001-initial/
              command.json
              env.json
              status.json
              stdout.raw
              stderr.raw
              prompt/
                common.md
                run-type.md
                role.md
                role-run-overlay.md
                project-context.md
                user-objective.md
                objective-lint.json
                previous-context.json
                review-target.patch
                output-schema.json
                composed-prompt.txt
                prompt-manifest.json
            002-repair/
              command.json
              env.json
              status.json
              stdout.raw
              stderr.raw
              prompt/
                repair-request.json
                output-schema.json
                composed-prompt.txt
                prompt-manifest.json
          validation/
            validation.001.json
            repair-request.001.json
            repair-response.001.raw
            repair-patch.001.json
            validation.002.json

      excerpts/
        F001.md
        F002.md

      validation/
        final-validation.json

      review_<review-uuidv7>.json
```

See [artifact-tree.txt](../examples/artifact-tree.txt) for a complete example.

## 3. Directory Identity

Path components must satisfy:

```text
session_id: ^s_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$
run_id:     ^r_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$
attempt_id: ^a_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$
review_id:  ^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$
```

KAR additionally parses the UUID and verifies version 7. It rejects separators, `.` and `..`, non-canonical case, and symlink traversal.

## 4. Artifact Ownership

| Artifact | Owner | Mutable during run | Mutable after run terminal state |
|---|---|---:|---:|
| `status.json` | KAR | Yes, atomic replacement | Final write only |
| Attempt raw output | Runtime | Bounded memory or quarantined secure temporary storage until scan acceptance | No |
| Validation records | Validator | New immutable files | No |
| `manifest.json` | Artifact store | Atomic replacement until sealing | No |
| `review_*.json` | Publisher | No partial visibility | No |
| `report.md` | Reporter | Generated before sealing | No |
| Source run artifacts | Source run | No | No |

A new followup, delta, or rerun never modifies source run files.
G008 implements immutable child/source lineage: a child run references validated immutable source artifacts and immutable lineage-edge bytes; it never adopts, rewrites, or deletes source-run bytes.

After child execution and before publication, followup, delta, and rerun independently reread and validate their immutable source authority. A reread failure, validation mismatch, or changed source identity or bytes is a security-policy failure: KAR publishes no child P2 result and projects exit `8`.

## 5. Session Metadata

`session.json` records:

```json
{
  "schema_version": "kar-session.v1",
  "session_id": "s_019f596a-cf80-7c67-b265-f37053d51ccf",
  "created_at": "2026-07-13T03:00:00Z",
  "root_run_id": "r_019f596a-cfe4-7c9c-b82e-7149158243ba"
}
```

It is immutable after creation. Session run discovery comes from validated run manifests, not from editing an ever-growing session file.

## 6. Run Manifest

`manifest.json` is the run index, publication journal, and integrity record. The v2 manifest records session and run IDs, run type and lineage references, immutable target identity, selected and required roles, attempt references, artifact schema versions, final review path/SHA-256 or `null`, and the four outcome axes:

```text
content_verdict
coverage_status
publication_status
ci_decision
```

It also records `persisted_journal_state`, `derived_publication_status`, expected staged/final path and hash where recovery requires them, and references to the immutable manifest, lineage-edge, and epoch observations. `persisted_journal_state` is only a recovery hint; reader authority and serialized `publication_status` come only from the durable classifier.
For G008 child runs, lineage edges are immutable, content-addressed child-to-parent records installed with the manifest in the composite publication transaction. Source target, prompt, and attempt bytes remain source-owned immutable bytes; a child may reference them or persist its own newly captured immutable bytes, but may not mutate either set.

Schemas:

- [Run manifest v2 schema](../schemas/kar-run-manifest.v2.schema.json)
- [Final review artifact v2 schema](../schemas/kar-review-artifact.v2.schema.json)

## 7. Final Review Artifact
A completed successful or policy-valid degraded run has at most one canonical final review file:

```text
review_{review_id}.json
```

The filename UUIDv7 reflects publication time. Programmatic ordering uses `created_at` and the UUID as a tiebreaker. The review artifact does not contain its own whole-file hash; the committed manifest records `review_id`, relative path, and SHA-256 to avoid self-reference. A followup, delta, or rerun never modifies source-run files.

The hash graph is acyclic. The final review does not embed the manifest whole-file hash; the manifest does not embed its own whole-file hash or the epoch whole-file hash. The manifest may carry the predetermined epoch path and immutable lineage-edge hash. Only the separately written epoch record references the completed manifest and lineage-edge hashes.

## 8. UUIDv7 and Ordering

UUIDv7 provides:

- globally practical uniqueness;
- embedded millisecond timestamp;
- convenient lexical grouping by creation time.

It does not replace:

- `created_at` for human and programmatic timestamps;
- coordinator `sequence` for exact same-run event ordering;
- SHA-256 for integrity;
- monotonic-clock durations for timeout and performance metrics.

Clock rollback must be recorded as a warning. An implementation may use a monotonic UUIDv7 generator within one process, but it must still persist real timestamps separately.

## 9. Atomic Writes and Composite Publication

Immutable publication uses a no-replace protocol only: resolve the destination directory from an anchored, no-symlink `dirfd`; create a same-directory, exclusive `0600` temporary file; scan and validate the complete serialized bytes; fsync the file; atomically install it with no replacement; fsync the containing directory; then clean up any remaining temporary entry and fsync that directory again. A destination collision, path-safety failure, scan/validation failure, or install failure fails closed and never replaces an immutable file. Only mutable run-state files may use complete atomic replacement; in-place partial updates are prohibited.

Every newly persisted untrusted byte channel first uses the shared secure writer in [Security and Trust](09-security-and-trust.md#8-shared-scan-before-write). Before scan acceptance, provider raw output remains only in bounded memory or quarantined secure temporary storage; it is never append-visible, reader-visible, or published. A secret match immediately purges the buffer and quarantined temporary bytes, returns exit `8`, and forbids repair, fallback, and publication. The normal immutable-publication protocol applies only after the writer accepts the bytes.

The secure-writer acceptance/install transition and composite publication transaction are serialized under one store-user lock and epoch:

```text
validate and fsync manifest temp and lineage-edge temp
-> atomically install both immutable members with no replacement
-> fsync their directory
-> write epoch record referencing both immutable member hashes
-> fsync epoch record and directory
```

A reader exposes a final review as published only through the valid epoch record. A final filename, manifest, or lineage edge by itself is not publication authority.

Every production root or child publication obtains its next root-scoped epoch atomically from the publication store and commits under that store-authorized transaction. Production publication must not derive authority from a process-local epoch counter. A store that cannot provide the atomic next-epoch contract fails closed before publication.

## 10. File Permissions and Git Ignore

Recommended defaults on Unix-like systems are `0700` for `.kar/` and session/run directories, and `0600` for artifact files. KAR warns when the artifact root is group- or world-readable. Artifacts may contain proprietary code, secrets, personal data, or internal paths.

`kar init` proposes:

```gitignore
.kar/
```

`kar init` never edits ignore files. Operators should ignore the entire private `.kar/` namespace; configuration, captured context references, prompt packets, and run artifacts are never versioned authority.

## 11. Retention, Export, and Transitive Protection

Deletion operates only below the validated artifact root, never follows symlinks, and uses the same store lock as secure-writer publication. A redacted export creates a new secure-writer package and never mutates original evidence, grants publication authority, or authorizes release.

A clean plan obtains `retention_age`, `min_age_for_size`, `target_bytes`, and explicit keep IDs from resolved retention policy; it freezes those resolved values with fixed `now` and store epoch `E0`.

```text
explicit keep IDs
∪ active runs
∪ uncommitted runs
∪ corrupt runs
∪ newest completed run per session
```

Each lineage edge is directed `child → parent ancestor`. A known valid edge has schema-valid child and parent IDs whose validated run manifests both exist. The retained seed adds the directed transitive ancestor closure over known valid edges: repeatedly follow each `child → parent` edge from every retained seed run.

For every non-dangling graph anomaly, every known endpoint and every identified anomaly run is an anomaly seed. KAR then protects the undirected transitive closure of those anomaly seeds over known valid edges, treating each such edge as connected in both directions. If any edge has a dangling or unknown endpoint, KAR fails closed by protecting the whole store and emitting no deletion action. Missing or invalid completion time is protected. These set operations use validated run IDs and canonical lexical ordering, so identical validated inputs produce the same protection closure. Reasons are exactly:

```text
protected_explicit
active
uncommitted
corrupt
newest_session
ancestor
graph_anomaly
missing_time
young
eligible_age
eligible_size
deleted_age
deleted_size
target_not_reached_protected
stale_epoch
partial_delete_resume
```

The `age_delete_set` contains completed, unprotected runs with `completed_at < now-retention_age`. The `size_delete_set` contains completed, unprotected runs not in the age set with `completed_at <= now-min_age_for_size`. Each set is ordered by `(completed_at UTC epoch nanos ascending, run_id UTF-8 ascending)`. Apply all age deletions first, then ordered size deletions until regular-file `lstat` bytes after planned deletions are no greater than `target_bytes`.

Dry-run emits the canonical clean-plan with its exact resolved-policy inputs, `E0`, ordered actions, reasons, edge references, byte accounting, and plan hash. Apply accepts the request's exact `expected_plan_sha256` and requires that hash, unchanged `E0`, and unchanged input policy; otherwise it fails as stale with exit `7`. Apply executes only the listed actions and never recomputes eligibility. Tombstone commit precedes deletion; restart resumes the tombstone; an unjournaled partial directory is protected as corrupt. Explain renders the same machine plan plus deterministic human rows.

`plan_hash` has one canonical, non-self-referential preimage. Construct `plan_hash_input` by removing the top-level fields `mode`, `plan_hash`, and `apply_identity` from the schema-valid clean-plan object. Serialize the remaining object as RFC 8785 canonical JSON UTF-8 bytes with no trailing newline, then compute:

```text
plan_hash = "sha256:" + lowercase_hex(
  SHA-256(ASCII("KAR-CLEAN-PLAN/1") || 0x00 || rfc8785_bytes(plan_hash_input))
)
```

Dry-run and explain therefore identify the same ordered plan. Apply supplies the dry-run hash through the frozen request field `expected_plan_sha256` and must verify that hash, the unchanged store epoch, and the unchanged input-policy hash before any tombstone or deletion.

## 12. Publication State Inputs

`persisted_journal_state` is a last-fsynced hint, with exactly these values:

```text
collecting
content_validated
final_staged
final_file_installed
manifest_committed
completed
```

`derived_publication_status` is recomputed on every recovery and is exactly `not_published`, `staged`, `installed`, `committed`, or `corrupt`. Serialized `publication_status` equals this derived result; it is never copied from the journal hint.

Durable observations normalize to these classes:

- `P2_COMMITTED`: a valid composite epoch record references matching immutable manifest and lineage-edge hashes; manifest state is committed; exactly one canonical final path exists; and the file SHA-256 equals the manifest.
- `P1_INSTALLED`: P2 is absent; exactly one canonical installed final is schema-valid and matches recovery-journal expected path and hash; composite commit is absent.
- `P0_STAGED`: P2 and P1 are absent; exactly one complete schema-valid staged temporary file matches the recovery-journal expected hash; no installed final exists.
- `P0_NONE`: no P2, P1, or P0 staged observation exists and no forbidden partial or multiple artifact exists.
- `AMBIGUOUS_OR_MISMATCH`: any multiple final or temp, manifest/edge/epoch mismatch, path/hash/schema mismatch, installed final without journal expectation, staged-plus-installed conflict, committed final missing, symlink, non-regular file, or path escape.

`P1_INSTALLED` and `P0_STAGED` require the expected path and hash in the recovery journal. A valid-looking file without them is `AMBIGUOUS_OR_MISMATCH`. P1 and P0 are recovery authority only; only P2 is publication authority.

## 13. Publication Authority and Recovery

The classifier takes the persisted hint, journal expected path/hash, staged and final observations, and manifest/edge/epoch observations. It applies exactly one ordered rule:

1. Any `AMBIGUOUS_OR_MISMATCH` produces `derived_publication_status=corrupt`, no authority, an immutable diagnostic, and exit `7`.
2. A complete `P2_COMMITTED` produces `committed` with P2 authority regardless of the hint. KAR reconstructs only mutable status/journal state and returns the stored normal outcome projection `0`, `1`, or `4`.
3. Without P2, `P1_INSTALLED` produces `installed` with P1 recovery authority regardless of the hint. Under the store lock, KAR idempotently completes the manifest, edge, and epoch composite commit, then reclassifies. Success returns final `0`, `1`, or `4`; an artifact failure returns `7`.
4. Without P2/P1, `P0_STAGED` produces `staged` with P0 recovery authority regardless of the hint. KAR revalidates, fsyncs, and atomically installs the temp, then follows rule 3. Success returns final `0`, `1`, or `4`; an artifact failure returns `7`.
5. With `P0_NONE`, `collecting` resumes collection and `content_validated` or `final_staged` recreates a stage from the immutable validated candidate. `final_file_installed`, `manifest_committed`, or `completed` without required durable effects is `corrupt`, exit `7`. Typed role/run failure during low-hint resume retains its typed exit.
6. Every remaining combination is `corrupt`, exit `7`.

The precedence is therefore `ambiguity/mismatch > valid P2 > valid P1 > valid P0 staged > P0-none hint recovery > corrupt default`. It is total and fail-closed: recovery never promotes a glob match, regenerates installed/final/completed bytes, deletes an ambiguous installed file, or lets a low hint downgrade valid P2/P1/P0 durability.

Normal persisted-state pairings are `collecting` and `content_validated` with P0_NONE/`not_published`, `final_staged` with P0_STAGED/`staged`, `final_file_installed` with P1_INSTALLED/`installed`, and `manifest_committed` or `completed` with P2_COMMITTED/`committed`. A higher valid durable class is recovered by the classifier; an absent required durable effect or conflict is corrupt.

The required cross-boundary cases are:

| Fixture ID | Durable observation and derived status | Required action and exit |
|---|---|---|
| `pub-cross-content-validated-staged-temp` | `content_validated` hint with valid P0 staged temp; `staged`, P0 | install, composite commit, reclassify P2; final `0`, `1`, or `4`, artifact failure `7` |
| `pub-cross-final-staged-installed-final` | `final_staged` hint with valid P1 final; `installed`, P1 | composite commit, reclassify P2; final `0`, `1`, or `4`, failure `7` |
| `pub-cross-final-installed-composite-commit` | `final_file_installed` hint with valid P2; `committed`, P2 | reconstruct mutable completed status only; `0`, `1`, or `4` |
| `pub-cross-manifest-committed-completed-side-effect` | `manifest_committed` hint with valid P2 and completed status already written; `committed`, P2 | verify or reconstruct status idempotently; stored `0`, `1`, or `4` |
| `pub-cross-hint-low-valid-p2` | `collecting` or `content_validated` hint with valid P2; `committed`, P2 | reconstruct status; no republish; stored `0`, `1`, or `4` |
| `pub-cross-staged-and-installed-conflict` | conflicting staged and installed bytes or multiples; `corrupt` | diagnostic only; no adoption or deletion; `7` |
| `pub-cross-p2-manifest-edge-mismatch` | incomplete or mismatched composite members; `corrupt` | diagnostic; final is untrusted; `7` |
| `pub-cross-completed-missing-final` | `completed` hint with epoch/manifest but missing final; `corrupt` | diagnostic; do not rewrite completed bytes; `7` |
| `pub-cross-final-installed-no-journal` | installed final with missing expected hash/path; `corrupt` | no adoption or regeneration; `7` |
| `pub-cross-p0-none-impossible-high-hint` | `manifest_committed` or `completed` hint with P0_NONE; `corrupt` | immutable diagnostic; `7` |

## 14. General Crash Recovery

At startup or `kar doctor artifacts`, KAR also reports abandoned running ownership, leftover temporary files, missing manifest references, final hash mismatches, and multiple top-level final names through the classifier. Recovery never fabricates a valid final review. It preserves immutable completed bytes, records a diagnostic, and offers a new rerun path when the durable facts are not authoritative.

## 15. G0 Gate Archive Resolution

The G0 receipt index keeps the canonical current Gate paths under `.gjc/_session-<session-id>/evidence/g0/gates/`. Those paths are mutable current pointers, not immutable historical storage. Every Gate issuance acquires one exclusive Gate-issuance lock through an anchored, no-symlink directory descriptor; all lock, current-pointer, archive, and receipt access is relative to that descriptor. Issuances are therefore serialized, and any lock, path, hash, or persistence failure fails closed with artifact exit `7`.

Before replacing a current Gate, the issuer reads its exact old bytes and verifies the supplied expected old SHA-256. That old-hash CAS is checked again immediately before pointer replacement. Before either CAS check can permit replacement, the issuer must archive the byte-for-byte old Gate and immutable copies of every mutable bound input under `gates/archive/<old-sha256>/`, using exclusive `0600` temporary files, file fsync, atomic no-replace installation, and archive-directory fsync. It then writes `gates/archive/<old-sha256>/resolution.json` by the same protocol; this receipt binds the archived Gate name/path/hash to the immediate successor Gate path/hash. An existing archive or resolution path is a collision, not a replacement opportunity.
The archived Gate retains its original canonical pointer fields so its bytes and hash remain unchanged. Verification derives immutable bound-input locations rather than rewriting those fields: Gate A1 manifests and P0 impact use `gates/archive-inputs/<input-sha256>/<canonical-basename>`; Gate A2 uses its immutable candidate evidence manifest, `gates/archive-inputs/<tool-lock-sha256>/tools.lock.json`, and `gates/archive/<gate-a1-sha256>/gate-a1.json`. The issuer create-once snapshots each derived input before pointer replacement. Bound-input inventories are exact, ordered by their contract definitions, and reject missing, extra, duplicate, path, hash, or schema mismatches before following a successor.

Archive fallback also requires one immutable candidate-specific `$CANDIDATE_ROOT/gate-archive-authority.json`, because multiple candidates may share the same Gate hash. Its exact schema is `kar-gate-archive-authority.v1`, with `candidate_oid`, `status="superseded"`, `promotion_authorized=false`, and the exact `authority_path` under `$CANDIDATE_ROOT`. It binds immutable candidate `receipt_index_path`/`receipt_index_sha256`/`receipt_index_root_sha256`, `readiness_path`/`readiness_sha256`, `scope_invalidation_path`/`scope_invalidation_sha256`/`scope_invalidation_reason`, and Architect and Critic review paths, hashes, verdicts, and reasons. Its exact `gate_entries` array has at most one entry per Gate and at most two entries total. Each entry must bind that candidate receipt index's initial Gate hash, archived path, first resolution path/hash, and immediate successor hash; unrelated, duplicate, or non-initial entries are invalid. The document is immutable and must never be extended for a future issuance. Every path and hash must resolve to immutable candidate or archive bytes, the candidate must be non-active and promotion-unapproved, and the initial Gate successor must match `resolution.json`. A diagnostic, absent, inferred, mutable, promotion-authorized, or candidate-mismatched record is not fallback authority.

Under the issuance lock, the issuer computes the successor bytes/hash first, writes the old Gate archive and `resolution.json`, then creates each newly superseded candidate's `gate-archive-authority.json` with that initial successor hash. Later issuances must not create, replace, or extend that authority. Only after those immutable writes and directory fsyncs succeed, and the second old-hash CAS still matches, may it atomically replace the mutable current pointer and fsync its directory. No pointer changes after a collision or failed step.

Receipt-index verification always tries the canonical Gate path first. A matching live file hash is authoritative. If the live hash differs, fallback requires the candidate's valid `gate-archive-authority.json` entry only for the initial candidate-bound archived Gate hash, plus the exact immutable global `resolution.json` hash-chain at every hop. Verification follows successor hashes until the live Gate hash; later hops are authorized by their preceding immutable `resolution.json`, not by extending the candidate authority. The chain must be complete, acyclic, and free of trailing entries. The exact 27-entry `(kind,path,sha256)` receipt-index cardinality is independent of archive depth and remains 27; archive traversal permits at most 32 hops, and issuance must reject a 33rd hop before writing an archive, candidate authority, or pointer. Archive fallback for an active candidate is always artifact corruption with exit `7`. A missing archive, initial authority, or resolution, mismatched path/candidate/hash/successor/bound input, malformed or diagnostic record, broken chain, cycle, trailing hop, or excessive depth also exits `7`.

This protocol never overwrites an old receipt, selects an archive by glob, treats an archive as current authority, or restores a superseded candidate.
