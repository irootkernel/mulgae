# Historical corpus provenance

Source commit: `ce88495ad339e7b3b7fcf47cc8c9313939cf496d`.
Its runtime sources match `d690af17dc334222425710821a458972882a828f`; the
intervening commit changes only the Epic verification profile documentation.

All source payloads, review messages, provider identities, images and prompts
are invented test inputs. No existing source archive, transcript, credential or
real review supplied any bytes. The PNG is the established one-pixel synthetic
fixture from `publication/serialization_test.go`. Text includes precomposed
`café`, decomposed `e\u0301`, Korean text, CRLF and terminal LF.

## One-time production

Temporary Go tests ran through Go overlays against the source commit. No
exporter, generator or update mode is retained in this package.

| Temporary symbol | Current helper or producer used |
|---|---|
| `TestTask060ExportPublication`, `task060Archive`, `task060Candidate`, `task060Save` | `publicationRuntimeCandidate`, `publicationTestCandidate`, `publicationCapturedNoChangeCandidate`, `ports.MarshalCapturedReviewMaterial`, `PreparedCandidate.WithCapturedMaterial`, `PreparedCandidate.Build`, `Service.Publish` |
| `TestTask060ExportLineage` | `NewChildPublicationContext`, fixed typed candidates, `Service.Publish` |
| `TestTask060ExportRecovery`, `TestTask060ExactClosure` | `failedRecoveryCoordinator`, `PrepareFailedRunRecovery`, `failedRecoveryTerminalReceipt`, `Service.PersistFailedRunRecovery`, `NewRecoveryRerunPublicationContext` |
| `TestTask060ExportComposite` | `copiedCompositeMixedEvidenceInput`, `query.Service.ReadCompositionSupport`, `compositesupport.RetainCapture`, `PrepareCompositeCandidate`, `Service.PublishCompositeNext` |
| `TestTask060ExportFollowup` | `newG008RealE2EFixture`, `executeAndPublishRoot`, `buildHistoricalChildFixture`, `buildHistoricalFollowupFixture` |
| `TestTask060ExportLegacyArchive` | `ports.MarshalCapturedReviewMaterialV1`, followed by JSON indentation and a final LF |
| `TestTask060EstablishExpectedConsumers` | Real-schema query reads, `report.Service.Render` and `NewRedactedExportService`; fixed report, ZIP and reconstructed-archive digests |

Publication fixtures use `publicationTestTime()`:
`2026-07-13T03:00:00.5Z`. Followup fixtures use the G008 clock:
`2026-07-14T12:00:00Z`. Expected export identity/time uses the deterministic
`g008RealE2EIDs` issuer starting at zero and `2026-10-24T00:00:00Z`.
The corpus records every exact session/run/review ID, attempt, epoch and logical
path. The fixed publication review ID is
`019f596a-d174-7321-b920-c2d312c82cc2`; lineage children use suffixes `b1`,
`b2`, `b3`, and recovery/composite fixtures use `b8`/`b9` in the corresponding
`019f596a-cfe4-7c9c-b82e-7149158243..` IDs. G008 and failed-recovery helpers
use their existing deterministic issuers.

## Deliberate fixture transformations

- Typed ordinary candidates omit synthetic attempt captures before publication.
  The followup builder requires a complete synthetic stdout observation. After
  that one-time publication, all attempt artifacts are removed from the frozen
  reader inputs, their support-index entries are removed, and affected digest
  references are rebound. No provider transcript enters the corpus.
- Legacy archive bytes are deliberately indented. Their support index is v1;
  complete-capture manifests and split blobs are absent. The target manifest,
  support index, run manifest and epoch bind the frozen v1 bytes.
- Integrity variants delete a member, tamper with bytes without rebinding, or
  rebind outer hashes around a wrong target, noncanonical artist path, unknown
  field or contradictory lineage. Their records distinguish these operations.
- The exact failed-rerun variant represents retained historical lineage using
  the generated recovery root, its original stdin/template/source scope, a
  selected failed role and fresh run/attempt/execution IDs (suffix `b7`).
  `failedRecoveryTerminalReceipt` supplies the matching synthetic closure
  receipt for that new run. Its
  synthetic stored document is constructed once because current public
  execution does not create historical failed reruns. Matching parent/hash,
  input and lineage acceptance is established by the real-schema recovery
  reader. Missing-manifest/blob, tampered-blob, foreign-scope and wrong-parent
  variants preserve their distinct rejected or unavailable outcomes.
- Changed outer publication records retain the Go encoder's field order and
  terminal LF. The archive representation exception applies only to the legacy
  archive. Publication recovery continues to enforce canonical outer documents.
- A native filesystem digest refusal reports `runtime artifact read failed`;
  the in-memory store can return a changed artifact, which the query layer
  rejects as `runtime artifact identity drifted`. The records preserve each
  operation boundary's existing reason.
- Expected consumer hashes are fixed after these transformations. Tests do not
  derive expectations from removable writers. ZIP hashes preserve the complete
  allowlisted bundle; native secure-writer sidecar receipts are checked through
  the installer rather than compared across temporary filesystem identities.

Digest domains stay distinct: file/blob hashes use raw SHA-256; complete stdin
uses `Mulgae-PROVIDER-STDIN/1\0`; capture identity binds
`mulgae-capture-manifest.v1\0` plus canonical capture bytes; composition uses
`mulgae-review-composition-v1\0` or `mulgae-review-composition-v2\0`.
Source and current excerpt digests retain their existing coordinate domains.

## Temporary source identities

These hashes identify the one-time sources, including test-local overlay copies.
They are an audit trail, not a requirement to retain or rerun the exporters.

| Temporary source | SHA-256 |
|---|---|
| `export_publication_test.go` | `751993e52b48c517d0598d2efee0b0c643a27420552644d5696e7aa52365eb51` |
| `export_followup_test.go` | `0884d9b57d4b05523529b1e84a1473c71ce71971d9aba183c9af539f3667228a` |
| `historical_child_fixture_test.go` | `42d46eda107494e2d565b40726accaf4e9651d28e7fba4832f4ac674c7530a77` |
| `g008_real_e2e_support_test.go` | `2861a81116144d6b0eb2a126371487d47ac7cf284c8593dca9c2dbf37e06eda2` |
| `freeze.py` | `4aa47fc390c10625f50742dc3a0e8d0f5377f2d7874b385e1ef4f1df60999f3a` |
| `expected_test.go` | `08d19b1f23aa837442825531337391625345a8621f9212b4a0c0cb5125769376` |

## Correction 1: committed attempts

The correction starts from C1 (`241cbefa0386922c6091588a37819ebb0c8aa4d4`)
on the same source commit. `TestTask060CorrectionBaseline` reads every attempt
in the eleven applicable published fixtures through real-schema
`query.Service.ReadCommittedAttempt`. It records the returned session, run,
review and attempt IDs, role/provider, prompt manifest path/hash, raw stdin
hash, complete-stdin identity and template identity. The selected frozen stdin
member supplies the byte comparison. No removable writer generates an
expectation. `ResolveCommittedAttempt` supplies the recorded ordinary/child
role/provider selections and no-match refusals. Kimi attempt reads retain
`retired_provider_artifact`.

Temporary `construct.py` clones ordinary-v2 into four synthetic controls:

- `attempt-missing-prompt` removes the first bound prompt manifest while keeping
  its index entry; the read fails with `runtime artifact read failed`.
- `attempt-tampered-stdin` changes the first stdin byte without rebinding its
  stored identity; the in-memory read fails with
  `runtime artifact identity drifted`.
- `attempt-wrong-prompt-role` replaces the logic prompt's role with security.
- `attempt-wrong-complete-stdin` replaces its complete-stdin identity with 64
  zeroes, keeping the raw stdin unchanged.

The last two controls rebind the prompt references in the target inventory,
then the support index, run manifest and epoch manifest hash. They preserve
canonical outer field order and terminal LF. Baseline reads reach
`runtime prompt manifest binding is invalid` and
`runtime complete stdin identity is invalid`, respectively. The untouched
second attempt remains readable in each control. Session/run/attempt IDs,
clocks and all other inputs stay those of ordinary-v2.

`TestTask060CorrectionConsumerBaseline` establishes the new controls' native
read/report/export/runtime-target results with the same deterministic export
identity and clock. The frozen `attempts` and `attempt_selectors` record fields
are consumed strictly; no update mode is retained. Both temporary Go tools use
only existing corpus bytes and readers. Their overlays and construction tool
are removed before final verification.

| Temporary correction source | SHA-256 |
|---|---|
| `construct.py` | `473113cc8dc3a9956cf490978197d7aa409b31c673c3c98d574212484b50c0f2` |
| `attempt_baseline_test.go` | `0438707a25b4b35f86031abd4fd79c24e4c71440cb6babecc445f474d331a67a` |
| `consumer_baseline_test.go` | `3490cff597733237b1a2c390792b41e94af607a032627d9b83c71355db8e9f90` |
