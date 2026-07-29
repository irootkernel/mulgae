# Reporting, CI, and Exit Codes

## 1. Reporting Surfaces

Mulgae exposes four related outputs:

| Output | Purpose | Source of truth |
|---|---|---:|
| `review_{uuidv7}.json` | Stable final machine contract | P2 committed only |
| `findings.json` | Convenient normalized finding index | Derived |
| `aggregation.json` | Role coverage, attempt selection, deduplication, and verdict inputs | Derived |
| `report.md` | Human-readable review | Derived |

Raw provider output is execution provenance, not verified review evidence. `consensus.json` is not used in the default primary/fallback strategy.
Current implementation status is `RELEASE_READY`: G013 passed deterministic acceptance, the login-recovering exact-binary root/child workflow, and subsequent live family capability coverage on the exact committed tree. G012 and prior integrated-gate evidence are historical and are not the current acceptance predicate. Release CI, asset creation, and publication remain separately approved actions.

## 2. Final Review Contents

A reader treats `review_{uuidv7}.json` as a final machine contract only when the durable publication classifier reports `publication_status=committed`. The v2 final artifact includes:

- schema version;
- session, run, and review identity;
- run type and lineage references;
- immutable target identity;
- selected and completed role coverage;
- normalized validation summary;
- `content_verdict`, `coverage_status`, `publication_status`, and `ci_decision`;
- role result summaries and attempt references;
- normalized findings with source and current evidence verification;
- limitations and degradation reasons; and
- Mulgae and adapter provenance.

Schemas:

- [mulgae-review-artifact.v1.schema.json](../schemas/mulgae-review-artifact.v1.schema.json)
- [mulgae-run-manifest.v1.schema.json](../schemas/mulgae-run-manifest.v1.schema.json)
- [mulgae-validation-result.v1.schema.json](../schemas/mulgae-validation-result.v1.schema.json)

## 3. Human Report Structure

Recommended `report.md` sections:

```text
1. Run summary
2. Target and lineage
3. Outcome axes and CI decision
4. Required role coverage
5. Findings ordered by severity
6. Followup resolution when applicable
7. Limitations and degraded coverage
8. Provider and attempt provenance
9. Validation and repair summary
10. Artifact references
```

Every finding section should include:

```text
finding ID
severity
role
provider instance
concise title
explanation
verified evidence excerpt or verification status
recommendation
source attempt reference
```

The report must not imply organizational approval.

## 4. Aggregation

Aggregation performs deterministic collection, validation-aware selection, and deduplication. It does not claim that different roles reached consensus.

Default rules:

1. Use the first valid terminal attempt for a role task according to primary/fallback state.
2. Retain primary failure provenance when fallback succeeds.
3. Normalize findings from valid selected attempts.
4. Group likely duplicates using fingerprint and evidence overlap, while retaining all source roles and providers.
5. Never discard a higher-severity source finding solely because another provider described it differently.
6. Record every merge or deduplication decision in `aggregation.json`.

A future explicit comparison strategy may produce provider agreement metrics. That is separate from default fallback execution.

## 5. Four Outcome Axes

Mulgae serializes four independent fields. They are never collapsed into a single verdict and a failure in one axis does not erase another.

| Field | Exact enum | Meaning and owner |
|---|---|---|
| `content_verdict` | `no_findings`, `findings_present`, `request_changes` | Aggregation of validated findings |
| `coverage_status` | `complete`, `degraded`, `incomplete` | Coordinator coverage reducer |
| `publication_status` | `not_published`, `staged`, `installed`, `committed`, `corrupt` | Durable publication classifier |
| `ci_decision` | `pass`, `fail` | Trusted CI policy projection with reason codes |

At the trusted default threshold, a `high`, `critical`, or `blocker` finding gives `content_verdict=request_changes`; lower validated findings give `findings_present`; no validated findings give `no_findings`. `content_verdict` is content, not a claim of complete coverage.

`coverage_status=complete` requires every selected role to have a valid policy-satisfying result. `degraded` permits a valid policy-permitted limited result; `incomplete` means any selected role is exhausted or lacks a valid result. A lane failure does not delete content: a valid high finding plus another selected-lane failure is serialized as `request_changes` and `incomplete`.

`publication_status` is derived from `persisted_journal_state` and durable observations, not from file existence. `persisted_journal_state` is exactly `collecting`, `content_validated`, `final_staged`, `final_file_installed`, `manifest_committed`, or `completed`; it is a hint only. `derived_publication_status` determines serialized `publication_status`. Only a valid P2 composite epoch, manifest, lineage edge, canonical final path, and matching final hash yields `committed`. P1 installed and P0 staged are recovery states, not publication. The complete P2 > P1 > P0 classifier is defined in [Artifacts, Lineage, and Storage](08-artifacts-lineage-and-storage.md#13-publication-authority-and-recovery).

`ci_decision` is computed from the other validated axes and trusted CI policy; it is exactly `pass` or `fail`. It can fail a valid `request_changes` result and can fail a policy-degraded result when `degraded_review_fails=true`. It cannot change content, coverage, or publication values.

## 6. CI Projection and Reporting

CI evaluates only a reader-visible P2 committed artifact. A valid P2 recovery returns the stored outcome projection `0`, `1`, or `4`; a crash after a durable P2 commit never becomes exit `7`. P1/P0 recovery finishes publication idempotently before final projection. Ambiguity, hash/schema mismatch, missing composite member, missing required journal expectation, or recovery artifact failure is exit `7`.

The default trusted policy is:

```yaml
ci:
  fail_on_severity:
    - high
    - critical
    - blocker
  degraded_review_fails: true
  incomplete_review_fails: true
```

Any exhausted selected role yields `coverage_status=incomplete`; it preserves valid content, fails the run, and returns exit `4` rather than being relabeled as an ordinary CI rejection. A valid limited result may yield `coverage_status=degraded` and project to `ci_decision=pass` or `fail` under trusted policy. Source/current evidence remains visible with its exact `verification` state; a source reference is never displayed as current `verified` evidence.

CI configuration comes from the admitted project-local `.mulgae/config.yaml`. Code-fixed safety floors remain invariants and cannot be weakened by configuration or interactive input.

## 7. CI Projection

CI is a trusted policy projection of a committed review artifact, not a `review` command mode. Automation invokes the same documented review command and consumes its committed outcome and JSON command-result envelope.

```text
human: render the command's human result and return its final operational status
json: emit the command-result envelope to stdout
CI: evaluate the committed artifact's trusted content, coverage, finding, and degradation policy
```

There is no `review --ci` flag and no CI request field. CI stdout stays concise. Detailed artifacts and all reason codes belong under `.mulgae/` or an explicitly requested secure export.

## 8. Exit Projection

| Code | Meaning |
|---:|---|
| `0` | A P2 committed valid result has `ci_decision=pass`; coverage is complete or trusted policy permits degraded coverage |
| `1` | A P2 committed valid result has `ci_decision=fail` because trusted finding or degraded policy rejected it |
| `2` | Usage, configuration, or trust-policy error, including rejected project weakening and every CI dangerous flag |
| `4` | Readiness is unverified where required, or allowed repair/fallback leaves required coverage `incomplete` |
| `7` | Artifact read/write/integrity/publication failure, including a corrupt publication classifier result |
| `8` | Security policy violation, including secret exposure or source mutation |
| `9` | User or parent-process cancellation |
| `10` | Mulgae internal error or invariant violation |

Private target admission uses the exact exit-8 reason `target_private_config_forbidden` for `.mulgae/config.yaml` and `target_private_namespace_forbidden` for `.mulgae` or any other descendant. The diagnostic never includes the rejected path bytes.

Exit `3` is not a typed G0 outcome and is reserved. The manifest records every observed failure and reason code even when one exit is selected.

An unresolved provider `login_required` is a pre-publication readiness failure at exit `4`, not an ordinary committed incomplete review. Machine output uses reason code `provider_login_required`, sets `retryable=false`, and names every affected configured provider instance in the safe message. Human output names the same providers. No P2 URI is returned. Kimi qualification alone may first perform one bounded native `kimi login` and one fresh qualification; repeated Kimi login requirements and every ZCode/AGY or execution-time login requirement retain this terminal behavior.

Other operational current-qualification rejection uses exit `4` and reason code `provider_qualification_failed`. Human and machine messages list each affected configured provider instance with only its closed safe reason code, set `retryable=true`, expose no P2 URI, and contain no raw provider output. A qualified candidate that is not required by any selected primary or fallback assignment does not fail the run merely because another configured candidate was rejected; exact selected assignments remain the authority.

A coordinator security-policy, configuration, artifact, internal, or cancellation stop is non-publishable. Mulgae projects its typed failure before P2 preparation, drains provider and workspace authority, and returns no P2 URI. It must not pass cancelled or blocked peer roles to publication and then collapse the resulting invariant error into generic readiness.

For a non-publishable provider execution stop, machine output uses reason code `provider_execution_failed`, preserves the highest-precedence typed exit, sets `retryable=false`, and names every unsuccessful lane's affected provider instance with only its closed attempt-condition code. Operational predecessor, lower-precedence, and peer-cancellation facts remain visible so fallback exhaustion or process termination cannot hide the initiating stop. Human output names the same provider facts. Raw provider output, paths, credentials, and free-form diagnostics are never projected.

Provider unavailability, exhausted invalid output, timeout, authentication, quota, and rate-limit execution failures are readiness failures at exit `4` when no higher-precedence failure is present. This projection applies equally to root review, followup, delta, exact rerun, and recomposed rerun.

Final exit precedence is:

```text
internal error (10)
> security or mutation violation (8)
> artifact failure (7)
> cancellation (9)
> configuration or trust-policy error (2)
> incomplete required coverage or readiness (4)
> valid committed CI rejection (1)
> valid committed CI pass (0)
```

This precedence is independent of the publication classifier's durable authority order. Valid P2 takes precedence over lower persisted journal hints; it does not suppress a separately observed higher-priority operational failure.

For `init`, `config`, and `doctor`, a pure `context.Canceled` or
`context.DeadlineExceeded` from native-home observation is the cancellation
reason `request_cancelled` at exit `9`. Init retains the already observed
destination without mutation, config withholds the accepted digest, and doctor
returns no partial doctor result. Security, artifact, and internal failures
continue to outrank cancellation.

<!-- BEGIN GENERATED INIT MUTATION OUTCOMES -->
### Init discovery source contract

Discovery is empty before completion and otherwise contains the fixed Kimi, ZCode, and AGY rows. Unselected families are not observed. Auto discovery retains ordinary unavailable rows when another family is a valid candidate; security failures still dominate after all three rows are assembled. Each row uses only its family-specific source fields:

- `kimi`: `executable_source=override|startup_path|not_discovered|not_selected`, `model_source=override|default_k3|not_selected`, `data_home_source=override|startup_environment|native_home_default|not_selected`
- `zcode`: `node_executable_source=override|startup_path|not_discovered|not_selected`, `launcher_source=override|bundled|not_discovered|not_selected`
- `agy`: `executable_source=override|startup_path|not_discovered|not_selected`, `native_home_source=os_account|verified_equal_input|not_selected`, `permission_mode_source=explicit|safe_default|not_selected`

There is no generic `auxiliary_source`.

### Init post-mutation outcome matrix

This table is generated from `internal/app/init.MutationOutcomeSpecs`; manual edits are overwritten. Provider IDs are the admitted candidate/configured set and discovery contains the fixed three rows.

| Write state | Destination | Category / code | Message | Retryable | Exit |
|---|---|---|---|---:|---:|
| `committed` | `present` | none / none | none | false | 0 |
| `existing_untouched` | `present` | configuration / `init_destination_exists` | The project-local Mulgae configuration already exists. | false | 2 |
| `existing_untouched` | `present` | security / `config_locality_drifted` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `existing_untouched` | `present` | security / `target_private_config_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `existing_untouched` | `present` | security / `target_private_namespace_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `not_committed` | `absent` | artifact / `init_write_failed` | The project-local Mulgae configuration could not be written. | true | 7 |
| `not_committed` | `not_observed` | artifact / `init_write_failed` | The project-local Mulgae configuration could not be written. | true | 7 |
| `not_committed` | `not_observed` | artifact / `init_private_dir_raced` | The private Mulgae directory changed during initialization. | true | 7 |
| `private_dir_created_unconfirmed` | `absent` | artifact / `init_private_dir_commit_unconfirmed` | The private Mulgae directory could not be durably confirmed. | true | 7 |
| `private_dir_created_unconfirmed` | `present` | artifact / `init_private_dir_commit_unconfirmed` | The private Mulgae directory could not be durably confirmed. | true | 7 |
| `private_dir_created_unconfirmed` | `not_observed` | artifact / `init_private_dir_commit_unconfirmed` | The private Mulgae directory could not be durably confirmed. | true | 7 |
| `private_dir_created_unconfirmed` | `absent` | security / `config_locality_drifted` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_created_unconfirmed` | `present` | security / `config_locality_drifted` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_created_unconfirmed` | `not_observed` | security / `config_locality_drifted` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_created_unconfirmed` | `absent` | security / `target_private_config_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_created_unconfirmed` | `present` | security / `target_private_config_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_created_unconfirmed` | `not_observed` | security / `target_private_config_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_created_unconfirmed` | `absent` | security / `target_private_namespace_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_created_unconfirmed` | `present` | security / `target_private_namespace_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_created_unconfirmed` | `not_observed` | security / `target_private_namespace_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_existing_unconfirmed` | `absent` | artifact / `init_existing_private_dir_commit_unconfirmed` | The existing private Mulgae directory could not be durably confirmed. | true | 7 |
| `private_dir_existing_unconfirmed` | `present` | artifact / `init_existing_private_dir_commit_unconfirmed` | The existing private Mulgae directory could not be durably confirmed. | true | 7 |
| `private_dir_existing_unconfirmed` | `not_observed` | artifact / `init_existing_private_dir_commit_unconfirmed` | The existing private Mulgae directory could not be durably confirmed. | true | 7 |
| `private_dir_existing_unconfirmed` | `absent` | security / `config_locality_drifted` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_existing_unconfirmed` | `present` | security / `config_locality_drifted` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_existing_unconfirmed` | `not_observed` | security / `config_locality_drifted` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_existing_unconfirmed` | `absent` | security / `target_private_config_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_existing_unconfirmed` | `present` | security / `target_private_config_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_existing_unconfirmed` | `not_observed` | security / `target_private_config_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_existing_unconfirmed` | `absent` | security / `target_private_namespace_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_existing_unconfirmed` | `present` | security / `target_private_namespace_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `private_dir_existing_unconfirmed` | `not_observed` | security / `target_private_namespace_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `installed_unconfirmed` | `present` | artifact / `init_commit_unconfirmed` | The installed Mulgae configuration could not be durably confirmed. | true | 7 |
| `installed_unconfirmed` | `not_observed` | artifact / `init_commit_unconfirmed` | The installed Mulgae configuration could not be durably confirmed. | true | 7 |
| `installed_unconfirmed` | `present` | security / `config_locality_drifted` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `installed_unconfirmed` | `not_observed` | security / `config_locality_drifted` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `installed_unconfirmed` | `present` | security / `target_private_config_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `installed_unconfirmed` | `not_observed` | security / `target_private_config_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `installed_unconfirmed` | `present` | security / `target_private_namespace_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `installed_unconfirmed` | `not_observed` | security / `target_private_namespace_forbidden` | The project-local Mulgae configuration failed locality admission. | false | 8 |
| `committed` | `present` | artifact / `init_result_delivery_failed` | The init result could not be delivered after commit. | true | 7 |
<!-- END GENERATED INIT MUTATION OUTCOMES -->

## 9. Status Command

`mulgae status --run <id>` should display:

- session and run identity;
- run state and elapsed duration;
- selected roles and `coverage_status`;
- `content_verdict`, `coverage_status`, `publication_status`, and `ci_decision`;
- lane queues and active attempts;
- primary and fallback transitions;
- parse, validation, and source/current evidence states;
- reader-visible final artifact path only when `publication_status=committed`;
- actionable next command.

`mulgae status --run r_019f596a-cf80-7c67-b265-f37053d51ccf --output json` returns a versioned status object.

## 10. Findings Commands

Examples:

```bash
mulgae findings --run r_019f596a-cf80-7c67-b265-f37053d51ccf --severity high --output json
mulgae findings --run r_019f596a-cf80-7c67-b265-f37053d51ccf --severity critical
mulgae excerpt --run r_019f596a-cf80-7c67-b265-f37053d51ccf --finding F001 \
  --current-target-sha256 sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --output json
```

Finding lookup always requires a canonical run ID and a supported minimum severity. Excerpt lookup additionally requires the finding ID and current target SHA-256.

## 11. Redacted Export

```bash
mulgae export --run latest --output-path exports/mulgae-review.zip --output json
```

A redacted export may omit:

- raw provider output;
- absolute local paths;
- sensitive environment metadata;
- target bytes not needed for shared excerpts;
- detected secrets.

It must retain:

- review and run identity;
- schema versions;
- normalized findings;
- evidence verification status;
- redaction manifest;
- source artifact hashes where disclosure policy permits.

## 15. Diagnostic Projection and Authority

Human and JSON command results may expose the same installed safe diagnostic URI after session/run identity exists. They must not project a nonexistent or failed-to-install path. Login-required and provider execution failures retain closed provider attribution while raw provider output, credentials, prompts, source bytes, paths, and free-form internal errors remain private.

Diagnostics cannot authorize a review artifact, CI pass, approval, release, retention decision, or cleanup of unrelated runs. `mulgae-runtime.jsonl` is chronological operational evidence and mutable status files are convenience projections; P2 remains the sole publication authority. Default export excludes diagnostics and raw streams.
