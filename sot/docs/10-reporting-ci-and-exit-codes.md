# Reporting, CI, and Exit Codes

## 1. Reporting Surfaces

KAR exposes four related outputs:

| Output | Purpose | Source of truth |
|---|---|---:|
| `review_{uuidv7}.json` | Stable final machine contract | P2 committed only |
| `findings.json` | Convenient normalized finding index | Derived |
| `aggregation.json` | Role coverage, attempt selection, deduplication, and verdict inputs | Derived |
| `report.md` | Human-readable review | Derived |

Raw provider output is execution provenance, not verified review evidence. `consensus.json` is not used in the default primary/fallback strategy.

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
- KAR and adapter provenance.

Schemas:

- [kar-review-artifact.v2.schema.json](../schemas/kar-review-artifact.v2.schema.json)
- [kar-run-manifest.v2.schema.json](../schemas/kar-run-manifest.v2.schema.json)
- [kar-validation-result.v2.schema.json](../schemas/kar-validation-result.v2.schema.json)

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

KAR serializes four independent fields. They are never collapsed into a single verdict and a failure in one axis does not erase another.

| Field | Exact enum | Meaning and owner |
|---|---|---|
| `content_verdict` | `no_findings`, `findings_present`, `request_changes` | Aggregation of validated findings |
| `coverage_status` | `complete`, `degraded`, `incomplete` | Coordinator coverage reducer |
| `publication_status` | `not_published`, `staged`, `installed`, `committed`, `corrupt` | Durable publication classifier |
| `ci_decision` | `pass`, `fail` | Trusted CI policy projection with reason codes |

At the trusted default threshold, a `high`, `critical`, or `blocker` finding gives `content_verdict=request_changes`; lower validated findings give `findings_present`; no validated findings give `no_findings`. `content_verdict` is content, not a claim of complete coverage.

`coverage_status=complete` requires all required roles to have valid policy-satisfying results. `degraded` permits an optional or otherwise policy-permitted limited result; `incomplete` means a required role is exhausted or lacks a valid result. A required failure does not delete content: a valid high finding plus required failure is serialized as `request_changes` and `incomplete`.

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

An optional exhausted role may yield `coverage_status=degraded`, preserve valid content, and project to `ci_decision=pass` or `fail` under trusted policy. A required exhausted role yields `coverage_status=incomplete`; it preserves content and returns exit `4` rather than being relabeled as an ordinary CI rejection. Source/current evidence remains visible with its exact `verification` state; a source reference is never displayed as current `verified` evidence.

CI configuration comes from the trusted-base reducer. Project configuration may strengthen it but cannot loosen required roles, severity, degraded/incomplete enforcement, workspace, provider command, or shell restrictions. Every interactive weakening request is tainted and non-proof; CI rejects it with exit `2`.

## 7. CI Modes

```text
interactive: render report and return the final operational status unless --ci is set
ci: apply trusted content, coverage, finding, and degradation policy
json: emit a concise machine status object to stdout
```

For example:

```bash
kar review --diff origin/main...HEAD --ci
```

CI stdout stays concise. Detailed artifacts and all reason codes belong under `.kar/` or an explicitly requested secure export.

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
| `10` | KAR internal error or invariant violation |

Exit `3` is not a typed G0 outcome and is reserved. The manifest records every observed failure and reason code even when one exit is selected.

Final exit precedence is:

```text
internal error (10)
> artifact failure (7)
> security or mutation violation (8)
> cancellation (9)
> configuration or trust-policy error (2)
> incomplete required coverage or readiness (4)
> valid committed CI rejection (1)
> valid committed CI pass (0)
```

This precedence is independent of the publication classifier's durable authority order. Valid P2 takes precedence over lower persisted journal hints; it does not suppress a separately observed higher-priority operational failure.

## 9. Status Command

`kar status --run <id>` should display:

- session and run identity;
- run state and elapsed duration;
- selected roles and `coverage_status`;
- `content_verdict`, `coverage_status`, `publication_status`, and `ci_decision`;
- lane queues and active attempts;
- primary and fallback transitions;
- parse, validation, and source/current evidence states;
- reader-visible final artifact path only when `publication_status=committed`;
- actionable next command.

`kar status --json` returns a versioned status object.

## 10. Findings Commands

Examples:

```bash
kar findings --latest
kar findings --run <run_id> --severity high
kar findings --run <run_id> --role security
kar excerpt --run <run_id> --finding F001
```

Finding lookup must validate the run-scoped reference. `F001` without a run is allowed only when the command has an unambiguous selected run.

## 11. Redacted Export

```bash
kar export --run latest --redacted --output kar-review.zip
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
