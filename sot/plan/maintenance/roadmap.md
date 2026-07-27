# KAR Maintenance and Release Handoff Roadmap

**Planning status:** COMPLETED HANDOFF (2026-07-26)
**Normative product SOT:** 1.12.0; this roadmap began from the historical 1.10.0 baseline

This planning-only roadmap replaces the historical root `todo.md`. Normative product contracts and completion status remain in `sot/`; this file does not override them and is excluded from the runtime SOT catalog and checksums.

## 1. Historical Audit Reconciliation

The 18 findings from the 2026-07-22 SOT 1.9.0 audit have been rechecked against the current tree. All are implemented and either already represented in the normative SOT or reconciled into it before this roadmap replaced `todo.md`. They are intentionally not copied here as open work.

Verified reconciliations include:

- followup meaningful-value and resolved/rationale semantic validation;
- reviewrun/provider qualification dependency inversion;
- child source-mutation security classification and exit `8`;
- init/config/doctor cancellation exit `9` metadata;
- canonical operational failure precedence;
- direct child-lineage rejection tests and store-owned publication epochs;
- production dependency enforcement, including build-ignore handling;
- blocked state transitions, canonical finding fingerprint framing, and closed workspace access;
- required config fields and `/2` prompt-layer ownership;
- required help exposure, architecture/asset documentation, decision-log table repair, and synchronized SOT status wording;
- durable historical Kimi receipts plus identifier/path property and security-case coverage.

These are completed facts, not maintenance tasks. Historical `.gjc/` evidence remains append-only.

## 2. Completed Ordered Work

The release handoff inherited from the deleted `todo.md` completed in the required order. The normative G010 checklist remains the completion authority.

- [x] Complete Diagnostics D-E01 through D-E04 in order using [the diagnostics roadmap](../diagnostics/roadmap.md). Evidence: all four epic status rows are `COMPLETE`.
- [x] After D-E04, complete G010-T05 using the preserved diagnostics to remove the actual-provider workflow failures and require truthful `make test-e2e` PASS. Evidence: the non-skipping full workflow passed in 842.993 seconds on 2026-07-26 and every normative T05 requirement is checked.
- [x] After T05 passes, complete G010-T06 on the exact final tree and require `make test` PASS before recording `RELEASE_READY`. Evidence: exact final-tree `make test` passed on 2026-07-26, including its 761.839-second live E2E package run.

Dependency:

```text
Diagnostics D-E01 -> D-E02 -> D-E03 -> D-E04
                                      -> G010-T05
                                      -> G010-T06
```

## 3. Gate Rules

- During Diagnostics D-E01 through D-E04, `make test-prepare`, `make test-unit`, and `make test-int` are required. The currently failing `make test-e2e`, and therefore `make test`, are non-gating only for those four diagnostics goals.
- An E2E failure remains a failure. Do not skip it, relabel it, weaken assertions, or record PASS.
- D-E04 may run `make test-e2e` to collect preserved diagnostic evidence. Fixing the discovered cause belongs to G010-T05.
- G010-T05 requires `make test-e2e` PASS. G010-T06 requires exact final-tree `make test` PASS.
- The normative checklist, not this planning mirror, grants G010 completion authority; planning completion is recorded only after the normative evidence exists.

## 4. Goal Handoff

Diagnostics goals are copied from `sot/plan/diagnostics/roadmap.md`. The following release handoffs were completed in order:

```text
/goal Complete G010-T05 after Diagnostics D-E04: use preserved runtime diagnostics to identify and remove the actual Kimi/ZCode/AGY E2E failure causes, restore the executable full-workflow E2E and strict no-skip prerequisite failures, and verify `make test-e2e` passes on the current tree with every normative T05 checkbox supported by evidence.
```

```text
/goal Complete G010-T06 after G010-T05: reconcile the final normative SOT and generated artifacts, run exact final-tree `make test`, and record RELEASE_READY only if the command passes with no skipped required actual-provider gate and no generated drift.
```
