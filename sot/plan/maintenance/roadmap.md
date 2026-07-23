# KAR Maintenance and Release Handoff Roadmap

**Planning status:** ACTIVE HANDOFF  
**Normative product SOT:** 1.10.0 until Diagnostics D-E01 promotes 1.11.0

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

## 2. Remaining Ordered Work

The only remaining sequence inherited from the deleted `todo.md` is the release handoff already tracked by the Diagnostics roadmap and the normative G010 checklist.

- [ ] Complete Diagnostics D-E01 through D-E04 in order using [the diagnostics roadmap](../diagnostics/roadmap.md).
- [ ] After D-E04, resume G010-T05 using the preserved diagnostics to identify and fix the actual-provider failure; require truthful `make test-e2e` PASS and complete every still-unchecked T05 requirement in `sot/IMPLEMENTATION_CHECKLIST.md`.
- [ ] After T05 passes, execute G010-T06 on the exact final tree; require `make test` PASS before recording `RELEASE_READY`.

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
- Do not check G010 items in this planning file; update the normative checklist with evidence when their actual completion gates pass.

## 4. Goal Handoff

Diagnostics goals are copied from `sot/plan/diagnostics/roadmap.md`. After D-E04 completes, use these release handoffs:

```text
/goal Complete G010-T05 after Diagnostics D-E04: use preserved runtime diagnostics to identify and remove the actual Kimi/ZCode/AGY E2E failure causes, restore the executable full-workflow E2E and strict no-skip prerequisite failures, and verify `make test-e2e` passes on the current tree with every normative T05 checkbox supported by evidence.
```

```text
/goal Complete G010-T06 after G010-T05: reconcile the final normative SOT and generated artifacts, run exact final-tree `make test`, and record RELEASE_READY only if the command passes with no skipped required actual-provider gate and no generated drift.
```

