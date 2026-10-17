# TODO candidates and active dossiers

This directory owns future epic-sized candidates and temporary development
dossiers for adopted active epics. The canonical roadmap alone owns epic and
task identity, ordering, dependencies, and status.

## Future candidates

- [AGY multiple-account support](agy-multiple-accounts.md) follows the
  single-account EPIC-011 delivery. Named profiles and verification with distinct
  accounts are deferred; they do not block EPIC-011.

## Adopted active dossiers

- [EPIC-008: Review completeness and iteration](EPIC-008-review-completeness-and-iteration.md)
  develops structured requirements review, bounded batch followup, and exact-run
  comparison as a preserved design held for redesign after EPIC-009 acceptance.
- [EPIC-010: Cursor ACP review provider](EPIC-010-cursor-acp-provider.md)
  records the planned ACP adapter, read-only session boundary, and TASK-040
  stop conditions. Adoption grants no current execution capability.
- [EPIC-011: AGY stream-json review provider](EPIC-011-agy-stream-json-provider.md)
  records the planned `stream-json` stdio adapter, Live-Source Seatbelt read-only
  boundary, single-account `--gemini_dir` credential isolation, `documentation`
  default routing, and TASK-043 stop conditions. Adoption grants no current
  execution capability.

Execute the Epics and their Tasks in the order owned by the
[roadmap](../roadmap/README.md#adopted-execution-order). Adoption does not imply
that implementation has begun or that the planned interfaces are available.

When a candidate is adopted with tasks, identify its epic here and link the
dossier from the roadmap as `Detailed SOT`. Epic closeout promotes durable
content, removes the dossier and this index entry, and records only canonical
outcome links in the roadmap.
