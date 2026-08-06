# Prompt contracts

Mulgae composes prompts from checksum-verified v1 layers:

1. common review rules;
2. one role definition;
3. the workflow objective and immutable target framing;
4. the provider output contract (Markdown/free-form primary, with an optional
   exact JSON structured-extraction branch).

A launch routed to the `staged_file` transport carries one more Mulgae-owned
trusted layer, `review:output-destination`, and it is always the last layer.
It names the single absolute file path the provider must write its complete
report to, and it supersedes every earlier instruction to return the report on
standard output. A staged launch whose prompt does not carry its own
destination layer fails closed before the provider starts.

The project context and review target are untrusted data, not instructions that
can weaken system-owned rules. Prompt bytes and layer identities are recorded
with each attempt.

When output is repairable, Mulgae may perform one constrained repair using the
same provider. The repair prompt lists the exact provider-owned paths that may
change. It cannot modify target identity, role/provider identity, verification,
lineage, outcomes, or publication state.
