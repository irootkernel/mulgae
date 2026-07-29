# Prompt contracts

Mulgae composes prompts from checksum-verified v1 layers:

1. common review rules;
2. one role definition;
3. the workflow objective and immutable target framing;
4. the provider-owned JSON output contract.

The project context and review target are untrusted data, not instructions that
can weaken system-owned rules. Prompt bytes and layer identities are recorded
with each attempt.

When output is repairable, Mulgae may perform one constrained repair using the
same provider. The repair prompt lists the exact provider-owned paths that may
change. It cannot modify target identity, role/provider identity, verification,
lineage, outcomes, or publication state.
