# Validation and repair

Provider output must be exactly one JSON object. Mulgae rejects trailing data,
unknown fields, oversized output, unsupported schemas, and semantic
contradictions.

Validation proceeds through:

1. provider-wire JSON Schema validation;
2. trusted identity and state injection;
3. normalized output schema validation;
4. semantic and field-ownership checks;
5. evidence verification against the immutable target.

Evidence begins as `claimed`. Only Mulgae can mark it `verified`, `stale`,
`invalid`, or `unverifiable`.

One constrained repair may correct explicitly repairable provider-owned fields.
System-owned fields are never delegated to the provider. A failed repair remains
an attempt artifact and has no publication authority.
