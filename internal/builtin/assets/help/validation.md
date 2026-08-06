# Validation and repair

Provider assistant output is admitted as bounded UTF-8. Markdown/free-form role
reports are the primary success form and are not validated as review JSON schema
documents.

When exact structured finding JSON is present, Mulgae may apply one constrained
repair and then proceeds through:

1. provider-wire JSON Schema validation;
2. trusted identity and state injection;
3. normalized output schema validation;
4. semantic and field-ownership checks;
5. evidence verification against the immutable target.

On that optional structured path, Mulgae rejects trailing data, unknown fields,
oversized output, unsupported schemas, and semantic contradictions.

Evidence begins as `claimed`. Only Mulgae can mark it `verified`, `stale`,
`invalid`, or `unverifiable`. Mulgae owns trusted identity, evidence state, and
publication.

One constrained repair may correct explicitly repairable provider-owned fields.
System-owned fields are never delegated to the provider. A failed structured
repair may still leave a Mulgae-owned free-form role report without structured
findings; it never grants publication authority by itself. Security,
configuration, integrity, cancellation, and internal failures never authorize
fallback or publication.
