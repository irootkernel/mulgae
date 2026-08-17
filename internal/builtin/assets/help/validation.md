# Validation, extraction, and repair

Provider assistant report output is admitted as UTF-8 without a fixed byte
ceiling. Markdown/free-form role reports are the primary success form and are
not validated as review JSON schema documents. Public diagnostic metadata and optional
structured JSON validation remain bounded.

When `validation.extraction.enabled` is set and a role is accepted with a
free-form report only, Mulgae runs one bounded structured extraction on the same
attempt, the same provider, and the same role. It transcribes the accepted report
into the same provider review wire contract and then runs the identical checks
below. The accepted Markdown remains the published role report, and Mulgae owns
the extraction's coverage: the transcription cannot mark a role incomplete or
degraded. Extraction consumes the one remaining invocation a role may use, so a
role that already spent it on a retry or a repair stays reports-only. Any
ordinary extraction failure leaves the accepted report and the role exactly as
they were; it can never fail a review that would otherwise publish. A security,
configuration, artifact, cancellation, or internal failure observed during
extraction is not absorbed: it keeps its precedence and still denies
publication.

A transcribed finding stays a provider claim. Mulgae cannot prove that it
restates something the accepted report said, so it admits a transcription only
when every finding verified against the immutable target. One unverified finding
rejects the whole transcription at any severity, and the role stays
reports-only. Read the role report for what the role actually said.

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
repair or publication.
