# Automation, CI, and exit codes

Use `--output json` for a `mulgae-command-result.v5` envelope. Command-result
v2/v3/v4 and review-preflight v2 are not accepted by this revision. Process exit codes
remain authoritative:

| Exit | Meaning |
|---:|---|
| 0 | success |
| 1 | policy outcome |
| 2 | usage or configuration failure |
| 4 | readiness or provider unavailable |
| 7 | artifact or integrity failure |
| 8 | security policy failure |
| 9 | cancellation |
| 10 | internal failure |

CI is derived from a committed final artifact and project policy. Provider
output, an attempt artifact, or an uncommitted candidate cannot decide CI.
Coverage and content verdict remain separate: a valid but incomplete review can
be published while still failing CI.

`validation.extraction.enabled` changes which runs can reach exit `1`. A role
that returns only a free-form report used to commit no findings, so
`ci.fail_on_severity` could not fire. With extraction, such a run may commit
findings and exit `1` as a policy outcome. Read the JSON envelope rather than
treating a nonzero exit as an execution failure.
