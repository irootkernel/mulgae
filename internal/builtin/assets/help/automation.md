# Automation, CI, and exit codes

Use `--output json` for a `mulgae-command-result.v3` envelope. Command-result v2
and review-preflight v2 are not accepted by this revision. Process exit codes
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
