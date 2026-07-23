# G010-T05 Actual-provider Evidence

Recorded on 2026-07-24 (Asia/Seoul) from the D-E04 tree after commit
`428a38a`.

## Observed failure

- Command: `make test-e2e`
- Make exit status: `2` (`go test` reported `FAIL`; this is not a PASS or SKIP)
- Failing test: `TestE2EActualProvidersThreeIndependentPrimaryLanes`
- Safe command outcome: readiness failure, `provider_login_required`, attributed to
  `kimi-default`
- Preserved private project (mode `0700`):
  `/var/folders/r7/7nmfk6290z910nk80prf0w640000gn/T/kar-e2e-project.EfQIur`
- Session: `s_019f9028-31d7-7d80-8908-71b0a958e34f`
- Run: `r_019f9028-31d7-79d0-9d1e-d3d9d5da914f`
- Diagnostic URI:
  `.kar/diagnostics/s_019f9028-31d7-7d80-8908-71b0a958e34f/r_019f9028-31d7-79d0-9d1e-d3d9d5da914f`
- Terminal status: `state=failed`, `terminal_cause=provider_login_required`,
  `last_seq=10`, `dropped_events=0`, `diagnostic_only=true`,
  `publication_authority=false`, and no P2 URI.

The preserved diagnostic contains `status.json` and `kar-runtime.jsonl`. Its ten
events have unique, strictly increasing sequence numbers and end with
`run_stopped` followed by `runtime_diagnostics_closed`. Qualification stopped
before any provider invocation, so no raw stream artifact is applicable and the
observed raw artifact reference count is zero. No raw bytes, credentials,
prompts, source bytes, or free-form provider errors are copied into this note.

## Investigation boundary

The evidence rejects these hypotheses without attempting the G010-T05 fix:

- It is not a pre-run failure: the review allocated a session and run and
  installed a terminal diagnostic.
- It is not a publication or P2 consistency failure: qualification rejected the
  provider before attempts and publication, and the terminal status truthfully
  has no P2 reference.
- It is not an output parsing, validation, repair, or fallback failure: the event
  chronology ends during qualification and contains no attempt or invocation.
- It is not a dangling diagnostic projection: the emitted relative URI resolves
  inside the preserved private project to both required metadata artifacts.

G010-T05 should diagnose and restore the native `kimi-default` authentication
state, then require `make test-e2e` to pass. D-E04 intentionally does not change
native authentication or claim G010-T05 completion.
