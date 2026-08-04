# Providers and lanes

Mulgae supports the `kimi`, `zcode`, and `agy` provider families. Provider
executables must be installed and authenticated before review.

Automatic initialization selects ZCode and AGY and requires both to be
available. Kimi is retained for existing Config v1 files and explicit
`mulgae init --providers kimi` compatibility; it is not part of auto selection.

```bash
mulgae providers
mulgae providers --include-unverified
mulgae providers --output json
```

Provider identity and capability are checked at runtime. An unknown version is
not rejected solely because it is new, but a missing required capability or a
known incompatible version fails closed.

Each configured role has a primary provider and may have one explicit fallback.
Mulgae serializes invocations that share a provider instance or credential
namespace. Fallback is allowed only for classified provider availability,
execution, or invalid-output failures; security, configuration, artifact,
cancellation, and internal failures never trigger it.

AGY reviews run headlessly with `dangerously-skip-permissions` by default so
AGY can read and inspect the supplied snapshot without an interactive prompt.
Mulgae still launches AGY with `--sandbox` and `--add-dir` limited to the
bounded, immutable review snapshot; that snapshot is the review's security
boundary.

Set `providers.agy.permission_mode: "safe"` only as an explicit opt-in. Mulgae
reports a warning in effective configuration because headless `read_file` and
command requests may be denied in safe mode. Permission denials are reported as
`provider_permission_denied`, not as output decode failures.
