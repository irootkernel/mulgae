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

Each configured role has a primary provider and may have an explicit fallback.
Mulgae serializes invocations that share a provider instance or credential
namespace. Fallback is allowed only for classified provider availability,
execution, or invalid-output failures; security, configuration, artifact,
cancellation, and internal failures never trigger it.

ZCode and AGY reviews run against Mulgae's immutable captured snapshot with
adapter-owned read-oriented tool boundaries. Providers may selectively
read/search that snapshot; they do not receive live project-tree access, write,
shell, or network authority from Mulgae. AGY keeps `--sandbox` and `--add-dir`
limited to the bounded snapshot. The default AGY `permission_mode` is `safe` so
headless write/shell requests remain denied. Set
`providers.agy.permission_mode: "dangerously-skip-permissions"` only as an
explicit opt-in; Mulgae reports a warning because that mode may approve write or
shell tool requests outside the read-oriented boundary. Permission denials under
`safe` are reported as `provider_permission_denied`, not as output decode failures.

Capability probes stay prompt-bound to the embedded fixture packet and must not
induce workspace or tool reads. ZCode capability remains tool-denied; selective
workspace reads apply only to review invocations. Kimi has no adapter-owned
workspace read tools; its process working directory is still the immutable
snapshot.
