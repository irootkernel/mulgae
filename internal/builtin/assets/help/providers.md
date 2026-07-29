# Providers and lanes

Mulgae supports the `kimi`, `zcode`, and `agy` provider families. Provider
executables must be installed and authenticated before review.

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

AGY runs with an explicit `safe` or `dangerously-skip-permissions` mode.
The default is `safe`; use the dangerous mode only when its implications are
understood and accepted.
