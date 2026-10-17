# AGY multiple-account support

This is a future candidate, not an adopted epic or a prerequisite for
[EPIC-011](../roadmap/README.md#epic-011-agy-stream-json-review-provider).
The operator directed EPIC-011 to implement and verify one AGY account first.

After the single-account route works, consider named AGY credential profiles,
project-level `default_credential_profile`, per-role `credential_profile`, and
machine-local `credential_homes`. Any adopted design must preserve original
credential-home protection, disposable token projection, and explicit provider
selection without fallback.

Future verification needs at least two distinct accounts. Establish
account selection, qualification identity, isolation between accounts, and
refresh confinement. Copies of one account do not prove multiple-account
support. Do not make these checks a completion gate for EPIC-011.

Adoption requires its own scope, roadmap identity, implementation plan, and
authorization. No multiple-account capability is claimed here.
