# Operations

Mulgae is a local CLI and attached MCP server, not an independently deployed
service or daemon. This delivery scope therefore has no separate production
environment, deployment control plane, or operations runbook.

Public installation, configuration, and user troubleshooting belong in the
repository [README](../../README.md). Development environment setup, test
execution, release preparation, and manual publication guidance belong to the
[implementation tips](../implementation-tips/README.md). Security requirements
for credentials, provider processes, workspaces, and local artifacts belong to
the [security specification](../specs/security.md).

Add a runbook here only if Mulgae gains an independently operated environment
with a verified owner, prerequisites, safe diagnosis, recovery, success checks,
rollback, and escalation boundary.
