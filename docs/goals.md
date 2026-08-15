# Project goals

## Purpose

Mulgae makes AI-assisted code review reproducible enough to inspect, automate,
and audit locally. A review is more than provider text: it has an immutable
target, explicit role and provider assignments, bounded execution, a validated
result, evidence status, lineage, and a durable publication record.

## Product goals

1. **Easy installation.** A supported user installs one self-contained binary
   with `go install github.com/irootkernel/mulgae@latest`.
2. **Multiple review lenses.** Logic, security, maintainability, product,
   documentation, testing, and UI-focused artist roles inspect a target through
   explicit assignments.
3. **Provider and run independence.** Kimi, ZCode, and AGY use separate
   adapters behind common application ports. Independent runs and projects do
   not consume one another's execution budget through a Mulgae-owned provider
   queue or lock; concurrency remains bounded explicitly within each process.
4. **Reproducible inputs.** Mulgae captures an immutable target and records
   prompts, provider identity, attempts, and hashes needed to understand it.
5. **Fail-closed contracts.** Untrusted provider output is admitted only as
   UTF-8 without a product byte ceiling. Markdown/free-form role reports are primary; optional exact
   JSON structured extraction requires parsing, schema, semantic, and evidence
   checks. Prose does not invent findings. Security, configuration, and
   integrity failures never authorize publication.
6. **Local ownership.** Shared project policy and private machine/runtime state
   remain project-local beneath `.mulgae/`; only the policy is Git-shareable.
7. **Inspectable automation.** Human output is convenient; `--output json`
   provides stable versioned envelopes and typed exits, while an attached
   stdio MCP process provides request/response automation without CLI polling.

## Non-goals

Mulgae does not:

- approve a merge, release, policy waiver, or security exception;
- claim that several provider opinions are consensus;
- silently substitute an unconfigured provider;
- execute commands supplied by project configuration;
- give a provider live access to the reviewed project tree;
- upload artifacts to a hosted Mulgae service;
- support platforms outside `darwin/arm64` in the initial release;
- preserve pre-release names, paths, environment variables, or contracts.

## Initial release boundary

The first public release is intentionally narrow:

- one binary named `mulgae`, including the `mulgae mcp` attached transport;
- Config v3 split between tracked `.mulgae/config.yaml` project policy and
  untracked mode-`0600` `.mulgae/local.yaml` machine paths;
- independently versioned machine contracts;
- Kimi, ZCode, and AGY provider families;
- macOS on Apple silicon;
- manual Git tagging after the complete local release gate passes.

New platforms or providers require explicit adapters, capability tests, security
review, documentation, and release evidence. They are not enabled by a generic
compatibility shim.
