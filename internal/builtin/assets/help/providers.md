# Providers and role paths

Mulgae supports the `zcode`, `grok`, and `codex` provider
families. Provider executables must be installed and authenticated before review.

Automatic initialization selects ZCode and Grok, requires both to be available,
and assigns every default role to ZCode. Codex remains explicit-only.

```bash
mulgae providers
mulgae providers --include-unverified
mulgae providers --output json
```

The command lists fixed trusted profiles without invoking them. Missing static
admission evidence is reported as `unverified` information and does not make
the command fail. JSON reports `offline_ready_provider_count` separately from
`static_evidence_ready_provider_count`. `mulgae doctor` checks exact local
binary identity and adapter-owned `--version` compatibility without a live
provider request. Static evidence and prior review qualification do not affect
that offline result.

Provider identity and capability are checked at runtime. An unknown version is
not rejected solely because it is new, but a missing required capability or a
known incompatible version fails closed.

Run a live synthetic heartbeat only with explicit authorization:

```bash
mulgae heartbeat --provider grok --authorize-live-request --output json
```

It may authenticate, use the network, incur cost, and create remote logs. It
never includes repository source, diffs, review prompts, or user content, and
it does not qualify a later review. Without the authorization flag Mulgae fails
before provider composition or execution.

Each configured role runs on exactly one provider. Mulgae never substitutes
another provider when one fails: the role is reported as failed with its typed
failure reason, every other role continues on its own provider, and choosing a
replacement is yours. A recomposed rerun may use that explicitly configured
replacement for a missing role, but composition rejects any attempt to replace
an accepted role. The final report lists each failed role, the provider it
ran on, why it stopped, and the `mulgae rerun` command to run it again
elsewhere. Provider invocations carry no hidden scheduling key and create no
provider queue or lock. Each run owns its provider registry and a temporary
namespace generation for every configured provider instance, so independent
runs may invoke the same provider
concurrently. Duplicate instances in one registry are invalid; an impossible
concurrent reuse inside that registry fails immediately instead of waiting.
`max_active_lanes` remains the explicit process capacity. Project-local
publication still serializes mutations of one project's durable artifacts.

Provider families authenticate independently, so a login or quota failure on one
family never cancels roles running on the others.

The initial assignment comes from the build-owned role document, which lists an
ordered provider preference per role. `mulgae init` intersects that order with
the providers it configured and takes the first match as the role's provider.
That is a generation-time default only: after init the shared project policy is
the sole routing authority and is never re-derived.

ZCode, Grok, and Codex reviews run against Mulgae's immutable captured directory view
with adapter-owned tool boundaries. Providers may selectively read/search that
view; they do not receive live project-tree access, shell, or network
authority from Mulgae. A single tree is under `current/`; Git comparisons are
under `before/` and `after/`. The view itself is read-only with
post-execution drift detection overriding provider success.

Role reports reach Mulgae over a per-family transport recorded in
`manifest.role_reports[].transport`:

- ZCode: `staged_file`. ZCode review and qualification speak the app-server
  protocol: Mulgae launches `zcode app-server` and conducts one
  newline-delimited protocol conversation, so no prompt, mode, or tool policy
  appears on the command line. Review conversations request `yolo` mode with
  the denylist `Bash,Edit,NotebookEdit,WebSearch,WebFetch,EnterPlanMode,ExitPlanMode`,
  so `Write` is enabled for one purpose only: writing `role-report.md` to the
  exact absolute staging path Mulgae names in the last trusted prompt layer.
  That directory sits in a disposable namespace outside the workspace view and
  outside `.mulgae`. Mulgae validates the file after the conversation
  completes, copies the accepted bytes into `role-reports/<role>.md`, and
  always removes staging. ZCode's write authority is not path-scoped by the
  provider; containment is Mulgae-side. ZCode qualification runs in plan mode
  and remains fully tool-denied.
- Grok: `staged_file` for review and stdout assistant evidence for qualification
  and extraction. Mulgae speaks ACP v1, supplies no MCP servers, installs an
  adapter-owned workspace policy in the disposable Grok home, and admits exactly
  one correlated `allow_once` permission for `Write` to the invocation-owned
  `role-report.md`. Any other permission request, tool path, active MCP server,
  protocol mismatch, or repeated write fails closed. Grok is text-only; an
  `artist` assignment fails preflight with `provider_capability_unsupported`.
- Codex: `stdout`, carrying the final assistant message from a completed
  app-server turn. The raw protocol transcript is private evidence.
- Exact replay (`rerun --replay exact`) keeps the provider family's transport. For
  ZCode and Grok, Mulgae preserves the stored review frames but replaces the
  expired output path with a fresh per-launch staging destination.

Capability probes stay prompt-bound to the embedded fixture packet and must not
induce workspace or tool reads. ZCode capability remains tool-denied; selective
workspace reads apply only to review invocations.

Codex 0.154.0 or newer uses a stdio app-server conversation for review,
extraction, and qualification. Mulgae starts a fresh ephemeral thread for each
invocation and records its final assistant message as the role report. A legacy
configuration uses only native `~/.codex/auth.json`. To route roles through
several authenticated environments,
set an operator-chosen `default_credential_profile` and optional role-level
`credential_profile` aliases in `.mulgae/config.yaml`, then map those aliases in
lexical order under `providers.codex.credential_homes` in private
`.mulgae/local.yaml`. Every profile uses the same real `codex` executable; do
not configure profile-specific wrappers. Run `mulgae help config` for the exact
two-file example.

Mulgae projects only the selected profile's `auth.json` into a disposable
`CODEX_HOME`, excludes ambient user configuration and project instructions, sets
approvals to `never`, applies an adapter-owned read-only permission profile that
denies credential-directory access to model tools, and disables web, apps,
plugins, browser, hooks, image generation, and multi-agent features. Optional
model and reasoning-effort settings are shared project policy; omission
preserves Codex CLI defaults.
