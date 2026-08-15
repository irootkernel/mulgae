# Providers and role paths

Mulgae supports the `kimi`, `zcode`, `agy`, and `codex` provider families. Provider
executables must be installed and authenticated before review.

Automatic initialization selects ZCode and AGY and requires both to be
available. Kimi is retained for explicit `mulgae init --providers kimi`
compatibility; it is not part of auto selection.
Codex is also explicit-only and does not change the ZCode/AGY auto topology.

```bash
mulgae providers
mulgae providers --include-unverified
mulgae providers --output json
```

Provider identity and capability are checked at runtime. An unknown version is
not rejected solely because it is new, but a missing required capability or a
known incompatible version fails closed.

Each configured role runs on exactly one provider. Mulgae never substitutes
another provider when one fails: the role is reported as failed with its typed
failure reason, every other role continues on its own provider, and choosing a
replacement is yours. The final report lists each failed role, the provider it
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

ZCode, AGY, and Codex reviews run against Mulgae's immutable captured directory view
with adapter-owned tool boundaries. Providers may selectively read/search that
view; they do not receive live project-tree access, shell, or network
authority from Mulgae. A single tree is under `current/`; Git comparisons are
under `before/` and `after/`. The view itself is read-only with
post-execution drift detection overriding provider success.

Role reports reach Mulgae over a per-family transport recorded in
`manifest.role_reports[].transport`:

- ZCode: `staged_file`. ZCode review runs in `--mode yolo` with the denylist
  `Bash,Edit,NotebookEdit,WebSearch,WebFetch`, so `Write` is enabled for one
  purpose only: writing `role-report.md` to the exact absolute staging path
  Mulgae names in the last trusted prompt layer. That directory sits in a
  disposable namespace outside the workspace view and outside `.mulgae`. Mulgae
  validates the file after the process exits, copies the accepted bytes into
  `role-reports/<role>.md`, and always removes staging. ZCode's write authority
  is not path-scoped by the provider; containment is Mulgae-side. ZCode
  qualification is unchanged and remains fully tool-denied.
- AGY, Kimi, and Codex: `stdout`. Headless AGY auto-denies `write_file` in
  safe mode.
- Exact replay (`rerun --exact`) is always `stdout`.

AGY keeps `--new-project --sandbox --add-dir <workspace> --mode plan` limited to
the immutable captured workspace. The default AGY `permission_mode` is `safe` so headless
write/shell requests remain denied. Set
`providers.agy.permission_mode: "dangerously-skip-permissions"` only as an
explicit opt-in; Mulgae reports a warning because that mode may approve write or
shell tool requests outside the read-oriented boundary. Permission denials under
`safe` are reported as `provider_permission_denied`, not as output decode failures.

Capability probes stay prompt-bound to the embedded fixture packet and must not
induce workspace or tool reads. ZCode capability remains tool-denied; selective
workspace reads apply only to review invocations. Kimi has no adapter-owned
workspace read tools; its process working directory is still the immutable
workspace view.

Codex 0.147.0 or newer uses stdin for the review packet and exact stdout for the
role report. A legacy configuration projects only native
`~/.codex/auth.json`. To route roles through several authenticated environments,
set an operator-chosen `default_credential_profile` and optional role-level
`credential_profile` aliases in `.mulgae/config.yaml`, then map those aliases in
lexical order under `providers.codex.credential_homes` in private
`.mulgae/local.yaml`. Every profile uses the same real `codex` executable; do
not configure profile-specific wrappers. Run `mulgae help config` for the exact
two-file example.

Mulgae projects only the selected profile's `auth.json` into a disposable
`CODEX_HOME`, ignores user configuration, rules, and project instructions, sets
approvals to `never`, applies an adapter-owned read-only permission profile that
denies credential-directory access to model tools, and disables web, apps,
plugins, browser, hooks, image generation, and multi-agent features. Optional
model and reasoning-effort settings are shared project policy; omission
preserves Codex CLI defaults.
