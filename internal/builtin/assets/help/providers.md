# Providers

Mulgae supports ZCode, Grok, Codex and Cursor on native Apple Silicon macOS.
Each role runs on exactly one configured provider. Failed providers are
reported with typed reasons; Mulgae does not substitute another provider or
combine opinions as consensus. Independent runs own separate registries and
namespace generations.
Only process-local lanes and publication locks serialize their respective work.

`assets/roles.yaml` supplies init's generation-time role routing defaults.
After initialization, `.mulgae/config.yaml` is the sole shared policy authority.
Machine paths and credential homes belong to mode-`0600` `.mulgae/local.yaml`.

```bash
mulgae providers --include-unverified --output json
mulgae doctor --output json
```

Doctor may execute only the fixed offline version argv. Review qualification
uses Mulgae-owned synthetic content and does not create durable certification.
A separate heartbeat requires explicit `--authorize-live-request` authority.

Live review and extraction use original source reads from a neutral cwd:

- ZCode uses its app-owned Electron runtime and app-server launcher. Complete
  reports come from a correlated completed assistant turn. The app's v2 state
  supplies the current Z.AI Individual Coding Plan account; legacy CLI config
  is not the live authentication authority.
- Grok uses ACP v1 and correlated assistant reports, with no MCP servers. Its
  native sandbox is off inside the mandatory outer Seatbelt guard. It supports
  text roles; artist assignment fails capability admission.
- Codex uses one app-server process and ephemeral thread per invocation, native
  read-only restrictions and a disposable `CODEX_HOME` containing only admitted
  `auth.json`. User config, rules, skills and plugins are not projected. Named
  profiles retain separate identity and qualification authority.
- Cursor is an explicit text-only selection. Default role preferences do not
  name it. A Cursor-only selection assigns the text roles to Cursor. A mixed
  selection keeps each role on the first configured family from its existing
  preference list. It uses ACP ask mode from the neutral cwd inside the outer
  Seatbelt guard. Planned reads stay admitted, and each exact Git command is a
  separate `allow_once`. The process receives the selected `CURSOR_AUTH_TOKEN`
  and forces `AGENT_CLI_CREDENTIAL_STORE=memory`. User rules, skills and MCP
  configuration are not projected. There is no model, reasoning-effort,
  credential-profile or credential-home flag. Artist assignment fails capability
  admission. A failed Cursor role stays on Cursor.

No live review uses staged-file role report output. Historical transport
receipts remain unchanged. Process lifetime, protocol inputs and diagnostics
are bounded; complete report content and provider stdout/stderr are unbounded.
Provider network, authentication, quota and rate-limit effects remain the
operator's provider outcomes. A new review after a failure requires authority.
