# Providers

Mulgae supports ZCode, Grok, Codex, Cursor and AGY on native Apple Silicon macOS.
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
- Grok (`1.0.89` and newer) runs through an isolated Mulgae-owned `herdr-core`
  terminal runtime (`PaneTTY`, OSC 7501 readiness and turn state) inside the
  mandatory outer Seatbelt guard, with a disposable `HOME`, a disposable
  `GROK_HOME` containing only a minimal `requirements.toml` (disabling compat
  hooks, MCPs, rules, skills, plugins and managed configs) and a mode-`0600`
  projected `auth.json` (never written back). Tools are
  purpose-scoped: workspace reviews run strictly shell-free
  (`read_file,grep,list_dir,Write`), index and commit reviews add `Bash` under
  the five-control `B-1` Seatbelt and post-`ESRCH` stability/survivor gate, and
  structured extraction and qualification run shell-free (`read_file,Write`).
  Prompts are staged read-only (`0400`) inside `<scratch>/input/` and outputs
  are validated strictly after verified process-group absence (`ESRCH`) with a
  mandatory per-invocation completion nonce before publication under
  `result_transport: "stdout"`. `--version` and doctor readiness checks remain
  offline and never start `herdr-core`. Grok supports text roles; artist
  assignment fails capability admission.
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

- AGY uses bidirectional stream-JSON in native plan mode inside the mandatory
  outer Seatbelt guard. Documentation prefers AGY when configured. Other text
  roles retain ZCode first; artist remains ZCode or Codex. It uses one default
  Gemini account and copies only the native default token into a disposable
  Gemini directory. Native model and effort defaults survive omission. No user
  rules, plugins or MCP configuration are imported. A report requires correlated
  completion, stdin half-close, drained EOF, natural exit zero and verified
  process-group absence. An uncertain drain retains the namespace and token
  copy. AGY is text-only; failures never select another provider.

AGY supports `1.2.9` and newer without a version-specific command allowlist.
Qualification binds the observed executable and isolated runtime. Native
permissions and exact tool checks constrain each read. `make test-agy` checks
the installed CLI's native command permissions, then exercises one
default-account documentation review and public report/export access.

Protocol providers return correlated assistant text directly; terminal-runtime
providers (Grok) validate an invocation-scoped staged file strictly after
verified process-group exit (`ESRCH`) and publish its accepted bytes under
`result_transport: "stdout"`. Historical transport receipts remain unchanged.
Process lifetime, protocol inputs and diagnostics are bounded; complete report
content and provider stdout/stderr are unbounded. Provider network,
authentication, quota and rate-limit effects remain the operator's provider
outcomes. A new review after a failure requires authority.
