# Providers

Mulgae supports ZCode and Grok on native Apple Silicon macOS.
Each role runs on exactly one configured provider. Failed providers are
reported with typed reasons; Mulgae does not substitute another provider or
combine opinions as consensus. Independent runs own separate registries and
namespace generations.
Only process-local lanes and publication locks serialize their respective work.

`assets/roles.yaml` supplies init's generation-time role routing defaults.
After initialization, `.mulgae/config.yaml` is the sole shared policy authority.
Machine paths belong to mode-`0600` `.mulgae/local.yaml`.

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
  is not the live authentication authority. ZCode supports all core text roles
  and artist.
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

Protocol providers (ZCode) return correlated assistant text directly;
terminal-runtime providers (Grok) validate an invocation-scoped staged file
strictly after verified process-group exit (`ESRCH`) and publish its accepted
bytes under `result_transport: "stdout"`. Historical transport receipts remain
unchanged. Process lifetime, protocol inputs and diagnostics are bounded;
complete report content and provider stdout/stderr are unbounded. Provider
network, authentication, quota and rate-limit effects remain the operator's
provider outcomes. A new review after a failure requires authority.
