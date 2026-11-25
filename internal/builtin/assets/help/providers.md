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

Doctor uses fixed offline compatibility commands and starts no terminal daemon.
Review qualification uses Mulgae-owned synthetic content and creates no durable
certification.
A separate heartbeat requires explicit `--authorize-live-request` authority.

Live review and extraction use original source reads from a neutral cwd:

- ZCode runs `herdr-zcode` through an isolated `herdr-core` terminal. The
  current Desktop Z.AI Individual Coding Plan account supplies the private
  invocation projection. ZCode supports all core text roles and artist.
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
  Grok supports text roles. Artist assignment fails capability admission.

Both providers read prompts from `0400` files under `<scratch>/input/`.
Mulgae validates the staged report or extraction file and its completion
nonce after verified process-group absence (`ESRCH`). It publishes the accepted
bytes under `result_transport: "stdout"`. Historical transport receipts keep
their stored meaning. Mulgae bounds process lifetime, transport controls and
diagnostic metadata. Complete reports and provider stdout and stderr have no
product byte limit. Provider network, authentication, quota and rate-limit
effects remain the operator's provider outcomes. A new review after a failure
requires authority.
