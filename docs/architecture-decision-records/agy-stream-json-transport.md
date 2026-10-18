# AGY stream-JSON transport

Status: Accepted

Roadmap: [EPIC-011](../roadmap/README.md#epic-011-agy-stream-json-review-provider)

## Decision

AGY is a text-role provider using one bidirectional stream-JSON conversation
per invocation. The adapter launches the selected executable with
`--input-format stream-json --output-format stream-json`, native plan mode,
disabled slash commands, an adapter-owned agent and a disposable Gemini
directory. Prompts travel through stdin after initialization; neither `-p`
nor `--print` carries the prompt, and no loopback hub is started.

The adapter accepts initialization and the exact `request-review` permission
acknowledgement before sending one user turn. Correlated tool starts and
completions must match the admitted original-source read plan. Unknown tools,
missing or mismatched inputs, failed results, and protocol errors fail closed.
Only the completed assistant turn supplies report text. Stderr is diagnostic.

Completion requires stdin half-close, drained output EOF, natural exit zero,
complete input, valid lifecycle evidence, no requested termination signals and
verified process-group absence. A stop signal never manufactures a successful
report. The shared protocol runner supplies half-close and process observations;
AGY owns their provider-specific acceptance rules.

## Native policy and source reads

The neutral reviewer cwd and original source lease are shared with other
providers. There is no source snapshot, copied checkout or replay tree. An
adapter-authored agent, settings and empty MCP policy live only inside the
private invocation namespace. Original project instructions and user settings,
skills, plugins and MCP definitions are not imported as authority.

AGY's native command grants use prefix matching. Each admitted command carries
the indexed `MULGAE_READ_GUARD[1]=1 ` prefix, including its trailing space, and
the policy explicitly denies `command(1)`. This prevents appended, fallback
and bare-command forms from inheriting an ordinary prefix grant. The driver
also checks byte-exact command operands and correlated completions. File grants
split at the first opening parenthesis and the final closing parenthesis,
so canonical paths containing parentheses remain valid. NUL, CR and LF remain forbidden.

Review and extraction require the outer macOS Seatbelt guard. It denies writes
outside admitted private runtime directories, source/Git/guide writes, and
reads, writes, links and Unix sockets at protected credential roots. It is not
general process, IPC, network or read containment. Native permission controls
and the outer guard serve distinct boundaries; neither replaces the other.

The declared version floor is `1.2.9`; the latest verified binary is `1.4.2`.
Command codecs are separately known for exactly `1.4.0` and `1.4.2`. A newer
version cannot acquire command authority solely by satisfying the floor.
Installed 1.4.2 native checks established positive guarded reads and rejection
of appended, fallback and bare commands. The guarded 1.4.0 codec is statically
checked; that is not a new native certification of 1.4.0.

Native 1.4.2 also omits `permissions.allow` when saving an empty allow list.
The audit accepts that omission only for 1.4.2 and an already-empty expected
set. Explicit null, omission of nonempty grants, added grants and changed deny
rules remain failures. This normalization grants no additional access.

## Credentials and lifetime

The only credential source is the OS user's default
`~/.gemini/antigravity-cli/antigravity-oauth-token`. Admission uses no-follow,
nonblocking file access and requires a nonempty regular mode-`0600` file owned
by the user with one link. There is no account scan, profile selector,
credential-home override or imported native configuration.

Each invocation gets a writable disposable HOME, Gemini directory and token
copy. Native refresh may update that copy; Mulgae never writes it back to the
original. `SSH_TTY=/dev/null` avoids the native interactive keychain route.
This does not claim a process-wide Keychain trace or forced-refresh proof.
Adapter-authored policy files remain descriptor-bound and are audited after
execution. Unverified drain retains policy, credentials and the namespace,
forbids reuse, and cannot yield a successful cleanup receipt. Composition
removes the namespace parent only when empty, before closing the reviewer home
or removing workspace roots. It never recursively erases a retained namespace.

## Public integration and verification

Config v5 adds optional AGY executable, model, reasoning-effort and timeout
fields under their existing local/project authorities. Omitted model and
effort preserve native defaults independently. Documentation prefers AGY only
when generating new policy; other default roles retain ZCode first. AGY
cannot serve artist and failures never substitute another provider.

CLI and MCP share configured execution, preflight, results and verified reads.
MCP has no initialization or provider-configuration tool. Qualification validates
one JSON object with exactly the expected `root`, `link` and `role` strings.
Native 1.4.2 repeats the proof across four internal turns when `--json-schema`
is supplied. The adapter omits that flag and keeps strict response validation;
it does not accept concatenated proofs as a workaround. A native synthetic
heartbeat verified one proof and one native turn with this invocation.
Offline doctor uses only fixed version argv. Heartbeat has a dedicated
`agy-logic` namespace even when generated policy assigns AGY only to
documentation; it still requires
explicit live-request authorization.

`make test-agy` builds the exact candidate release binary and performs one
documentation review with the default account. A parenthesized source path
contains an undisclosed marker that must appear in the report. The gate checks
one initial invocation, protocol closure, publication, public report/query and
export access, unchanged original token/source/Git state, and removed private
runtime roots. Private evidence survives both success and failure. It supplies
no multi-account, installation, release or durable provider-certificate claim.
Successful invocation diagnostics retain process terminal facts rather than
individual session receipts. The driver and registry enforce half-close, EOF,
complete input, no requested signals and verified process-group absence before
publication; negative owner tests cover those rejection paths.

## Rejected alternatives

- A print-argv prompt or hub transport would bypass the selected correlated
  stream protocol and add another execution surface.
- Treating signal termination as success would hide incomplete input or an
  undrained process group.
- Importing native user settings or credential profiles would expand authority
  beyond the single default account and the admitted read plan.
- Re-admitting all historical AGY artifacts by family or version token would
  weaken captured/composite lineage retirement checks.
