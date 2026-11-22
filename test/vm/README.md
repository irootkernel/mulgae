# Mulgae guest qualification

This harness prepares a candidate, seals explicit inputs, and submits one managed
Haepari Job. Local contract checks do not establish guest, live-provider, manual,
release or Epic acceptance. Automatic native cases, manual observations and
live-provider qualification have separate [required observations](scenarios.md).
An automatic success requires every native case output, successful helper and
controller cleanup, recipe inventory, and the native Job result.

The host adapter follows Haepari v0.1.0's `examples/project-test` contract at
`800da97b7e2ca84a15d4ee5921702ec57bbc7d61`. Its released executable is
`sha256:e1a4c0a047f9d6b6e7048fdcfea961b7bafb3a3c627786619cff3796433d6b20`.
The published archive is
`sha256:6667cab322f326eb390b8cab89fd292e22d7436312434e7facd66213fe1a8a18`.
Build revision `fc3b975f8a99cacb96aecc988d3adbc04dda7309` and release
source revision remain separate identities. Empty `qualified_backends` is
not a predicate for UTM support; use the selected resource's native doctor.

## Local preparation

CO prepares the environment records from observed existing guest inventory and
an explicitly declared candidate fixture target. An existing user-created
profile file is not required; the declared target is never reported as an
observed or accepted guest version.

Run `make test-vm-contract` for scripted host-contract, guest-policy and actual
local process/socket lifecycle checks. It starts no controller, VM, provider or
Go installation.
`make test-vm-driver-compile` compiles the guest-only Go driver without running
it. Ordinary offline and release gates remain separate.

Prepare under a new physical private directory:

```sh
./dev exec -- python3 -B test/vm/prepare.py \
  --commit <accepted-production-commit> \
  --output /private/tmp/<owned-parent>/prepared
```

[prepare.py](prepare.py) reads immutable Git build inputs and uses
`go install -trimpath` with the committed release version and revision linker
values, isolated GOBIN, module/compiler caches and a local Go toolchain. It
records the binary hash, production input hashes, complete skill Git tree,
per-file hashes, and the working-tree test overlay's base provenance.
The candidate travels as deterministic gzip so the complete fixture fits the
released controller's transport limit. Admission and guest expansion both
verify the original executable hash; compression does not rebuild the binary.
The six skill files must equal the selected Git tree. Build material is never
used as provider review source.

Supply an external `mulgae.haepari-vm-request/v2` JSON document with:

| Section | Required binding |
|---|---|
| `haepari` | Executable/path/hash, explicit Installation root and native ID |
| `resource` | Registered `utm-macos` ID and current configuration revision |
| `guest` | Actual expected hardware UUID and absolute `go_executable`, `python_executable`, `prior_go_executable` paths |
| `profiles` | Starting/target IDs, external files and their distinct SHA256 values |
| `candidate` | Prepared source commit, actual binary SHA256, full skill Git tree and authorization reference |
| `prior_release` | `v0.1.26`, commit `c422590155f62380709c8f6fd08c9ad423badaaa`, install target `github.com/irootkernel/mulgae@v0.1.26`, historical rebuild Go version (derived from `PRIOR_GO_VERSION`), GOPROXY and declared network exposure |
| `review_controller_home` | New isolated absolute guest directory, separate from the outer Installation |
| `live_accounts` | Existing authorized guest account aliases, native app/client paths and the primary Codex home, when selecting live checks |

The guest must already have the exact current Go, Python and historical-rebuild
Go declared in `tools/toolchains.env`, and the requested native clients. Versions
are derived during admission and bound to the prepared candidate's sealed pin
file and runner. Each declared path is checked against its own role before work.
See [toolchain setup](../../docs/implementation-tips/toolchains.md). Regenerate
v1 execution requests; old stored evidence is not rewritten.

The preparation command can stage the selected released controller with
`--haepari <absolute-executable>` for a private fixture copy when Haepari is
absent from the guest PATH. Its hash must match the admitted released unit.
Qualification performs no automatic language installation, sign-in, profile
change, credential copy or guest provisioning.
The prior release has no published binary assets; its provenance is an actual
tag-pinned Go rebuild. Before compilation, the guest compares its downloaded
module's production inputs with hashes from the pinned old Git commit.

## Admission and replay

After the concrete guest effects and account use are authorized:

```sh
make test-vm PREPARED_DIR=/private/tmp/<owned-parent>/prepared \
  REQUEST=/private/tmp/<owned-parent>/request.json \
  HAEPARI_HOME=<selected-host-installation-root> RESOURCE=<registered-resource> \
  SUITE=guest-qualification MODE=auto RUN_DIR=/private/tmp/<owned-run-directory>
```

A custom external project config may select finite phase budgets through
`host.py --config`; retain its prepared selected-file inventory. In particular,
manual setup and workload smoke execute within the **prepare** budget, so a
prior-release rebuild must fit that admitted budget. Never change a running
Job's deadlines or relabel a starting profile as its target.

[host.py](host.py) persists the original key, spec, sealed manifest, request and
resource identity before submission. It consumes native
`haepari.envelope/v1`, Receipt and Result shapes. Retry the same saved run to
observe/replay that Job. An unavailable response, wait timeout or failed
extraction supplies no PASS and does not authorize a replacement Job.

The native workspace contains `bundle/` and `results/`. Workload cwd is
`bundle`; [run.sh](run.sh) writes `../results/<suite>`. It verifies the actual
Darwin hypervisor and hardware UUID, native ParentChain array and sealed input.
There are no physical-host guard override commands. Parent context stays
inherited and its nonce is never copied into reports. The guest never submits
another outer VM Job or issues power commands.

## Live and manual work

`SUITE=live-providers` serially runs the existing owning targets:
`test-e2e`, `test-grok`, `test-agy`, enabled
`test-e2e-opt-in`, and `test-mcp-requirements-clients`.
The admitted account block supplies ZCode's app, Grok/AGY/Codex executables,
the primary Codex home, and Codex/Claude MCP client paths. Account aliases
record operator authorization; they do not prove a provider's private backend
identity.

Live workloads use [gui.py](gui.py) to enter the logged-in guest user's Aqua
session through one temporary launchd helper. The SSH caller keeps the original
outer Job. A private in-memory lifeline passes its environment and unchanged
ParentChain, cancels work on caller loss, and joins the helper before cleanup.
The recipe records command termination, GUI helper teardown and native Job
cleanup separately. No persistent LaunchAgent is installed.

Check account readiness in that GUI session. An SSH keychain-access failure can
make an existing Claude login appear unavailable. The helper does not copy
host credentials, export refresh tokens or perform login. Missing credentials
remain a prerequisite failure.

The Make targets accept `MULGAE_TEST_INSTALLED_BINARY`,
`MULGAE_TEST_SOURCE_COMMIT` and `MULGAE_TEST_PREPARED_MANIFEST` for this sealed
guest recipe. They copy the exact installed candidate rather than rebuild a
different binary. All three inputs must be supplied together; the source commit
must be a full lowercase Git SHA. Each owning target records the supplied source
label and SHA-256 of the executable and preparation manifest. These records do
not replace sealed-request admission or prove a release's source provenance.
`make test` refuses these overrides and builds its own exact candidate. Normal
target defaults are unchanged. Private logs and any retained failure projects
stay in the owned guest runtime directory.

For `MODE=manual`, successful preparation holds capacity in
`awaiting_manual`; smoke never supplies human PASS. Read
[scenarios.md](scenarios.md), retain the installed fixture through all manual
observations, stop and wait every owned process, then run
[finalize.py](finalize.py) against its exact staging record while still awaiting
manual completion. Transfer the original observations and bound cleanup/inventory
through the authorized existing manual transport to the saved host run. The host
adapter checks them before submitting the closed native manual result. Native
acknowledgment, collection, native cleanup and final verdict remain separate.
