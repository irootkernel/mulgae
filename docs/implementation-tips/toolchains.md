# Development toolchains

`tools/toolchains.env` owns the exact Go and Python execution versions.
`GO_VERSION` covers builds, generation, formatting, tests and release binaries.
`PYTHON_VERSION` covers development checks and the VM host/guest tools.
`PRIOR_GO_VERSION` independently pins the compiler used to rebuild the historical
release in VM qualification.

`tools/mise.toml` is an empty isolation configuration. The launcher passes it to
mise in place of user-global and system configuration; it declares no versions.

The `go` directive in `go.mod` remains the minimum Go requirement. Module and
Go-tool dependencies remain in `go.mod` and `go.sum`; `go.sum` verifies module
contents and does not pin the compiler. Python helpers use the standard library,
so they have no third-party dependency lockfile. No separate minimum Python
support range is promised; development uses the exact declared version.

## Setup

Install mise explicitly if it is missing:

```sh
brew install mise
make toolchain-install
make toolchain-check
```

`toolchain-install` installs the declared versions using mise's built-in Go and
Python installers. Python uses precompiled CPython only. A missing distribution
fails installation. The command does not edit the pins, select a global language
default, activate shell hooks or install default packages. It does not install or
upgrade mise itself. Go archives retain mise's checksum verification.

Existing installations can be selected with absolute paths in the invoking
environment. These paths undergo the same exact-version checks:

```sh
export MULGAE_GO_EXECUTABLE=/absolute/path/to/go
export MULGAE_PYTHON_EXECUTABLE=/absolute/path/to/python3
export MULGAE_PRIOR_GO_EXECUTABLE=/absolute/path/to/prior-go
make toolchain-check
```

Do not commit machine-specific paths. The `GO` and `PYTHON` Make overrides also
accept executable paths and pass them through the same guard. They cannot bypass
version checks.

## Commands

| Command | Purpose |
|---|---|
| `make help` | Show development commands without requiring either language |
| `make toolchain-install` | Explicitly provision declared versions; requires mise |
| `make toolchain-check` | Show each role's declared/observed version and selected/physical path |
| `./dev go ...` | Build, test or inspect with the pinned Go |
| `./dev python ...` | Execute with the pinned Python |
| `./dev exec -- command ...` | Supply both verified runtimes to a command and its children |
| `make generate` | Run both canonical asset generators |
| `make fmt` | Automatically format project Go files with the pinned gofmt |
| `make fmt-check` | Check formatting with the selected Go distribution's gofmt |
| `make vuln-check` | Run the module's declared govulncheck tool |
| `make test-toolchain` | Check selection, installation boundaries and negative cases using fixtures |
| `make test-offline` | Run preparation, unit and integration checks in order |

The existing release, live-provider, MCP and VM Make targets retain their scopes.
`make test`, `make test-offline` and `make test-prepare` format Go files after
code generation and before static checks. Formatting includes tracked and
non-ignored untracked Go files, excluding `vendor/`. `make fmt-check` checks the
same files without rewriting them.
Running an arbitrary system `go` or `python3` directly is outside the development
entrypoints. Use `./dev` for focused commands and editor/tool launches that need
the project's runtimes. Public consumer installation remains documented in the
root README.

Ordinary execution never provisions a missing runtime and never selects a system
replacement. It uses an exact mise installation or an explicitly supplied path,
verifies the actual executable, and executes that physical file. Discovery and
version probes have a ten-second deadline. Go uses `GOTOOLCHAIN=local`,
`GOENV=off` and `GOWORK=off`; gofmt comes from that Go distribution. Python
selection clears ambient interpreter path overrides and disables user packages.

## Upgrade

Edit the relevant exact version in `tools/toolchains.env`, run
`make toolchain-install`, then `make toolchain-check` and the affected checks.
Changing current Go leaves `PRIOR_GO_VERSION` unchanged. Change `go.mod` only
when deliberately changing the minimum supported Go version, and update
dependencies only when that is separately intended. Historical evidence keeps
its original version labels.

Run `make generate` twice after generation changes and confirm the second run
adds no diff. Use `make test-offline`, VM contract/driver checks and
`make test-release` for this tooling surface. Full release readiness still needs
the repository's complete release gate and its live-provider evidence.

Fresh VM requests use `mulgae.haepari-vm-request/v2`. Declare the guest's absolute
`go_executable`, `python_executable` and `prior_go_executable` paths. Admission
derives the version map from the canonical pins; preparation seals the pin file
and runner with the candidate, and the guest checks the same versions before
work. Regenerate v1 execution requests. Old stored evidence is retained; no VM
provisioning or runtime installation occurs during qualification.
