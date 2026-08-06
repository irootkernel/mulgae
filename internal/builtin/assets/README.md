# Embedded runtime assets

This directory contains files compiled directly into the Mulgae binary:

- v1 JSON Schemas and one valid example for each schema;
- root-review prompt layers;
- focused CLI help topics;
- the generated SHA-256 inventory.

The role definitions are not here. `assets/roles.yaml` at the repository root
carries every role's review guidance, its ordered provider preference for
`mulgae init`, and the artist input defaults. A `go:embed` pattern cannot escape
its own package directory, so that document is embedded by the root `assets`
package and overlaid into this catalog under the same checksum inventory.

`go generate ./internal/builtin` rebuilds `CHECKSUMS.sha256`, covering both this
directory and the root role document. The runtime catalog verifies a one-to-one
checksum relationship before returning any asset.

These files are runtime contracts, not a second contributor-documentation tree.
Project goals and architecture live in the repository-level `docs/` directory.
