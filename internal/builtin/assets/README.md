# Embedded runtime assets

This directory contains files compiled directly into the Mulgae binary:

- v1 JSON Schemas and one valid example for each schema;
- root-review prompt layers;
- role definitions;
- focused CLI help topics;
- the generated SHA-256 inventory.

`go generate ./internal/builtin` rebuilds `CHECKSUMS.sha256`. The runtime catalog
verifies a one-to-one checksum relationship before returning any asset.

These files are runtime contracts, not a second contributor-documentation tree.
Project goals and architecture live in the repository-level `docs/` directory.
