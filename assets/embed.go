// Package assets holds the human-authored, build-owned catalog documents that
// ship inside the mulgae binary. It sits at the repository root so the tunable
// role defaults are discoverable without reading internal packages.
//
// The documents here are generation-time authorities only. They supply the
// review system prompts and the default provider preference order that
// mulgae init writes into a new project configuration. They are never a
// runtime configuration authority: no command resolves a configured value from
// embedded bytes, and .mulgae/config.yaml is never re-derived after init.
package assets

import _ "embed"

// RolesYAML is the mulgae-roles.v1 document describing every fixed review role.
//
//go:embed roles.yaml
var RolesYAML []byte
