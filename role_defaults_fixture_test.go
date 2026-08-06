//go:build darwin && arm64

package main

import (
	"context"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/app/roleassets"
	"github.com/irootkernel/mulgae/internal/builtin"
)

// testRoleDefaults returns the build-owned role defaults exactly as production
// resolves them.
func testRoleDefaults() adapterconfig.RoleDefaults {
	definitions, err := roleassets.Load(context.Background(), builtin.NewCatalog())
	if err != nil {
		panic(err)
	}
	defaults, err := roleassets.Defaults(definitions)
	if err != nil {
		panic(err)
	}
	return defaults
}
