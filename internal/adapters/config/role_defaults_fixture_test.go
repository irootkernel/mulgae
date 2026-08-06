package config

import (
	"context"

	"github.com/irootkernel/mulgae/internal/app/roleassets"
	"github.com/irootkernel/mulgae/internal/builtin"
)

// testRoleDefaults returns the build-owned role defaults exactly as production
// resolves them. Tests never spell a default provider order themselves; the root
// role document is the only authority.
func testRoleDefaults() RoleDefaults {
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
