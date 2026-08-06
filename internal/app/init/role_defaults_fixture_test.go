package init

import (
	"context"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/roleassets"
	"github.com/irootkernel/mulgae/internal/builtin"
)

// testRoleDefaults returns the build-owned role defaults exactly as production
// resolves them.
func testRoleDefaults() appconfig.RoleDefaults {
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
