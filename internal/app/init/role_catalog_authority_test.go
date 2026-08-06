package init

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// rewrittenRoleCatalog serves the production catalog with the role document's
// bytes replaced. Load validates the asset's source and media type but not its
// digest, so this is enough to stand in for an edited assets/roles.yaml.
type rewrittenRoleCatalog struct {
	inner   ports.ContractCatalog
	replace func([]byte) []byte
	err     error
}

func (catalog rewrittenRoleCatalog) Read(ctx context.Context, id ports.AssetID) (ports.AssetMetadata, []byte, error) {
	metadata, raw, err := catalog.inner.Read(ctx, id)
	if err != nil || id.String() != "sot:roles.yaml" {
		return metadata, raw, err
	}
	if catalog.err != nil {
		return ports.AssetMetadata{}, nil, catalog.err
	}
	return metadata, catalog.replace(raw), nil
}

func (catalog rewrittenRoleCatalog) List(ctx context.Context) ([]ports.AssetMetadata, error) {
	return catalog.inner.List(ctx)
}

func initServiceWithCatalog(t *testing.T, catalog ports.ContractCatalog) (*Service, ports.AnchoredRoot, Overrides) {
	t.Helper()
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatalf("chmod project root: %v", err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatalf("anchor project root: %v", err)
	}
	launcher := filepath.Join(t.TempDir(), "zcode.cjs")
	if err := os.WriteFile(launcher, []byte("module.exports = {}\n"), 0o600); err != nil {
		t.Fatalf("write zcode launcher: %v", err)
	}
	service, err := NewService(&testInstaller{}, testInspector{}, testAttestor{}, testResultPrevalidator{}, testClock{}, adapterconfig.SourceFactory{}, adapterconfig.YAMLCodec{}, catalog)
	if err != nil {
		t.Fatalf("build init service: %v", err)
	}
	overrides := Overrides{
		KimiExecutable:      "/bin/kimi",
		ZCodeNodeExecutable: "/bin/node",
		ZCodeLauncher:       launcher,
		AGYExecutable:       "/bin/agy",
	}
	return service, root, overrides
}

// TestInitOutputFollowsEditedRoleProviderPreferences is the load-bearing proof
// that assets/roles.yaml is the authority. Editing one role's preference order
// must change that role's generated assignment and leave every other role alone.
func TestInitOutputFollowsEditedRoleProviderPreferences(t *testing.T) {
	edited := rewrittenRoleCatalog{
		inner: builtin.NewCatalog(),
		replace: func(raw []byte) []byte {
			original := []byte("  - id: testing\n    order: 6\n    activation: always\n    provider_preferences: [zcode, agy, kimi]\n")
			if !bytes.Contains(raw, original) {
				t.Fatalf("role document does not carry the expected testing entry")
			}
			return bytes.Replace(raw, original, []byte("  - id: testing\n    order: 6\n    activation: always\n    provider_preferences: [kimi, agy, zcode]\n"), 1)
		},
	}
	service, root, overrides := initServiceWithCatalog(t, edited)
	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root,
		ProjectName: "project",
		NativeHome:  "/Users/test",
		Selection:   Selection{Mode: SelectionSelected, ProviderIDs: []string{"kimi", "zcode", "agy"}},
		RoleIDs:     []string{"logic", "security", "testing"},
		Overrides:   overrides,
	})
	if err != nil {
		t.Fatalf("initialize project: %v (%+v)", err, result)
	}
	data, err := os.ReadFile(filepath.Join(root.String(), adapterconfig.ConfigRelativePath))
	if err != nil {
		t.Fatalf("read installed config: %v", err)
	}
	config, err := adapterconfig.Decode(data)
	if err != nil {
		t.Fatalf("decode installed config: %v", err)
	}
	if config.Roles.Testing.PrimaryProvider != "kimi" || config.Roles.Testing.FallbackProvider != "agy" {
		t.Fatalf("edited testing role = %s/%s, want kimi/agy", config.Roles.Testing.PrimaryProvider, config.Roles.Testing.FallbackProvider)
	}
	if config.Roles.Security.PrimaryProvider != "zcode" || config.Roles.Security.FallbackProvider != "agy" {
		t.Fatalf("untouched security role = %s/%s, want zcode/agy", config.Roles.Security.PrimaryProvider, config.Roles.Security.FallbackProvider)
	}
	if config.Roles.Logic.PrimaryProvider != "kimi" || config.Roles.Logic.FallbackProvider != "zcode" {
		t.Fatalf("untouched logic role = %s/%s, want kimi/zcode", config.Roles.Logic.PrimaryProvider, config.Roles.Logic.FallbackProvider)
	}
}

func TestInitializeProjectFailsClosedWhenRoleCatalogIsUnreadable(t *testing.T) {
	unreadable := rewrittenRoleCatalog{inner: builtin.NewCatalog(), err: errors.New("role document unavailable")}
	service, root, overrides := initServiceWithCatalog(t, unreadable)
	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root,
		ProjectName: "project",
		NativeHome:  "/Users/test",
		Selection:   Selection{Mode: SelectionSelected, ProviderIDs: []string{"kimi", "zcode", "agy"}},
		RoleIDs:     []string{"logic"},
		Overrides:   overrides,
	})
	var failure *Failure
	if !errors.As(err, &failure) {
		t.Fatalf("initialize project error = %v, want typed failure", err)
	}
	if failure.Code() != "init_role_catalog_invalid" || failure.Class() != domain.FailureInternal || failure.Retryable() {
		t.Fatalf("failure = %s/%s retryable=%t, want init_role_catalog_invalid/internal_failure retryable=false", failure.Code(), failure.Class(), failure.Retryable())
	}
	if result.WriteState != "not_attempted" || result.ConfigSHA256 != "" || result.Committed {
		t.Fatalf("result = %+v, want an untouched not_attempted outcome", result)
	}
	if _, err := os.Stat(filepath.Join(root.String(), ".mulgae")); !os.IsNotExist(err) {
		t.Fatalf("stat .mulgae = %v, want it to be absent", err)
	}
}

// TestInitializeProjectRejectsRoleCatalogMissingArtistDefaults proves the artist
// input defaults are sourced from the document rather than restated in Go.
func TestInitializeProjectRejectsRoleCatalogMissingArtistDefaults(t *testing.T) {
	stripped := rewrittenRoleCatalog{
		inner: builtin.NewCatalog(),
		replace: func(raw []byte) []byte {
			lines := strings.Split(string(raw), "\n")
			kept := make([]string, 0, len(lines))
			dropping := false
			for _, line := range lines {
				if strings.TrimSpace(line) == "default_inputs:" {
					dropping = true
					continue
				}
				if dropping {
					if strings.HasPrefix(line, "      ") {
						continue
					}
					dropping = false
				}
				kept = append(kept, line)
			}
			return []byte(strings.Join(kept, "\n"))
		},
	}
	service, root, overrides := initServiceWithCatalog(t, stripped)
	_, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root,
		ProjectName: "project",
		NativeHome:  "/Users/test",
		Selection:   Selection{Mode: SelectionSelected, ProviderIDs: []string{"kimi", "zcode", "agy"}},
		RoleIDs:     []string{"logic"},
		Overrides:   overrides,
	})
	var failure *Failure
	if !errors.As(err, &failure) || failure.Code() != "init_role_catalog_invalid" {
		t.Fatalf("initialize project error = %v, want init_role_catalog_invalid", err)
	}
}
