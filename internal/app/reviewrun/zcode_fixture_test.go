package reviewrun

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/herdr"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/zcodefixture"
)

var zcodeFixture struct {
	sync.Once
	root string
	pkg  herdr.ZCodePackage
	err  error
}

func TestMain(m *testing.M) {
	status := m.Run()
	if zcodeFixture.root != "" {
		if err := os.RemoveAll(zcodeFixture.root); err != nil {
			fmt.Fprintln(os.Stderr, "failed to clean ZCode test fixture")
			if status == 0 {
				status = 1
			}
		}
	}
	os.Exit(status)
}

func authorityTestZCodeCompanion(t *testing.T, version string) ports.ZCodeCompanionObservation {
	t.Helper()
	zcodeFixture.Do(func() {
		zcodeFixture.root, zcodeFixture.err = os.MkdirTemp("", "mulgae-app-test-companion-")
		if zcodeFixture.err != nil {
			return
		}
		canonical, err := filepath.EvalSymlinks(zcodeFixture.root)
		if err != nil {
			zcodeFixture.err = err
			return
		}
		zcodeFixture.root = canonical
		zcodeFixture.pkg, zcodeFixture.err = makeAuthorityTestZCodePackage(zcodeFixture.root)
	})
	if zcodeFixture.err != nil {
		t.Fatal(zcodeFixture.err)
	}
	if !validVersionText(version) {
		version = "0.2.0"
	}
	bundle := filepath.Join(zcodeFixture.root, "ZCode.app")
	return ports.ZCodeCompanionObservation{
		Executable: zcodeFixture.pkg.Launcher.Path, ExecutableSHA256: zcodeFixture.pkg.Launcher.SHA256,
		PackageSHA256: zcodeFixture.pkg.PackageSHA256, Version: version, AppVersion: "4.0.0",
		AppBundle: bundle, BundleOverride: bundle, MinimumAppVersion: "3.18.2",
	}
}

func makeAuthorityTestZCodePackage(root string) (herdr.ZCodePackage, error) {
	_, launcher, err := zcodefixture.Create(root)
	if err != nil {
		return herdr.ZCodePackage{}, err
	}
	const catalog = `{"revision":1}`
	const auth = `{"providerId":"account:zai-individual-coding-plan","identity":"fixture","accountAccess":{"type":"zhipu-account","mode":"individual-coding-plan","accountType":"zai"}}`
	script := fmt.Sprintf(`#!/bin/sh
set -eu
[ "$1" = prepare-isolated ] && [ "$2" = --out-dir ]
printf '%%s' '%s' > "$3/auth.json"
printf '%%s' '%s' > "$3/catalog.json"
chmod 600 "$3/auth.json"
chmod 400 "$3/catalog.json"
printf '{"authFile":"%%s/auth.json","catalogFile":"%%s/catalog.json","catalogRevision":1,"catalogSHA256":"%x","catalogSource":"bundled","appVersion":"4.0.0","minZcodeAppVersion":"3.18.2","providerId":"account:zai-individual-coding-plan","accountIdentitySHA256":"%x"}\n' "$3" "$3"
`, auth, catalog, sha256.Sum256([]byte(catalog)), sha256.Sum256([]byte("fixture")))
	if err := os.WriteFile(launcher, []byte(script), 0o700); err != nil {
		return herdr.ZCodePackage{}, err
	}
	return herdr.ResolveZCodePackage(herdr.ResolveOptions{OverridePath: launcher, HasOverride: true})
}
