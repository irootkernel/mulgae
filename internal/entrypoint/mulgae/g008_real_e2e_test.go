package mulgae

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
)

func mustG008RealExportInstaller(t *testing.T, fixture *g008RealE2EFixture) *filesystem.ExportInstaller {
	t.Helper()
	installer, err := filesystem.NewExportInstaller(fixture.writer)
	if err != nil {
		t.Fatal(err)
	}
	return installer
}

func g008RealTargetHash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
