//go:build darwin

package config

import (
	"os"
	"path/filepath"

	"github.com/irootkernel/mulgae/internal/ports"
)

// SelectLocality preserves the caller's .git observation and fallback timing.
func SelectLocality(root ports.AnchoredRoot, attestor ports.ConfigLocalityAttestor) (ports.ConfigLocalityAttestor, bool, error) {
	if _, err := os.Lstat(filepath.Join(root.String(), ".git")); os.IsNotExist(err) {
		return NewFilesystemLocalityAttestor(), true, nil
	} else if err != nil {
		return nil, false, err
	}
	return attestor, false, nil
}
