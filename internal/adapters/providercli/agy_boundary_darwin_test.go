//go:build darwin && arm64

package providercli_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func liveAgyInstalledHome(current func() (*user.User, error), effectiveUID int, override string) (string, error) {
	installed, err := current()
	if err != nil || installed == nil || !filepath.IsAbs(installed.HomeDir) || filepath.Clean(installed.HomeDir) != installed.HomeDir {
		return "", fmt.Errorf("installed user home is unavailable")
	}
	uid, err := strconv.ParseUint(installed.Uid, 10, 32)
	if err != nil || int(uid) != effectiveUID {
		return "", fmt.Errorf("installed user identity does not match effective UID")
	}
	if override != "" && override != installed.HomeDir {
		return "", fmt.Errorf("MULGAE_LIVE_AGY_HOME differs from the installed user home")
	}
	return installed.HomeDir, nil
}

func TestAgyInstalledHomeRejectsOverrideMismatch(t *testing.T) {
	current := func() (*user.User, error) {
		return &user.User{Uid: "501", HomeDir: "/Users/installed"}, nil
	}
	if _, err := liveAgyInstalledHome(current, 501, "/tmp/override"); err == nil {
		t.Fatal("accepted an AGY home override that differs from the installed user home")
	}
	if _, err := liveAgyInstalledHome(current, 502, ""); err == nil {
		t.Fatal("accepted an installed user whose UID differs from the effective UID")
	}
}

func liveAgyHomeAvailable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func liveAgyExecutableAvailable(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode()&0111 != 0
}

func liveAgyFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	buffer := make([]byte, 32<<10)
	defer func() {
		for index := range buffer {
			buffer[index] = 0
		}
	}()
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			if _, err := digest.Write(buffer[:count]); err != nil {
				return "", err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

type liveAgyAuthSettingsEntry struct {
	relative string
	mode     os.FileMode
	size     int64
	modified int64
	sha256   string
	device   int32
	inode    uint64
}

func liveAgyAuthSettingsManifest(home string) ([]liveAgyAuthSettingsEntry, error) {
	relatives := []string{
		".gemini/antigravity-cli/antigravity-oauth-token",
		".gemini/antigravity-cli/installation_id",
		".gemini/antigravity-cli/settings.json",
	}
	entries := make([]liveAgyAuthSettingsEntry, 0, len(relatives))
	for _, relative := range relatives {
		path := filepath.Join(home, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			entries = append(entries, liveAgyAuthSettingsEntry{relative: relative})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", relative, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("inspect %s: auth/settings path is not a regular file", relative)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("inspect %s: unsupported file identity", relative)
		}
		entry := liveAgyAuthSettingsEntry{
			relative: relative,
			mode:     info.Mode(),
			size:     info.Size(),
			modified: info.ModTime().UnixNano(),
			device:   stat.Dev,
			inode:    stat.Ino,
		}
		digest, err := liveAgyFileSHA256(path)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", relative, err)
		}
		entry.sha256 = digest
		entries = append(entries, entry)
	}
	return entries, nil
}

func liveAgyRequireNoCopiedNativeSettings(namespaceRoot string) error {
	return filepath.Walk(namespaceRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(namespaceRoot, path)
		if err != nil {
			return err
		}
		normalized := filepath.ToSlash(relative)
		if info.IsDir() {
			return nil
		}
		if strings.Contains("/"+normalized, "/home/.gemini/antigravity-cli/") ||
			strings.HasSuffix(normalized, "/home/.gemini/antigravity-cli") ||
			strings.Contains("/"+normalized, "/settings/") ||
			strings.HasSuffix(normalized, "/settings") ||
			strings.Contains("/"+normalized, "/auth/") ||
			strings.HasSuffix(normalized, "/auth") {
			return fmt.Errorf("unexpected namespace file %s", normalized)
		}
		return nil
	})
}

func TestAgyNamespaceRejectsCopiedNativeSettings(t *testing.T) {
	root := t.TempDir()
	copied := filepath.Join(root, "lease", "home", ".gemini", "antigravity-cli", "settings.json")
	if err := os.MkdirAll(filepath.Dir(copied), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copied, []byte(`{"token":"native"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := liveAgyRequireNoCopiedNativeSettings(root); err == nil {
		t.Fatal("accepted copied native AGY settings in a disposable namespace")
	}
}

func TestAgyAuthSettingsManifestDetectsMutation(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".gemini", "antigravity-cli", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"setting":"before"}`), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := liveAgyAuthSettingsManifest(home)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := liveAgyAuthSettingsManifest(home)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, unchanged) {
		t.Fatal("unchanged native AGY auth/settings manifests differ")
	}
	if err := os.WriteFile(settings, []byte(`{"setting":"after"}`), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := liveAgyAuthSettingsManifest(home)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(before, after) {
		t.Fatal("native AGY auth/settings manifest did not detect a mutation")
	}
}
