//go:build darwin && arm64

package haepari

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/strictjson"
	"golang.org/x/sys/unix"
)

const (
	HaepariMaxControlEnvelopeBytes = 4 << 20
	maxSocketPathBytes             = 103
	maxParentContextBytes          = 8192
	maxParentEntries               = 32
	parentContextHeader            = "X-Haepari-Parent-Context"
	lockGrantHeader                = "X-Haepari-Lock-Grant"
	protocolHeader                 = "X-Haepari-Protocol"
	protocolMinHeader              = "X-Haepari-Protocol-Min"
	protocolMaxHeader              = "X-Haepari-Protocol-Max"
)

type StateRoot struct {
	Home       string
	SocketPath string
}

// ResolveStateRoot validates an explicit HAEPARI_HOME and its existing private
// control.sock without creating, repairing, or falling back to ~/.haepari.
func ResolveStateRoot(rawHome string) (StateRoot, error) {
	if strings.TrimSpace(rawHome) == "" {
		return StateRoot{}, &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonInstallationNotSelected,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_HOME is not set",
		}
	}
	if strings.ContainsRune(rawHome, 0) || !filepath.IsAbs(rawHome) {
		return StateRoot{}, &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_HOME must be an absolute path without NUL bytes",
		}
	}

	cleaned := filepath.Clean(rawHome)
	for _, systemLink := range []string{"/tmp", "/var"} {
		if cleaned == systemLink || strings.HasPrefix(cleaned, systemLink+"/") {
			if target, err := filepath.EvalSymlinks(systemLink); err == nil && filepath.IsAbs(target) {
				cleaned = filepath.Clean(target + strings.TrimPrefix(cleaned, systemLink))
			}
			break
		}
	}
	if cleaned == "/" {
		return StateRoot{}, &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_HOME cannot be root directory",
		}
	}

	uid := os.Getuid()
	for cur := cleaned; ; cur = filepath.Dir(cur) {
		info, err := os.Lstat(cur)
		if err != nil {
			return StateRoot{}, &ports.ReviewCoordinationError{
				Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
				Retry:   ports.ReviewCoordinationRetryWhenAvailable,
				Message: "HAEPARI_HOME ancestor or directory is unavailable",
				Cause:   err,
			}
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return StateRoot{}, &ports.ReviewCoordinationError{
				Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
				Retry:   ports.ReviewCoordinationRetryNever,
				Message: "HAEPARI_HOME or ancestor is a symlink or non-directory",
			}
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return StateRoot{}, &ports.ReviewCoordinationError{
				Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
				Retry:   ports.ReviewCoordinationRetryNever,
				Message: "HAEPARI_HOME stat metadata unavailable",
			}
		}
		if int(st.Uid) != uid && st.Uid != 0 {
			return StateRoot{}, &ports.ReviewCoordinationError{
				Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
				Retry:   ports.ReviewCoordinationRetryNever,
				Message: "HAEPARI_HOME or ancestor is owned by a foreign user",
			}
		}
		if info.Mode().Perm()&0o022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return StateRoot{}, &ports.ReviewCoordinationError{
				Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
				Retry:   ports.ReviewCoordinationRetryNever,
				Message: "HAEPARI_HOME or ancestor is group or world writable",
			}
		}
		var fs unix.Statfs_t
		if err := unix.Statfs(cur, &fs); err != nil || fs.Flags&unix.MNT_LOCAL == 0 {
			return StateRoot{}, &ports.ReviewCoordinationError{
				Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
				Retry:   ports.ReviewCoordinationRetryNever,
				Message: "HAEPARI_HOME must reside on a local filesystem",
				Cause:   err,
			}
		}
		if cur == cleaned {
			if int(st.Uid) != uid || info.Mode().Perm()&0o077 != 0 {
				return StateRoot{}, &ports.ReviewCoordinationError{
					Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
					Retry:   ports.ReviewCoordinationRetryNever,
					Message: "HAEPARI_HOME must be owned by current user with private 0700 permissions",
				}
			}
		}
		if cur == "/" {
			break
		}
	}

	socketPath := filepath.Join(cleaned, "control.sock")
	if len([]byte(socketPath)) > maxSocketPathBytes {
		return StateRoot{}, &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_HOME control.sock path exceeds Unix socket length bound",
		}
	}
	sockInfo, err := os.Lstat(socketPath)
	if err != nil {
		return StateRoot{}, &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
			Retry:   ports.ReviewCoordinationRetryWhenAvailable,
			Message: "HAEPARI_HOME control.sock is unavailable",
			Cause:   err,
		}
	}
	if sockInfo.Mode()&os.ModeSymlink != 0 || sockInfo.Mode()&os.ModeSocket == 0 {
		return StateRoot{}, &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_HOME control.sock is not a regular Unix socket",
		}
	}
	sockStat, ok := sockInfo.Sys().(*syscall.Stat_t)
	if !ok || int(sockStat.Uid) != uid || sockInfo.Mode().Perm()&0o077 != 0 {
		return StateRoot{}, &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonControllerUnreachable,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_HOME control.sock must be owned by current user with private permissions",
		}
	}

	return StateRoot{
		Home:       cleaned,
		SocketPath: socketPath,
	}, nil
}

type parentContextEntry struct {
	InstallationID  string `json:"installation_id"`
	JobID           string `json:"job_id"`
	LeaseGeneration int64  `json:"lease_generation"`
	Nonce           string `json:"nonce"`
}

// ValidateParentContext validates HAEPARI_PARENT_CONTEXT locally against
// Haepari v0.1.0's DecodeParentChain contract before any socket dial.
func ValidateParentContext(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > maxParentContextBytes {
		return "", &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonParentContextInvalid,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_PARENT_CONTEXT exceeds 8192 bytes",
		}
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "null" || trimmed == "[]" {
		return raw, nil
	}

	decoder := json.NewDecoder(strings.NewReader(raw))
	var rawEntries []json.RawMessage
	if err := decoder.Decode(&rawEntries); err != nil || rawEntries == nil {
		return "", &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonParentContextInvalid,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_PARENT_CONTEXT must be a valid JSON array",
			Cause:   err,
		}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonParentContextInvalid,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_PARENT_CONTEXT contains trailing JSON tokens",
		}
	}
	if len(rawEntries) > maxParentEntries {
		return "", &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonParentContextInvalid,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_PARENT_CONTEXT exceeds 32 entries",
		}
	}

	entries := make([]parentContextEntry, 0, len(rawEntries))
	for _, item := range rawEntries {
		var entry parentContextEntry
		if err := strictjson.DecodeObject(item, &entry); err != nil {
			return "", &ports.ReviewCoordinationError{
				Reason:  ports.ReviewCoordinationReasonParentContextInvalid,
				Retry:   ports.ReviewCoordinationRetryNever,
				Message: "HAEPARI_PARENT_CONTEXT entry is malformed",
				Cause:   err,
			}
		}
		if !ports.ValidHaepariIdentifier(entry.InstallationID) ||
			!ports.ValidHaepariIdentifier(entry.JobID) ||
			entry.LeaseGeneration <= 0 ||
			!ports.ValidHaepariDigest(entry.Nonce) {
			return "", &ports.ReviewCoordinationError{
				Reason:  ports.ReviewCoordinationReasonParentContextInvalid,
				Retry:   ports.ReviewCoordinationRetryNever,
				Message: "HAEPARI_PARENT_CONTEXT entry failed field validation",
			}
		}
		entries = append(entries, entry)
	}

	reencoded, err := json.Marshal(entries)
	if err != nil || len(reencoded) > maxParentContextBytes {
		return "", &ports.ReviewCoordinationError{
			Reason:  ports.ReviewCoordinationReasonParentContextInvalid,
			Retry:   ports.ReviewCoordinationRetryNever,
			Message: "HAEPARI_PARENT_CONTEXT canonical encoding exceeds 8192 bytes",
			Cause:   err,
		}
	}
	return raw, nil
}
