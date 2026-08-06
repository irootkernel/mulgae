//go:build darwin && arm64

package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const maxDiagnosticSessions = 4096

func (*DiagnosticStatusReader) ReadRunStatus(ctx context.Context, root ports.AnchoredRoot, runID domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	if ctx == nil || !root.Valid() {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: invalid request")
	}
	if err := ctx.Err(); err != nil {
		return ports.RuntimeDiagnosticRunStatus{}, err
	}
	if _, err := domain.ParseRunID(runID.String()); err != nil {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: invalid run ID")
	}
	diagnosticsPath := filepath.Join(root.String(), "diagnostics")
	diagnosticsDirectory, err := walkPrivateDirectory(root, []string{"diagnostics"}, false)
	if errors.Is(err, unix.ENOENT) {
		return ports.RuntimeDiagnosticRunStatus{}, ports.ErrRuntimeDiagnosticRunNotFound
	}
	if err != nil {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: validate diagnostics namespace: %w", err)
	}
	closeFD(diagnosticsDirectory)
	entries, err := os.ReadDir(diagnosticsPath)
	if errors.Is(err, os.ErrNotExist) {
		return ports.RuntimeDiagnosticRunStatus{}, ports.ErrRuntimeDiagnosticRunNotFound
	}
	if err != nil {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: list sessions: %w", err)
	}
	if len(entries) > maxDiagnosticSessions {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: session namespace exceeds bound")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var matched ports.RuntimeDiagnosticRunStatus
	found := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return ports.RuntimeDiagnosticRunStatus{}, err
		}
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "s_") {
			continue
		}
		sessionID, err := domain.ParseSessionID(entry.Name())
		if err != nil {
			continue
		}
		parts := []string{"diagnostics", sessionID.String(), runID.String()}
		directory, err := walkPrivateDirectory(root, parts, false)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: validate run namespace: %w", err)
		}
		data, readErr := readDiagnosticStatusFile(directory)
		closeFD(directory)
		if readErr != nil {
			return ports.RuntimeDiagnosticRunStatus{}, readErr
		}
		status, decodeErr := decodeDiagnosticRunStatus(data, sessionID, runID)
		if decodeErr != nil {
			return ports.RuntimeDiagnosticRunStatus{}, decodeErr
		}
		if found {
			return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: multiple matching runs")
		}
		matched, found = status, true
	}
	if !found {
		return ports.RuntimeDiagnosticRunStatus{}, ports.ErrRuntimeDiagnosticRunNotFound
	}
	return matched, nil
}

func readDiagnosticStatusFile(directory int) ([]byte, error) {
	fd, err := unix.Openat(directory, "status.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("diagnostic query: open status: %w", err)
	}
	defer closeFD(fd)
	if err := verifyPrivateRegularFile(fd); err != nil {
		return nil, fmt.Errorf("diagnostic query: verify status: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Size <= 0 || stat.Size > ports.RuntimeDiagnosticStatusMaxBytes {
		return nil, fmt.Errorf("diagnostic query: invalid status size")
	}
	data := make([]byte, int(stat.Size))
	for offset := 0; offset < len(data); {
		count, readErr := unix.Pread(fd, data[offset:], int64(offset))
		if count > 0 {
			offset += count
		}
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil || count == 0 {
			return nil, fmt.Errorf("diagnostic query: read status: %w", errors.Join(readErr, io.ErrUnexpectedEOF))
		}
	}
	return data, nil
}

func decodeDiagnosticRunStatus(data []byte, sessionID domain.SessionID, runID domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	var wire runtimeDiagnosticRunStatusWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: decode status: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: status has trailing content")
	}
	if wire.SchemaVersion != ports.RuntimeDiagnosticRunStatusSchema || wire.SessionID != sessionID.String() || wire.RunID != runID.String() || !wire.DiagnosticOnly || wire.PublicationAuthority {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: status identity or authority mismatch")
	}
	startedAt, startedErr := time.Parse(time.RFC3339Nano, wire.StartedAt)
	updatedAt, updatedErr := time.Parse(time.RFC3339Nano, wire.UpdatedAt)
	completedAt := time.Time{}
	hasCompletedAt := wire.CompletedAt != ""
	var completedErr error
	if hasCompletedAt {
		completedAt, completedErr = time.Parse(time.RFC3339Nano, wire.CompletedAt)
	}
	if startedErr != nil || updatedErr != nil || completedErr != nil {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: invalid status time")
	}
	p2URI := ports.SafeRelativePath{}
	hasP2URI := wire.P2URI != ""
	if hasP2URI {
		var pathErr error
		p2URI, pathErr = ports.NewSafeRelativePath(wire.P2URI)
		if pathErr != nil {
			return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: invalid P2 URI")
		}
	}
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: sessionID, RunID: runID, State: wire.State, StartedAt: startedAt, UpdatedAt: updatedAt,
		CompletedAt: completedAt, HasCompletedAt: hasCompletedAt, SelectedRoles: wire.SelectedRoles,
		LaneTotal: wire.LaneTotal, LaneCompleted: wire.LaneCompleted, LaneFailed: wire.LaneFailed,
		LastSequence: wire.LastSequence, TerminalCause: wire.TerminalCause, TerminalPhase: wire.TerminalPhase, P2URI: p2URI,
		HasP2URI: hasP2URI, DroppedEvents: wire.DroppedEvents,
	})
	if err != nil {
		return ports.RuntimeDiagnosticRunStatus{}, fmt.Errorf("diagnostic query: invalid status: %w", err)
	}
	return status, nil
}
