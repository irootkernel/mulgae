//go:build darwin && arm64

package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestProviderToolDiagnosticOrder(t *testing.T) {
	type operation struct{ id, path, status string }
	// Expected paths are literal witnesses of ascending raw Go string IDs.
	// No production ordering helper is used to construct the oracle.
	cases := []struct {
		name       string
		operations []operation
		wantPaths  []string
		wantCode   ports.LiveSourceErrorCode
		pending    bool
	}{
		{name: "no tools"},
		{name: "one admitted read", operations: []operation{{"2", "good.txt", "completed"}}, wantPaths: []string{"worktree:good.txt"}},
		{name: "one pending", operations: []operation{{"2", "good.txt", "pending"}}, pending: true},
		{name: "one invalidated read", operations: []operation{{"2", "unsafe.txt", "completed"}}, wantPaths: []string{"worktree:unsafe.txt"}, wantCode: ports.LiveSourceUnsafe},
		{
			name:       "numeric and Unicode IDs are raw strings",
			operations: []operation{{"é", "composed.txt", "completed"}, {"2", "two.txt", "completed"}, {"10", "ten.txt", "completed"}, {"e\u0301", "decomposed.txt", "completed"}},
			wantPaths:  []string{"worktree:ten.txt", "worktree:two.txt", "worktree:decomposed.txt", "worktree:composed.txt"},
		},
		{
			name:       "raw ID whitespace is not sanitized",
			operations: []operation{{"2", "two.txt", "completed"}, {" 2", "space.txt", "completed"}},
			wantPaths:  []string{"worktree:space.txt", "worktree:two.txt"},
		},
		{
			name:       "invalidated read before pending violation",
			operations: []operation{{"2", "good.txt", "pending"}, {"10", "unsafe.txt", "completed"}, {"é", "other.txt", "completed"}},
			wantPaths:  []string{"worktree:unsafe.txt"}, wantCode: ports.LiveSourceUnsafe,
		},
		{
			name:       "pending violation before invalidated read",
			operations: []operation{{"2", "unsafe.txt", "completed"}, {"10", "good.txt", "pending"}}, pending: true,
		},
		{
			name:       "valid prefix before invalidated read and pending violation",
			operations: []operation{{"é", "other.txt", "pending"}, {"2", "unsafe.txt", "completed"}, {"10", "good.txt", "completed"}},
			wantPaths:  []string{"worktree:good.txt", "worktree:unsafe.txt"}, wantCode: ports.LiveSourceUnsafe,
		},
		{
			name:       "distinct simultaneous source errors",
			operations: []operation{{"2", "unsafe.txt", "completed"}, {"10", "absent.txt", "completed"}},
			wantPaths:  []string{"worktree:absent.txt"}, wantCode: ports.LiveSourceUnavailable,
		},
		{name: "identical pending diagnostics", operations: []operation{{"2", "good.txt", "pending"}, {"10", "other.txt", "pending"}}, pending: true},
	}
	for _, family := range []string{"cursor"} {
		stages := []string{"prompt"}
		for _, stage := range stages {
			for _, test := range cases {
				for _, reverse := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/reverse=%t", family, stage, test.name, reverse), func(t *testing.T) {
						ctx := context.Background()
						counted, original, project := countingLiveFixture(t, domain.LiveSourceWorkspace)
						trace, execution := task064TraceExecution(t, original)
						for _, name := range []string{"good.txt", "unsafe.txt", "absent.txt", "other.txt", "ten.txt", "two.txt", "composed.txt", "decomposed.txt", "space.txt"} {
							if err := os.WriteFile(filepath.Join(project, name), []byte("original\n"), 0600); err != nil {
								t.Fatal(err)
							}
						}
						authority, err := newCursorLiveReadAuthority(ctx, execution)
						if err != nil {
							t.Fatal(err)
						}
						session := cursorMatrixSession(t, authority)
						state := cursorACPConversation{session: session, tools: make(map[string]*cursorToolState), outstanding: "cursor-initialize"}
						for _, line := range cursorMatrixAppend(cursorMatrixPrefix(true), cursorMatrixMessage("report")) {
							var message cursorACPMessage
							if err := json.Unmarshal(line, &message); err != nil {
								t.Fatal(err)
							}
							if done, err := state.handle(ctx, &scriptedCodexExchange{}, message); err != nil || done {
								t.Fatalf("Cursor prefix did not reach live prompt: done=%t error=%v", done, err)
							}
						}
						if !state.promptSent || len(session.assistant) == 0 {
							t.Fatal("Cursor prefix never established a report turn")
						}
						observe := func(op operation) error {
							var message cursorACPMessage
							if err := json.Unmarshal(cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": op.id, "kind": "read", "status": op.status, "rawInput": map[string]string{"path": filepath.Join(project, op.path)}}), &message); err != nil {
								t.Fatal(err)
							}
							return state.handleUpdate(ctx, nil, message)
						}
						finish := func() error {
							current := state
							done, err := current.handle(ctx, &scriptedCodexExchange{}, cursorACPMessage{ID: json.RawMessage(`"cursor-prompt"`), Result: json.RawMessage(`{"stopReason":"end_turn"}`)})
							if !done || (err == nil) != current.promptCompleted {
								t.Fatalf("Cursor final acceptance disagrees with error: done=%t completed=%t error=%v", done, current.promptCompleted, err)
							}
							return err
						}
						completed := 0
						for i := range test.operations {
							if reverse {
								i = len(test.operations) - 1 - i
							}
							op := test.operations[i]
							if err := observe(op); err != nil {
								t.Fatalf("operation %q failed before final validation: %v", op.id, err)
							}
							if op.status == "completed" {
								completed++
							}
						}
						if counted.reads != 0 || counted.admits != completed {
							t.Fatalf("setup did not admit every completed read: reads=%d admits=%d want=%d", counted.reads, counted.admits, completed)
						}
						// Every completed read was valid. Invalidate its target only
						// after the completion handler has successfully admitted it.
						if err := os.Remove(filepath.Join(project, "unsafe.txt")); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink("good.txt", filepath.Join(project, "unsafe.txt")); err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(filepath.Join(project, "absent.txt")); err != nil {
							t.Fatal(err)
						}
						mismatches, firstMismatch := 0, ""
						// A fixed corpus, never a retry-until-red or timing oracle.
						for trial := 0; trial < 64; trial++ {
							trace.paths = nil
							before := counted.admits
							err := finish()
							wantFailure := test.pending || test.wantCode != ""
							if (err != nil) != wantFailure {
								t.Fatalf("final refusal changed: error=%v want failure=%t", err, wantFailure)
							}
							if err != nil {
								assertTask064ProtocolCause(t, err, domain.DiagnosticCausePermissionDenied)
							}
							var sourceError *ports.LiveSourceError
							hasSource := errors.As(err, &sourceError)
							diagnosticMatches := err == nil
							if test.pending {
								wantText := "cursor ACP tool completion is missing"
								if family == "grok" {
									wantText = "grok ACP failure: live ACP tool completion is missing"
								}
								diagnosticMatches = !hasSource && err != nil && err.Error() == wantText
							} else if test.wantCode != "" {
								wantText := "live source: " + string(test.wantCode)
								if family == "grok" {
									wantText = "grok ACP failure: live ACP completed tool rejected: " + wantText
								}
								diagnosticMatches = hasSource && sourceError.Code() == test.wantCode && err.Error() == wantText
							}
							if !reflect.DeepEqual(trace.paths, test.wantPaths) || !diagnosticMatches {
								mismatches++
								if firstMismatch == "" {
									firstMismatch = fmt.Sprintf("trial=%d actual paths=%q error=%v; want raw-ID paths=%q pending=%t source=%s", trial, trace.paths, err, test.wantPaths, test.pending, test.wantCode)
								}
							}
							if counted.reads != 0 || counted.admits-before != len(trace.paths) {
								t.Fatalf("final validation lost body-free admission: reads=%d admissions=%d paths=%v", counted.reads, counted.admits-before, trace.paths)
							}
						}
						if mismatches != 0 {
							t.Errorf("DF-007: %d/64 raw-ID selection mismatches with unchanged typed refusal; %s", mismatches, firstMismatch)
						}
					})
				}
			}
		}
	}
	t.Run("AGY multiple unfinished steps retain the same refusal", func(t *testing.T) {
		for _, indices := range [][]int{{2}, {2, 10}, {10, 2}} {
			session := agyTestSession(t)
			frames := [][]byte{agyTestInit()}
			for _, index := range indices {
				frames = append(frames, agyTestStep(map[string]any{"conversation_id": "conversation-1", "step_index": index, "step_type": "tool", "state": "ACTIVE", "tool_name": "view_file", "tool_info": map[string]any{"parameters": map[string]string{"AbsolutePath": "/source/a"}}}))
			}
			frames = append(frames, agyTestResult(nil))
			err := session.Drive(context.Background(), &agyTestExchange{frames: frames})
			assertTask064ProtocolCause(t, err, domain.DiagnosticCauseProviderTurnFailed)
			if !strings.Contains(err.Error(), "unfinished tool operation at result") || len(session.AssistantEvidenceText()) != 0 {
				t.Fatalf("unfinished AGY steps changed acceptance: %v", err)
			}
		}
	})
}
