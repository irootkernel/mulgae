package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// grokLiveReadAuthority admits exact native read operations. It does not parse
// arbitrary shell commands or grant a provider a source-tree write destination.
type grokLiveReadAuthority struct {
	execution   ports.LiveReviewExecution
	gitCommands map[string]bool
}

type grokLiveToolObservation struct {
	kind, variant, path, command string
	terminal                     bool
}

func (state *grokACPConversation) observeLiveTool(ctx context.Context, id, kind, variant, path, command, status string) error {
	if id == "" || state.liveReads == nil {
		return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("uncorrelated live ACP tool operation"))
	}
	if state.liveTools == nil {
		state.liveTools = make(map[string]grokLiveToolObservation)
	}
	observed := state.liveTools[id]
	if observed.terminal && status != "" && !strings.EqualFold(status, "completed") && !strings.EqualFold(status, "failed") {
		return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("live ACP completed tool was reopened"))
	}
	if variant != "" && observed.variant != "" && observed.variant != variant {
		return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("live ACP tool variant changed"))
	}
	if kind != "" {
		observed.kind = kind
	}
	if variant != "" {
		observed.variant = variant
	}
	if path != "" {
		observed.path = path
	}
	if command != "" {
		observed.command = command
	}
	if strings.EqualFold(status, "completed") || strings.EqualFold(status, "failed") {
		observed.terminal = true
	}
	if observed.terminal {
		if err := state.liveReads.allow(ctx, observed.kind, observed.variant, observed.path, observed.command); err != nil {
			return grokACPFailure(domain.DiagnosticCausePermissionDenied, fmt.Errorf("live ACP tool operation rejected: %w", err))
		}
	}
	state.liveTools[id] = observed
	return nil
}

func (state *grokACPConversation) finishLiveTools(ctx context.Context) error {
	for _, observed := range state.liveTools {
		if !observed.terminal {
			return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("live ACP tool completion is missing"))
		}
		if err := state.liveReads.allow(ctx, observed.kind, observed.variant, observed.path, observed.command); err != nil {
			return grokACPFailure(domain.DiagnosticCausePermissionDenied, fmt.Errorf("live ACP completed tool rejected: %w", err))
		}
	}
	return nil
}

func newGrokLiveReadAuthority(ctx context.Context, execution ports.LiveReviewExecution) (*grokLiveReadAuthority, error) {
	if err := execution.Revalidate(ctx); err != nil {
		return nil, err
	}
	authority := &grokLiveReadAuthority{execution: execution, gitCommands: make(map[string]bool)}
	for _, read := range execution.Reads() {
		if read.GitCommand() != "" {
			authority.gitCommands[read.GitCommand()] = true
		}
	}
	return authority, nil
}

func (authority *grokLiveReadAuthority) allow(ctx context.Context, kind, variant, path, command string) error {
	if authority == nil {
		return fmt.Errorf("missing live read authority")
	}
	if err := authority.execution.Revalidate(ctx); err != nil {
		return err
	}
	if kind == "execute" && variant == "Bash" && authority.gitCommands[strings.TrimSpace(command)] {
		return nil
	}
	if kind != "read" || variant != "ReadFile" || authority.execution.Target().Selector().Scope() != domain.LiveSourceWorkspace || !validCanonicalAbsolute(path) {
		return fmt.Errorf("native operation is outside the live read plan")
	}
	relative, err := filepath.Rel(authority.execution.Binding().Root.String(), path)
	if err != nil {
		return err
	}
	selected, err := ports.NewSafeRelativePath(filepath.ToSlash(relative))
	if err != nil {
		return err
	}
	// The source reader owns runtime/credential exclusion and path safety. This
	// check grants no replacement policy and does not retain a source snapshot.
	_, err = authority.execution.SourceReader().Read(ctx, domain.LiveSourceWorktree, selected)
	return err
}

func (state *grokACPConversation) handleLiveReadPermission(ctx context.Context, exchange ports.ProviderSessionExchange, message grokACPMessage) error {
	if message.Method != grokACPRequestPermission || state.liveReads == nil {
		return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("unexpected live ACP server request"))
	}
	var params struct {
		SessionID string `json:"sessionId"`
		ToolCall  struct {
			ToolCallID string `json:"toolCallId"`
			Kind       string `json:"kind"`
			RawInput   struct {
				Variant    string `json:"variant"`
				TargetFile string `json:"target_file"`
				Command    string `json:"command"`
			} `json:"rawInput"`
		} `json:"toolCall"`
		Options []struct {
			OptionID string `json:"optionId"`
			Kind     string `json:"kind"`
		} `json:"options"`
	}
	if json.Unmarshal(message.Params, &params) != nil || params.SessionID != state.sessionID || params.ToolCall.ToolCallID == "" {
		return grokACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("uncorrelated live ACP permission request"))
	}
	input := params.ToolCall.RawInput
	if err := state.liveReads.allow(ctx, params.ToolCall.Kind, input.Variant, input.TargetFile, input.Command); err != nil {
		return grokACPFailure(domain.DiagnosticCausePermissionDenied, fmt.Errorf("live ACP read permission rejected: %w", err))
	}
	for _, option := range params.Options {
		if option.Kind == "allow_once" && option.OptionID != "" {
			return sendGrokACPResponse(ctx, exchange, message.ID, map[string]any{"outcome": map[string]string{"outcome": "selected", "optionId": option.OptionID}})
		}
	}
	return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("live ACP permission response unavailable"))
}
