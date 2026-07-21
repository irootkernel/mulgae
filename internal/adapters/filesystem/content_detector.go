//go:build darwin && arm64

package filesystem

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const dangerousProviderInstructionCode = "dangerous_provider_instruction"

// ContentDetector rejects credentials and provider auto-instructions before
// review input is hashed, persisted, or exposed to a provider.
type ContentDetector struct{}

var (
	_ ports.ReviewInputContentDetector         = (*ContentDetector)(nil)
	_ ports.ReviewInputContentDetectorIdentity = (*ContentDetector)(nil)
	_ ports.WorkspaceContentDetector           = (*ContentDetector)(nil)
)

// NewContentDetector constructs the fixed production content admission policy.
func NewContentDetector() *ContentDetector { return &ContentDetector{} }

// ReviewInputDetectorIdentity returns the immutable version of the admission
// policy used to screen review inputs.
func (detector *ContentDetector) ReviewInputDetectorIdentity() string {
	if detector == nil {
		return ""
	}
	return "filesystem-content-detector-v1"
}

// DetectReviewInput checks one complete immutable input channel. Only
// reference snapshots use their source ID as a workspace path; target,
// objective, and packet source IDs are labels and cannot trigger path policy.
func (detector *ContentDetector) DetectReviewInput(ctx context.Context, channel ports.ReviewInputChannel, sourceID string, bytes []byte) (ports.ReviewInputDetection, error) {
	if ctx == nil {
		return ports.ReviewInputDetection{}, fmt.Errorf("review input detector: invalid context")
	}
	if err := ctx.Err(); err != nil {
		return ports.ReviewInputDetection{}, err
	}
	if detector == nil || !channel.Valid() {
		return ports.ReviewInputDetection{}, fmt.Errorf("review input detector: invalid channel")
	}
	if !validReviewInputSource(channel, sourceID) {
		return ports.ReviewInputDetection{}, fmt.Errorf("review input detector: invalid source")
	}
	if channel == ports.ReviewInputReference && dangerousProviderInstructionPath(sourceID) {
		return blockedReviewInput(dangerousProviderInstructionCode)
	}
	if match, found := scanReviewInputCredentials(bytes); found {
		return blockedReviewInput(match.detector)
	}
	return ports.NewReviewInputDetection(ports.ReviewInputClean, "", 0)
}

// DetectWorkspaceContent maps the review-input policy onto the existing
// workspace detector port without exposing source paths or content in errors.
func (detector *ContentDetector) DetectWorkspaceContent(ctx context.Context, path ports.SafeRelativePath, bytes []byte) (ports.WorkspaceContentVerdict, error) {
	if ctx == nil {
		return "", fmt.Errorf("workspace content detector: invalid context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if detector == nil || !path.Valid() {
		return "", fmt.Errorf("workspace content detector: invalid input")
	}
	if dangerousProviderInstructionPath(path.String()) {
		return ports.WorkspaceContentDangerousProviderInstruction, nil
	}
	if _, found := scanReviewInputCredentials(bytes); found {
		return ports.WorkspaceContentSecret, nil
	}
	return ports.WorkspaceContentClean, nil
}

func blockedReviewInput(code string) (ports.ReviewInputDetection, error) {
	return ports.NewReviewInputDetection(ports.ReviewInputBlocked, code, 1)
}

func validReviewInputSource(channel ports.ReviewInputChannel, sourceID string) bool {
	if sourceID == "" || len(sourceID) > 4096 || !utf8.ValidString(sourceID) || strings.ContainsAny(sourceID, "\x00\r\n") {
		return false
	}
	if channel != ports.ReviewInputReference {
		return true
	}
	_, err := ports.NewSafeRelativePath(sourceID)
	return err == nil
}

func scanReviewInputCredentials(bytes []byte) (scanMatch, bool) {
	var scanner credentialScanner
	defer scanner.Reset()
	for len(bytes) > 0 {
		length := scannerChunkSize
		if length > len(bytes) {
			length = len(bytes)
		}
		if match, found := scanner.Scan(bytes[:length]); found {
			return match, true
		}
		bytes = bytes[length:]
	}
	return scanMatch{}, false
}

func dangerousProviderInstructionPath(path string) bool {
	components := strings.Split(path, "/")
	for _, component := range components {
		if equalFoldAny(component,
			".cursorrules", "AGENTS.md", "CLAUDE.md", "GEMINI.md", ".windsurfrules",
			"KIMI.md", "ZCODE.md", "AGY.md",
		) {
			return true
		}
	}
	for index := 0; index+1 < len(components); index++ {
		if equalFoldAny(components[index], ".cursor", ".claude", ".gemini", ".windsurf", ".kimi", ".zcode", ".agy") {
			return true
		}
		if strings.EqualFold(components[index], ".github") && strings.EqualFold(components[index+1], "copilot-instructions.md") {
			return true
		}
		if index+2 < len(components) && strings.EqualFold(components[index], ".github") && strings.EqualFold(components[index+1], "instructions") && strings.HasSuffix(strings.ToLower(components[index+2]), ".instructions.md") {
			return true
		}
	}
	return false
}

func equalFoldAny(value string, values ...string) bool {
	for _, candidate := range values {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}
