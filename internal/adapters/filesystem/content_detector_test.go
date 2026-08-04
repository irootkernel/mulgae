//go:build darwin && arm64

package filesystem

import (
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestContentDetectorAllowsCredentialLikeReviewEvidence(t *testing.T) {
	detector := NewContentDetector()
	fixtures := []string{
		"changePassword: vi.fn()",
		"Authorization: Bearer abcdefghijklmnop",
		"api_key = placeholder-api-key",
		"-----BEGIN RSA PRIVATE KEY-----\nplaceholder\n-----END RSA PRIVATE KEY-----",
		"DATABASE_PASSWORD=development-only",
		"AKIAIOSFODNN7EXAMPLE",
	}
	for _, channel := range []ports.ReviewInputChannel{ports.ReviewInputTarget, ports.ReviewInputReference, ports.ReviewInputObjective, ports.ReviewInputPacket} {
		t.Run(string(channel), func(t *testing.T) {
			source := "review-input"
			if channel == ports.ReviewInputReference {
				source = "security/redaction_test.go"
			}
			detection, err := detector.DetectReviewInput(context.Background(), channel, source, []byte(strings.Join(fixtures, "\n")))
			if err != nil {
				t.Fatal(err)
			}
			if detection.Verdict() != ports.ReviewInputClean || detection.DetectorCode() != "" || detection.Count() != 0 {
				t.Fatalf("detection = (%q, %q, %d), want clean", detection.Verdict(), detection.DetectorCode(), detection.Count())
			}
		})
	}
}

func TestContentDetectorRejectsEveryProviderInstructionPath(t *testing.T) {
	detector := NewContentDetector()
	paths := []string{
		".cursorrules",
		"nested/AGENTS.md",
		"CLAUDE.md",
		"docs/GEMINI.md",
		".github/copilot-instructions.md",
		".windsurfrules",
		".cursor/rules/review.md",
		".claude/settings.json",
		".gemini/settings.json",
		".windsurf/rules/review.md",
		".kimi/config.json",
		".zcode/config.json",
		".agy/config.json",
		"KIMI.md",
		"ZCODE.md",
		"AGY.md",
		".github/instructions/review.instructions.md",
		"NESTED/agents.MD",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			detection, err := detector.DetectReviewInput(context.Background(), ports.ReviewInputReference, path, []byte("clean"))
			if err != nil {
				t.Fatal(err)
			}
			if detection.Verdict() != ports.ReviewInputBlocked || detection.DetectorCode() != dangerousProviderInstructionCode || detection.Count() != 1 {
				t.Fatalf("detection = (%q, %q, %d), want dangerous provider instruction", detection.Verdict(), detection.DetectorCode(), detection.Count())
			}
		})
	}
}

func TestContentDetectorDoesNotApplyReferencePathPolicyToOtherChannels(t *testing.T) {
	detector := NewContentDetector()
	for _, channel := range []ports.ReviewInputChannel{ports.ReviewInputTarget, ports.ReviewInputObjective, ports.ReviewInputPacket} {
		t.Run(string(channel), func(t *testing.T) {
			detection, err := detector.DetectReviewInput(context.Background(), channel, "AGENTS.md", []byte("@roadmap.md"))
			if err != nil {
				t.Fatal(err)
			}
			if detection.Verdict() != ports.ReviewInputClean || detection.DetectorCode() != "" || detection.Count() != 0 {
				t.Fatalf("detection = (%q, %q, %d), want clean", detection.Verdict(), detection.DetectorCode(), detection.Count())
			}
		})
	}
}

func TestContentDetectorReturnsRedactedErrorsAndCleanInput(t *testing.T) {
	detector := NewContentDetector()
	clean, err := detector.DetectReviewInput(context.Background(), ports.ReviewInputObjective, "objective", []byte("@roadmap.md"))
	if err != nil {
		t.Fatal(err)
	}
	if clean.Verdict() != ports.ReviewInputClean || clean.DetectorCode() != "" || clean.Count() != 0 {
		t.Fatalf("clean detection = (%q, %q, %d)", clean.Verdict(), clean.DetectorCode(), clean.Count())
	}
	for _, test := range []struct {
		name    string
		channel ports.ReviewInputChannel
		source  string
	}{
		{"invalid channel", "invalid", "credential=secret-value"},
		{"empty source", ports.ReviewInputTarget, ""},
		{"reference traversal", ports.ReviewInputReference, "../credential=secret-value"},
		{"source control", ports.ReviewInputPacket, "credential=secret-value\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := detector.DetectReviewInput(context.Background(), test.channel, test.source, []byte("clean"))
			if err == nil {
				t.Fatal("accepted invalid input")
			}
			if strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "credential=") {
				t.Fatalf("error leaked input: %q", err)
			}
		})
	}
}

func TestContentDetectorMapsWorkspaceDetectorPort(t *testing.T) {
	detector := NewContentDetector()
	for _, test := range []struct {
		name string
		path string
		data string
		want ports.WorkspaceContentVerdict
	}{
		{"clean", "src/main.go", "package main", ports.WorkspaceContentClean},
		{"credential fixture", "src/redaction_test.go", "Authorization: Bearer token\npassword=development-only", ports.WorkspaceContentClean},
		{"instruction", ".github/copilot-instructions.md", "clean", ports.WorkspaceContentDangerousProviderInstruction},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, err := ports.NewSafeRelativePath(test.path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := detector.DetectWorkspaceContent(context.Background(), path, []byte(test.data))
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("verdict = %q, want %q", got, test.want)
			}
		})
	}
}
