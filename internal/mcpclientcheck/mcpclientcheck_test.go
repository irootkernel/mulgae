//go:build mcpclientcheck

package mcpclientcheck_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	mulgaeBinaryEnv = "MULGAE_MCP_CLIENT_BINARY"
	codexBinaryEnv  = "MULGAE_MCP_CODEX_BINARY"
	claudeBinaryEnv = "MULGAE_MCP_CLAUDE_BINARY"
	clientTimeout   = 30 * time.Second
	toolTimeoutSec  = 54_000
	toolTimeoutMS   = 54_000_000
	maxOutputBytes  = 1 << 20
)

func TestCodexInitializesRequiredMulgaeServer(t *testing.T) {
	mulgae := requiredExecutable(t, mulgaeBinaryEnv)
	codex := requiredExecutable(t, codexBinaryEnv)
	project := newGitProject(t)
	configHome := filepath.Join(t.TempDir(), "codex")
	if err := os.Mkdir(configHome, 0o700); err != nil {
		t.Fatal(err)
	}

	version := run(t, codex, []string{"--version"}, project, nil)
	if !strings.Contains(version, "codex-cli") {
		t.Fatalf("unexpected Codex version output: %q", version)
	}
	quotedArgs := fmt.Sprintf("[%s,%s,%s]", strconv.Quote("mcp"), strconv.Quote("--project-root"), strconv.Quote(project))
	output := run(t, codex, []string{
		"debug", "prompt-input",
		"-c", "mcp_servers.mulgae.command=" + strconv.Quote(mulgae),
		"-c", "mcp_servers.mulgae.args=" + quotedArgs,
		"-c", "mcp_servers.mulgae.cwd=" + strconv.Quote(project),
		"-c", "mcp_servers.mulgae.required=true",
		"-c", "mcp_servers.mulgae.startup_timeout_sec=30",
		"-c", fmt.Sprintf("mcp_servers.mulgae.tool_timeout_sec=%d", toolTimeoutSec),
	}, project, []string{"CODEX_HOME=" + configHome})
	if err := validateCodexPromptInput(output); err != nil {
		t.Fatalf("Codex did not produce valid prompt input: %v", err)
	}
	t.Logf("initialized required Mulgae server through %s", strings.TrimSpace(version))
}

func TestClaudeReportsConnectedMulgaeServer(t *testing.T) {
	mulgae := requiredExecutable(t, mulgaeBinaryEnv)
	claude := requiredExecutable(t, claudeBinaryEnv)
	project := newGitProject(t)
	configHome := filepath.Join(t.TempDir(), "claude")
	if err := os.Mkdir(configHome, 0o700); err != nil {
		t.Fatal(err)
	}
	environment := []string{"CLAUDE_CONFIG_DIR=" + configHome}

	version := run(t, claude, []string{"--version"}, project, environment)
	run(t, claude, []string{
		"mcp", "add", "--scope", "user", "mulgae", "--",
		mulgae, "mcp", "--project-root", project,
	}, project, environment)
	setClaudeTimeout(t, filepath.Join(configHome, ".claude.json"))
	output := run(t, claude, []string{"mcp", "get", "mulgae"}, project, environment)
	if !strings.Contains(output, "Connected") {
		t.Fatal("Claude did not report a connected Mulgae server")
	}
	t.Logf("connected Mulgae server through Claude Code %s", strings.TrimSpace(version))
}

func validateCodexPromptInput(output string) error {
	var messages []struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal([]byte(output), &messages); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	for _, message := range messages {
		if message.Type != "message" || message.Role != "developer" {
			continue
		}
		for _, content := range message.Content {
			if content.Type == "input_text" && content.Text != "" {
				return nil
			}
		}
	}
	return fmt.Errorf("developer input message is missing")
}

func TestValidateCodexPromptInput(t *testing.T) {
	for _, test := range []struct {
		name    string
		output  string
		wantErr bool
	}{
		{
			name:   "developer input",
			output: `[{"type":"message","role":"developer","content":[{"type":"input_text","text":"instructions"}]}]`,
		},
		{
			name:    "substring is not structure",
			output:  `[{"type":"message","role":"user","content":[{"type":"input_text","text":"role: developer"}]}]`,
			wantErr: true,
		},
		{name: "malformed JSON", output: `[`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateCodexPromptInput(test.output)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateCodexPromptInput() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func newGitProject(t *testing.T) string {
	t.Helper()
	project := filepath.Join(t.TempDir(), "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	run(t, "git", []string{"init", "--quiet", project}, project, nil)
	return project
}

func setClaudeTimeout(t *testing.T, path string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(contents, &config); err != nil {
		t.Fatal(err)
	}
	servers, ok := config["mcpServers"].(map[string]any)
	if !ok {
		t.Fatal("Claude config has no mcpServers object")
	}
	server, ok := servers["mulgae"].(map[string]any)
	if !ok {
		t.Fatal("Claude config has no Mulgae server")
	}
	server["timeout"] = toolTimeoutMS
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func requiredExecutable(t *testing.T, name string) string {
	t.Helper()
	path := os.Getenv(name)
	info, err := os.Stat(path)
	if path == "" || err != nil || !filepath.IsAbs(path) || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s must name an absolute executable file", name)
	}
	return path
}

func run(t *testing.T, binary string, arguments []string, directory string, overrides []string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), overrides...)
	var output limitedBuffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		t.Fatalf("%s %v: %v; output=%q", binary, arguments, err, output.String())
	}
	if ctx.Err() != nil {
		t.Fatalf("%s %v: %v", binary, arguments, ctx.Err())
	}
	return output.String()
}

type limitedBuffer struct {
	bytes.Buffer
}

func (buffer *limitedBuffer) Write(contents []byte) (int, error) {
	remaining := maxOutputBytes - buffer.Len()
	if remaining <= 0 {
		return len(contents), nil
	}
	if len(contents) > remaining {
		_, _ = buffer.Buffer.Write(contents[:remaining])
		return len(contents), nil
	}
	return buffer.Buffer.Write(contents)
}
