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
	if err := validateCodexVersion(version); err != nil {
		t.Fatal(err)
	}
	arguments := append([]string{"debug", "prompt-input"}, codexMulgaeOverrides(mulgae, project)...)
	output := run(t, codex, arguments, project, []string{"CODEX_HOME=" + configHome})
	if err := validateCodexPromptInput(output); err != nil {
		t.Fatalf("Codex did not produce valid prompt input: %v", err)
	}
	t.Logf("initialized required Mulgae server through %s", strings.TrimSpace(version))
}

func TestCodexReportsObservableMulgaeServerConfiguration(t *testing.T) {
	mulgae := requiredExecutable(t, mulgaeBinaryEnv)
	codex := requiredExecutable(t, codexBinaryEnv)
	project := newGitProject(t)
	configHome := filepath.Join(t.TempDir(), "codex")
	if err := os.Mkdir(configHome, 0o700); err != nil {
		t.Fatal(err)
	}

	version := run(t, codex, []string{"--version"}, project, nil)
	if err := validateCodexVersion(version); err != nil {
		t.Fatal(err)
	}
	arguments := append([]string{"mcp", "get", "mulgae", "--json"}, codexMulgaeOverrides(mulgae, project)...)
	output := run(t, codex, arguments, project, []string{"CODEX_HOME=" + configHome})
	requiredObserved, err := validateCodexMCPGet(output, mulgae, project)
	if err != nil {
		t.Fatalf("Codex did not report the observable Mulgae MCP configuration: %v", err)
	}
	t.Logf("validated Codex MCP get contract through %s; required_observed=%t", strings.TrimSpace(version), requiredObserved)
}

func codexMulgaeOverrides(mulgae, project string) []string {
	quotedArgs := fmt.Sprintf("[%s,%s,%s]", strconv.Quote("mcp"), strconv.Quote("--project-root"), strconv.Quote(project))
	return []string{
		"-c", "mcp_servers.mulgae.command=" + strconv.Quote(mulgae),
		"-c", "mcp_servers.mulgae.args=" + quotedArgs,
		"-c", "mcp_servers.mulgae.cwd=" + strconv.Quote(project),
		"-c", "mcp_servers.mulgae.required=true",
		"-c", "mcp_servers.mulgae.startup_timeout_sec=30",
		"-c", fmt.Sprintf("mcp_servers.mulgae.tool_timeout_sec=%d", toolTimeoutSec),
	}
}

func validateCodexVersion(output string) error {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) != 2 || fields[0] != "codex-cli" {
		return fmt.Errorf("unexpected Codex version output: %q", output)
	}
	core := strings.SplitN(fields[1], "-", 2)[0]
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return fmt.Errorf("unexpected Codex version output: %q", output)
	}
	version := [3]int{}
	for index, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return fmt.Errorf("unexpected Codex version output: %q", output)
		}
		version[index] = value
	}
	minimum := [3]int{0, 147, 0}
	for index := range version {
		if version[index] > minimum[index] {
			return nil
		}
		if version[index] < minimum[index] {
			return fmt.Errorf("Codex %s is below the supported minimum 0.147.0", fields[1])
		}
	}
	return nil
}

func validateCodexMCPGet(output, mulgae, project string) (bool, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return false, fmt.Errorf("decode JSON: %w", err)
	}
	for _, field := range []string{"name", "enabled", "disabled_reason", "transport", "enabled_tools", "disabled_tools", "startup_timeout_sec", "tool_timeout_sec"} {
		if _, found := raw[field]; !found {
			return false, fmt.Errorf("observable field %q is missing", field)
		}
	}
	var observed struct {
		Name           string  `json:"name"`
		Enabled        bool    `json:"enabled"`
		DisabledReason *string `json:"disabled_reason"`
		Transport      struct {
			Type    string            `json:"type"`
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
			EnvVars []string          `json:"env_vars"`
			CWD     string            `json:"cwd"`
		} `json:"transport"`
		EnabledTools      []string `json:"enabled_tools"`
		DisabledTools     []string `json:"disabled_tools"`
		StartupTimeoutSec float64  `json:"startup_timeout_sec"`
		ToolTimeoutSec    float64  `json:"tool_timeout_sec"`
	}
	if err := json.Unmarshal([]byte(output), &observed); err != nil {
		return false, fmt.Errorf("decode observable configuration: %w", err)
	}
	wantArgs := []string{"mcp", "--project-root", project}
	if observed.Name != "mulgae" || !observed.Enabled || observed.DisabledReason != nil ||
		observed.Transport.Type != "stdio" || observed.Transport.Command != mulgae ||
		!equalStrings(observed.Transport.Args, wantArgs) || observed.Transport.Env != nil || len(observed.Transport.EnvVars) != 0 ||
		observed.Transport.CWD != project || observed.EnabledTools != nil || observed.DisabledTools != nil ||
		observed.StartupTimeoutSec != 30 || observed.ToolTimeoutSec != toolTimeoutSec {
		return false, fmt.Errorf("unexpected observable configuration: %#v", observed)
	}
	requiredRaw, requiredObserved := raw["required"]
	if !requiredObserved {
		return false, nil
	}
	var required bool
	if err := json.Unmarshal(requiredRaw, &required); err != nil || !required {
		return true, fmt.Errorf("observed required field does not preserve configured true")
	}
	return true, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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

func TestValidateCodexVersion(t *testing.T) {
	for _, test := range []struct {
		output  string
		wantErr bool
	}{
		{output: "codex-cli 0.147.0\n"},
		{output: "codex-cli 0.148.0-alpha.1\n"},
		{output: "codex-cli 0.146.9\n", wantErr: true},
		{output: "codex 0.147.0\n", wantErr: true},
	} {
		t.Run(strings.TrimSpace(test.output), func(t *testing.T) {
			err := validateCodexVersion(test.output)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateCodexVersion() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestValidateCodexMCPGetPreservesUnobservedRequired(t *testing.T) {
	const mulgae = "/opt/mulgae"
	const project = "/work/project"
	base := map[string]any{
		"name": "mulgae", "enabled": true, "disabled_reason": nil,
		"transport": map[string]any{
			"type": "stdio", "command": mulgae,
			"args": []string{"mcp", "--project-root", project},
			"env":  nil, "env_vars": []string{}, "cwd": project,
		},
		"enabled_tools": nil, "disabled_tools": nil,
		"startup_timeout_sec": 30.0, "tool_timeout_sec": float64(toolTimeoutSec),
	}
	encode := func(value map[string]any) string {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}

	observed, err := validateCodexMCPGet(encode(base), mulgae, project)
	if err != nil || observed {
		t.Fatalf("absent required = observed %t, error %v; want unobserved", observed, err)
	}
	base["required"] = true
	observed, err = validateCodexMCPGet(encode(base), mulgae, project)
	if err != nil || !observed {
		t.Fatalf("true required = observed %t, error %v; want observed true", observed, err)
	}
	base["required"] = false
	if observed, err = validateCodexMCPGet(encode(base), mulgae, project); err == nil || !observed {
		t.Fatalf("false required = observed %t, error %v; want rejected observation", observed, err)
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
