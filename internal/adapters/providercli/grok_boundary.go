package providercli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"syscall"
)

// grokCandidateFamily is deliberately not part of validFamily or the public
// runtime registry during TASK-011. It names only the isolated ACP gate.
const grokCandidateFamily = "grok"

var grokReviewArgvTail = []string{
	"--no-auto-update",
	"--sandbox", "mulgae",
	"--disable-web-search",
	"--no-subagents",
	"--permission-mode", "dontAsk",
	"--tools", "read_file,grep,list_dir,Write",
	"--deny", "MCPTool",
	"agent",
	"--no-leader",
	"stdio",
}

func grokACPArgv(executable string, purpose protocolInvocationPurpose) ([]string, error) {
	if !validCanonicalAbsolute(executable) {
		return nil, fmt.Errorf("grok ACP invocation: invalid executable")
	}
	argv := []string{executable, "--no-auto-update", "--sandbox", "mulgae", "--disable-web-search", "--no-subagents", "--permission-mode", "dontAsk"}
	switch purpose {
	case protocolPurposeReview:
		argv = append(argv, "--tools", "read_file,grep,list_dir,Write")
	case protocolPurposeExtraction, protocolPurposeQualification:
		argv = append(argv, "--tools", "")
	default:
		return nil, fmt.Errorf("grok ACP invocation: unsupported purpose")
	}
	return append(argv, "--deny", "MCPTool", "agent", "--no-leader", "stdio"), nil
}

func validateGrokACPArgv(executable string, purpose protocolInvocationPurpose, argv []string) error {
	want, err := grokACPArgv(executable, purpose)
	if err != nil || !reflect.DeepEqual(argv, want) {
		return fmt.Errorf("grok ACP invocation: argv drift")
	}
	return nil
}

type grokBoundaryFile struct {
	path   string
	bytes  []byte
	sha256 string
	info   os.FileInfo
}

type grokBoundaryBundle struct {
	root  string
	files []grokBoundaryFile
}

func grokBoundaryFileContents(nativeHome, liveProjectRoot string) (map[string][]byte, error) {
	if !validCanonicalAbsolute(nativeHome) || !validCanonicalAbsolute(liveProjectRoot) || nativeHome == string(filepath.Separator) || liveProjectRoot == string(filepath.Separator) {
		return nil, fmt.Errorf("grok boundary: invalid denied root")
	}
	config := []byte(`[compat.claude]
agents = false
hooks = false
mcps = false
rules = false
skills = false

[compat.codex]
hooks = false
skills = false

[compat.cursor]
agents = false
hooks = false
mcps = false
rules = false
skills = false

[features]
campaigns = false
codebase_indexing = false
managed_config = false
mcp_auto_restart = false
mcp_liveness_watchers = false
mcp_recursive_config_watch = false
repo_status_in_system_prompt = false

[paths]
extra_rule_dirs = []
extra_skill_dirs = []

[plugins]
enabled = []
paths = []
`)
	managed := []byte(`allow_managed_mcp_servers_only = true
enable_all_project_mcp_servers = false
allowed_mcp_servers = []
plugin_auto_update = false
`)
	sandbox := []byte("[profiles.mulgae]\n" +
		"extends = \"workspace\"\n" +
		"deny = [" + strconv.Quote(nativeHome) + ", " + strconv.Quote(liveProjectRoot) + "]\n")
	return map[string][]byte{
		"config.toml":         config,
		"managed_config.toml": managed,
		"sandbox.toml":        sandbox,
	}, nil
}

// installGrokBoundaryBundle installs the sterile, invocation-independent Grok
// configuration into an already private namespace home.
func installGrokBoundaryBundle(grokHome, nativeHome, liveProjectRoot string) (grokBoundaryBundle, error) {
	contents, err := grokBoundaryFileContents(nativeHome, liveProjectRoot)
	if err != nil || !validCanonicalAbsolute(grokHome) {
		return grokBoundaryBundle{}, fmt.Errorf("grok boundary: invalid installation request")
	}
	info, err := os.Lstat(grokHome)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return grokBoundaryBundle{}, fmt.Errorf("grok boundary: unsafe Grok home")
	}
	names := make([]string, 0, len(contents))
	for name := range contents {
		names = append(names, name)
	}
	sort.Strings(names)
	bundle := grokBoundaryBundle{root: grokHome}
	for _, name := range names {
		path := filepath.Join(grokHome, name)
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if openErr != nil {
			return grokBoundaryBundle{}, fmt.Errorf("grok boundary: install %s", name)
		}
		bytes := contents[name]
		count, writeErr := file.Write(bytes)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil || count != len(bytes) {
			_ = os.Remove(path)
			return grokBoundaryBundle{}, fmt.Errorf("grok boundary: install %s", name)
		}
		installed, statErr := os.Lstat(path)
		if statErr != nil || !installed.Mode().IsRegular() || installed.Mode().Perm() != 0600 || installed.Size() != int64(len(bytes)) {
			_ = os.Remove(path)
			return grokBoundaryBundle{}, fmt.Errorf("grok boundary: verify %s", name)
		}
		sum := sha256.Sum256(bytes)
		bundle.files = append(bundle.files, grokBoundaryFile{path: path, bytes: append([]byte(nil), bytes...), sha256: hex.EncodeToString(sum[:]), info: installed})
	}
	return bundle, nil
}

func (bundle grokBoundaryBundle) Validate() error {
	if !validCanonicalAbsolute(bundle.root) || len(bundle.files) != 3 {
		return fmt.Errorf("grok boundary: incomplete bundle")
	}
	for _, expected := range bundle.files {
		info, err := os.Lstat(expected.path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !os.SameFile(expected.info, info) {
			return fmt.Errorf("grok boundary: policy identity drift")
		}
		bytes, err := os.ReadFile(expected.path)
		if err != nil {
			return fmt.Errorf("grok boundary: policy unreadable")
		}
		sum := sha256.Sum256(bytes)
		if hex.EncodeToString(sum[:]) != expected.sha256 || !reflect.DeepEqual(bytes, expected.bytes) {
			return fmt.Errorf("grok boundary: policy content drift")
		}
	}
	return nil
}
