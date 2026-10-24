// Package historical loads the byte-fixed synthetic compatibility corpus.
// It supplies test input only; it never invokes an artifact producer.
package historical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// File binds a logical store path to immutable ordinary testdata bytes.
type File struct {
	Path       string `json:"path"`
	Data       string `json:"data"`
	SHA256     string `json:"sha256"`
	ByteLength int    `json:"byte_length"`
}

// Expected records the preserved operation result, not a new acceptance policy.
type Expected struct {
	NativeReadReason    string `json:"native_read_reason"`
	NativeRuntimeReason string `json:"native_runtime_reason"`
	ExportSHA256        string `json:"export_sha256"`
	ArchiveSHA256       string `json:"archive_sha256"`
	ReadReason          string `json:"read_reason"`
	RuntimeReason       string `json:"runtime_reason"`
	RecoveryReason      string `json:"recovery_reason"`
	Publication         string `json:"publication"`
	Content             string `json:"content"`
	Coverage            string `json:"coverage"`
	CI                  string `json:"ci"`
	Exit                int    `json:"exit"`
	Findings            int    `json:"findings"`
	Report              string `json:"report"`
	Cleanup             string `json:"cleanup"`
}

// Attempt records a baseline committed-attempt result and its frozen inputs.
type Attempt struct {
	SessionID            string `json:"session_id,omitempty"`
	RunID                string `json:"run_id,omitempty"`
	ReviewID             string `json:"review_id,omitempty"`
	AttemptID            string `json:"attempt_id"`
	Role                 string `json:"role,omitempty"`
	Provider             string `json:"provider,omitempty"`
	PromptManifestPath   string `json:"prompt_manifest_path,omitempty"`
	PromptManifestSHA256 string `json:"prompt_manifest_sha256,omitempty"`
	StdinPath            string `json:"stdin_path,omitempty"`
	StdinSHA256          string `json:"stdin_sha256,omitempty"`
	CompleteStdinSHA256  string `json:"complete_stdin_sha256,omitempty"`
	TemplateID           string `json:"template_id,omitempty"`
	TemplateVersion      string `json:"template_version,omitempty"`
	TemplateSHA256       string `json:"template_sha256,omitempty"`
	Reason               string `json:"reason"`
}

// AttemptSelector records an exact role/provider selection or its refusal.
type AttemptSelector struct {
	Role      string `json:"role"`
	Provider  string `json:"provider"`
	AttemptID string `json:"attempt_id"`
	Reason    string `json:"reason"`
}

// Case is one complete logical store, including its required ancestors.
type Case struct {
	ID               string            `json:"id"`
	Family           string            `json:"family"`
	SessionID        string            `json:"session_id"`
	RunID            string            `json:"run_id"`
	ReviewID         string            `json:"review_id"`
	Formats          []string          `json:"formats"`
	Bindings         []string          `json:"bindings"`
	Controls         []string          `json:"controls"`
	Expected         Expected          `json:"expected"`
	Files            []File            `json:"files"`
	Attempts         []Attempt         `json:"attempts,omitempty"`
	AttemptSelectors []AttemptSelector `json:"attempt_selectors,omitempty"`
	bytes            map[string][]byte
}

// Corpus is a test-only inventory; its format is not a public Mulgae contract.
type Corpus struct {
	Version      int    `json:"version"`
	SourceCommit string `json:"source_commit"`
	Cases        []Case `json:"cases"`
}

// Load reads the checked-in corpus without generating or rewriting any bytes.
func Load() (Corpus, error) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		return Corpus{}, fmt.Errorf("historical corpus: source location unavailable")
	}
	return LoadFrom(filepath.Join(filepath.Dir(source), "testdata"))
}

// LoadFrom also permits checksum tests against an isolated corpus copy.
func LoadFrom(directory string) (Corpus, error) {
	raw, err := os.ReadFile(filepath.Join(directory, "corpus.json"))
	if err != nil {
		return Corpus{}, err
	}
	var corpus Corpus
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		return Corpus{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Corpus{}, fmt.Errorf("historical corpus: trailing JSON")
	}
	if corpus.Version != 1 || corpus.SourceCommit == "" || len(corpus.Cases) == 0 {
		return Corpus{}, fmt.Errorf("historical corpus: incomplete record")
	}
	seen := map[string]bool{}
	for i := range corpus.Cases {
		c := &corpus.Cases[i]
		if c.ID == "" || seen[c.ID] || len(c.Formats) == 0 || len(c.Bindings) == 0 || len(c.Files) == 0 {
			return Corpus{}, fmt.Errorf("historical corpus: invalid case %q", c.ID)
		}
		seen[c.ID] = true
		c.bytes = map[string][]byte{}
		for _, file := range c.Files {
			if !safePath(file.Path) || !safePath(file.Data) || c.bytes[file.Path] != nil {
				return Corpus{}, fmt.Errorf("historical corpus: invalid path in %s", c.ID)
			}
			raw, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(file.Data)))
			if err != nil {
				return Corpus{}, err
			}
			digest := sha256.Sum256(raw)
			if file.SHA256 != "sha256:"+hex.EncodeToString(digest[:]) || len(raw) != file.ByteLength {
				return Corpus{}, fmt.Errorf("historical corpus: checksum mismatch: %s/%s", c.ID, file.Path)
			}
			c.bytes[file.Path] = raw
		}
	}
	return corpus, nil
}

func safePath(path string) bool {
	if !filepath.IsLocal(path) || strings.Contains(path, "\\") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".mulgae" || part == ".." || part == "" {
			return false
		}
	}
	return true
}

// Artifacts returns owned copies of the fixed stored bytes.
func (c Case) Artifacts() map[string][]byte {
	result := make(map[string][]byte, len(c.bytes))
	for path, raw := range c.bytes {
		result[path] = bytes.Clone(raw)
	}
	return result
}

// Materialize installs only frozen fixture members beneath a caller-owned root.
func (c Case) Materialize(root string) error {
	for path, raw := range c.bytes {
		destination := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(destination, raw, 0600); err != nil {
			return err
		}
	}
	return nil
}
