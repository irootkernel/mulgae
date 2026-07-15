package config

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const defaultProjectConfigPath = ".kar.yaml"

// ResolveRequest contains caller-provided global trusted configuration bytes and
// an optional trusted-base project proposal request.
type ResolveRequest struct {
	GlobalYAML []byte
	Project    *ProjectConfigRequest
}

// ProjectConfigRequest selects an optional project proposal. Path is optional;
// a nil Path selects .kar.yaml. ExpectedCommit is the required immutable
// trusted base captured before this request. Reference is resolved exactly once
// only to confirm that it still identifies ExpectedCommit before the project
// file is read.
type ProjectConfigRequest struct {
	Root           ports.AnchoredRoot
	ExpectedCommit ports.GitObjectID
	Reference      string
	Path           *ports.SafeRelativePath
}

// ProjectProvenance identifies the immutable Git source of an accepted project
// proposal. Its fields are deliberately private so a Resolution cannot expose
// mutable source state.
type ProjectProvenance struct {
	root   ports.AnchoredRoot
	commit ports.GitObjectID
	path   ports.SafeRelativePath
}

// Root returns the anchored repository root used for the immutable read.
func (provenance ProjectProvenance) Root() ports.AnchoredRoot { return provenance.root }

// Commit returns the resolved immutable project-config commit.
func (provenance ProjectProvenance) Commit() ports.GitObjectID { return provenance.commit }

// Path returns the trusted project-config path within Root.
func (provenance ProjectProvenance) Path() ports.SafeRelativePath { return provenance.path }

// Resolution is a complete, immutable effective policy result. It is returned
// only after every requested configuration layer has been accepted.
type Resolution struct {
	config       ResolvedConfig
	project      *ProjectProvenance
	redactedJSON []byte
}

// Config returns the immutable effective policy.
func (resolution Resolution) Config() ResolvedConfig { return resolution.config }

// Project returns the immutable Git provenance of the accepted project proposal.
func (resolution Resolution) Project() (ProjectProvenance, bool) {
	if resolution.project == nil {
		return ProjectProvenance{}, false
	}
	return *resolution.project, true
}

// RedactedJSON returns a caller-owned deterministic JSON representation of the
// redacted effective policy.
func (resolution Resolution) RedactedJSON() []byte {
	return append([]byte(nil), resolution.redactedJSON...)
}

// Service resolves global configuration and optional project proposals through
// the immutable trusted-project reader boundary.
type Service struct {
	projectReader ports.TrustedProjectReader
}

// NewService constructs a configuration resolution service.
func NewService(projectReader ports.TrustedProjectReader) (*Service, error) {
	if nilInterface(projectReader) {
		return nil, fmt.Errorf("resolve configuration: nil trusted project reader")
	}
	return &Service{projectReader: projectReader}, nil
}

// Resolve atomically decodes and reduces trusted configuration. A project
// proposal is read only after its resolved reference equals the caller's
// expected immutable commit; no working-tree read or fallback source exists.
func (service *Service) Resolve(ctx context.Context, request ResolveRequest) (Resolution, error) {
	var zero Resolution
	if ctx == nil {
		return zero, fmt.Errorf("resolve configuration: nil context")
	}
	if service == nil || nilInterface(service.projectReader) {
		return zero, fmt.Errorf("resolve configuration: invalid service dependencies")
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("resolve configuration: context: %w", err)
	}

	projectPath, err := validateResolveRequest(request)
	if err != nil {
		return zero, err
	}
	global, err := adapterconfig.DecodeGlobal("global configuration", request.GlobalYAML)
	if err != nil {
		return zero, fmt.Errorf("resolve configuration: global configuration rejected: %w", err)
	}

	var project *adapterconfig.ProjectConfig
	var provenance *ProjectProvenance
	if request.Project != nil {
		commit, err := service.projectReader.ResolveCommit(ctx, request.Project.Root, request.Project.Reference)
		if err != nil {
			return zero, fmt.Errorf("resolve configuration: resolve trusted project commit: %w", err)
		}
		if !commit.Valid() {
			return zero, fmt.Errorf("resolve configuration: trusted project reader returned an invalid commit")
		}
		if commit != request.Project.ExpectedCommit {
			return zero, fmt.Errorf("resolve configuration: resolved project reference does not match the expected commit")
		}

		contents, err := service.projectReader.ReadFileAtCommit(ctx, request.Project.Root, request.Project.ExpectedCommit, projectPath)
		if err != nil {
			return zero, fmt.Errorf("resolve configuration: read trusted project configuration: %w", err)
		}
		decodedProject, err := adapterconfig.DecodeProject(projectConfigSource(request.Project.ExpectedCommit, projectPath), contents)
		if err != nil {
			return zero, fmt.Errorf("resolve configuration: project configuration rejected: %w", err)
		}
		project = &decodedProject
		provenance = &ProjectProvenance{
			root:   request.Project.Root,
			commit: request.Project.ExpectedCommit,
			path:   projectPath,
		}
	}

	resolved, err := ResolveConfiguration(global, project)
	if err != nil {
		return zero, fmt.Errorf("resolve configuration: policy rejected: %w", err)
	}
	redactedJSON, err := json.Marshal(Redact(resolved))
	if err != nil {
		return zero, fmt.Errorf("resolve configuration: redact policy: %w", err)
	}
	return Resolution{
		config:       resolved,
		project:      provenance,
		redactedJSON: append([]byte(nil), redactedJSON...),
	}, nil
}

func validateResolveRequest(request ResolveRequest) (ports.SafeRelativePath, error) {
	if request.Project == nil {
		return ports.SafeRelativePath{}, nil
	}
	if !request.Project.Root.Valid() {
		return ports.SafeRelativePath{}, fmt.Errorf("resolve configuration: invalid project root")
	}
	if !request.Project.ExpectedCommit.Valid() {
		return ports.SafeRelativePath{}, fmt.Errorf("resolve configuration: invalid expected project commit")
	}
	if err := validateReference(request.Project.Reference); err != nil {
		return ports.SafeRelativePath{}, fmt.Errorf("resolve configuration: project reference: %w", err)
	}
	if request.Project.Path != nil {
		if !request.Project.Path.Valid() {
			return ports.SafeRelativePath{}, fmt.Errorf("resolve configuration: invalid project configuration path")
		}
		return *request.Project.Path, nil
	}
	path, err := ports.NewSafeRelativePath(defaultProjectConfigPath)
	if err != nil {
		return ports.SafeRelativePath{}, fmt.Errorf("resolve configuration: default project configuration path: %w", err)
	}
	return path, nil
}

func validateReference(reference string) error {
	if reference == "" || len(reference) > 4096 {
		return fmt.Errorf("must be non-empty and at most 4096 bytes")
	}
	if strings.TrimSpace(reference) != reference || strings.Contains(reference, "\\") || strings.ContainsAny(reference, "\x00\r\n") {
		return fmt.Errorf("must be canonical and safe")
	}
	return nil
}

func projectConfigSource(commit ports.GitObjectID, path ports.SafeRelativePath) string {
	return "trusted project configuration at " + commit.String() + ":" + path.String()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflectValue := reflect.ValueOf(value)
	switch reflectValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflectValue.IsNil()
	default:
		return false
	}
}
