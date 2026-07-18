package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const serviceGlobalYAML = `
version: 1
runtime:
  home: /private/global-home
  path:
    inherit: true
    prepend: [/private/global-bin]
    append: [/private/global-append]
  env_allowlist: [HOME, PATH]
  max_active_lanes: 3
execution:
  strategy: primary_with_fallback
  workspace_access: readonly_snapshot
  cross_process_lane_lock: true
providers:
  kimi-main:
    driver: kimi
    status: unverified
    bin: /private/kimi
    args: [--private-arg]
    concurrency_key: kimi-main
    timeout_sec: 180
    max_stdout_bytes: 262144
    max_stderr_bytes: 262144
roles:
  logic: {enabled: true}
  security: {enabled: true}
  maintainability: {enabled: true}
  product: {enabled: true}
  documentation: {enabled: true}
  testing: {enabled: true}
review:
  request_changes_on: [high, critical, blocker]
validation:
  reject_unknown_fields: true
  reject_empty_strings: true
  reject_placeholder_values: true
  evidence:
    require_verified_for: [high, critical, blocker]
  repair:
    enabled: true
    max_attempts: 1
    same_provider: true
trust:
  required_roles: [logic, security]
  project_config: trusted_base_only
  project_prompt_overrides: false
  project_prompt_source: target_base
  allow_project_provider_commands: false
  allow_project_shell: false
resources:
  primary_repair_attempts: 1
  fallback_repair_attempts: 1
  role_max_invocations: 4
  run_max_invocations: 24
  run_total_output_cap: 64MiB
ci:
  fail_on_severity: [high, critical, blocker]
  degraded_review_fails: true
artifacts:
  root: .kar
  directory_mode: "0700"
  file_mode: "0600"
  preserve_raw_output: true
safety:
  redact_secrets: true
  secret_output_policy: block
  mutation_detection: true
`

const serviceProjectYAML = `
version: 1
trusted_base: true
project:
  name: trusted-project
  root: .
  context: .kar/private-context.md
`

const weakeningProjectYAML = `
version: 1
trusted_base: true
project:
  name: trusted-project
  root: .
  context: .kar/private-context.md
resources:
  role_max_invocations: 5
`

func TestServiceResolvesAuthoritativeEmbeddedGlobalDefault(t *testing.T) {
	ctx := context.Background()
	catalog := builtin.NewCatalog()
	id, err := ports.ParseAssetID("defaults:global-config")
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := catalog.Read(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(&fakeTrustedProjectReader{})
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := service.Resolve(ctx, ResolveRequest{GlobalYAML: raw})
	if err != nil {
		t.Fatalf("Resolve(authoritative default) error = %v", err)
	}
	wantDrivers := map[string]string{
		"kimi-main":  "kimi",
		"zcode-main": "zcode",
		"agy-main":   "agy",
	}
	providers := resolution.Config().Providers()
	if len(providers) != len(wantDrivers) {
		t.Fatalf("Resolve(authoritative default) providers = %#v, want exactly %#v", providers, wantDrivers)
	}
	for providerID, wantDriver := range wantDrivers {
		provider, ok := providers[providerID]
		if !ok || provider.Driver != wantDriver {
			t.Fatalf("Resolve(authoritative default) provider %q = %#v, want driver %q", providerID, provider, wantDriver)
		}
	}
	if len(resolution.RedactedJSON()) == 0 {
		t.Fatal("Resolve(authoritative default) returned empty redacted JSON")
	}
}
func TestServiceResolveReadsOnlyResolvedTrustedProjectConfig(t *testing.T) {
	root := serviceRoot(t)
	path := servicePath(t, "policy/trusted-project.yaml")
	commit := serviceCommit(t, "a")
	reader := &fakeTrustedProjectReader{
		commit:              commit,
		contents:            []byte(serviceProjectYAML),
		workingTreeContents: []byte("this must never be read"),
	}
	service, err := NewService(reader)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Resolve(context.Background(), ResolveRequest{
		GlobalYAML: []byte(serviceGlobalYAML),
		Project: &ProjectConfigRequest{
			Root:           root,
			ExpectedCommit: commit,
			Reference:      "trusted-base",
			Path:           &path,
		},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got, want := reader.resolveCalls, []resolveCall{{root: root.String(), reference: "trusted-base"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveCommit() calls = %#v, want %#v", got, want)
	}
	if got, want := reader.readCalls, []readCall{{root: root.String(), commit: commit.String(), path: path.String()}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadFileAtCommit() calls = %#v, want %#v", got, want)
	}
	if reader.workingTreeRead {
		t.Fatal("Resolve() read the working tree")
	}

	provenance, ok := result.Project()
	if !ok {
		t.Fatal("Project() reported no project provenance")
	}
	if got, want := provenance.Root().String(), root.String(); got != want {
		t.Errorf("Project().Root() = %q, want %q", got, want)
	}
	if got, want := provenance.Commit().String(), commit.String(); got != want {
		t.Errorf("Project().Commit() = %q, want %q", got, want)
	}
	if got, want := provenance.Path().String(), path.String(); got != want {
		t.Errorf("Project().Path() = %q, want %q", got, want)
	}
	project, ok := result.Config().Project()
	if !ok || project.Name != "trusted-project" {
		t.Fatalf("Config().Project() = %#v, %t; want trusted project metadata", project, ok)
	}

	wantRedacted, err := json.Marshal(Redact(result.Config()))
	if err != nil {
		t.Fatal(err)
	}
	redacted := result.RedactedJSON()
	if !bytes.Equal(redacted, wantRedacted) {
		t.Errorf("RedactedJSON() = %s, want %s", redacted, wantRedacted)
	}
	for _, forbidden := range []string{root.String(), path.String(), "/private/global-home", "/private/kimi", "--private-arg", ".kar/private-context.md"} {
		if bytes.Contains(redacted, []byte(forbidden)) {
			t.Errorf("RedactedJSON() leaked %q", forbidden)
		}
	}
	redacted[0] = 'X'
	if got := result.RedactedJSON(); !bytes.Equal(got, wantRedacted) {
		t.Errorf("RedactedJSON() returned an aliased slice: %s", got)
	}
}
func TestServiceResolveRejectsMismatchedExpectedCommitBeforeRead(t *testing.T) {
	root := serviceRoot(t)
	resolvedCommit := serviceCommit(t, "e")
	expectedCommit := serviceCommit(t, "f")
	reader := &fakeTrustedProjectReader{
		commit:              resolvedCommit,
		contents:            []byte(serviceProjectYAML),
		workingTreeContents: []byte("this must never be read"),
	}
	service, err := NewService(reader)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Resolve(context.Background(), ResolveRequest{
		GlobalYAML: []byte(serviceGlobalYAML),
		Project: &ProjectConfigRequest{
			Root:           root,
			ExpectedCommit: expectedCommit,
			Reference:      "trusted-base",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "does not match the expected commit") {
		t.Fatalf("Resolve() error = %v, want expected-commit mismatch", err)
	}
	if !reflect.DeepEqual(result, Resolution{}) {
		t.Errorf("Resolve() result = %#v, want zero value", result)
	}
	if got, want := reader.resolveCalls, []resolveCall{{root: root.String(), reference: "trusted-base"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveCommit() calls = %#v, want %#v", got, want)
	}
	if len(reader.readCalls) != 0 {
		t.Errorf("ReadFileAtCommit() calls = %#v, want none", reader.readCalls)
	}
	if reader.workingTreeRead {
		t.Error("Resolve() read the working tree")
	}
}

func TestServiceResolveUsesDefaultProjectPathAndSkipsProjectWhenAbsent(t *testing.T) {
	root := serviceRoot(t)
	commit := serviceCommit(t, "b")
	reader := &fakeTrustedProjectReader{commit: commit, contents: []byte(serviceProjectYAML)}
	service, err := NewService(reader)
	if err != nil {
		t.Fatal(err)
	}

	withProject, err := service.Resolve(context.Background(), ResolveRequest{
		GlobalYAML: []byte(serviceGlobalYAML),
		Project: &ProjectConfigRequest{
			Root:           root,
			ExpectedCommit: commit,
			Reference:      "refs/heads/trusted-base",
		},
	})
	if err != nil {
		t.Fatalf("Resolve() with project error = %v", err)
	}
	if got, want := reader.readCalls, []readCall{{root: root.String(), commit: commit.String(), path: defaultProjectConfigPath}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default ReadFileAtCommit() calls = %#v, want %#v", got, want)
	}
	if provenance, ok := withProject.Project(); !ok || provenance.Path().String() != defaultProjectConfigPath {
		t.Fatalf("default project provenance = %#v, %t", provenance, ok)
	}

	withoutProjectReader := &fakeTrustedProjectReader{}
	withoutProjectService, err := NewService(withoutProjectReader)
	if err != nil {
		t.Fatal(err)
	}
	withoutProject, err := withoutProjectService.Resolve(context.Background(), ResolveRequest{GlobalYAML: []byte(serviceGlobalYAML)})
	if err != nil {
		t.Fatalf("Resolve() without project error = %v", err)
	}
	if len(withoutProjectReader.resolveCalls) != 0 || len(withoutProjectReader.readCalls) != 0 {
		t.Fatalf("project reader calls without project = resolves %#v, reads %#v", withoutProjectReader.resolveCalls, withoutProjectReader.readCalls)
	}
	if _, ok := withoutProject.Project(); ok {
		t.Fatal("Project() reported provenance without a project request")
	}
	if _, ok := withoutProject.Config().Project(); ok {
		t.Fatal("Config().Project() reported metadata without a project request")
	}
}

func TestServiceResolveKeepsFailuresAtomicWithoutFallback(t *testing.T) {
	root := serviceRoot(t)
	commit := serviceCommit(t, "c")
	gitFailure := errors.New("resolve failed")
	readFailure := errors.New("read failed")
	cases := []struct {
		name         string
		globalYAML   []byte
		reader       *fakeTrustedProjectReader
		wantResolves int
		wantReads    int
		secret       string
	}{
		{
			name:         "global_decode",
			globalYAML:   []byte("unknown: global-secret-material\n"),
			reader:       &fakeTrustedProjectReader{commit: commit},
			wantResolves: 0,
			wantReads:    0,
			secret:       "global-secret-material",
		},
		{
			name:         "git_resolution",
			globalYAML:   []byte(serviceGlobalYAML),
			reader:       &fakeTrustedProjectReader{resolveErr: gitFailure, workingTreeContents: []byte(serviceProjectYAML)},
			wantResolves: 1,
			wantReads:    0,
		},
		{
			name:         "immutable_read",
			globalYAML:   []byte(serviceGlobalYAML),
			reader:       &fakeTrustedProjectReader{commit: commit, readErr: readFailure, workingTreeContents: []byte(serviceProjectYAML)},
			wantResolves: 1,
			wantReads:    1,
		},
		{
			name:         "project_decode",
			globalYAML:   []byte(serviceGlobalYAML),
			reader:       &fakeTrustedProjectReader{commit: commit, contents: []byte("unknown: project-secret-material\n"), workingTreeContents: []byte(serviceProjectYAML)},
			wantResolves: 1,
			wantReads:    1,
			secret:       "project-secret-material",
		},
		{
			name:         "weakening_reducer",
			globalYAML:   []byte(serviceGlobalYAML),
			reader:       &fakeTrustedProjectReader{commit: commit, contents: []byte(weakeningProjectYAML), workingTreeContents: []byte(serviceProjectYAML)},
			wantResolves: 1,
			wantReads:    1,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service, err := NewService(testCase.reader)
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Resolve(context.Background(), ResolveRequest{
				GlobalYAML: testCase.globalYAML,
				Project: &ProjectConfigRequest{
					Root:           root,
					ExpectedCommit: commit,
					Reference:      "trusted-base",
				},
			})
			if err == nil {
				t.Fatal("Resolve() error = nil, want rejection")
			}
			if !reflect.DeepEqual(result, Resolution{}) {
				t.Errorf("Resolve() result = %#v, want zero value after rejection", result)
			}
			if got := len(testCase.reader.resolveCalls); got != testCase.wantResolves {
				t.Errorf("ResolveCommit() calls = %d, want %d", got, testCase.wantResolves)
			}
			if got := len(testCase.reader.readCalls); got != testCase.wantReads {
				t.Errorf("ReadFileAtCommit() calls = %d, want %d", got, testCase.wantReads)
			}
			if testCase.reader.workingTreeRead {
				t.Error("Resolve() fell back to the working tree")
			}
			if testCase.secret != "" && strings.Contains(err.Error(), testCase.secret) {
				t.Errorf("Resolve() error leaked configuration bytes %q: %v", testCase.secret, err)
			}
		})
	}
}

func TestServiceResolveRejectsNilDependenciesContextsAndInvalidRequests(t *testing.T) {
	var typedNil *fakeTrustedProjectReader
	if _, err := NewService(typedNil); err == nil {
		t.Fatal("NewService() error = nil for typed-nil reader")
	}

	reader := &fakeTrustedProjectReader{commit: serviceCommit(t, "d"), contents: []byte(serviceProjectYAML)}
	service, err := NewService(reader)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := service.Resolve(nil, ResolveRequest{GlobalYAML: []byte(serviceGlobalYAML)}); err == nil || !reflect.DeepEqual(result, Resolution{}) {
		t.Fatalf("Resolve(nil) = %#v, %v; want zero result and error", result, err)
	}
	if len(reader.resolveCalls) != 0 || len(reader.readCalls) != 0 {
		t.Fatal("Resolve(nil) called the project reader")
	}

	invalidPath := ports.SafeRelativePath{}
	expectedCommit := reader.commit
	invalidCases := []ProjectConfigRequest{
		{Reference: "trusted-base"},
		{Root: serviceRoot(t), ExpectedCommit: expectedCommit, Reference: " trusted-base"},
		{Root: serviceRoot(t), ExpectedCommit: expectedCommit, Reference: "trusted-base", Path: &invalidPath},
		{Root: serviceRoot(t), Reference: "trusted-base"},
	}
	for _, request := range invalidCases {
		result, err := service.Resolve(context.Background(), ResolveRequest{GlobalYAML: []byte(serviceGlobalYAML), Project: &request})
		if err == nil {
			t.Fatalf("Resolve(%#v) error = nil", request)
		}
		if !reflect.DeepEqual(result, Resolution{}) {
			t.Errorf("Resolve(%#v) result = %#v, want zero", request, result)
		}
	}
	if len(reader.resolveCalls) != 0 || len(reader.readCalls) != 0 {
		t.Fatalf("invalid requests called the project reader: resolves %#v, reads %#v", reader.resolveCalls, reader.readCalls)
	}

	invalidService := &Service{}
	if result, err := invalidService.Resolve(context.Background(), ResolveRequest{GlobalYAML: []byte(serviceGlobalYAML)}); err == nil || !reflect.DeepEqual(result, Resolution{}) {
		t.Fatalf("invalid service Resolve() = %#v, %v; want zero result and error", result, err)
	}
}

type resolveCall struct {
	root      string
	reference string
}

type readCall struct {
	root   string
	commit string
	path   string
}

type fakeTrustedProjectReader struct {
	commit              ports.GitObjectID
	contents            []byte
	resolveErr          error
	readErr             error
	resolveCalls        []resolveCall
	readCalls           []readCall
	workingTreeContents []byte
	workingTreeRead     bool
}

func (reader *fakeTrustedProjectReader) ResolveCommit(_ context.Context, root ports.AnchoredRoot, reference string) (ports.GitObjectID, error) {
	reader.resolveCalls = append(reader.resolveCalls, resolveCall{root: root.String(), reference: reference})
	if reader.resolveErr != nil {
		return ports.GitObjectID{}, reader.resolveErr
	}
	return reader.commit, nil
}

func (reader *fakeTrustedProjectReader) ReadFileAtCommit(_ context.Context, root ports.AnchoredRoot, commit ports.GitObjectID, path ports.SafeRelativePath) ([]byte, error) {
	reader.readCalls = append(reader.readCalls, readCall{root: root.String(), commit: commit.String(), path: path.String()})
	if reader.readErr != nil {
		return nil, reader.readErr
	}
	return append([]byte(nil), reader.contents...), nil
}

// ReadWorkingTree is intentionally outside ports.TrustedProjectReader. It lets
// the tests detect an accidental escape from the immutable-read boundary.
func (reader *fakeTrustedProjectReader) ReadWorkingTree() []byte {
	reader.workingTreeRead = true
	return append([]byte(nil), reader.workingTreeContents...)
}

func serviceRoot(t *testing.T) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot("/trusted/project")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func servicePath(t *testing.T, value string) ports.SafeRelativePath {
	t.Helper()
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func serviceCommit(t *testing.T, digit string) ports.GitObjectID {
	t.Helper()
	commit, err := ports.ParseGitObjectID(strings.Repeat(digit, 40))
	if err != nil {
		t.Fatal(err)
	}
	return commit
}
