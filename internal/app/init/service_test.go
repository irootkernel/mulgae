package init

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestInitializeProjectWritesStrictConfigurationAndExactUnverifiedProviderSet(t *testing.T) {
	root := testRoot(t)
	contextPath := testRelativePath(t, ".kar/context.md")
	wantYAML := "version: 1\ntrusted_base: true\nproject:\n  name: \"project-alpha\"\n  root: \".\"\n  context: \".kar/context.md\"\n"
	writer := &fakeSecureWriter{receipt: receiptFor(t, projectConfigPath, []byte(wantYAML))}
	clockTime := time.Date(2026, time.July, 14, 12, 30, 45, 0, time.FixedZone("test", 9*60*60))
	service := mustNewService(t, writer, fixedClock{now: clockTime})

	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot:         root,
		ProjectName:         "project-alpha",
		ContextPath:         &contextPath,
		IntendedProviderIDs: []string{"kimi", "zcode", "agy"},
	})
	if err != nil {
		t.Fatalf("InitializeProject() error = %v", err)
	}

	if got, want := writer.calls, []string{"ensure:.kar", "write:.kar.yaml"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("writer calls = %#v, want %#v", got, want)
	}
	if got := string(writer.source); got != wantYAML {
		t.Fatalf("written YAML = %q, want %q", got, wantYAML)
	}
	if writer.sourceErr != nil {
		t.Fatalf("read write source: %v", writer.sourceErr)
	}
	if got, want := writer.writeRequest.Channel(), projectConfigChannel; got != want {
		t.Fatalf("write channel = %q, want %q", got, want)
	}
	if got, want := writer.writeRequest.MaxBytes(), int64(len(wantYAML)); got != want {
		t.Fatalf("write max bytes = %d, want %d", got, want)
	}
	if got, want := writer.writeRequest.SourceIDs(), []string{projectConfigSourceID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("write source IDs = %#v, want %#v", got, want)
	}
	if writer.writeRequest.Abort() == nil {
		t.Fatal("write abort callback is nil")
	}
	if got, want := result.ConfigReceipt.Destination().String(), projectConfigPath; got != want {
		t.Fatalf("receipt destination = %q, want %q", got, want)
	}
	if got, want := result.ConfigReceipt.ByteLength(), int64(len(wantYAML)); got != want {
		t.Fatalf("receipt byte length = %d, want %d", got, want)
	}
	if got, want := result.ConfigReceipt.SHA256(), sha256ID([]byte(wantYAML)); got != want {
		t.Fatalf("receipt SHA256 = %q, want %q", got, want)
	}
	if got, want := result.ProviderStatuses, []ProviderStatus{
		{ID: "kimi", Status: "unverified"},
		{ID: "zcode", Status: "unverified"},
		{ID: "agy", Status: "unverified"},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("provider statuses = %#v, want %#v", got, want)
	}
	if got, want := result.GitignoreSuggestions, []string{".kar/s_*/", ".kar/cache/"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("gitignore suggestions = %#v, want %#v", got, want)
	}
	if !result.InitializedAt.Equal(clockTime) {
		t.Fatalf("initialized at = %s, want %s", result.InitializedAt, clockTime)
	}
}

func TestInitializeProjectRejectsDuplicateAndUnsupportedIntendedProvidersBeforeWriting(t *testing.T) {
	root := testRoot(t)
	tests := []struct {
		name    string
		request InitializeProjectRequest
	}{
		{
			name: "duplicate intended",
			request: InitializeProjectRequest{
				ProjectRoot:         root,
				ProjectName:         "project",
				IntendedProviderIDs: []string{"kimi", "kimi"},
			},
		},
		{
			name: "unknown intended",
			request: InitializeProjectRequest{
				ProjectRoot:         root,
				ProjectName:         "project",
				IntendedProviderIDs: []string{"unknown"},
			},
		},
		{
			name: "codex intended",
			request: InitializeProjectRequest{
				ProjectRoot:         root,
				ProjectName:         "project",
				IntendedProviderIDs: []string{"codex"},
			},
		},
		{
			name: "claude intended",
			request: InitializeProjectRequest{
				ProjectRoot:         root,
				ProjectName:         "project",
				IntendedProviderIDs: []string{"claude"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := &fakeSecureWriter{}
			service := mustNewService(t, writer, fixedClock{})
			result, err := service.InitializeProject(context.Background(), test.request)
			if err == nil {
				t.Fatal("InitializeProject() succeeded")
			}
			if !isZeroInitializeProjectResult(result) {
				t.Fatalf("result = %#v, want zero result", result)
			}
			if len(writer.calls) != 0 {
				t.Fatalf("writer calls = %#v, want none", writer.calls)
			}
		})
	}
}

func TestInitializeProjectDoesNotReturnPartialSuccessOnWriterFailure(t *testing.T) {
	root := testRoot(t)
	wantYAML := []byte("version: 1\ntrusted_base: true\nproject:\n  name: \"project\"\n  root: \".\"\n")
	existing := errors.New("destination already exists")
	drop, err := ports.NewDropMetadata(projectConfigChannel, "credential_assignment", 1, []string{projectConfigSourceID})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name             string
		writer           *fakeSecureWriter
		wantCalls        []string
		wantAbortInvoked bool
		wantError        error
	}{
		{
			name:      "private directory failure",
			writer:    &fakeSecureWriter{ensureErr: errors.New("unsafe directory")},
			wantCalls: []string{"ensure:.kar"},
		},
		{
			name:      "existing destination collision",
			writer:    &fakeSecureWriter{receipt: receiptFor(t, projectConfigPath, wantYAML), writeErr: existing},
			wantCalls: []string{"ensure:.kar", "write:.kar.yaml"},
			wantError: existing,
		},
		{
			name: "security drop",
			writer: &fakeSecureWriter{
				receipt:     receiptFor(t, projectConfigPath, wantYAML),
				writeDrop:   &drop,
				writeErr:    errors.New("secure writer dropped configuration"),
				invokeAbort: true,
			},
			wantCalls:        []string{"ensure:.kar", "write:.kar.yaml"},
			wantAbortInvoked: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := mustNewService(t, test.writer, fixedClock{})
			result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
				ProjectRoot: root,
				ProjectName: "project",
			})
			if err == nil {
				t.Fatal("InitializeProject() succeeded")
			}
			if test.wantError != nil && !errors.Is(err, test.wantError) {
				t.Fatalf("InitializeProject() error = %v, want wrapped %v", err, test.wantError)
			}
			if !isZeroInitializeProjectResult(result) {
				t.Fatalf("result = %#v, want zero result", result)
			}
			if got := test.writer.calls; !reflect.DeepEqual(got, test.wantCalls) {
				t.Fatalf("writer calls = %#v, want %#v", got, test.wantCalls)
			}
			if got := test.writer.abortCalls != 0; got != test.wantAbortInvoked {
				t.Fatalf("abort invoked = %t, want %t", got, test.wantAbortInvoked)
			}
		})
	}
}

func TestNewServiceRejectsNilWriter(t *testing.T) {
	if service, err := NewService(nil, fixedClock{}); err == nil || service != nil {
		t.Fatalf("NewService(nil, clock) = (%#v, %v), want nil service and error", service, err)
	}
}

func TestInitializeProjectRejectsMismatchedWriterReceipt(t *testing.T) {
	root := testRoot(t)
	wrongReceipt := receiptFor(t, ".kar/other.yaml", []byte("other"))
	writer := &fakeSecureWriter{receipt: wrongReceipt}
	service := mustNewService(t, writer, fixedClock{})

	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root,
		ProjectName: "project",
	})
	if err == nil {
		t.Fatal("InitializeProject() succeeded")
	}
	if !isZeroInitializeProjectResult(result) {
		t.Fatalf("result = %#v, want zero result", result)
	}
	if got, want := writer.calls, []string{"ensure:.kar", "write:.kar.yaml"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("writer calls = %#v, want %#v", got, want)
	}
}

func TestInitializeProjectOnlyReturnsGitignoreSuggestions(t *testing.T) {
	root := testRoot(t)
	wantYAML := []byte("version: 1\ntrusted_base: true\nproject:\n  name: \"project\"\n  root: \".\"\n")
	writer := &fakeSecureWriter{receipt: receiptFor(t, projectConfigPath, wantYAML)}
	service := mustNewService(t, writer, fixedClock{})

	result, err := service.InitializeProject(context.Background(), InitializeProjectRequest{
		ProjectRoot: root,
		ProjectName: "project",
	})
	if err != nil {
		t.Fatalf("InitializeProject() error = %v", err)
	}
	if got, want := writer.calls, []string{"ensure:.kar", "write:.kar.yaml"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("writer calls = %#v, want %#v", got, want)
	}
	if got, want := result.GitignoreSuggestions, []string{".kar/s_*/", ".kar/cache/"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("gitignore suggestions = %#v, want %#v", got, want)
	}
}

type fixedClock struct {
	now time.Time
}

func (clock fixedClock) Now() time.Time {
	return clock.now
}

type fakeSecureWriter struct {
	calls        []string
	ensureErr    error
	writeErr     error
	writeDrop    *ports.DropMetadata
	receipt      ports.SecureWriteReceipt
	writeRequest ports.SecureWriteRequest
	source       []byte
	sourceErr    error
	invokeAbort  bool
	abortCalls   int
}

func (writer *fakeSecureWriter) EnsurePrivateDir(_ ports.AnchoredRoot, directory ports.SafeRelativePath) error {
	writer.calls = append(writer.calls, "ensure:"+directory.String())
	return writer.ensureErr
}

func (writer *fakeSecureWriter) Write(_ context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	writer.calls = append(writer.calls, "write:"+request.Destination().String())
	writer.writeRequest = request
	writer.source, writer.sourceErr = io.ReadAll(request.Source())
	if writer.invokeAbort {
		writer.abortCalls++
		request.Abort()(writer.writeErr)
	}
	return writer.receipt, writer.writeDrop, writer.writeErr
}

func mustNewService(t *testing.T, writer ports.SecureFileWriter, clock ports.Clock) *Service {
	t.Helper()
	service, err := NewService(writer, clock)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testRoot(t *testing.T) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot("/private/project")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func testRelativePath(t *testing.T, value string) ports.SafeRelativePath {
	t.Helper()
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func receiptFor(t *testing.T, destination string, data []byte) ports.SecureWriteReceipt {
	t.Helper()
	path := testRelativePath(t, destination)
	receipt, err := ports.NewSecureWriteReceipt(testRoot(t), path, sha256ID(data), int64(len(data)), projectConfigChannel, []string{projectConfigSourceID})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func sha256ID(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isZeroInitializeProjectResult(result InitializeProjectResult) bool {
	return result.ConfigReceipt.Destination().String() == "" &&
		result.ConfigReceipt.SHA256() == "" &&
		result.ConfigReceipt.ByteLength() == 0 &&
		result.ProviderStatuses == nil &&
		result.GitignoreSuggestions == nil &&
		result.InitializedAt.IsZero()
}
