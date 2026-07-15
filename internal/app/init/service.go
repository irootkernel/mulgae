// Package init provides the application service for creating a project proposal.
package init

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	privateDirectoryPath     = ".kar"
	projectConfigPath        = ".kar.yaml"
	projectConfigChannel     = "project_config"
	projectConfigSourceID    = "init:project-config:v1"
	unverifiedProviderStatus = "unverified"
)

var gitignoreSuggestions = []string{
	".kar/s_*/",
	".kar/cache/",
}

// InitializeProjectRequest describes the caller-validated project location and
// the provider families that init must report without claiming readiness.
type InitializeProjectRequest struct {
	ProjectRoot         ports.AnchoredRoot
	ProjectName         string
	ContextPath         *ports.SafeRelativePath
	IntendedProviderIDs []string
	OptionalProviderIDs []string
}

// ProviderStatus records one requested provider family. Init never promotes a
// provider to a readiness state; doctor owns readiness observations.
type ProviderStatus struct {
	ID     string
	Status string
}

// InitializeProjectResult contains the accepted configuration receipt and
// advisory data. GitignoreSuggestions are intentionally not applied by init.
type InitializeProjectResult struct {
	ConfigReceipt        ports.SecureWriteReceipt
	ProviderStatuses     []ProviderStatus
	GitignoreSuggestions []string
	InitializedAt        time.Time
}

// Service creates an initial strict project proposal through the secure writer
// boundary. It has no filesystem, configuration-adapter, or CLI dependency.
type Service struct {
	writer ports.SecureFileWriter
	clock  ports.Clock
}

// NewService constructs an init service with the mandatory secure persistence
// and time dependencies.
func NewService(writer ports.SecureFileWriter, clock ports.Clock) (*Service, error) {
	if isNilInterface(writer) {
		return nil, fmt.Errorf("initialize project: nil secure file writer")
	}
	if isNilInterface(clock) {
		return nil, fmt.Errorf("initialize project: nil clock")
	}
	return &Service{writer: writer, clock: clock}, nil
}

// InitializeProject writes .kar.yaml once after creating its private .kar
// directory. It returns no result on any failed directory or write operation.
func (service *Service) InitializeProject(ctx context.Context, request InitializeProjectRequest) (InitializeProjectResult, error) {
	var zero InitializeProjectResult
	if ctx == nil {
		return zero, fmt.Errorf("initialize project: nil context")
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("initialize project: context unavailable: %w", err)
	}
	if service == nil || isNilInterface(service.writer) {
		return zero, fmt.Errorf("initialize project: nil secure file writer")
	}
	if isNilInterface(service.clock) {
		return zero, fmt.Errorf("initialize project: nil clock")
	}

	statuses, err := validateInitializeProjectRequest(request)
	if err != nil {
		return zero, err
	}
	document, err := RenderProjectYAML(request.ProjectName, request.ContextPath)
	if err != nil {
		return zero, fmt.Errorf("initialize project: render project configuration: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("initialize project: context unavailable before filesystem effects: %w", err)
	}
	privateDirectory, err := ports.NewSafeRelativePath(privateDirectoryPath)
	if err != nil {
		return zero, fmt.Errorf("initialize project: private directory contract: %w", err)
	}
	if err := service.writer.EnsurePrivateDir(request.ProjectRoot, privateDirectory); err != nil {
		return zero, fmt.Errorf("initialize project: ensure private directory: %w", err)
	}

	destination, err := ports.NewSafeRelativePath(projectConfigPath)
	if err != nil {
		return zero, fmt.Errorf("initialize project: configuration destination contract: %w", err)
	}
	var abortCause error
	writeRequest, err := ports.NewSecureWriteRequest(
		request.ProjectRoot,
		destination,
		projectConfigChannel,
		bytes.NewReader(document),
		int64(len(document)),
		[]string{projectConfigSourceID},
		func(cause error) {
			abortCause = cause
		},
	)
	if err != nil {
		return zero, fmt.Errorf("initialize project: configuration write contract: %w", err)
	}

	receipt, drop, writeErr := service.writer.Write(ctx, writeRequest)
	if drop != nil || abortCause != nil {
		cause := errors.Join(writeErr, abortCause)
		if cause == nil {
			cause = errors.New("secure writer rejected configuration")
		}
		failure, failureErr := domain.NewFailure(
			"init.secure_write",
			domain.FailureSecurityPolicy,
			"secure writer rejected project configuration",
			cause,
		)
		if failureErr != nil {
			return zero, fmt.Errorf("initialize project: secure writer rejection invariant")
		}
		return zero, failure
	}
	if writeErr != nil {
		return zero, fmt.Errorf("initialize project: write project configuration: %w", writeErr)
	}
	if err := validateConfigReceipt(receipt, request.ProjectRoot, destination, document); err != nil {
		return zero, err
	}

	return InitializeProjectResult{
		ConfigReceipt:        receipt,
		ProviderStatuses:     cloneProviderStatuses(statuses),
		GitignoreSuggestions: cloneStrings(gitignoreSuggestions),
		InitializedAt:        service.clock.Now(),
	}, nil
}

func validateInitializeProjectRequest(request InitializeProjectRequest) ([]ProviderStatus, error) {
	if !request.ProjectRoot.Valid() {
		return nil, fmt.Errorf("initialize project: invalid project root")
	}
	if err := validateProjectName(request.ProjectName); err != nil {
		return nil, fmt.Errorf("initialize project: project name: %w", err)
	}
	if request.ContextPath != nil && !request.ContextPath.Valid() {
		return nil, fmt.Errorf("initialize project: invalid context path")
	}

	statuses := make([]ProviderStatus, 0, len(request.IntendedProviderIDs)+len(request.OptionalProviderIDs))
	seen := make(map[string]struct{}, len(request.IntendedProviderIDs)+len(request.OptionalProviderIDs))
	for _, providerID := range request.IntendedProviderIDs {
		if !intendedProvider(providerID) {
			return nil, fmt.Errorf("initialize project: intended provider %q is not allowed", providerID)
		}
		if _, duplicate := seen[providerID]; duplicate {
			return nil, fmt.Errorf("initialize project: duplicate provider %q", providerID)
		}
		seen[providerID] = struct{}{}
		statuses = append(statuses, ProviderStatus{ID: providerID, Status: unverifiedProviderStatus})
	}
	for _, providerID := range request.OptionalProviderIDs {
		if !optionalProvider(providerID) {
			return nil, fmt.Errorf("initialize project: optional provider %q is not allowed", providerID)
		}
		if _, duplicate := seen[providerID]; duplicate {
			return nil, fmt.Errorf("initialize project: duplicate provider %q", providerID)
		}
		seen[providerID] = struct{}{}
		statuses = append(statuses, ProviderStatus{ID: providerID, Status: unverifiedProviderStatus})
	}
	return statuses, nil
}

func validateProjectName(value string) error {
	if len(value) == 0 || len(value) > 64 {
		return fmt.Errorf("must contain 1 through 64 bytes")
	}
	for index := range value {
		character := value[index]
		if index == 0 || index == len(value)-1 {
			if !lowerAlphaNumeric(character) {
				return fmt.Errorf("must start and end with a lowercase letter or digit")
			}
			continue
		}
		if !lowerAlphaNumeric(character) && character != '.' && character != '-' && character != '_' {
			return fmt.Errorf("must use lowercase letters, digits, dots, hyphens, or underscores")
		}
	}
	return nil
}

func lowerAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func intendedProvider(value string) bool {
	switch value {
	case "kimi", "zcode", "agy":
		return true
	default:
		return false
	}
}

func optionalProvider(value string) bool {
	switch value {
	case "codex", "claude":
		return true
	default:
		return false
	}
}

func validateConfigReceipt(receipt ports.SecureWriteReceipt, root ports.AnchoredRoot, destination ports.SafeRelativePath, document []byte) error {
	if receipt.Root() != root {
		return fmt.Errorf("initialize project: secure writer receipt root does not match request root")
	}
	if receipt.Destination().String() != destination.String() {
		return fmt.Errorf("initialize project: secure writer receipt destination %q does not match %q", receipt.Destination().String(), destination.String())
	}
	if receipt.Channel() != projectConfigChannel {
		return fmt.Errorf("initialize project: secure writer receipt channel %q does not match %q", receipt.Channel(), projectConfigChannel)
	}
	sourceIDs := receipt.SourceIDs()
	if len(sourceIDs) != 1 || sourceIDs[0] != projectConfigSourceID {
		return fmt.Errorf("initialize project: secure writer receipt source IDs do not match configuration")
	}
	if receipt.ByteLength() != int64(len(document)) {
		return fmt.Errorf("initialize project: secure writer receipt byte length %d does not match %d", receipt.ByteLength(), len(document))
	}
	sum := sha256.Sum256(document)
	if receipt.SHA256() != "sha256:"+hex.EncodeToString(sum[:]) {
		return fmt.Errorf("initialize project: secure writer receipt checksum does not match configuration")
	}
	return nil
}

func cloneProviderStatuses(value []ProviderStatus) []ProviderStatus {
	if value == nil {
		return nil
	}
	copyValue := make([]ProviderStatus, len(value))
	copy(copyValue, value)
	return copyValue
}

func cloneStrings(value []string) []string {
	if value == nil {
		return nil
	}
	copyValue := make([]string, len(value))
	copy(copyValue, value)
	return copyValue
}

func isNilInterface(value any) bool {
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
