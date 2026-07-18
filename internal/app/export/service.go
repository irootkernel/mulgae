package export

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

var (
	// ErrUnverifiedSource reports a source reader that cannot supply the exact P2
	// projection selected by the request.
	ErrUnverifiedSource = errors.New("export source is not a verified committed projection")
	// ErrSecureInstall reports an incomplete or mismatched secure-writer effect.
	ErrSecureInstall = errors.New("secure export installation failed")
)

// CommittedProjectionReader supplies only projections reconstructed from a
// verified P2 commit. Implementations must reject P0/P1, mutable, working-tree,
// and raw-provider sources rather than falling back to any of them.
type CommittedProjectionReader interface {
	ReadCommittedProjection(context.Context, ExportSource) (VerifiedSourceProjection, error)
}

// ExportInstaller owns the composite export effect. It must install both files
// with no-replace semantics, or durably record enough verified state to resume
// after process restart. On retry, an exact existing journal, bundle, or manifest
// must be revalidated at its anchored root and containing directory, synced, then
// revalidated with exact bytes before it is reported as installed. It invokes
// ManifestForBundleReceipt only after the bundle receipt has actually been
// issued. A failed or cancelled call may be retried with the same request
// without treating an installed bundle as a new conflicting export.
type ExportInstaller interface {
	Install(context.Context, ExportInstallRequest) (ExportInstallResult, error)
}

// ExportInstallRequest is the complete composite effect. Bundle is caller-owned
// immutable input. ManifestForBundleReceipt must be called with the actual
// bundle receipt, never a predicted digest.
type ExportInstallRequest struct {
	Root                     ports.AnchoredRoot
	BundlePath               ports.SafeRelativePath
	ManifestPath             ports.SafeRelativePath
	Bundle                   []byte
	SourceIDs                []string
	MaxBytes                 int64
	ManifestForBundleReceipt func(ports.SecureWriteReceipt) ([]byte, error)
}

// ExportInstallResult proves that both members of an export pair were durably
// installed or re-adopted after exact-byte verification and directory sync.
type ExportInstallResult struct {
	BundleReceipt   ports.SecureWriteReceipt
	ManifestReceipt ports.SecureWriteReceipt
	ManifestBytes   []byte
}

// ExportSource identifies the committed review selected for export.
type ExportSource struct {
	SessionID string
	RunID     string
	ReviewID  string
}

// ExportRequest gives the service a validated destination pair. Both files are
// immutable secure-writer outputs; the manifest is a sidecar and not a member
// of the bundle.
type ExportRequest struct {
	Source       ExportSource
	Root         ports.AnchoredRoot
	BundlePath   ports.SafeRelativePath
	ManifestPath ports.SafeRelativePath
	ExportID     string
	CreatedAt    time.Time
}

// ExportResult is returned only after both immutable files have accepted,
// matching secure-writer receipts. All byte slices are caller-owned copies.
type ExportResult struct {
	Bundle          Bundle
	Manifest        ExportManifest
	ManifestBytes   []byte
	BundleReceipt   ports.SecureWriteReceipt
	ManifestReceipt ports.SecureWriteReceipt
}

// Service composes a verified committed projection reader with a recoverable
// composite export installer. It has no filesystem or single-file fallback.
type Service struct {
	reader    CommittedProjectionReader
	installer ExportInstaller
	maxBytes  int64
}

// NewService creates an export service with one positive cap for each emitted
// artifact. The installer is responsible for durable paired installation.
func NewService(reader CommittedProjectionReader, installer ExportInstaller, maxBytes int64) (*Service, error) {
	if nilInterface(reader) {
		return nil, fmt.Errorf("export service: nil committed projection reader")
	}
	if nilInterface(installer) {
		return nil, fmt.Errorf("export service: nil recoverable export installer")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("export service: max bytes must be positive")
	}
	return &Service{reader: reader, installer: installer, maxBytes: maxBytes}, nil
}

// ExportRedactedRun reads exactly one P2 projection, creates deterministic
// redacted bytes, and delegates the two-file effect to a recoverable installer.
func (service *Service) ExportRedactedRun(ctx context.Context, request ExportRequest) (ExportResult, error) {
	if service == nil || nilInterface(service.reader) || nilInterface(service.installer) {
		return ExportResult{}, fmt.Errorf("%w: uninitialized service", ErrSecureInstall)
	}
	if err := validateExportRequest(request); err != nil {
		return ExportResult{}, err
	}
	source, err := service.reader.ReadCommittedProjection(ctx, request.Source)
	if err != nil {
		return ExportResult{}, fmt.Errorf("%w: %w", ErrUnverifiedSource, err)
	}
	if source.SessionID != request.Source.SessionID || source.RunID != request.Source.RunID || source.ReviewID != request.Source.ReviewID {
		return ExportResult{}, fmt.Errorf("%w: selected source does not match projection", ErrUnverifiedSource)
	}

	bundle, manifestTemplate, err := BuildRedactedBundle(cloneProjection(source), BuildOptions{ExportID: request.ExportID, CreatedAt: request.CreatedAt})
	if err != nil {
		return ExportResult{}, err
	}
	if int64(len(bundle.Bytes)) > service.maxBytes {
		return ExportResult{}, fmt.Errorf("%w: bundle exceeds maximum bytes", ErrSecureInstall)
	}

	var manifest ExportManifest
	installed, err := service.installer.Install(ctx, ExportInstallRequest{
		Root: request.Root, BundlePath: request.BundlePath, ManifestPath: request.ManifestPath,
		Bundle: append([]byte(nil), bundle.Bytes...), SourceIDs: []string{source.RunID, source.ReviewID}, MaxBytes: service.maxBytes,
		ManifestForBundleReceipt: func(receipt ports.SecureWriteReceipt) ([]byte, error) {
			if err := validateBundleReceipt(receipt, request, bundle); err != nil {
				return nil, err
			}
			var bindErr error
			manifest, bindErr = BindManifestToBundleReceipt(manifestTemplate, receipt)
			if bindErr != nil {
				return nil, bindErr
			}
			bytes, marshalErr := MarshalManifest(manifest)
			if marshalErr != nil {
				return nil, fmt.Errorf("%w: marshal manifest: %v", ErrSecureInstall, marshalErr)
			}
			if int64(len(bytes)) > service.maxBytes {
				return nil, fmt.Errorf("%w: manifest exceeds maximum bytes", ErrSecureInstall)
			}
			return bytes, nil
		},
	})
	if err != nil {
		return ExportResult{}, fmt.Errorf("%w: %w", ErrSecureInstall, err)
	}
	if err := validateBundleReceipt(installed.BundleReceipt, request, bundle); err != nil {
		return ExportResult{}, err
	}
	manifestBytes, err := bindAndVerifyInstalledManifest(manifestTemplate, installed, request, bundle)
	if err != nil {
		return ExportResult{}, err
	}
	manifest, err = BindManifestToBundleReceipt(manifestTemplate, installed.BundleReceipt)
	if err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Bundle: Bundle{Bytes: append([]byte(nil), bundle.Bytes...), Members: append([]Member(nil), bundle.Members...)}, Manifest: manifest, ManifestBytes: manifestBytes, BundleReceipt: installed.BundleReceipt, ManifestReceipt: installed.ManifestReceipt}, nil
}

func validateBundleReceipt(receipt ports.SecureWriteReceipt, request ExportRequest, bundle Bundle) error {
	if receipt.Root() != request.Root || receipt.Destination() != request.BundlePath || receipt.Channel() != "export_bundle" || receipt.SHA256() != digest(bundle.Bytes) || receipt.ByteLength() != int64(len(bundle.Bytes)) {
		return fmt.Errorf("%w: invalid bundle receipt", ErrSecureInstall)
	}
	return nil
}

func bindAndVerifyInstalledManifest(template ExportManifest, installed ExportInstallResult, request ExportRequest, bundle Bundle) ([]byte, error) {
	manifest, err := BindManifestToBundleReceipt(template, installed.BundleReceipt)
	if err != nil {
		return nil, err
	}
	want, err := MarshalManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal manifest: %v", ErrSecureInstall, err)
	}
	if installed.ManifestReceipt.Root() != request.Root || installed.ManifestReceipt.Destination() != request.ManifestPath || installed.ManifestReceipt.Channel() != "export_manifest" || installed.ManifestReceipt.SHA256() != digest(want) || installed.ManifestReceipt.ByteLength() != int64(len(want)) || !reflect.DeepEqual(installed.ManifestBytes, want) {
		return nil, fmt.Errorf("%w: invalid manifest receipt", ErrSecureInstall)
	}
	return append([]byte(nil), want...), nil
}

func validateExportRequest(request ExportRequest) error {
	if !request.Root.Valid() || !request.BundlePath.Valid() || !request.ManifestPath.Valid() || request.BundlePath == request.ManifestPath {
		return fmt.Errorf("%w: invalid or colliding destination", ErrSecureInstall)
	}
	if !idPatterns["session"].MatchString(request.Source.SessionID) || !idPatterns["run"].MatchString(request.Source.RunID) || !idPatterns["review"].MatchString(request.Source.ReviewID) || !idPatterns["export"].MatchString(request.ExportID) || request.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invalid request identity", ErrMalformedProjection)
	}
	return nil
}

func cloneProjection(source VerifiedSourceProjection) VerifiedSourceProjection {
	copy := source
	copy.SchemaVersions = append([]string(nil), source.SchemaVersions...)
	copy.Findings = append([]Finding(nil), source.Findings...)
	copy.Evidence = append([]Evidence(nil), source.Evidence...)
	copy.Redaction.Dropped = append([]string(nil), source.Redaction.Dropped...)
	return copy
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
