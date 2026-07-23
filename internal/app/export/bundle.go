package export

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"sort"
	"time"
)

var zipTimestamp = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// BuildRedactedBundle builds only in-memory bytes, scanning the allowlisted
// payload before packaging. Its manifest template cannot be serialized until
// BindManifestToBundleReceipt receives an actually issued receipt.
func BuildRedactedBundle(source VerifiedSourceProjection, options BuildOptions) (Bundle, ExportManifest, error) {
	if err := validateProjection(source, options); err != nil {
		return Bundle{}, ExportManifest{}, err
	}

	redacted, changed, err := redactedProjection(source)
	if err != nil {
		return Bundle{}, ExportManifest{}, err
	}
	members, err := bundleMembers(redacted, changed)
	if err != nil {
		return Bundle{}, ExportManifest{}, err
	}
	bundle, err := buildZIP(members)
	if err != nil {
		return Bundle{}, ExportManifest{}, err
	}
	manifest := ExportManifest{
		SchemaVersion:   manifestSchemaVersion,
		ExportID:        options.ExportID,
		CreatedAt:       options.CreatedAt.UTC(),
		ImmutableSource: ImmutableSource{SessionID: source.SessionID, RunID: source.RunID, ReviewID: source.ReviewID, RunManifestRef: source.RunManifest, ReviewArtifactRef: source.ReviewArtifact},
		SourceIdentity:  source.SourceIdentity,
		CurrentIdentity: source.CurrentIdentity,
		SecureWriter:    SecureWriterReceipt{Contract: secureWriterContract, ScanBeforeWrite: true, RedactionPolicy: "redacted_export", RedactionStatus: writerRedactionStatus(changed), SecretBlockEvidence: SecretBlockEvidence{ScanStatus: "clear", OnDetection: "abort_export", SecretPersisted: false, BlockedContentHashPersisted: false}},
		Bundle:          BundleIdentity{MemberCount: len(bundle.Members), SizeBytes: int64(len(bundle.Bytes)), SHA256: digest(bundle.Bytes)},
		Members:         append([]Member(nil), bundle.Members...),
	}
	return bundle, manifest, nil
}

// BindManifestToBundleReceipt binds a manifest template to the actual accepted
// bundle write. It rejects a receipt that is not exact evidence for the bundle.
func BindManifestToBundleReceipt(template ExportManifest, receipt ports.SecureWriteReceipt) (ExportManifest, error) {
	if receipt.SHA256() != template.Bundle.SHA256 || receipt.ByteLength() != template.Bundle.SizeBytes || receipt.Channel() != "export_bundle" {
		return ExportManifest{}, fmt.Errorf("%w: bundle receipt does not match bundle", ErrSecureInstall)
	}
	manifest := template
	manifest.SecureWriter.ReceiptSHA256 = receipt.SHA256()
	return manifest, nil
}

// MarshalManifest returns stable sidecar JSON for a manifest bound to an actual
// bundle receipt. The manifest is never embedded in its bundle.
func MarshalManifest(manifest ExportManifest) ([]byte, error) {
	if !sha256Pattern.MatchString(manifest.SecureWriter.ReceiptSHA256) {
		return nil, fmt.Errorf("%w: missing actual bundle receipt", ErrSecureInstall)
	}
	return json.Marshal(manifest)
}

type packageProjection struct {
	SessionID    string                 `json:"session_id"`
	RunID        string                 `json:"run_id"`
	ReviewID     string                 `json:"review_id"`
	Review       Review                 `json:"review"`
	SourceHashes []ImmutableArtifactRef `json:"source_hashes"`
}

type redactedSource struct {
	VerifiedSourceProjection
}

func redactedProjection(source VerifiedSourceProjection) (redactedSource, bool, error) {
	result := redactedSource{VerifiedSourceProjection: source}
	result.SchemaVersions = append([]string(nil), source.SchemaVersions...)
	sort.Strings(result.SchemaVersions)
	result.Findings = append([]Finding(nil), source.Findings...)
	result.Evidence = append([]Evidence(nil), source.Evidence...)
	result.Redaction = RedactionManifest{
		Policy:  "redacted_export",
		Dropped: []string{"absolute_paths", "environment_metadata", "raw_provider_output", "runtime_diagnostics", "secrets", "target_bytes"},
	}
	changed := false
	for i := range result.Findings {
		fields := []*string{&result.Findings[i].Title, &result.Findings[i].Description, &result.Findings[i].Recommendation}
		for _, field := range fields {
			value, err := redactText(*field)
			if err != nil {
				return redactedSource{}, false, err
			}
			changed = changed || value != *field
			*field = value
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].ID < result.Findings[j].ID })
	sort.Slice(result.Evidence, func(i, j int) bool {
		if result.Evidence[i].FindingID != result.Evidence[j].FindingID {
			return result.Evidence[i].FindingID < result.Evidence[j].FindingID
		}
		if result.Evidence[i].Path != result.Evidence[j].Path {
			return result.Evidence[i].Path < result.Evidence[j].Path
		}
		return result.Evidence[i].LineStart < result.Evidence[j].LineStart
	})
	return result, changed, nil
}

func bundleMembers(source redactedSource, changed bool) ([]bundleMember, error) {
	projection := packageProjection{SessionID: source.SessionID, RunID: source.RunID, ReviewID: source.ReviewID, Review: source.Review, SourceHashes: []ImmutableArtifactRef{source.RunManifest, source.ReviewArtifact}}
	items := []struct {
		name   string
		value  any
		status string
	}{
		{"evidence.json", source.Evidence, "not_required"},
		{"findings.json", source.Findings, redactionStatus(changed)},
		{"redaction.json", source.Redaction, "applied"},
		{"review.json", projection, "not_required"},
		{"run.json", source.Run, "not_required"},
		{"schemas.json", source.SchemaVersions, "not_required"},
	}
	members := make([]bundleMember, 0, len(items))
	for _, item := range items {
		if !canonicalPathPattern.MatchString(item.name) {
			return nil, fmt.Errorf("%w: member name", ErrMalformedProjection)
		}
		body, err := json.Marshal(item.value)
		if err != nil {
			return nil, err
		}
		if absolutePathPattern.Match(body) {
			return nil, fmt.Errorf("%w: absolute path in member", ErrMalformedProjection)
		}
		if secretPattern.Match(body) {
			return nil, secretDetectedFailure()
		}
		members = append(members, bundleMember{name: item.name, body: body, status: item.status})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
	return members, nil
}

type bundleMember struct {
	name   string
	body   []byte
	status string
}

func buildZIP(source []bundleMember) (Bundle, error) {
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	members := make([]Member, 0, len(source))
	for _, item := range source {
		header := &zip.FileHeader{Name: item.name, Method: zip.Store, Modified: zipTimestamp}
		header.SetMode(0600)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return Bundle{}, err
		}
		if _, err := entry.Write(item.body); err != nil {
			return Bundle{}, err
		}
		members = append(members, Member{Path: item.name, SHA256: digest(item.body), SizeBytes: int64(len(item.body)), MediaType: "application/json", RedactionStatus: item.status})
	}
	if err := writer.Close(); err != nil {
		return Bundle{}, err
	}
	return Bundle{Bytes: append([]byte(nil), output.Bytes()...), Members: members}, nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func redactionStatus(changed bool) string {
	if changed {
		return "applied"
	}
	return "not_required"
}
func writerRedactionStatus(changed bool) string {
	if changed {
		return "complete"
	}
	return "not_required"
}
