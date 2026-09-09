// Package recovery owns immutable failed-run inputs and accepted partial results.
// A recovery manifest grants replay authority, never final review publication.
package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const SchemaVersion = "mulgae-run-recovery.v1"
const SchemaURI = "https://mulgae.local/schemas/mulgae-run-recovery.v1.schema.json"

// Blob binds source-sized content without imposing a product byte ceiling.
type Blob struct {
	SHA256     string `json:"sha256"`
	ByteLength int64  `json:"byte_length"`
}

type Target struct {
	Kind              domain.TargetKind    `json:"kind"`
	SHA256            string               `json:"sha256"`
	RepositoryID      string               `json:"repository_id"`
	BaseObjectID      string               `json:"base_object_id"`
	HeadObjectID      string               `json:"head_object_id"`
	HeadTreeObjectID  string               `json:"head_tree_object_id"`
	IndexTreeObjectID string               `json:"index_tree_object_id"`
	GitMode           domain.GitTargetMode `json:"git_mode"`
	Bytes             Blob                 `json:"bytes"`
	CapturedArchive   Blob                 `json:"captured_archive"`
}

func (target Target) Identity() (domain.TargetIdentity, error) {
	return domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: target.Kind, SHA256: strings.TrimPrefix(target.SHA256, "sha256:"), RepositoryID: target.RepositoryID, BaseObjectID: target.BaseObjectID, HeadObjectID: target.HeadObjectID, HeadTreeObjectID: target.HeadTreeObjectID, IndexTreeObjectID: target.IndexTreeObjectID, GitMode: target.GitMode})
}

type Source struct {
	Kind                   string  `json:"kind"`
	RunID                  string  `json:"run_id"`
	ReviewID               *string `json:"review_id"`
	RecoveryManifestSHA256 *string `json:"recovery_manifest_sha256"`
	AttemptID              string  `json:"attempt_id"`
	ReplayMode             string  `json:"replay_mode"`
}

func (source Source) Reference() (domain.SourceReference, error) {
	run, err := domain.ParseRunID(source.RunID)
	if err != nil {
		return domain.SourceReference{}, err
	}
	if source.Kind == "published_review" && source.ReviewID != nil && source.RecoveryManifestSHA256 == nil {
		review, err := domain.ParseReviewID(*source.ReviewID)
		if err != nil {
			return domain.SourceReference{}, err
		}
		return domain.NewPublishedSourceReference(run, review)
	}
	if source.Kind == "failed_run_recovery" && source.ReviewID == nil && source.RecoveryManifestSHA256 != nil {
		return domain.NewRecoverySourceReference(run, *source.RecoveryManifestSHA256)
	}
	return domain.SourceReference{}, fmt.Errorf("recovery source: ambiguous identity")
}

type Prompt struct {
	Stdin                 Blob              `json:"stdin"`
	SourceInvocationID    string            `json:"source_invocation_id"`
	ExecutionInvocationID string            `json:"execution_invocation_id"`
	TemplateID            string            `json:"template_id"`
	TemplateVersion       string            `json:"template_version"`
	TemplateSHA256        string            `json:"template_sha256"`
	AdapterProfile        string            `json:"adapter_profile"`
	AdapterParameters     map[string]string `json:"adapter_parameters"`
	Scope                 string            `json:"scope"`
}

type Attempt struct {
	AttemptID        string              `json:"attempt_id"`
	Role             domain.Role         `json:"role"`
	ProviderInstance string              `json:"provider_instance"`
	State            domain.AttemptState `json:"state"`
	FailureClass     domain.FailureClass `json:"failure_class"`
	ReasonCode       string              `json:"reason_code"`
	InitialPrompt    Prompt              `json:"initial_prompt"`
}

type Role struct {
	Role             domain.Role `json:"role"`
	Required         bool        `json:"required"`
	Outcome          string      `json:"outcome"`
	AttemptID        string      `json:"attempt_id"`
	ProviderInstance string      `json:"provider_instance"`
	ReportsOnly      bool        `json:"reports_only"`
	Report           *Blob       `json:"report"`
	FindingIDs       []string    `json:"finding_ids"`
}

type Visual struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}
type Evidence struct {
	TargetSHA256  string        `json:"target_sha256"`
	Side          evidence.Side `json:"side"`
	Path          string        `json:"path"`
	LineStart     int           `json:"line_start"`
	LineEnd       int           `json:"line_end"`
	Quote         string        `json:"quote"`
	ExcerptSHA256 string        `json:"excerpt_sha256"`
	Visual        *Visual       `json:"visual"`
}
type Finding struct {
	ID               string                  `json:"id"`
	Fingerprint      string                  `json:"fingerprint"`
	Role             domain.Role             `json:"role"`
	ProviderInstance string                  `json:"provider_instance"`
	Severity         domain.Severity         `json:"severity"`
	Title            string                  `json:"title"`
	Description      string                  `json:"description"`
	Recommendation   string                  `json:"recommendation"`
	Confidence       domain.Confidence       `json:"confidence"`
	Lifecycle        domain.FindingLifecycle `json:"lifecycle"`
	Evidence         []Evidence              `json:"evidence"`
}

// Document is the bounded manifest. Provider content remains in hash-bound blobs.
type Document struct {
	SchemaVersion            string          `json:"schema_version"`
	SessionID                string          `json:"session_id"`
	RunID                    string          `json:"run_id"`
	RunType                  domain.RunType  `json:"run_type"`
	RunState                 domain.RunState `json:"run_state"`
	Threshold                domain.Severity `json:"threshold"`
	Source                   *Source         `json:"source"`
	Target                   Target          `json:"target"`
	SnapshotManifestSHA256   string          `json:"snapshot_manifest_sha256"`
	WorkspaceTerminalReceipt string          `json:"workspace_terminal_receipt"`
	Roles                    []Role          `json:"roles"`
	Attempts                 []Attempt       `json:"attempts"`
	Findings                 []Finding       `json:"findings"`
}

type Prepared struct {
	document Document
	blobs    map[string][]byte
}
type Snapshot struct {
	document Document
	blobs    map[string][]byte
	manifest []byte
}

func NewPrepared(ctx context.Context, document Document, blobs map[string][]byte) (Prepared, error) {
	if err := ctx.Err(); err != nil {
		return Prepared{}, err
	}
	if document.WorkspaceTerminalReceipt != "" {
		return Prepared{}, fmt.Errorf("recovery: closure must be supplied after preparation")
	}
	document.SchemaVersion = SchemaVersion
	if err := validate(ctx, document, blobs, false); err != nil {
		return Prepared{}, err
	}
	prepared := Prepared{cloneDocument(document), cloneBlobs(blobs)}
	if err := ctx.Err(); err != nil {
		return Prepared{}, err
	}
	return prepared, nil
}

// Seal requires the real successful workspace release and provider termination
// receipt for this run. It cannot authorize an ordinary final review.
func (prepared Prepared) Seal(ctx context.Context, receipt ports.WorkspaceTerminalReceipt) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if !receipt.Valid() || receipt.RunID() != prepared.document.RunID || receipt.WorkspaceSnapshotIdentity().ManifestSHA256() != prepared.document.SnapshotManifestSHA256 {
		return Snapshot{}, fmt.Errorf("recovery: complete matching cleanup receipt is required")
	}
	document := cloneDocument(prepared.document)
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	document.WorkspaceTerminalReceipt = receipt.ReceiptID()
	if err := validate(ctx, document, prepared.blobs, true); err != nil {
		return Snapshot{}, err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return Snapshot{}, err
	}
	blobs := cloneBlobs(prepared.blobs)
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{document, blobs, raw}, nil
}

func DecodeManifest(raw []byte) (Document, error) {
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, err
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Document{}, fmt.Errorf("recovery: manifest is not canonical")
	}
	if _, err := document.Target.Identity(); err != nil {
		return Document{}, err
	}
	return document, nil
}
func Restore(ctx context.Context, raw []byte, blobs map[string][]byte) (Snapshot, error) {
	document, err := DecodeManifest(raw)
	if err != nil {
		return Snapshot{}, err
	}
	if err := validate(ctx, document, blobs, true); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{document, cloneBlobs(blobs), append([]byte(nil), raw...)}, nil
}
func (snapshot Snapshot) Document() Document { return cloneDocument(snapshot.document) }
func (snapshot Snapshot) Manifest() []byte   { return append([]byte(nil), snapshot.manifest...) }
func (snapshot Snapshot) Blob(blob Blob) []byte {
	return append([]byte(nil), snapshot.blobs[blob.SHA256]...)
}
func (snapshot Snapshot) Reference() (domain.SourceReference, error) {
	run, err := domain.ParseRunID(snapshot.document.RunID)
	if err != nil {
		return domain.SourceReference{}, err
	}
	return domain.NewRecoverySourceReference(run, Digest(snapshot.manifest))
}
func Digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func AddBlob(blobs map[string][]byte, value []byte) Blob {
	identity := Blob{Digest(value), int64(len(value))}
	blobs[identity.SHA256] = append([]byte(nil), value...)
	return identity
}
func ManifestPath(run ports.PublicationRun) (ports.SafeRelativePath, error) {
	return ports.NewSafeRelativePath(run.SessionID().String() + "/" + run.RunID().String() + "/recovery/manifest.json")
}
func BlobPath(run ports.PublicationRun, blob Blob) (ports.SafeRelativePath, error) {
	if !validDigest(blob.SHA256) {
		return ports.SafeRelativePath{}, fmt.Errorf("recovery: invalid blob digest")
	}
	return ports.NewSafeRelativePath(run.SessionID().String() + "/" + run.RunID().String() + "/recovery/blobs/sha256-" + strings.TrimPrefix(blob.SHA256, "sha256:"))
}
func (document Document) Blobs() []Blob {
	byHash := map[string]Blob{document.Target.Bytes.SHA256: document.Target.Bytes, document.Target.CapturedArchive.SHA256: document.Target.CapturedArchive}
	for _, attempt := range document.Attempts {
		byHash[attempt.InitialPrompt.Stdin.SHA256] = attempt.InitialPrompt.Stdin
	}
	for _, role := range document.Roles {
		if role.Report != nil {
			byHash[role.Report.SHA256] = *role.Report
		}
	}
	result := make([]Blob, 0, len(byHash))
	for _, blob := range byHash {
		result = append(result, blob)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SHA256 < result[j].SHA256 })
	return result
}
func cloneDocument(document Document) Document {
	raw, _ := json.Marshal(document)
	var result Document
	_ = json.Unmarshal(raw, &result)
	return result
}
func cloneBlobs(blobs map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(blobs))
	for key, value := range blobs {
		result[key] = append([]byte(nil), value...)
	}
	return result
}
func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	digest := strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32 && strings.ToLower(digest) == digest
}
func safeText(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r")
}
