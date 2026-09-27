package reviewrun

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const CaptureManifestVersion = "mulgae-capture-manifest.v1"

var ErrCaptureIdentityUnavailable = errors.New("capture_identity_unavailable")

// CaptureManifest is canonical verification support, not a publication or an
// assertion that a stored digest has been verified. NewCaptureManifest derives
// it from admitted immutable material; VerifyCaptureManifest checks that material.
type CaptureManifest struct {
	SchemaVersion  string         `json:"schema_version"`
	Target         CaptureTarget  `json:"target"`
	PolicyIdentity string         `json:"policy_identity"`
	Sides          []string       `json:"sides"`
	Files          []CaptureFile  `json:"files"`
	Context        CaptureContext `json:"context"`
}

type CaptureTarget struct {
	Kind              string `json:"kind"`
	GitMode           string `json:"git_mode"`
	SHA256            string `json:"sha256"`
	Size              int64  `json:"size"`
	BaseObjectID      string `json:"base_object_id"`
	HeadObjectID      string `json:"head_object_id"`
	HeadTreeObjectID  string `json:"head_tree_object_id"`
	IndexTreeObjectID string `json:"index_tree_object_id"`
}

type CaptureFile struct {
	Side        string `json:"side"`
	Path        string `json:"path"`
	MediaType   string `json:"media_type"`
	Disposition string `json:"disposition"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

type CaptureContext struct {
	Present bool   `json:"present"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

func NewCaptureManifest(material ports.CapturedReviewMaterial) (CaptureManifest, error) {
	if !material.Valid() {
		return CaptureManifest{}, fmt.Errorf("capture manifest: invalid material")
	}
	target := material.Target().Identity()
	manifest := CaptureManifest{
		SchemaVersion:  CaptureManifestVersion,
		Target:         CaptureTarget{string(target.Kind()), string(target.GitMode()), "sha256:" + target.SHA256(), int64(len(material.Target().Bytes())), target.BaseObjectID(), target.HeadObjectID(), target.HeadTreeObjectID(), target.IndexTreeObjectID()},
		PolicyIdentity: material.Snapshot().PolicyIdentity(),
		Sides:          []string{}, Files: []CaptureFile{},
		Context: CaptureContext{Present: material.HasProjectContext()},
	}
	if manifest.Context.Present {
		manifest.Context.Size = int64(len(material.ProjectContext()))
		manifest.Context.SHA256 = identitySHA256(material.ProjectContext())
	}
	appendFiles := func(side string, files []ports.WorkspaceSnapshotFile) {
		manifest.Sides = append(manifest.Sides, side)
		for _, file := range files {
			disposition := "text"
			if !file.IsText() {
				disposition = "binary_preserved"
			}
			manifest.Files = append(manifest.Files, CaptureFile{side, file.Path().String(), file.MediaType(), disposition, int64(len(file.Bytes())), file.SHA256()})
		}
	}
	for _, side := range []ports.CapturedEvidenceSide{ports.CapturedEvidenceBase, ports.CapturedEvidenceHead, ports.CapturedEvidenceIndex} {
		if files, present := material.Evidence().Files(side); present {
			appendFiles(string(side), files)
		}
	}
	appendFiles("snapshot", material.Snapshot().Files())
	if files, present := material.Evidence().Files(ports.CapturedEvidenceWorktree); present {
		appendFiles("worktree", files)
	}
	if !manifest.completeSides() {
		return CaptureManifest{}, ErrCaptureIdentityUnavailable
	}
	if err := manifest.Validate(); err != nil {
		return CaptureManifest{}, err
	}
	return manifest, nil
}

func (manifest CaptureManifest) completeSides() bool {
	has := func(side string) bool { return slices.Contains(manifest.Sides, side) }
	if !has("snapshot") {
		return false
	}
	switch domain.TargetKind(manifest.Target.Kind) {
	case domain.TargetGit:
		if manifest.Target.GitMode == string(domain.GitTargetStage) && manifest.Target.IndexTreeObjectID == "" {
			return false
		}
		after := "head"
		if manifest.Target.GitMode == string(domain.GitTargetDirty) {
			after = "worktree"
		} else if manifest.Target.GitMode == string(domain.GitTargetStage) || manifest.Target.IndexTreeObjectID != "" {
			after = "index"
		}
		return has("base") && has(after)
	case domain.TargetWorkspace:
		return has("worktree")
	case domain.TargetPatch, domain.TargetStdin:
		return has("head")
	default:
		return false
	}
}

func (manifest CaptureManifest) Validate() error {
	invalid := func() error { return fmt.Errorf("capture manifest: invalid canonical support") }
	if manifest.SchemaVersion != CaptureManifestVersion || manifest.PolicyIdentity == "" || !utf8.ValidString(manifest.PolicyIdentity) || strings.ContainsRune(manifest.PolicyIdentity, 0) || manifest.Files == nil || !manifest.completeSides() {
		return invalid()
	}
	target := manifest.Target
	repository := ""
	if target.Kind == string(domain.TargetGit) {
		repository = "capture"
	}
	_, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetKind(target.Kind), SHA256: strings.TrimPrefix(target.SHA256, "sha256:"), RepositoryID: repository, GitMode: domain.GitTargetMode(target.GitMode), BaseObjectID: target.BaseObjectID, HeadObjectID: target.HeadObjectID, HeadTreeObjectID: target.HeadTreeObjectID, IndexTreeObjectID: target.IndexTreeObjectID})
	if err != nil || !identityDigestValid(target.SHA256) || target.Size < 0 || (target.Kind != string(domain.TargetGit) && target.Size == 0) || (target.Size == 0 && target.SHA256 != identitySHA256(nil)) {
		return invalid()
	}
	if target.Kind == string(domain.TargetGit) && !domain.GitTargetMode(target.GitMode).Valid() {
		return invalid()
	}
	previousSide := ""
	for _, side := range manifest.Sides {
		if side <= previousSide || (side != "snapshot" && !ports.CapturedEvidenceSide(side).Valid()) {
			return invalid()
		}
		previousSide = side
	}
	previous := ""
	folded := make(map[string]bool, len(manifest.Files))
	for _, file := range manifest.Files {
		key := file.Side + "/" + file.Path
		if key <= previous || !slices.Contains(manifest.Sides, file.Side) {
			return invalid()
		}
		if _, err := ports.NewSafeRelativePath(file.Path); err != nil || !utf8.ValidString(file.Path) {
			return invalid()
		}
		if _, err := ports.NewContentIdentity(file.SHA256, file.Size, file.MediaType); err != nil {
			return invalid()
		}
		if file.Size == 0 && file.SHA256 != identitySHA256(nil) {
			return invalid()
		}
		if file.Disposition != "text" && file.Disposition != "binary_preserved" {
			return invalid()
		}
		if (file.MediaType == "text/plain") != (file.Disposition == "text") {
			return invalid()
		}
		if !slices.Contains([]string{"text/plain", "application/octet-stream", "image/png", "image/jpeg", "image/webp"}, file.MediaType) {
			return invalid()
		}
		if folded[strings.ToLower(key)] {
			return invalid()
		}
		folded[strings.ToLower(key)] = true
		previous = key
	}
	for key := range folded {
		for parent := key; strings.Contains(parent, "/"); {
			parent = parent[:strings.LastIndexByte(parent, '/')]
			if folded[parent] {
				return invalid()
			}
		}
	}
	context := manifest.Context
	if context.Size < 0 || (!context.Present && (context.Size != 0 || context.SHA256 != "")) || (context.Present && (!identityDigestValid(context.SHA256) || (context.Size == 0 && context.SHA256 != identitySHA256(nil)))) {
		return invalid()
	}
	return nil
}

func (manifest CaptureManifest) CanonicalBytes() ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

func (manifest CaptureManifest) Identity() (domain.CaptureIdentity, error) {
	data, err := manifest.CanonicalBytes()
	if err != nil {
		return domain.CaptureIdentity{}, err
	}
	return domain.ParseCaptureIdentity(identitySHA256(append([]byte(CaptureManifestVersion+"\x00"), data...)))
}

// DecodeCaptureManifest admits only canonical field, number and array encoding
// (insignificant JSON whitespace is allowed). This rejects duplicate/unknown or
// omitted fields instead of letting a permissive decoder erase them.
func DecodeCaptureManifest(data []byte) (CaptureManifest, error) {
	var manifest CaptureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return CaptureManifest{}, fmt.Errorf("capture manifest: invalid JSON")
	}
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		return CaptureManifest{}, err
	}
	var compact bytes.Buffer
	if json.Compact(&compact, data) != nil || !bytes.Equal(canonical, compact.Bytes()) {
		return CaptureManifest{}, fmt.Errorf("capture manifest: noncanonical encoding")
	}
	return manifest, nil
}

// VerifyCaptureManifest requires the complete hash-verified retained archive;
// neither a stored digest nor current-tree content can stand in for it.
func VerifyCaptureManifest(data []byte, material ports.CapturedReviewMaterial, expected domain.CaptureIdentity) error {
	stored, err := DecodeCaptureManifest(data)
	if err != nil {
		return err
	}
	actual, err := NewCaptureManifest(material)
	if err != nil {
		return fmt.Errorf("capture manifest: retained material cannot verify bound support: %v", err)
	}
	want, err := actual.Identity()
	if err != nil {
		return err
	}
	got, err := stored.Identity()
	if err != nil || !expected.Valid() || want != expected || got != expected {
		return fmt.Errorf("capture manifest: integrity mismatch")
	}
	return nil
}

func identitySHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func identityDigestValid(value string) bool {
	_, err := domain.ParseCaptureIdentity(value)
	return err == nil
}
