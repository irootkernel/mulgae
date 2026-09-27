// Package compositesupport owns portable, self-contained composite provenance.
package compositesupport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/capture"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const Version = "mulgae-composite-support.v1"
const DocumentPath = "support/composite.json"

// Source is portable provenance, deliberately excluding local project binding.
// Failed recovery sources have a manifest digest, not a P2 receipt.
type Source struct {
	Role                   domain.Role `json:"role"`
	SessionID              string      `json:"session_id"`
	RunID                  string      `json:"run_id"`
	ReviewID               string      `json:"review_id"`
	AttemptID              string      `json:"attempt_id"`
	RecoveryManifestSHA256 string      `json:"recovery_manifest_sha256"`
	FinalSHA256            string      `json:"final_sha256"`
	ManifestSHA256         string      `json:"manifest_sha256"`
	SupportSHA256          string      `json:"support_sha256"`
	LineageSHA256          string      `json:"lineage_sha256"`
	Epoch                  uint64      `json:"epoch"`
	TargetSHA256           string      `json:"target_sha256"`
	ProviderIdentities     []string    `json:"provider_identities"`
	CaptureIdentity        string      `json:"capture_identity"`
	CaptureAvailability    string      `json:"capture_availability"`
}

type Evidence struct {
	Index         int           `json:"index"`
	Availability  string        `json:"availability"`
	TargetSHA256  string        `json:"target_sha256"`
	Side          evidence.Side `json:"side"`
	Path          string        `json:"path"`
	LineStart     int           `json:"line_start"`
	LineEnd       int           `json:"line_end"`
	ExcerptSHA256 string        `json:"excerpt_sha256"`
	ContentSHA256 string        `json:"content_sha256"`
}

type Finding struct {
	ID              string      `json:"id"`
	Role            domain.Role `json:"role"`
	SourceFindingID string      `json:"source_finding_id"`
	OriginalSHA256  string      `json:"original_sha256"`
	Evidence        []Evidence  `json:"evidence"`
}

type Document struct {
	SchemaVersion string    `json:"schema_version"`
	Sources       []Source  `json:"sources"`
	Findings      []Finding `json:"findings"`
}

// Material is collected while the source is independently verified. IDs in its
// findings are remapped before it crosses the publication boundary.
type Material struct {
	Source          Source
	CaptureManifest []byte
	CapturedArchive []byte
	Findings        []FindingMaterial
}

type FindingMaterial struct {
	Finding  Finding
	Original []byte
	Excerpts [][]byte
}

func Clone(material Material) Material {
	material.Source.ProviderIdentities = append([]string(nil), material.Source.ProviderIdentities...)
	material.CaptureManifest = bytes.Clone(material.CaptureManifest)
	material.CapturedArchive = bytes.Clone(material.CapturedArchive)
	material.Findings = append([]FindingMaterial(nil), material.Findings...)
	for i := range material.Findings {
		f := &material.Findings[i]
		f.Finding.Evidence = append([]Evidence(nil), f.Finding.Evidence...)
		f.Original = bytes.Clone(f.Original)
		f.Excerpts = append([][]byte(nil), f.Excerpts...)
		for j := range f.Excerpts {
			f.Excerpts[j] = bytes.Clone(f.Excerpts[j])
		}
	}
	return material
}

func SHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func SourcePrefix(role domain.Role) string { return "support/sources/" + string(role) + "/target/" }
func FindingPath(id string) string         { return "support/findings/" + id + ".json" }
func ExcerptPath(id string, index int) string {
	return fmt.Sprintf("excerpts/%s_%d.md", id, index+1)
}

func Build(session domain.SessionID, run domain.RunID, materials []Material) ([]ports.ImmutablePublicationArtifact, error) {
	if len(materials) == 0 {
		return nil, fmt.Errorf("composite sources absent")
	}
	prefix := session.String() + "/" + run.String() + "/"
	doc := Document{SchemaVersion: Version, Sources: []Source{}, Findings: []Finding{}}
	artifacts := []ports.ImmutablePublicationArtifact{}
	add := func(relative string, raw []byte) error {
		path, err := ports.NewSafeRelativePath(prefix + relative)
		if err != nil {
			return err
		}
		a, err := ports.NewImmutablePublicationArtifact(path, SHA256(raw), raw)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, a)
		return nil
	}
	for _, material := range materials {
		doc.Sources = append(doc.Sources, material.Source)
		if material.Source.CaptureAvailability == "verified" {
			if err := add(SourcePrefix(material.Source.Role)+"capture-manifest.json", material.CaptureManifest); err != nil {
				return nil, err
			}
			captured, err := ports.UnmarshalCapturedReviewMaterial(material.CapturedArchive)
			if err != nil {
				return nil, err
			}
			archive, err := ports.NewCapturedReviewArchive(captured)
			if err != nil {
				return nil, err
			}
			if err = add(SourcePrefix(material.Source.Role)+"captured-review.json", archive.Manifest()); err != nil {
				return nil, err
			}
			for _, blob := range archive.Blobs() {
				if err = add(SourcePrefix(material.Source.Role)+blob.Path().String(), blob.Bytes()); err != nil {
					return nil, err
				}
			}
		} else if len(material.CaptureManifest) != 0 || len(material.CapturedArchive) != 0 {
			return nil, fmt.Errorf("unavailable source has capture material")
		}
		for _, item := range material.Findings {
			if item.Finding.Evidence == nil {
				item.Finding.Evidence = []Evidence{}
			}
			doc.Findings = append(doc.Findings, item.Finding)
			if len(item.Excerpts) != len(item.Finding.Evidence) {
				return nil, fmt.Errorf("evidence inventory differs")
			}
			if err := add(FindingPath(item.Finding.ID), item.Original); err != nil {
				return nil, err
			}
			for i, e := range item.Finding.Evidence {
				if e.Availability == "verified" {
					if err := add(ExcerptPath(item.Finding.ID, i), item.Excerpts[i]); err != nil {
						return nil, err
					}
				} else if len(item.Excerpts[i]) != 0 {
					return nil, fmt.Errorf("unavailable evidence has bytes")
				}
			}
		}
	}
	sort.Slice(doc.Sources, func(i, j int) bool { return roleIndex(doc.Sources[i].Role) < roleIndex(doc.Sources[j].Role) })
	sort.Slice(doc.Findings, func(i, j int) bool { return doc.Findings[i].ID < doc.Findings[j].ID })
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if err = add(DocumentPath, append(raw, '\n')); err != nil {
		return nil, err
	}
	byPath := map[string]ports.ImmutablePublicationArtifact{}
	for _, a := range artifacts {
		if _, ok := byPath[a.Path().String()]; ok {
			return nil, fmt.Errorf("duplicate composite support")
		}
		byPath[a.Path().String()] = a
	}
	if _, err = Verify(session, run, doc.Sources[0].TargetSHA256, byPath); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func Decode(raw []byte) (Document, error) {
	var doc Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return doc, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return doc, fmt.Errorf("composite support trailing data")
	}
	canonical, err := json.Marshal(doc)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, raw) != nil || !bytes.Equal(compact.Bytes(), canonical) {
		return doc, fmt.Errorf("composite support is not canonical")
	}
	return doc, nil
}

func roleIndex(role domain.Role) int {
	for i, r := range domain.FixedRoleOrder() {
		if r == role {
			return i
		}
	}
	return -1
}
func validDigest(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 71 {
		return false
	}
	b, err := hex.DecodeString(s[7:])
	return err == nil && len(b) == 32 && strings.ToLower(s) == s
}
func validFindingID(s string) bool {
	if len(s) < 4 || len(s) > 64 || s[0] != 'F' {
		return false
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Verify checks every copied byte and reconstructs each advertised capture. The
// caller additionally compares this document with its final finding/source map.
func Verify(session domain.SessionID, run domain.RunID, target string, artifacts map[string]ports.ImmutablePublicationArtifact) (Document, error) {
	prefix := session.String() + "/" + run.String() + "/"
	for path, artifact := range artifacts {
		if !artifact.Valid() || artifact.Path().String() != path {
			return Document{}, fmt.Errorf("composite support artifact identity invalid")
		}
	}
	artifact, ok := artifacts[prefix+DocumentPath]
	if !ok {
		return Document{}, fmt.Errorf("composite support absent")
	}
	doc, err := Decode(artifact.Bytes())
	if err != nil {
		return doc, err
	}
	if doc.SchemaVersion != Version || len(doc.Sources) == 0 || len(doc.Sources) > len(domain.FixedRoleOrder()) || doc.Findings == nil || len(doc.Findings) > 999 {
		return doc, fmt.Errorf("composite support inventory invalid")
	}
	expected := map[string]bool{prefix + DocumentPath: true}
	sources := map[domain.Role]Source{}
	last := -1
	for _, s := range doc.Sources {
		if !s.Role.Valid() || roleIndex(s.Role) <= last || s.TargetSHA256 != target || !validDigest(target) {
			return doc, fmt.Errorf("composite source selection invalid")
		}
		last = roleIndex(s.Role)
		if _, err := domain.ParseSessionID(s.SessionID); err != nil {
			return doc, err
		}
		if _, err := domain.ParseRunID(s.RunID); err != nil {
			return doc, err
		}
		if _, err := domain.ParseAttemptID(s.AttemptID); err != nil {
			return doc, err
		}
		if s.RecoveryManifestSHA256 != "" {
			if !validDigest(s.RecoveryManifestSHA256) || s.ReviewID != "" || s.FinalSHA256 != "" || s.ManifestSHA256 != "" || s.SupportSHA256 != "" || s.LineageSHA256 != "" || s.Epoch != 0 {
				return doc, fmt.Errorf("recovery source claims publication")
			}
		} else {
			if _, err := domain.ParseReviewID(s.ReviewID); err != nil {
				return doc, err
			}
			if !validDigest(s.FinalSHA256) || !validDigest(s.ManifestSHA256) || !validDigest(s.SupportSHA256) || !validDigest(s.LineageSHA256) || s.Epoch == 0 {
				return doc, fmt.Errorf("source publication receipt incomplete")
			}
		}
		if len(s.ProviderIdentities) == 0 || !sort.StringsAreSorted(s.ProviderIdentities) {
			return doc, fmt.Errorf("source provider provenance absent")
		}
		for i, p := range s.ProviderIdentities {
			if strings.TrimSpace(p) == "" || i > 0 && p == s.ProviderIdentities[i-1] {
				return doc, fmt.Errorf("source provider provenance invalid")
			}
		}
		sourcePrefix := prefix + SourcePrefix(s.Role)
		switch s.CaptureAvailability {
		case "verified":
			m, ok := artifacts[sourcePrefix+"capture-manifest.json"]
			if !ok {
				return doc, fmt.Errorf("source capture manifest absent")
			}
			manifest, err := capture.DecodeCaptureManifest(m.Bytes())
			if err != nil {
				return doc, err
			}
			var base, head *string
			if manifest.Target.BaseObjectID != "" {
				base = &manifest.Target.BaseObjectID
			}
			if manifest.Target.HeadObjectID != "" {
				head = &manifest.Target.HeadObjectID
			}
			id, err := capture.VerifySupportAt(sourcePrefix, target, base, head, artifacts)
			if err != nil {
				return doc, fmt.Errorf("source capture verification failed: %w", err)
			}
			if id.String() != s.CaptureIdentity {
				return doc, fmt.Errorf("source capture identity differs")
			}
			expected[sourcePrefix+"capture-manifest.json"] = true
			expected[sourcePrefix+"captured-review.json"] = true
			refs, err := ports.CapturedReviewArchiveBlobReferences(artifacts[sourcePrefix+"captured-review.json"].Bytes())
			if err != nil {
				return doc, err
			}
			for _, ref := range refs {
				expected[sourcePrefix+ref.Path().String()] = true
			}
		case "capture_identity_unavailable":
			if s.CaptureIdentity != "" {
				return doc, fmt.Errorf("unavailable capture has identity")
			}
		default:
			return doc, fmt.Errorf("source capture availability invalid")
		}
		sources[s.Role] = s
	}
	lastID := ""
	for _, f := range doc.Findings {
		if !validFindingID(f.ID) || f.ID <= lastID || !validFindingID(f.SourceFindingID) || f.Evidence == nil || len(f.Evidence) > 20 {
			return doc, fmt.Errorf("composite finding inventory invalid")
		}
		lastID = f.ID
		if _, ok := sources[f.Role]; !ok {
			return doc, fmt.Errorf("finding role absent")
		}
		path := prefix + FindingPath(f.ID)
		original, ok := artifacts[path]
		if !ok || original.SHA256() != f.OriginalSHA256 || !json.Valid(original.Bytes()) {
			return doc, fmt.Errorf("original finding binding invalid")
		}
		expected[path] = true
		var originalID struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(original.Bytes(), &originalID) != nil || originalID.ID != f.SourceFindingID {
			return doc, fmt.Errorf("source finding ID differs")
		}
		for i, e := range f.Evidence {
			if e.Index != i || e.TargetSHA256 != target {
				return doc, fmt.Errorf("evidence index or target invalid")
			}
			if !e.Side.Valid() || e.LineStart < 1 || e.LineEnd < e.LineStart || !validDigest(e.ExcerptSHA256) {
				return doc, fmt.Errorf("evidence claim invalid")
			}
			if _, err := ports.NewSafeRelativePath(e.Path); err != nil {
				return doc, err
			}
			path := prefix + ExcerptPath(f.ID, i)
			switch e.Availability {
			case "verified":
				a, ok := artifacts[path]
				if !ok || a.SHA256() != e.ContentSHA256 {
					return doc, fmt.Errorf("copied evidence absent or corrupt")
				}
				claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{TargetSHA256: e.TargetSHA256, Side: e.Side, Path: e.Path, LineStart: e.LineStart, LineEnd: e.LineEnd, Quote: string(a.Bytes())})
				if err != nil {
					return doc, err
				}
				hash, err := claim.ExcerptSHA256(a.Bytes())
				if err != nil || hash != e.ExcerptSHA256 {
					return doc, fmt.Errorf("copied evidence identity differs")
				}
				expected[path] = true
			case "evidence_unavailable":
				if e.ContentSHA256 != "" {
					return doc, fmt.Errorf("unavailable evidence has content identity")
				}
			default:
				return doc, fmt.Errorf("evidence availability invalid")
			}
		}
	}
	for path := range artifacts {
		if strings.HasPrefix(path, prefix+"support/sources/") || strings.HasPrefix(path, prefix+"support/findings/") || path == prefix+DocumentPath || strings.HasPrefix(path, prefix+"excerpts/") {
			if !expected[path] {
				return doc, fmt.Errorf("unlisted composite support artifact")
			}
		}
	}
	return doc, nil
}

func (doc Document) CommonCapture() string {
	common := ""
	for _, s := range doc.Sources {
		if s.CaptureAvailability != "verified" || s.CaptureIdentity == "" {
			return ""
		}
		if common == "" {
			common = s.CaptureIdentity
		} else if common != s.CaptureIdentity {
			return ""
		}
	}
	return common
}

// RetainCapture reconstructs historical material only when all required sides
// are present; partial legacy archives stay explicitly unavailable.
func RetainCapture(material *Material, raw []byte) error {
	material.Source.CaptureAvailability = "capture_identity_unavailable"
	if len(raw) == 0 {
		return nil
	}
	captured, err := ports.UnmarshalCapturedReviewMaterial(raw)
	if err != nil {
		return err
	}
	manifest, err := capture.NewCaptureManifest(captured)
	if errors.Is(err, capture.ErrCaptureIdentityUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	id, err := manifest.Identity()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	material.CaptureManifest = append(encoded, '\n')
	material.CapturedArchive = bytes.Clone(raw)
	material.Source.CaptureIdentity = id.String()
	material.Source.CaptureAvailability = "verified"
	return nil
}
