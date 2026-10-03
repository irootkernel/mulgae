package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const LiveSourceIdentityVersion = "mulgae-live-source.v1"

// LiveSourceIdentity binds the declared selector and resolved Git operands. It
// does not identify workspace or index contents, an inventory, or a snapshot.
type LiveSourceIdentity struct {
	target ports.LiveSourceTarget
	bytes  []byte
	sha256 string
}

type liveSourceWire struct {
	SchemaVersion string                 `json:"schema_version"`
	Scope         domain.LiveSourceScope `json:"scope"`
	Operand       string                 `json:"operand"`
	BaseOID       string                 `json:"base_oid"`
	HeadOID       string                 `json:"head_oid"`
	EmptyBase     bool                   `json:"empty_base"`
}

func NewLiveSourceIdentity(target ports.LiveSourceTarget) (LiveSourceIdentity, error) {
	// Candidate paths are an observation, not part of the source identity.
	identityTarget, err := ports.NewLiveSourceTarget(target.Selector(), target.Base(), target.Head(), target.EmptyBase(), nil)
	if err != nil {
		return LiveSourceIdentity{}, fmt.Errorf("live source identity: %w", err)
	}
	data, err := json.Marshal(liveSourceWire{
		SchemaVersion: LiveSourceIdentityVersion, Scope: target.Selector().Scope(),
		Operand: target.Selector().Value(), BaseOID: target.Base().String(),
		HeadOID: target.Head().String(), EmptyBase: target.EmptyBase(),
	})
	if err != nil {
		return LiveSourceIdentity{}, fmt.Errorf("live source identity: %w", err)
	}
	digest := sha256.Sum256(data)
	return LiveSourceIdentity{target: identityTarget, bytes: data, sha256: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

// DecodeLiveSourceIdentity accepts only the exact canonical metadata encoding.
func DecodeLiveSourceIdentity(data []byte) (LiveSourceIdentity, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire liveSourceWire
	if err := decoder.Decode(&wire); err != nil {
		return LiveSourceIdentity{}, fmt.Errorf("live source identity: decode: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF || wire.SchemaVersion != LiveSourceIdentityVersion {
		return LiveSourceIdentity{}, fmt.Errorf("live source identity: invalid version or trailing value")
	}
	selector, err := ports.NewLiveSourceSelector(wire.Scope, wire.Operand)
	if err != nil {
		return LiveSourceIdentity{}, fmt.Errorf("live source identity: %w", err)
	}
	var base, head ports.GitObjectID
	if wire.BaseOID != "" {
		base, err = ports.ParseGitObjectID(wire.BaseOID)
		if err != nil {
			return LiveSourceIdentity{}, fmt.Errorf("live source identity: base: %w", err)
		}
	}
	if wire.HeadOID != "" {
		head, err = ports.ParseGitObjectID(wire.HeadOID)
		if err != nil {
			return LiveSourceIdentity{}, fmt.Errorf("live source identity: head: %w", err)
		}
	}
	target, err := ports.NewLiveSourceTarget(selector, base, head, wire.EmptyBase, nil)
	if err != nil {
		return LiveSourceIdentity{}, err
	}
	identity, err := NewLiveSourceIdentity(target)
	if err != nil || !bytes.Equal(identity.bytes, data) {
		return LiveSourceIdentity{}, fmt.Errorf("live source identity: noncanonical metadata")
	}
	return identity, nil
}

func (identity LiveSourceIdentity) Valid() bool {
	return identity.sha256 != "" && len(identity.bytes) != 0
}
func (identity LiveSourceIdentity) SHA256() string                 { return identity.sha256 }
func (identity LiveSourceIdentity) Bytes() []byte                  { return append([]byte(nil), identity.bytes...) }
func (identity LiveSourceIdentity) Target() ports.LiveSourceTarget { return identity.target }

// RunTarget preserves the distinction between selection and content identity.
func (identity LiveSourceIdentity) RunTarget() (domain.TargetIdentity, error) {
	if !identity.Valid() {
		return domain.TargetIdentity{}, fmt.Errorf("live source identity: invalid run target")
	}
	return domain.NewLiveTargetIdentity(identity.SHA256()[len("sha256:"):], identity.target.Base().String(), identity.target.Head().String())
}

// SupportsSide rejects sides that do not belong to this declared selector.
func (identity LiveSourceIdentity) SupportsSide(side Side) bool {
	if !identity.Valid() || side == SideBase && identity.Target().EmptyBase() {
		return false
	}
	_, err := liveEvidenceSide(identity.Target().Selector().Scope(), side)
	return err == nil
}

// NewLiveClaim binds a provider location/quote to trusted source metadata. The
// digest asserts source selection, never the contents of a mutable source.
func NewLiveClaim(identity LiveSourceIdentity, side Side, path string, lineStart, lineEnd int, quote string) (CurrentClaim, error) {
	if !identity.Valid() {
		return CurrentClaim{}, fmt.Errorf("live evidence claim: invalid source identity")
	}
	claim, err := NewCurrentClaim(CurrentClaimInput{
		TargetSHA256: identity.SHA256(), Side: side, Path: path,
		LineStart: lineStart, LineEnd: lineEnd, Quote: quote,
	})
	if err != nil {
		return CurrentClaim{}, err
	}
	claim.liveSource = true
	return claim, nil
}

// NewLiveVerifier reads the original source through the source-reader port. It
// owns no source copy and makes no immutable-tree or mutable-drift assertion.
func NewLiveVerifier(reader ports.LiveSourceReader) (*Verifier, error) {
	if nilLiveReader(reader) {
		return nil, fmt.Errorf("live evidence verifier: nil source reader")
	}
	identity, err := NewLiveSourceIdentity(reader.Target())
	if err != nil {
		return nil, err
	}
	return &Verifier{liveReader: reader, liveIdentity: identity}, nil
}

func nilLiveReader(reader ports.LiveSourceReader) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func (verifier *Verifier) readLive(ctx context.Context, claim CurrentClaim) ([]byte, error) {
	if !claim.liveSource || claim.targetSHA256 != verifier.liveIdentity.SHA256() {
		return nil, fmt.Errorf("live evidence verification: source identity mismatch")
	}
	side, err := liveEvidenceSide(verifier.liveIdentity.Target().Selector().Scope(), claim.side)
	if err != nil {
		return nil, err
	}
	file, err := verifier.liveReader.Read(ctx, side, claim.path)
	if err != nil {
		return nil, err
	}
	if file.Path() != claim.path || !file.IsText() {
		return nil, ports.NewLiveSourceError(ports.LiveSourceUnsupported, nil)
	}
	return file.Bytes(), nil
}

func liveEvidenceSide(scope domain.LiveSourceScope, side Side) (domain.LiveSourceSide, error) {
	switch {
	case side == SideWorktree && scope == domain.LiveSourceWorkspace:
		return domain.LiveSourceWorktree, nil
	case side == SideIndex && scope == domain.LiveSourceStage:
		return domain.LiveSourceIndex, nil
	case side == SideBase && (scope == domain.LiveSourceStage || scope == domain.LiveSourceCommit || scope == domain.LiveSourceDiff):
		return domain.LiveSourceBefore, nil
	case side == SideHead && (scope == domain.LiveSourceHead || scope == domain.LiveSourceCommit || scope == domain.LiveSourceDiff):
		return domain.LiveSourceAfter, nil
	default:
		return "", ports.NewLiveSourceError(ports.LiveSourceInvalid, nil)
	}
}

// LiveBinaryReceipt retains one explicitly selected raster observation. The
// source digest is metadata identity; FileSHA256 hashes only these image bytes.
type LiveBinaryReceipt struct {
	source LiveSourceIdentity
	side   Side
	file   ports.LiveSourceFile
}

func (receipt LiveBinaryReceipt) Source() LiveSourceIdentity   { return receipt.source }
func (receipt LiveBinaryReceipt) Side() Side                   { return receipt.side }
func (receipt LiveBinaryReceipt) Path() ports.SafeRelativePath { return receipt.file.Path() }
func (receipt LiveBinaryReceipt) FileSHA256() string           { return receipt.file.SHA256() }
func (receipt LiveBinaryReceipt) MediaType() string            { return receipt.file.MediaType() }
func (receipt LiveBinaryReceipt) Bytes() []byte                { return receipt.file.Bytes() }
func (receipt LiveBinaryReceipt) Valid() bool {
	return receipt.source.Valid() && receipt.source.SupportsSide(receipt.side) && receipt.file.Path().Valid() &&
		(receipt.file.MediaType() == "image/png" || receipt.file.MediaType() == "image/jpeg" || receipt.file.MediaType() == "image/webp")
}

// VerifyBinary reads selected image evidence. Its verifier-owned receipt binds
// the exact bytes and source side; caller- or provider-created digests are not proof.
func (verifier *Verifier) VerifyBinary(ctx context.Context, side Side, path ports.SafeRelativePath, expectedSHA256 string) (LiveBinaryReceipt, error) {
	if verifier == nil || nilLiveReader(verifier.liveReader) || !verifier.liveIdentity.Valid() || ctx == nil || !path.Valid() {
		return LiveBinaryReceipt{}, fmt.Errorf("live binary evidence: invalid verifier, context or path")
	}
	if err := ctx.Err(); err != nil {
		return LiveBinaryReceipt{}, err
	}
	liveSide, err := liveEvidenceSide(verifier.liveIdentity.Target().Selector().Scope(), side)
	if err != nil {
		return LiveBinaryReceipt{}, err
	}
	file, err := verifier.liveReader.Read(ctx, liveSide, path)
	if err != nil {
		return LiveBinaryReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return LiveBinaryReceipt{}, err
	}
	receipt := LiveBinaryReceipt{source: verifier.liveIdentity, side: side, file: file}
	if !receipt.Valid() || file.Path() != path || file.SHA256() != expectedSHA256 {
		return LiveBinaryReceipt{}, fmt.Errorf("live binary evidence: unsupported or mismatched image")
	}
	return receipt, nil
}
