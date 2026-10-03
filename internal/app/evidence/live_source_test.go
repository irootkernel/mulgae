package evidence

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type liveEvidenceReader struct {
	target ports.LiveSourceTarget
	files  map[domain.LiveSourceSide]ports.LiveSourceFile
	err    error
	calls  int
	closed bool
}

type reboundLiveEvidenceReader struct {
	*liveEvidenceReader
	file ports.LiveSourceFile
}

func (reader reboundLiveEvidenceReader) Read(context.Context, domain.LiveSourceSide, ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	return reader.file, nil
}

func (reader *liveEvidenceReader) Root() ports.AnchoredRoot       { return ports.AnchoredRoot{} }
func (reader *liveEvidenceReader) Target() ports.LiveSourceTarget { return reader.target }
func (reader *liveEvidenceReader) RevalidateExecution(context.Context) (ports.ProjectBindingObservation, error) {
	return ports.ProjectBindingObservation{}, reader.err
}
func (reader *liveEvidenceReader) List(context.Context, domain.LiveSourceSide) ([]ports.SafeRelativePath, error) {
	return nil, reader.err
}
func (reader *liveEvidenceReader) Read(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	reader.calls++
	if err := ctx.Err(); err != nil {
		return ports.LiveSourceFile{}, err
	}
	if reader.err != nil {
		return ports.LiveSourceFile{}, reader.err
	}
	if file, ok := reader.files[side]; ok && file.Path() == path && !reader.closed {
		return file, nil
	}
	return ports.LiveSourceFile{}, ports.NewLiveSourceError(ports.LiveSourceUnavailable, nil)
}
func (reader *liveEvidenceReader) Close() error { reader.closed = true; return nil }

func liveEvidenceTarget(t *testing.T, scope domain.LiveSourceScope) ports.LiveSourceTarget {
	t.Helper()
	operand := ""
	if scope == domain.LiveSourceCommit {
		operand = "HEAD~1"
	}
	if scope == domain.LiveSourceDiff {
		operand = "left...right"
	}
	selector, err := ports.NewLiveSourceSelector(scope, operand)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
	head, _ := ports.ParseGitObjectID(strings.Repeat("b", 40))
	if scope == domain.LiveSourceWorkspace || scope == domain.LiveSourceHead {
		base = ports.GitObjectID{}
	}
	if scope == domain.LiveSourceWorkspace || scope == domain.LiveSourceStage {
		head = ports.GitObjectID{}
	}
	target, err := ports.NewLiveSourceTarget(selector, base, head, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func liveEvidenceFile(t *testing.T, path string, data []byte, mediaType string) ports.LiveSourceFile {
	t.Helper()
	safePath, err := ports.NewSafeRelativePath(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := ports.NewLiveSourceFile(safePath, data, mediaType)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestLiveSourceIdentityPreservesSelectorsWithoutContentIdentity(t *testing.T) {
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceWorkspace, domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceDiff} {
		t.Run(string(scope), func(t *testing.T) {
			target := liveEvidenceTarget(t, scope)
			identity, err := NewLiveSourceIdentity(target)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeLiveSourceIdentity(identity.Bytes())
			if err != nil || decoded.SHA256() != identity.SHA256() || decoded.Target().Selector() != target.Selector() || decoded.Target().Base() != target.Base() || decoded.Target().Head() != target.Head() {
				t.Fatalf("round trip: %v", err)
			}
			path, _ := ports.NewSafeRelativePath("selected.txt")
			change := ports.LiveSourceChange{Kind: "added", After: path}
			if scope == domain.LiveSourceWorkspace || scope == domain.LiveSourceHead {
				change.Kind = "included"
			}
			changedTarget, err := ports.NewLiveSourceTarget(target.Selector(), target.Base(), target.Head(), false, []ports.LiveSourceChange{change})
			if err != nil {
				t.Fatal(err)
			}
			changedIdentity, err := NewLiveSourceIdentity(changedTarget)
			if err != nil || changedIdentity.SHA256() != identity.SHA256() {
				t.Fatal("candidate inventory became a source-content fingerprint")
			}
			if bytes.Contains(identity.Bytes(), []byte("selected.txt")) || bytes.Contains(identity.Bytes(), []byte("content_sha256")) {
				t.Fatal("source metadata claimed captured content")
			}
			mutated := identity.Bytes()
			mutated[0] = 'x'
			if !bytes.Equal(identity.Bytes(), decoded.Bytes()) {
				t.Fatal("identity bytes were not defensive")
			}
		})
	}
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceStage, domain.LiveSourceCommit} {
		target := liveEvidenceTarget(t, scope)
		rootTarget, err := ports.NewLiveSourceTarget(target.Selector(), ports.GitObjectID{}, target.Head(), true, nil)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := NewLiveSourceIdentity(rootTarget)
		if err != nil || !identity.Target().EmptyBase() {
			t.Fatalf("empty base: %v", err)
		}
		if _, err := DecodeLiveSourceIdentity(identity.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLiveSourceIdentityRejectsMalformedOrReinterpretedMetadata(t *testing.T) {
	identity, err := NewLiveSourceIdentity(liveEvidenceTarget(t, domain.LiveSourceWorkspace))
	if err != nil {
		t.Fatal(err)
	}
	data := string(identity.Bytes())
	for _, invalid := range []string{
		data + "{}", " " + data, strings.Replace(data, "mulgae-live-source.v1", "mulgae-live-source.v2", 1),
		strings.Replace(data, `"base_oid":""`, `"base_oid":"`+strings.Repeat("a", 40)+`"`, 1),
		strings.Replace(data, `"scope":"workspace"`, `"scope":"stage"`, 1),
		strings.TrimSuffix(data, "}") + `,"content_sha256":"` + strings.Repeat("a", 64) + `"}`,
		strings.TrimSuffix(data, "}") + `,"scope":"workspace"}`,
	} {
		if _, err := DecodeLiveSourceIdentity([]byte(invalid)); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
	if _, err := NewLiveSourceIdentity(ports.LiveSourceTarget{}); err == nil {
		t.Fatal("accepted absent metadata")
	}
}

func TestVerifyLiveCurrentUsesOnlyDeclaredSourceSide(t *testing.T) {
	cases := []struct {
		scope      domain.LiveSourceScope
		side       Side
		sourceSide domain.LiveSourceSide
	}{
		{domain.LiveSourceWorkspace, SideWorktree, domain.LiveSourceWorktree},
		{domain.LiveSourceStage, SideIndex, domain.LiveSourceIndex},
		{domain.LiveSourceStage, SideBase, domain.LiveSourceBefore},
		{domain.LiveSourceHead, SideHead, domain.LiveSourceAfter},
		{domain.LiveSourceCommit, SideBase, domain.LiveSourceBefore},
		{domain.LiveSourceCommit, SideHead, domain.LiveSourceAfter},
		{domain.LiveSourceDiff, SideBase, domain.LiveSourceBefore},
		{domain.LiveSourceDiff, SideHead, domain.LiveSourceAfter},
	}
	for _, test := range cases {
		t.Run(string(test.scope)+"/"+string(test.side), func(t *testing.T) {
			reader := &liveEvidenceReader{target: liveEvidenceTarget(t, test.scope), files: map[domain.LiveSourceSide]ports.LiveSourceFile{
				test.sourceSide: liveEvidenceFile(t, "src.go", []byte("support\nobserved\nend"), "text/plain"),
			}}
			verifier, err := NewLiveVerifier(reader)
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := NewLiveSourceIdentity(reader.Target())
			claim, err := NewLiveClaim(identity, test.side, "src.go", 2, 2, "observed\n")
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := verifier.VerifyCurrent(context.Background(), claim)
			if err != nil || receipt.Status() != ReceiptVerified || !receipt.Claim().IsLiveSource() || receipt.Claim().TargetSHA256() != "" || receipt.Claim().SourceIdentitySHA256() != identity.SHA256() {
				t.Fatalf("live verification: %+v, %v", receipt, err)
			}
			_ = reader.Close()
			reader.files[test.sourceSide] = liveEvidenceFile(t, "src.go", []byte("changed"), "text/plain")
			if string(receipt.Excerpt()) != "observed\n" || reader.calls != 1 {
				t.Fatal("retained evidence reopened the source")
			}
			data := receipt.Excerpt()
			data[0] = 'x'
			if string(receipt.Excerpt()) != "observed\n" {
				t.Fatal("receipt did not own its excerpt")
			}
		})
	}
}

func TestVerifyLiveCurrentRejectsWrongSourceProofAndOperationalFailures(t *testing.T) {
	reader := &liveEvidenceReader{target: liveEvidenceTarget(t, domain.LiveSourceStage), files: map[domain.LiveSourceSide]ports.LiveSourceFile{
		domain.LiveSourceIndex: liveEvidenceFile(t, "src.go", []byte("index\n"), "text/plain"),
	}}
	verifier, err := NewLiveVerifier(reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := NewLiveSourceIdentity(reader.Target())
	claim, _ := NewLiveClaim(identity, SideIndex, "src.go", 1, 1, "index\n")
	legacyClaim, _ := NewCurrentClaim(CurrentClaimInput{TargetSHA256: identity.SHA256(), Side: SideIndex, Path: "src.go", LineStart: 1, LineEnd: 1, Quote: "index\n"})
	if receipt, err := verifier.VerifyCurrent(context.Background(), legacyClaim); err == nil || receipt.Status() == ReceiptVerified || reader.calls != 0 {
		t.Fatal("accepted historical proof as live evidence")
	}
	legacyReader := &fakeImmutableTargetReader{availability: ImmutableTargetAvailable, bytes: []byte("index\n")}
	legacyVerifier, _ := NewVerifier(legacyReader)
	if receipt, err := legacyVerifier.VerifyCurrent(context.Background(), claim); err == nil || receipt.Status() == ReceiptVerified || legacyReader.calls != 0 {
		t.Fatal("accepted live observation as immutable target evidence")
	}
	otherIdentity, _ := NewLiveSourceIdentity(liveEvidenceTarget(t, domain.LiveSourceHead))
	otherClaim, _ := NewLiveClaim(otherIdentity, SideHead, "src.go", 1, 1, "index\n")
	if receipt, err := verifier.VerifyCurrent(context.Background(), otherClaim); err == nil || receipt.Status() == ReceiptVerified || reader.calls != 0 {
		t.Fatal("accepted another source selection")
	}
	wrongSide, _ := NewLiveClaim(identity, SideWorktree, "src.go", 1, 1, "index\n")
	if receipt, err := verifier.VerifyCurrent(context.Background(), wrongSide); err == nil || receipt.Status() == ReceiptVerified || reader.calls != 0 {
		t.Fatal("stage evidence fell back to worktree")
	}
	wrongQuote, _ := NewLiveClaim(identity, SideIndex, "src.go", 1, 1, "worktree\n")
	if receipt, err := verifier.VerifyCurrent(context.Background(), wrongQuote); err != nil || receipt.Status() != ReceiptInvalid || receipt.ReasonCode() != ReasonQuoteMismatch || receipt.Excerpt() != nil {
		t.Fatalf("wrong quote: %+v, %v", receipt, err)
	}
	reader.err = ports.NewLiveSourceError(ports.LiveSourceUnsafe, errors.New("private filesystem detail"))
	if receipt, err := verifier.VerifyCurrent(context.Background(), claim); err == nil || receipt.Status() == ReceiptVerified {
		t.Fatal("source failure authorized evidence")
	} else {
		var typed *ports.LiveSourceError
		if !errors.As(err, &typed) || typed.Code() != ports.LiveSourceUnsafe {
			t.Fatal("lost typed source error")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if receipt, err := verifier.VerifyCurrent(ctx, claim); !errors.Is(err, context.Canceled) || receipt.Excerpt() != nil {
		t.Fatal("lost cancellation")
	}
	var nilReader *liveEvidenceReader
	if _, err := NewLiveVerifier(nilReader); err == nil {
		t.Fatal("accepted typed-nil reader")
	}
}

func TestVerifyLiveBinaryRetainsOnlySelectedRasterObservation(t *testing.T) {
	for _, test := range []struct {
		path, media string
		data        []byte
	}{
		{"diagram.png", "image/png", []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}},
		{"diagram.jpg", "image/jpeg", []byte{255, 216, 255, 0}},
		{"diagram.webp", "image/webp", []byte("RIFF1234WEBPdata")},
	} {
		t.Run(test.media, func(t *testing.T) {
			file := liveEvidenceFile(t, test.path, test.data, test.media)
			reader := &liveEvidenceReader{target: liveEvidenceTarget(t, domain.LiveSourceWorkspace), files: map[domain.LiveSourceSide]ports.LiveSourceFile{domain.LiveSourceWorktree: file}}
			verifier, _ := NewLiveVerifier(reader)
			receipt, err := verifier.VerifyBinary(context.Background(), SideWorktree, file.Path(), file.SHA256())
			if err != nil || !receipt.Valid() || receipt.MediaType() != test.media || !bytes.Equal(receipt.Bytes(), test.data) {
				t.Fatalf("binary receipt: %v", err)
			}
			_ = reader.Close()
			retained := receipt.Bytes()
			retained[0] = 0
			if !bytes.Equal(receipt.Bytes(), test.data) || reader.calls != 1 {
				t.Fatal("binary evidence lost its retained observation")
			}
			reader.closed = false
			if _, err := verifier.VerifyBinary(context.Background(), SideWorktree, file.Path(), "sha256:"+strings.Repeat("a", 64)); err == nil {
				t.Fatal("accepted wrong image digest")
			}
			identity, _ := NewLiveSourceIdentity(reader.Target())
			claim, _ := NewLiveClaim(identity, SideWorktree, test.path, 1, 1, "unrelated quote")
			if receipt, err := verifier.VerifyCurrent(context.Background(), claim); err == nil || receipt.Status() == ReceiptVerified {
				t.Fatal("image decoded as source text")
			}
		})
	}
}

func TestVerifyLiveBinaryRejectsReboundPathsAndText(t *testing.T) {
	selected, _ := ports.NewSafeRelativePath("selected.png")
	for name, file := range map[string]ports.LiveSourceFile{
		"rebound path": liveEvidenceFile(t, "other.png", []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}, "image/png"),
		"text":         liveEvidenceFile(t, "selected.png", []byte("plain text"), "text/plain"),
	} {
		t.Run(name, func(t *testing.T) {
			reader := reboundLiveEvidenceReader{liveEvidenceReader: &liveEvidenceReader{target: liveEvidenceTarget(t, domain.LiveSourceWorkspace)}, file: file}
			verifier, err := NewLiveVerifier(reader)
			if err != nil {
				t.Fatal(err)
			}
			if receipt, err := verifier.VerifyBinary(context.Background(), SideWorktree, selected, file.SHA256()); err == nil || receipt.Valid() {
				t.Fatal("invalid source read authorized binary evidence")
			}
		})
	}
}
