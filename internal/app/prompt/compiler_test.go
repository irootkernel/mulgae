package prompt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

type testInvocationIssuer struct {
	sources      []SourceInvocationID
	executions   []ExecutionInvocationID
	sourceAt     int
	executionAt  int
	sourceErr    error
	executionErr error
}

func (issuer *testInvocationIssuer) NewSourceInvocationID() (SourceInvocationID, error) {
	if issuer.sourceErr != nil {
		return SourceInvocationID{}, issuer.sourceErr
	}
	if issuer.sourceAt == len(issuer.sources) {
		return SourceInvocationID{}, fmt.Errorf("source ids exhausted")
	}
	value := issuer.sources[issuer.sourceAt]
	issuer.sourceAt++
	return value, nil
}

func (issuer *testInvocationIssuer) NewExecutionInvocationID() (ExecutionInvocationID, error) {
	if issuer.executionErr != nil {
		return ExecutionInvocationID{}, issuer.executionErr
	}
	if issuer.executionAt == len(issuer.executions) {
		return ExecutionInvocationID{}, fmt.Errorf("execution ids exhausted")
	}
	value := issuer.executions[issuer.executionAt]
	issuer.executionAt++
	return value, nil
}

func TestComposeTrustedTemplateOwnsTrustedLayerJoining(t *testing.T) {
	first, err := NewTrustedLayer("builtin:common", "1", []byte("common contract"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTrustedLayer("builtin:role", "1", []byte("role guide"))
	if err != nil {
		t.Fatal(err)
	}
	template, err := ComposeTrustedTemplate("builtin:review", "1", first, second)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(template.Bytes()), "common contract\n\nrole guide"; got != want {
		t.Fatalf("template bytes = %q, want %q", got, want)
	}
	if _, err := NewTrustedLayer("builtin:bad", "1", []byte("bad\n")); err == nil {
		t.Fatal("NewTrustedLayer() accepted trailing LF")
	}
	if _, err := ComposeTrustedTemplate("builtin:empty", "1"); err == nil {
		t.Fatal("ComposeTrustedTemplate() accepted no layers")
	}
}
func TestComposeTrustedTemplatePreservesOrderedLayerProvenance(t *testing.T) {
	commonBytes := []byte("common")
	roleBytes := []byte("role")
	common, err := NewTrustedLayer("builtin:common", "2", commonBytes)
	if err != nil {
		t.Fatal(err)
	}
	role, err := NewTrustedLayer("builtin:role/logic", "2", roleBytes)
	if err != nil {
		t.Fatal(err)
	}
	template, err := ComposeTrustedTemplate("builtin:review", "2", common, role)
	if err != nil {
		t.Fatal(err)
	}
	manifest := template.TrustedLayerManifest()
	if len(manifest) != 2 {
		t.Fatalf("manifest length = %d, want 2", len(manifest))
	}
	for index, want := range []struct {
		id, version string
		bytes       []byte
	}{
		{id: "builtin:common", version: "2", bytes: commonBytes},
		{id: "builtin:role/logic", version: "2", bytes: roleBytes},
	} {
		sum := sha256.Sum256(want.bytes)
		got := manifest[index]
		if got.Ordinal() != index+1 || got.ID() != want.id || got.Version() != want.version ||
			got.SHA256() != hex.EncodeToString(sum[:]) || got.ByteLength() != len(want.bytes) {
			t.Fatalf("manifest[%d] = ordinal=%d id=%q version=%q sha256=%q byte_length=%d",
				index, got.Ordinal(), got.ID(), got.Version(), got.SHA256(), got.ByteLength())
		}
	}
	manifest[0] = TrustedLayerProvenance{}
	if template.TrustedLayerManifest()[0].ID() != "builtin:common" {
		t.Fatal("TrustedLayerManifest() exposed compiler-owned provenance")
	}
	first, err := template.TrustedLayerManifestJSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := template.TrustedLayerManifestJSON()
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"schema_version":"mulgae-trusted-layer-manifest.v1","layers":[{"ordinal":1,"id":"builtin:common","version":"2","sha256":"` +
		manifestSHA256(commonBytes) + `","byte_length":6},{"ordinal":2,"id":"builtin:role/logic","version":"2","sha256":"` +
		manifestSHA256(roleBytes) + `","byte_length":4}]}`
	if first != wantJSON || second != wantJSON {
		t.Fatalf("manifest JSON = %q and %q, want %q", first, second, wantJSON)
	}
	direct, err := NewTrustedTemplate("builtin:direct", "1", []byte("opaque"))
	if err != nil {
		t.Fatal(err)
	}
	if len(direct.TrustedLayerManifest()) != 0 {
		t.Fatal("NewTrustedTemplate() unexpectedly gained provenance")
	}
	opaque, err := NewTrustedTemplateWithOpaqueLayer("builtin:direct", "1", []byte("opaque"))
	if err != nil {
		t.Fatal(err)
	}
	if got := opaque.TrustedLayerManifest(); len(got) != 1 || got[0].ID() != "builtin:direct" ||
		got[0].SHA256() != manifestSHA256([]byte("opaque")) || got[0].ByteLength() != len("opaque") {
		t.Fatalf("opaque manifest = %#v", got)
	}
}

func TestRestoreTrustedLayerManifestReconstructsExactProvenance(t *testing.T) {
	first, err := NewTrustedLayer("builtin:common", "1", []byte("common"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTrustedLayer("builtin:role", "1", []byte("role"))
	if err != nil {
		t.Fatal(err)
	}
	composed, err := ComposeTrustedTemplate("builtin:review", "1", first, second)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := composed.TrustedLayerManifestJSON()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := NewTrustedTemplate(composed.ID(), composed.Version(), composed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreTrustedLayerManifest(direct, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if restored.SHA256() != composed.SHA256() || len(restored.TrustedLayerManifest()) != 2 {
		t.Fatalf("restored template = sha:%s layers:%d", restored.SHA256(), len(restored.TrustedLayerManifest()))
	}
	if _, err := RestoreTrustedLayerManifest(direct, manifest+" "); err == nil {
		t.Fatal("RestoreTrustedLayerManifest() accepted a non-canonical manifest")
	}
}

func manifestSHA256(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}
func TestCompileEmitsCanonicalSOTPacket(t *testing.T) {
	compiler := newTestCompiler(t, []int{5}, []int{6})
	input := testCompileInput(t)

	compiled, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	stdin := compiled.Stdin()
	if !bytes.HasPrefix(stdin, []byte("trusted contract\nMulgae-FRAMES/1\n")) {
		t.Fatalf("stdin prefix = %q", stdin)
	}
	if !bytes.HasSuffix(stdin, []byte("Mulgae-FRAMES-END/1\n")) {
		t.Fatalf("stdin has no exact end sentinel: %q", stdin)
	}

	sections := compiled.Sections()
	wantKinds := []SectionKind{
		SectionProjectContext,
		SectionReviewTarget,
		SectionPriorProviderOutput,
		SectionPriorFinding,
		SectionPriorReport,
		SectionExternalLog,
		SectionExternalLog,
	}
	if len(sections) != len(wantKinds) {
		t.Fatalf("section count = %d, want %d", len(sections), len(wantKinds))
	}
	for index, section := range sections {
		if section.Kind() != wantKinds[index] {
			t.Fatalf("section %d kind = %q, want %q", index, section.Kind(), wantKinds[index])
		}
		wantID := independentlyDerivedSectionID(compiled.Scope().SourceInvocationID(), uint64(index+1), section.Kind(), section.Payload())
		if section.ID() != wantID {
			t.Fatalf("section %d id = %q, want %q", index, section.ID(), wantID)
		}
		if !bytes.Contains(section.FrameBytes(), []byte("scope:"+compiled.Scope().FrameScope().String()+"\n")) {
			t.Fatalf("section %d does not contain its canonical scope", index)
		}
	}
	if occurrences(stdin, []byte("kind:review_target\n")) != 1 {
		t.Fatalf("review_target occurrences = %d, want 1", occurrences(stdin, []byte("kind:review_target\n")))
	}

	parsed, err := ParseStdin(compiled.TrustedTemplate(), stdin)
	if err != nil {
		t.Fatalf("ParseStdin() error = %v", err)
	}
	if !parsed.Scope().equal(compiled.Scope().FrameScope()) {
		t.Fatalf("parsed scope = %q, want %q", parsed.Scope(), compiled.Scope().FrameScope())
	}
	if !sectionsEqual(parsed.Sections(), sections) {
		t.Fatal("parsed sections differ from compiled sections")
	}
	wantDigest := independentlyHashedStdin(stdin)
	if compiled.CompleteStdinSHA256() != wantDigest || compiled.WireIdentity() != wantDigest {
		t.Fatalf("wire digest = %q, want %q", compiled.CompleteStdinSHA256(), wantDigest)
	}
	if got := compiler.sourceWireIdentity[rawUUID(compiled.Scope().SourceInvocationID().String())]; got != wantDigest {
		t.Fatalf("source wire identity = %q, want %q", got, wantDigest)
	}
}
func TestCompileEmitsHardCodedFullPacketGolden(t *testing.T) {
	template, err := NewTrustedTemplate("builtin:golden", "1", []byte("trusted"))
	if err != nil {
		t.Fatal(err)
	}
	sourceID, err := ParseSourceInvocationID("i_" + testUUID(5))
	if err != nil {
		t.Fatal(err)
	}
	executionID, err := ParseExecutionInvocationID(testUUID(6))
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCompiler(template, &testInvocationIssuer{
		sources:    []SourceInvocationID{sourceID},
		executions: []ExecutionInvocationID{executionID},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := testCompileInput(t)
	input.ProjectContext = nil
	input.ReviewTarget = NewPayload([]byte("target"))
	input.PriorProviderOutput = nil
	input.PriorFinding = nil
	input.PriorReport = nil
	input.ExternalLogs = nil

	compiled, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	const wantStdin = "trusted\n" +
		"Mulgae-FRAMES/1\n" +
		"Mulgae-UNTRUSTED/1\n" +
		"scope:s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7002-8002-000000000002/rt_019f5a09-5eec-7003-8003-000000000003/a_019f5a09-5eec-7004-8004-000000000004/i_019f5a09-5eec-7005-8005-000000000005\n" +
		"section-id:e68f4ab7bcb7e7a543cd9e879337b13d\n" +
		"kind:review_target\n" +
		"length:6\n" +
		"sha256:34a04005bcaf206eec990bd9637d9fdb6725e0a0c0d4aebf003f17f4c956eb5c\n" +
		"\n" +
		"target\n" +
		"Mulgae-END/e68f4ab7bcb7e7a543cd9e879337b13d\n" +
		"Mulgae-FRAMES-END/1\n"
	const wantDigest = "8f9475685bbe2074784abf938c6325f6bddf469fcf4f34ff620f6313019bc011"
	if got := string(compiled.Stdin()); got != wantStdin {
		t.Fatalf("stdin = %q, want %q", got, wantStdin)
	}
	if got := compiled.CompleteStdinSHA256(); got != wantDigest {
		t.Fatalf("complete stdin digest = %q, want %q", got, wantDigest)
	}
}

func TestCompilerRejectsInvalidTemplateScopeTargetAndIdentityReuse(t *testing.T) {
	if _, err := NewTrustedTemplate("builtin:test", "1", []byte("ends with LF\n")); err == nil {
		t.Fatal("NewTrustedTemplate() accepted trailing LF")
	}
	if _, err := ParseRoleTaskID("rt_019f5a09-5eec-6000-8000-000000000001"); err == nil {
		t.Fatal("ParseRoleTaskID() accepted non-v7 UUID")
	}

	compiler := newTestCompiler(t, []int{5, 5}, []int{6, 7})
	input := testCompileInput(t)
	if _, err := compiler.Compile(input); err != nil {
		t.Fatalf("first Compile() error = %v", err)
	}
	if _, err := compiler.Compile(input); err == nil {
		t.Fatal("Compile() accepted a reused source identity")
	}
}
func TestCompilerIdentityFailuresAreTypedAndReservationsPersist(t *testing.T) {
	cause := errors.New("issuer unavailable")
	compiler := newTestCompiler(t, []int{5, 5}, []int{6})
	issuer := compiler.issuer.(*testInvocationIssuer)
	issuer.executionErr = cause

	_, err := compiler.Compile(testCompileInput(t))
	identityErr := requireIdentityError(t, err)
	if !errors.Is(identityErr, cause) {
		t.Fatalf("IdentityError did not unwrap issuer failure: %v", err)
	}
	if got, want := identityErr.Operation(), "compile execution invocation issuance"; got != want {
		t.Fatalf("IdentityError operation = %q, want %q", got, want)
	}
	if got := issuer.sourceAt; got != 1 {
		t.Fatalf("source issuer calls = %d, want 1", got)
	}
	if _, reserved := compiler.usedInvocationUUID[rawUUID("i_"+testUUID(5))]; !reserved {
		t.Fatal("source UUID reservation was rolled back after execution issuer failure")
	}
	if _, bound := compiler.sourceWireIdentity[rawUUID("i_"+testUUID(5))]; bound {
		t.Fatal("failed Compile() bound a source UUID to a wire identity")
	}

	issuer.executionErr = nil
	_, err = compiler.Compile(testCompileInput(t))
	requireIdentityError(t, err)
	if got := issuer.executionAt; got != 0 {
		t.Fatalf("execution issuer calls = %d, want 0 after reused source rejection", got)
	}

	template, err := NewTrustedTemplate("builtin:identity", "1", []byte("trusted"))
	if err != nil {
		t.Fatal(err)
	}
	invalidIssuer := &testInvocationIssuer{
		sources: []SourceInvocationID{{value: "not-a-source-uuid"}},
	}
	invalidCompiler, err := NewCompiler(template, invalidIssuer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = invalidCompiler.Compile(testCompileInput(t))
	requireIdentityError(t, err)

}

func TestParseStdinRejectsMalformedTruncatedTrailingAndNonCanonicalFrames(t *testing.T) {
	compiled, err := newTestCompiler(t, []int{5}, []int{6}).Compile(testCompileInput(t))
	if err != nil {
		t.Fatal(err)
	}
	stdin := compiled.Stdin()
	first := compiled.Sections()[0]
	endID := []byte("Mulgae-END/" + first.ID())

	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "missing frames preamble",
			mutate: func(value []byte) []byte {
				return bytes.Replace(value, []byte("Mulgae-FRAMES/1"), []byte("Mulgae-FRAMES/X"), 1)
			},
		},
		{
			name: "CR in header",
			mutate: func(value []byte) []byte {
				return bytes.Replace(value, []byte("kind:project_context"), []byte("kind:\rproject_context"), 1)
			},
		},
		{
			name: "leading zero length",
			mutate: func(value []byte) []byte {
				return bytes.Replace(value, []byte("length:15\n"), []byte("length:015\n"), 1)
			},
		},
		{
			name: "mismatched end id",
			mutate: func(value []byte) []byte {
				return bytes.Replace(value, endID, []byte("Mulgae-END/00000000000000000000000000000000"), 1)
			},
		},
		{
			name: "truncated payload",
			mutate: func(value []byte) []byte {
				return value[:len(value)-4]
			},
		},
		{
			name: "trailing byte",
			mutate: func(value []byte) []byte {
				return append(value, 'x')
			},
		},
		{
			name: "duplicate review target",
			mutate: func(value []byte) []byte {
				target := compiled.Sections()[1].FrameBytes()
				return bytes.Replace(value, []byte(framesEnd), append(target, []byte(framesEnd)...), 1)
			},
		},
		{
			name: "forged section id",
			mutate: func(value []byte) []byte {
				return bytes.Replace(value, []byte(first.ID()), []byte("00000000000000000000000000000000"), -1)
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseStdin(compiled.TrustedTemplate(), test.mutate(cloneBytes(stdin))); err == nil {
				t.Fatal("ParseStdin() accepted malformed input")
			}
		})
	}

	coordinates := compiled.Scope().Coordinates()
	frameScope, err := NewFrameScope(coordinates, compiled.Scope().SourceInvocationID())
	if err != nil {
		t.Fatal(err)
	}
	fullPayload := []byte("review target")
	truncatedPayload := fullPayload[:len("review")]
	selfConsistentTruncated := makeFrame(
		frameScope,
		deriveSectionID(frameScope.SourceInvocationID(), 1, SectionReviewTarget, fullPayload),
		SectionReviewTarget,
		truncatedPayload,
	)
	if _, err := ParseStdin(compiled.TrustedTemplate(), composeStdin(compiled.TrustedTemplate().bytes, []FramedSection{selfConsistentTruncated})); err == nil {
		t.Fatal("ParseStdin() accepted a self-consistent truncated payload with a forged section id")
	}
	reviewPayload := []byte("target")
	projectPayload := []byte("context")
	outOfOrder := []FramedSection{
		makeFrame(frameScope, deriveSectionID(frameScope.SourceInvocationID(), 1, SectionReviewTarget, reviewPayload), SectionReviewTarget, reviewPayload),
		makeFrame(frameScope, deriveSectionID(frameScope.SourceInvocationID(), 2, SectionProjectContext, projectPayload), SectionProjectContext, projectPayload),
	}
	if _, err := ParseStdin(compiled.TrustedTemplate(), composeStdin(compiled.TrustedTemplate().bytes, outOfOrder)); err == nil {
		t.Fatal("ParseStdin() accepted frames out of canonical order")
	}
	duplicateTarget := []FramedSection{
		makeFrame(frameScope, deriveSectionID(frameScope.SourceInvocationID(), 1, SectionReviewTarget, reviewPayload), SectionReviewTarget, reviewPayload),
		makeFrame(frameScope, deriveSectionID(frameScope.SourceInvocationID(), 2, SectionReviewTarget, projectPayload), SectionReviewTarget, projectPayload),
	}
	if _, err := ParseStdin(compiled.TrustedTemplate(), composeStdin(compiled.TrustedTemplate().bytes, duplicateTarget)); err == nil {
		t.Fatal("ParseStdin() accepted more than one review_target frame")
	}
	otherSource, err := ParseSourceInvocationID("i_" + testUUID(12))
	if err != nil {
		t.Fatal(err)
	}
	otherScope, err := NewFrameScope(coordinates, otherSource)
	if err != nil {
		t.Fatal(err)
	}
	firstScope := []byte("scope:" + frameScope.String())
	if _, err := ParseStdin(compiled.TrustedTemplate(), bytes.Replace(stdin, firstScope, []byte("scope:"+otherScope.String()), 1)); err == nil {
		t.Fatal("ParseStdin() accepted divergent frame scopes")
	}
}

func TestExactReplayAndRecompositionHaveDistinctIdentities(t *testing.T) {
	compiler := newTestCompiler(t, []int{5, 8}, []int{6, 7, 9})
	input := testCompileInput(t)
	initial, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := compiler.Replay(initial)
	if err != nil {
		t.Fatal(err)
	}
	recomposed, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}

	if !replay.ExactReplay() {
		t.Fatal("Replay() did not mark exact replay")
	}
	if replay.Scope().SourceInvocationID() != initial.Scope().SourceInvocationID() {
		t.Fatal("Replay() changed source invocation identity")
	}
	if replay.Scope().ExecutionInvocationID() == initial.Scope().ExecutionInvocationID() {
		t.Fatal("Replay() reused execution invocation identity")
	}
	if !bytes.Equal(replay.Stdin(), initial.Stdin()) || replay.WireIdentity() != initial.WireIdentity() {
		t.Fatal("Replay() did not retain byte-identical stdin and wire identity")
	}
	replayedSource, ok := replay.ReplayedSourceInvocationID()
	if !ok || replayedSource != initial.Scope().SourceInvocationID() {
		t.Fatalf("replay source = %q, %t", replayedSource, ok)
	}

	if recomposed.ExactReplay() {
		t.Fatal("Compile() marked a recomposition as replay")
	}
	if recomposed.Scope().SourceInvocationID() == initial.Scope().SourceInvocationID() {
		t.Fatal("recomposition reused source invocation identity")
	}
	if recomposed.Scope().ExecutionInvocationID() == initial.Scope().ExecutionInvocationID() {
		t.Fatal("recomposition reused execution invocation identity")
	}
	if bytes.Equal(recomposed.Stdin(), initial.Stdin()) || recomposed.WireIdentity() == initial.WireIdentity() {
		t.Fatal("recomposition retained exact replay wire identity")
	}
	if recomposed.Sections()[1].ID() == initial.Sections()[1].ID() {
		t.Fatal("recomposition reused section identity")
	}
}

func TestReplayStoredReconstructsPersistedPacketWithFreshExecutionIdentity(t *testing.T) {
	initial, err := newTestCompiler(t, []int{41}, []int{42}).Compile(testCompileInput(t))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := newTestCompiler(t, nil, []int{43}).ReplayStored(initial.Stdin(), initial.Scope().ExecutionInvocationID())
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.ExactReplay() || replayed.Scope().SourceInvocationID() != initial.Scope().SourceInvocationID() || replayed.Scope().ExecutionInvocationID() == initial.Scope().ExecutionInvocationID() {
		t.Fatalf("stored replay identity = source:%s execution:%s exact:%t", replayed.Scope().SourceInvocationID(), replayed.Scope().ExecutionInvocationID(), replayed.ExactReplay())
	}
	if !bytes.Equal(replayed.Stdin(), initial.Stdin()) || replayed.CompleteStdinSHA256() != initial.CompleteStdinSHA256() {
		t.Fatal("stored replay changed provider wire bytes")
	}
}

func TestReplayStoredWithReboundTemplatePreservesFramedAuthority(t *testing.T) {
	initialCompiler := newTestCompiler(t, []int{41}, []int{42})
	initial, err := initialCompiler.Compile(testCompileInput(t))
	if err != nil {
		t.Fatal(err)
	}
	reboundTemplate, err := NewTrustedTemplate("builtin:review-provider", "1", []byte("current transport contract"))
	if err != nil {
		t.Fatal(err)
	}
	replayIssuer := newTestCompiler(t, nil, []int{43}).issuer
	replayCompiler, err := NewCompiler(reboundTemplate, replayIssuer)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := replayCompiler.ReplayStoredWithReboundTemplate(
		initial.TrustedTemplate(), initial.Stdin(), initial.Scope().ExecutionInvocationID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("\nMulgae-FRAMES/1\n")
	initialFrames := initial.Stdin()[bytes.Index(initial.Stdin(), marker):]
	replayedFrames := replayed.Stdin()[bytes.Index(replayed.Stdin(), marker):]
	if !bytes.Equal(initialFrames, replayedFrames) || bytes.Equal(initial.Stdin(), replayed.Stdin()) {
		t.Fatal("rebound replay did not preserve exactly the stored frames")
	}
	if replayed.Scope().SourceInvocationID() != initial.Scope().SourceInvocationID() ||
		replayed.Scope().ExecutionInvocationID() == initial.Scope().ExecutionInvocationID() || !replayed.ExactReplay() {
		t.Fatalf("rebound replay identity = source:%s execution:%s exact:%t",
			replayed.Scope().SourceInvocationID(), replayed.Scope().ExecutionInvocationID(), replayed.ExactReplay())
	}
	wrongSource, err := NewTrustedTemplate(initial.TrustedTemplate().ID(), initial.TrustedTemplate().Version(), []byte("wrong source"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replayCompiler.ReplayStoredWithReboundTemplate(wrongSource, initial.Stdin(), initial.Scope().ExecutionInvocationID()); err == nil {
		t.Fatal("ReplayStoredWithReboundTemplate() accepted the wrong source template")
	}
}
func TestReplayBindsExternalSourceToWireIdentity(t *testing.T) {
	input := testCompileInput(t)
	initial, err := newTestCompiler(t, []int{5}, []int{6}).Compile(input)
	if err != nil {
		t.Fatal(err)
	}

	differentInput := testCompileInput(t)
	differentInput.ReviewTarget = NewPayload([]byte("different review target"))
	differentWire, err := newTestCompiler(t, []int{5}, []int{7}).Compile(differentInput)
	if err != nil {
		t.Fatal(err)
	}
	if differentWire.WireIdentity() == initial.WireIdentity() {
		t.Fatal("test setup did not produce a distinct wire identity")
	}

	replayCompiler := newTestCompiler(t, nil, []int{8, 9})
	if _, err := replayCompiler.Replay(initial); err != nil {
		t.Fatalf("first external Replay() error = %v", err)
	}
	if _, err := replayCompiler.Replay(initial); err != nil {
		t.Fatalf("same external Replay() error = %v", err)
	}
	_, err = replayCompiler.Replay(differentWire)
	requireIdentityError(t, err)
	if got := replayCompiler.issuer.(*testInvocationIssuer).executionAt; got != 2 {
		t.Fatalf("execution issuer calls = %d, want 2 after different-wire rejection", got)
	}
}

func TestReplayRejectsExternalSourceExecutionReuse(t *testing.T) {
	initial, err := newTestCompiler(t, []int{5}, []int{6}).Compile(testCompileInput(t))
	if err != nil {
		t.Fatal(err)
	}
	replayCompiler := newTestCompiler(t, nil, []int{6})

	_, err = replayCompiler.Replay(initial)
	identityErr := requireIdentityError(t, err)
	if got, want := identityErr.Operation(), "replay execution invocation freshness"; got != want {
		t.Fatalf("IdentityError operation = %q, want %q", got, want)
	}
	if got := replayCompiler.issuer.(*testInvocationIssuer).executionAt; got != 1 {
		t.Fatalf("execution issuer calls = %d, want 1", got)
	}
}

func TestReplayRejectsChainedHistoricalExecutionReuse(t *testing.T) {
	initial, err := newTestCompiler(t, []int{5}, []int{6}).Compile(testCompileInput(t))
	if err != nil {
		t.Fatal(err)
	}
	replayCompiler := newTestCompiler(t, nil, []int{8, 6})
	firstReplay, err := replayCompiler.Replay(initial)
	if err != nil {
		t.Fatal(err)
	}

	_, err = replayCompiler.Replay(firstReplay)
	requireIdentityError(t, err)
	if got := replayCompiler.issuer.(*testInvocationIssuer).executionAt; got != 2 {
		t.Fatalf("execution issuer calls = %d, want 2", got)
	}
}

func TestReplayRejectsCrossSourceHistoricalExecutionCollision(t *testing.T) {
	first, err := newTestCompiler(t, []int{5}, []int{6}).Compile(testCompileInput(t))
	if err != nil {
		t.Fatal(err)
	}
	second, err := newTestCompiler(t, []int{7}, []int{6}).Compile(testCompileInput(t))
	if err != nil {
		t.Fatal(err)
	}
	replayCompiler := newTestCompiler(t, nil, []int{8})
	if _, err := replayCompiler.Replay(first); err != nil {
		t.Fatal(err)
	}

	_, err = replayCompiler.Replay(second)
	requireIdentityError(t, err)
	if got := replayCompiler.issuer.(*testInvocationIssuer).executionAt; got != 1 {
		t.Fatalf("execution issuer calls = %d, want 1 after cross-source collision", got)
	}
}

func TestReplayRejectsSourceExecutionNamespaceCollision(t *testing.T) {
	compiler := newTestCompiler(t, []int{5}, []int{6, 8})
	if _, err := compiler.Compile(testCompileInput(t)); err != nil {
		t.Fatal(err)
	}
	external, err := newTestCompiler(t, []int{6}, []int{7}).Compile(testCompileInput(t))
	if err != nil {
		t.Fatal(err)
	}

	_, err = compiler.Replay(external)
	requireIdentityError(t, err)
	if got := compiler.issuer.(*testInvocationIssuer).executionAt; got != 1 {
		t.Fatalf("execution issuer calls = %d, want 1 after namespace collision", got)
	}
}

func TestPromptGettersAreDefensive(t *testing.T) {
	compiled, err := newTestCompiler(t, []int{5}, []int{6}).Compile(testCompileInput(t))
	if err != nil {
		t.Fatal(err)
	}
	stdin := compiled.Stdin()
	stdin[0] ^= 0xff
	template := compiled.TrustedTemplate()
	template.bytes[0] ^= 0xff
	sections := compiled.Sections()
	sections[0].payload[0] ^= 0xff
	sections[0].frame[0] ^= 0xff
	if err := compiled.Validate(); err != nil {
		t.Fatalf("mutating getters changed compiled prompt: %v", err)
	}
	if bytes.Equal(compiled.Stdin(), stdin) {
		t.Fatal("Stdin() did not return a defensive copy")
	}
	if bytes.Equal(compiled.TrustedTemplate().bytes, template.bytes) {
		t.Fatal("TrustedTemplate() did not return defensive bytes")
	}
	if bytes.Equal(compiled.Sections()[0].Payload(), sections[0].payload) {
		t.Fatal("Sections() did not return defensive payload bytes")
	}
}

func TestCompilerParserRoundTripArbitraryPayloads(t *testing.T) {
	issuer := &testInvocationIssuer{}
	for index := 1; index <= 80; index++ {
		source, err := ParseSourceInvocationID("i_" + testUUID(index*2+20))
		if err != nil {
			t.Fatal(err)
		}
		execution, err := ParseExecutionInvocationID(testUUID(index*2 + 21))
		if err != nil {
			t.Fatal(err)
		}
		issuer.sources = append(issuer.sources, source)
		issuer.executions = append(issuer.executions, execution)
	}
	template, err := NewTrustedTemplate("builtin:property", "1", []byte("trusted"))
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCompiler(template, issuer)
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewSource(99))
	for iteration := 0; iteration < 80; iteration++ {
		payload := make([]byte, random.Intn(2048))
		for index := range payload {
			payload[index] = byte(random.Intn(256))
		}
		input := testCompileInput(t)
		input.ReviewTarget = NewPayload(payload)
		if iteration%2 == 0 {
			context := NewPayload([]byte{})
			input.ProjectContext = &context
		}
		if iteration%3 == 0 {
			input.ExternalLogs = []Payload{NewPayload(payload), NewPayload([]byte("\nMulgae-FRAMES-END/1\n"))}
		}
		compiled, err := compiler.Compile(input)
		if err != nil {
			t.Fatalf("iteration %d Compile() error = %v", iteration, err)
		}
		parsed, err := ParseStdin(compiled.TrustedTemplate(), compiled.Stdin())
		if err != nil {
			t.Fatalf("iteration %d ParseStdin() error = %v", iteration, err)
		}
		if !sectionsEqual(parsed.Sections(), compiled.Sections()) {
			t.Fatalf("iteration %d changed arbitrary payload bytes", iteration)
		}
	}
}

func testCompileInput(t *testing.T) CompileInput {
	t.Helper()
	sessionID, err := domain.ParseSessionID("s_" + testUUID(1))
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_" + testUUID(2))
	if err != nil {
		t.Fatal(err)
	}
	roleTaskID, err := ParseRoleTaskID("rt_" + testUUID(3))
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := domain.ParseAttemptID("a_" + testUUID(4))
	if err != nil {
		t.Fatal(err)
	}
	scope, err := NewScopeCoordinates(sessionID, runID, roleTaskID, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	projectContext := NewPayload([]byte("context payload"))
	priorOutput := NewPayload([]byte("prior output"))
	priorFinding := NewPayload([]byte("prior finding"))
	priorReport := NewPayload([]byte("prior report"))
	return CompileInput{
		Scope:               scope,
		ProjectContext:      &projectContext,
		ReviewTarget:        NewPayload([]byte("review target")),
		PriorProviderOutput: &priorOutput,
		PriorFinding:        &priorFinding,
		PriorReport:         &priorReport,
		ExternalLogs: []Payload{
			NewPayload([]byte("external one")),
			NewPayload([]byte("external two")),
		},
	}
}

func newTestCompiler(t *testing.T, sourceNumbers, executionNumbers []int) *Compiler {
	t.Helper()
	issuer := &testInvocationIssuer{}
	for _, number := range sourceNumbers {
		source, err := ParseSourceInvocationID("i_" + testUUID(number))
		if err != nil {
			t.Fatal(err)
		}
		issuer.sources = append(issuer.sources, source)
	}
	for _, number := range executionNumbers {
		execution, err := ParseExecutionInvocationID(testUUID(number))
		if err != nil {
			t.Fatal(err)
		}
		issuer.executions = append(issuer.executions, execution)
	}
	template, err := NewTrustedTemplate("builtin:review-provider", "1", []byte("trusted contract"))
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCompiler(template, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}

func testUUID(number int) string {
	return fmt.Sprintf("019f5a09-5eec-7%03x-8%03x-%012x", number&0x0fff, number&0x0fff, number)
}

func independentlyDerivedSectionID(source SourceInvocationID, ordinal uint64, kind SectionKind, payload []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROMPT-SECTION/1\x00"))
	_, _ = hash.Write([]byte(source.String()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(fmt.Sprintf("%d", ordinal)))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(kind))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(payload)
	return hex.EncodeToString(hash.Sum(nil)[:16])
}

func independentlyHashedStdin(stdin []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1\x00"))
	_, _ = hash.Write(stdin)
	return hex.EncodeToString(hash.Sum(nil))
}

func requireIdentityError(t *testing.T, err error) *IdentityError {
	t.Helper()
	var identityErr *IdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("error = %T %v, want *IdentityError", err, err)
	}
	return identityErr
}
func occurrences(content, needle []byte) int {
	count := 0
	for {
		index := bytes.Index(content, needle)
		if index < 0 {
			return count
		}
		count++
		content = content[index+len(needle):]
	}
}
