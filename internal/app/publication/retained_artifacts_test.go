package publication

import (
	"bytes"
	"context"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRetainedLiveManifestRoleReportRecordsTransport(t *testing.T) {
	t.Parallel()

	stdoutOnly := retainedLiveCandidate(t, false).ValidatedCandidateSHA256()
	candidate := retainedLiveCandidate(t, false)
	candidate.roles[1].outputTransport = ports.ProviderOutputTransportStagedFile
	if digest := candidate.ValidatedCandidateSHA256(); digest == "" || digest == stdoutOnly {
		t.Fatalf("validated candidate identity = %q, want a value bound to the role output transport", digest)
	}
	bundle, err := candidate.Build(context.Background(), retainedSchema(t), publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !bundle.Valid() {
		t.Fatal("bundle with mixed role-report transports failed its semantic reopen")
	}
	var manifest runManifestWire
	if err := unmarshalExact(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.RoleReports) != 2 ||
		manifest.RoleReports[0].Transport != string(ports.ProviderOutputTransportStdout) ||
		manifest.RoleReports[1].Transport != string(ports.ProviderOutputTransportStagedFile) {
		t.Fatalf("manifest role report transports = %#v", manifest.RoleReports)
	}

	snapshot, err := ports.NewCommittedPublicationSnapshot(
		bundle.Final(), bundle.Manifest(), bundle.LineageEdge(), bundle.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := ProjectCommittedRoleReports(snapshot)
	if err != nil {
		t.Fatalf("ProjectCommittedRoleReports() error = %v", err)
	}
	if len(reports) != 2 ||
		reports[0].Transport != string(ports.ProviderOutputTransportStdout) ||
		reports[1].Transport != string(ports.ProviderOutputTransportStagedFile) {
		t.Fatalf("committed role report transports = %#v", reports)
	}
}

func TestRetainedLiveManifestRoleReportsRejectUnknownTransport(t *testing.T) {
	t.Parallel()

	candidate := retainedLiveCandidate(t, false)
	bundle, err := candidate.Build(context.Background(), retainedSchema(t), publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	var manifest runManifestWire
	if err := unmarshalExact(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	var final finalReviewWire
	if err := unmarshalExact(bundle.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	if err := validateManifestRoleReports(manifest, final); err != nil {
		t.Fatalf("committed role reports rejected before tampering: %v", err)
	}
	for _, transport := range []string{"carrier_pigeon", "STDOUT", ""} {
		tampered := manifest
		tampered.RoleReports = append([]manifestRoleReportWire(nil), manifest.RoleReports...)
		tampered.RoleReports[0].Transport = transport
		if err := validateManifestRoleReports(tampered, final); err == nil {
			t.Fatalf("reader accepted role report transport %q", transport)
		}
	}

	emitted := bundle.Manifest().Bytes()
	stripped := bytes.Replace(emitted, []byte(`,"transport":"stdout"`), nil, 1)
	if bytes.Equal(stripped, emitted) {
		t.Fatal("manifest did not emit a canonical role-report transport")
	}
	var decoded runManifestWire
	if err := unmarshalCanonicalPublicationRecord(stripped, &decoded, "committed manifest"); err == nil {
		t.Fatal("reader accepted a manifest whose role report omits transport")
	}
}

func TestRetainedLiveAttemptCaptureArtifactsAreImmutableAndSecretBytesAreDropped(t *testing.T) {
	t.Parallel()

	candidate := retainedLiveCandidate(t, false)
	initial := []byte(`{"prompt":"initial"}`)
	capture, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactInitialCandidate, initial, false)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStderr, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	attemptID := candidate.roles[0].attempts[0].id
	if err := candidate.bindAttemptArtifacts([]AttemptArtifactInput{
		{AttemptID: attemptID, InvocationSequence: 1, Artifact: capture},
		{AttemptID: attemptID, InvocationSequence: 1, Artifact: secret},
	}); err != nil {
		t.Fatal(err)
	}
	initial[0] = 'X'
	bundle, err := candidate.Build(
		context.Background(), retainedSchema(t), publicationTestReviewID(t), publicationTestTime(), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	var raw, status []byte
	for _, artifact := range bundle.Excerpts() {
		switch {
		case bytes.Contains([]byte(artifact.Path().String()), []byte("/candidate.initial.json")):
			raw = artifact.Bytes()
		case bytes.Contains([]byte(artifact.Path().String()), []byte("/attempts/"+attemptID.String()+"/status.json")):
			status = artifact.Bytes()
		}
	}
	if !bytes.Equal(raw, []byte(`{"prompt":"initial"}`)) {
		t.Fatalf("raw capture = %q, want defensive original", raw)
	}
	if len(status) == 0 || !bytes.Contains(status, []byte("security_rejected")) ||
		!bytes.Contains(status, []byte("/candidate.initial.json")) ||
		!bytes.Contains(status, []byte(sha256Identifier([]byte(`{"prompt":"initial"}`)))) {
		t.Fatalf("attempt status does not record canonical persisted and rejected captures: %s", status)
	}
	if bytes.Contains(status, []byte("secret")) || bytes.Contains(raw, []byte("secret")) {
		t.Fatal("security-rejected bytes were persisted")
	}
}
func TestRetainedLiveAttemptCaptureAbsentPreservesRootPublicationBytes(t *testing.T) {
	t.Parallel()

	candidate := retainedLiveCandidate(t, false)
	reviewID := publicationTestReviewID(t)
	legacy, err := candidate.Build(context.Background(), retainedSchema(t), reviewID, publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.bindAttemptArtifacts(nil); err != nil {
		t.Fatal(err)
	}
	withoutCapture, err := candidate.Build(context.Background(), retainedSchema(t), reviewID, publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacy.Final().Bytes(), withoutCapture.Final().Bytes()) ||
		!bytes.Equal(legacy.Manifest().Bytes(), withoutCapture.Manifest().Bytes()) {
		t.Fatal("root publication bytes changed without attempt capture")
	}
}

func TestRetainedLivePublicationBundleAcceptsLargeProviderStreams(t *testing.T) {
	t.Parallel()
	candidate := retainedLiveCandidate(t, false)
	invocation := &candidate.roles[0].attempts[0].invocations[0]
	largeStream := bytes.Repeat([]byte("provider output\n"), 600_000)
	if int64(len(largeStream)) <= ports.PublicationStructuredMemberMaxBytes {
		t.Fatal("provider stream fixture does not exceed the structured member limit")
	}
	invocation.artifacts = append(invocation.artifacts,
		preparedAttemptArtifact{kind: ports.AttemptArtifactStdout, bytes: largeStream},
		preparedAttemptArtifact{kind: ports.AttemptArtifactStderr, bytes: largeStream},
	)
	bundle, err := candidate.Build(context.Background(), retainedSchema(t), publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePublicationBundleSize(bundle, ports.PublicationStructuredMemberMaxBytes); err != nil {
		t.Fatalf("provider streams were capped as structured members: %v", err)
	}
}

func TestRetainedLivePublicationBundleBindsCanonicalSupportIndex(t *testing.T) {
	t.Parallel()

	bundle, err := retainedLiveCandidate(t, false).Build(
		context.Background(), retainedSchema(t), publicationTestReviewID(t), publicationTestTime(), 42,
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	var manifest runManifestWire
	if err := unmarshalExact(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	indexPath := bundle.Excerpts()[len(bundle.Excerpts())-1].Path()
	if got, want := indexPath.String(), bundle.Manifest().Path().String()[:0]+
		"s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/support/index.json"; got != want {
		t.Fatalf("support index path = %q, want canonical %q", got, want)
	}
	if manifest.CompositeIdentity.SupportIndex.Path != indexPath.String() ||
		manifest.CompositeIdentity.SupportIndex.SHA256 != bundle.Excerpts()[len(bundle.Excerpts())-1].SHA256() {
		t.Fatal("manifest does not bind the exact support index")
	}
	var index runSupportIndexWire
	if err := unmarshalExact(bundle.Excerpts()[len(bundle.Excerpts())-1].Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	if index.SchemaVersion != "mulgae-run-support-index.v4" || len(index.Artifacts) == 0 {
		t.Fatalf("support index is not canonical runtime inventory: %#v", index)
	}
	for _, artifact := range index.Artifacts {
		if artifact.Path == indexPath.String() {
			t.Fatal("support index recursively inventories itself")
		}
	}
}
