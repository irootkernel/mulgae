package publication

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestReducePublicationEvidenceUsesTotalAuthorityReducer(t *testing.T) {
	t.Parallel()

	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetPatch, SHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	finding, err := domain.NewFinding(domain.FindingInput{
		Severity: domain.SeverityLow, Path: "internal/example.go", LineStart: 1,
		Role: domain.RoleLogic, ProviderInstance: "logic-provider", Title: "low",
		Description: "description", Recommendation: "recommendation", Confidence: domain.ConfidenceLow,
		Lifecycle: domain.FindingOpen, EvidenceState: domain.EvidenceUnverified,
		NormalizedRuleCategory: "low", NormalizedEvidenceRegion: "line one",
	})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: "sha256:" + target.SHA256(), Side: evidence.SideWorktree,
		Path: "internal/example.go", LineStart: 1, LineEnd: 1, Quote: "line one\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	unavailable, err := evidence.NewVerifier(publicationEvidenceReader{availability: evidence.ImmutableTargetUnavailable})
	if err != nil {
		t.Fatal(err)
	}
	unavailableReceipt, err := unavailable.VerifyCurrent(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	items, authoritative, err := reducePublicationEvidence(
		[]evidence.CurrentReceipt{unavailableReceipt}, make([]validation.VerifiedVisualReference, 1), finding, target, "F001",
	)
	if err != nil || authoritative || len(items) != 0 {
		t.Fatalf("allowed low patch exception = (%#v, %t, %v), want no authority or excerpts", items, authoritative, err)
	}

	verified, err := evidence.NewVerifier(publicationEvidenceReader{
		availability: evidence.ImmutableTargetAvailable, bytes: []byte("line one\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedReceipt, err := verified.VerifyCurrent(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reducePublicationEvidence(
		[]evidence.CurrentReceipt{verifiedReceipt, unavailableReceipt}, make([]validation.VerifiedVisualReference, 2), finding, target, "F001",
	); err == nil {
		t.Fatal("mixed evidence authority was accepted")
	}
}

type publicationEvidenceReader struct {
	availability evidence.ImmutableTargetAvailability
	bytes        []byte
}

func (reader publicationEvidenceReader) ReadImmutableTarget(
	context.Context,
	string,
	evidence.Side,
	ports.SafeRelativePath,
) (evidence.ImmutableTargetAvailability, []byte, error) {
	return reader.availability, append([]byte(nil), reader.bytes...), nil
}
func TestPrepareNoChangeCandidateSerializesZeroAttempts(t *testing.T) {
	t.Parallel()

	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetGit, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		RepositoryID: "repository:test", BaseObjectID: strings.Repeat("a", 40),
		HeadObjectID: strings.Repeat("b", 40), HeadTreeObjectID: strings.Repeat("c", 40),
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := PrepareNoChangeCandidate(sessionID, runID, target,
		[]domain.Role{domain.RoleLogic, domain.RoleSecurity}, domain.SeverityHigh, NoChangeProvenance{
			BuildProduct: "kar", BuildVersion: "test", BuildCommit: "0123456789abcdef",
			SnapshotManifestSHA256:   "sha256:" + strings.Repeat("a", 64),
			WorkspaceTerminalReceipt: "workspace-terminal:v1:sha256:" + strings.Repeat("b", 64),
		})
	if err != nil {
		t.Fatal(err)
	}
	if !candidate.Valid() {
		t.Fatal("no-change candidate is invalid")
	}
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var final finalReviewWire
	var manifest runManifestWire
	if err := json.Unmarshal(bundle.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Attempts) != 0 || len(final.Findings) != 0 || len(final.RoleOutcomes) != 2 {
		t.Fatalf("no-change publication retained attempts, findings, or roles: %#v", manifest)
	}
	for _, role := range final.RoleOutcomes {
		if role.Outcome != "not_applicable" || role.AttemptID != nil || role.ProviderInstance != nil || role.SelectedVia != nil {
			t.Fatalf("role outcome is not provider-free: %#v", role)
		}
	}
}

func TestProductionPublicationContextCopiesAndRejectsIncompleteProvenance(t *testing.T) {
	t.Parallel()
	provenance := ProductionReviewProvenance{
		BuildProduct: "kar", BuildVersion: "1.9.0", BuildCommit: "abc123",
		SnapshotManifestSHA256: sha256Identifier([]byte("snapshot")), WorkspaceTerminalReceipt: sha256Identifier([]byte("workspace-terminal")),
		Providers: []ProductionProviderProvenance{{
			Family: "kimi", Instance: "kimi-main", Version: "0.23.6", Executable: "/private/bin/kimi",
			ExecutableSHA256: sha256Identifier([]byte("kimi")), Launcher: "/private/bin/kimi",
			LauncherSHA256: sha256Identifier([]byte("kimi")), ProfileGeneration: "generation", AdapterProfile: "kimi-default",
			QualificationReceiptIDs: []string{sha256Identifier([]byte("qualification"))}, PacketTransportReceiptIDs: []string{sha256Identifier([]byte("transport"))},
			NamespaceTerminalReceipt: sha256Identifier([]byte("namespace-terminal")),
		}},
	}
	context, err := NewProductionPublicationContext(provenance)
	if err != nil {
		t.Fatal(err)
	}
	provenance.Providers[0].QualificationReceiptIDs[0] = sha256Identifier([]byte("mutated"))
	if got := context.immutableProductionProvenance().Providers[0].QualificationReceiptIDs[0]; got != sha256Identifier([]byte("qualification")) {
		t.Fatalf("context retained caller mutation: %q", got)
	}
	incomplete := provenance
	incomplete.Providers[0].NamespaceTerminalReceipt = ""
	if _, err := NewProductionPublicationContext(incomplete); err == nil {
		t.Fatal("incomplete production provenance was accepted")
	}
}
func TestPreparedCandidateRejectsMalformedAndUnvalidatedBuild(t *testing.T) {
	t.Parallel()
	candidate := PreparedCandidate{}
	if candidate.Valid() {
		t.Fatal("zero candidate is valid")
	}
	reviewID := publicationTestReviewID(t)
	validator := &publicationTestValidator{}
	if _, err := candidate.Build(context.Background(), validator, reviewID, publicationTestTime(), 1); err == nil {
		t.Fatal("Build accepted an unvalidated candidate")
	}
	if len(validator.ids) != 0 {
		t.Fatalf("validator saw %d schemas for invalid candidate", len(validator.ids))
	}

	valid := publicationTestCandidate(t, false)
	valid.roles[0].validFindingIDs = []string{"F002"}
	if valid.Valid() {
		t.Fatal("candidate with malformed finding binding is valid")
	}
	if _, err := valid.Build(context.Background(), validator, reviewID, publicationTestTime(), 1); err == nil {
		t.Fatal("Build accepted malformed candidate")
	}
}
func TestRunSupportArtifactIdentityRecognizesOnlyCanonicalPromptManifests(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, false)
	attemptID := candidate.roles[0].attempts[0].id
	path, err := ports.NewSafeRelativePath(
		candidate.sessionID.String() + "/" + candidate.runID.String() +
			"/prompts/" + attemptID.String() + "/001-initial.manifest.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ports.NewImmutablePublicationArtifact(path, sha256Identifier([]byte("manifest")), []byte("manifest"))
	if err != nil {
		t.Fatal(err)
	}
	gotAttemptID, sequence, ok := runSupportArtifactIdentity(artifact).promptManifestBinding()
	if !ok || gotAttemptID != attemptID || sequence != 1 {
		t.Fatalf("prompt manifest binding = (%q, %d, %t), want (%q, 1, true)", gotAttemptID, sequence, ok, attemptID)
	}

	finalPath, err := ports.NewSafeRelativePath(candidate.sessionID.String() + "/" + candidate.runID.String() + "/review.json")
	if err != nil {
		t.Fatal(err)
	}
	finalArtifact, err := ports.NewImmutablePublicationArtifact(finalPath, sha256Identifier([]byte("final")), []byte("final"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := runSupportArtifactIdentity(finalArtifact).promptManifestBinding(); ok {
		t.Fatal("final-review identity accepted as a prompt manifest")
	}
}

func TestPreparedCandidateRejectsMismatchedExcerptIdentity(t *testing.T) {
	t.Parallel()
	candidate := publicationTestCandidate(t, true)
	candidate.findings[0].evidence[0].currentExcerptSHA256 = "sha256:" + strings.Repeat("c", 64)
	if candidate.Valid() {
		t.Fatal("candidate accepted excerpt bytes that do not match the verified excerpt identity")
	}
}
func TestPublicationBundleRejectsFinalManifestOutcomeMismatch(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, true)
	bundle, err := candidate.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	var manifest runManifestWire
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.CIDecision = string(domain.CIPass)
	bytes, err := marshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := ports.NewImmutablePublicationArtifact(
		bundle.Manifest().Path(),
		sha256Identifier(bytes),
		bytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle.manifest = replaced
	if bundle.Valid() {
		t.Fatal("bundle accepted a manifest whose CI axis differs from the final review")
	}
}
func TestPublicationBundleDerivesValidationStatusFromRepairedAttempts(t *testing.T) {
	t.Parallel()

	repaired := publicationTestCandidate(t, false)
	repaired.roles[0].repaired = true
	repairedBundle, err := repaired.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !repairedBundle.Valid() {
		t.Fatal("bundle with repaired final attempt is invalid")
	}

	var repairedManifest runManifestWire
	if err := json.Unmarshal(repairedBundle.Manifest().Bytes(), &repairedManifest); err != nil {
		t.Fatal(err)
	}
	repairedManifest.Attempts[0].ValidationState = "valid"
	repairedManifestBytes, err := marshalCanonical(repairedManifest)
	if err != nil {
		t.Fatal(err)
	}
	repairedManifestArtifact, err := ports.NewImmutablePublicationArtifact(
		repairedBundle.Manifest().Path(),
		sha256Identifier(repairedManifestBytes),
		repairedManifestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	repairedBundle.manifest = repairedManifestArtifact
	if repairedBundle.Valid() {
		t.Fatal("bundle accepted repaired status without repaired attempt facts")
	}

	unrepaired := publicationTestCandidate(t, false)
	unrepairedBundle, err := unrepaired.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	var unrepairedManifest runManifestWire
	if err := json.Unmarshal(unrepairedBundle.Manifest().Bytes(), &unrepairedManifest); err != nil {
		t.Fatal(err)
	}
	unrepairedManifest.Attempts[0].ValidationState = "repaired_valid"
	unrepairedManifestBytes, err := marshalCanonical(unrepairedManifest)
	if err != nil {
		t.Fatal(err)
	}
	unrepairedManifestArtifact, err := ports.NewImmutablePublicationArtifact(
		unrepairedBundle.Manifest().Path(),
		sha256Identifier(unrepairedManifestBytes),
		unrepairedManifestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	unrepairedBundle.manifest = unrepairedManifestArtifact
	if unrepairedBundle.Valid() {
		t.Fatal("bundle accepted valid status despite repaired attempt facts")
	}
}

func TestPublicationBundleRejectsUnderivedReportProjections(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, true)
	bundle, err := candidate.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	var final finalReviewWire
	if err := json.Unmarshal(bundle.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	final.CIReasonCodes = []string{"policy_evaluated"}
	final.Findings[0].Evidence[0].Current.Verification = "unverified"
	finalBytes, err := marshalCanonical(final)
	if err != nil {
		t.Fatal(err)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(
		bundle.Final().Identity().ReviewID(),
		bundle.Final().Identity().Path(),
		sha256Identifier(finalBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	finalArtifact, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	bundle.final = finalArtifact
	if bundle.Valid() {
		t.Fatal("bundle accepted underived CI reasons and evidence projection")
	}

	bundle, err = candidate.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	tamperedExcerptBytes := []byte("tampered excerpt")
	tamperedExcerpt, err := ports.NewImmutablePublicationArtifact(
		bundle.Excerpts()[0].Path(),
		sha256Identifier(tamperedExcerptBytes),
		tamperedExcerptBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle.excerpts[0] = tamperedExcerpt
	if bundle.Valid() {
		t.Fatal("bundle accepted an excerpt that does not match final evidence")
	}

	bundle, err = candidate.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	var manifest runManifestWire
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Warnings = []string{"unexpected warning"}
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestArtifact, err := ports.NewImmutablePublicationArtifact(
		bundle.Manifest().Path(),
		sha256Identifier(manifestBytes),
		manifestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle.manifest = manifestArtifact
	if bundle.Valid() {
		t.Fatal("bundle accepted G006 manifest warnings")
	}
}

func TestPreparedCandidateRejectsNonCanonicalAttemptSequences(t *testing.T) {
	t.Parallel()
	fallbackID, err := domain.ParseAttemptID("a_019f596a-d049-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	extraID, err := domain.ParseAttemptID("a_019f596a-d04a-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*PreparedCandidate)
	}{
		{
			name: "fallback without primary",
			mutate: func(candidate *PreparedCandidate) {
				candidate.roles[0].attempts[0].kind = review.AttemptKindFallback
			},
		},
		{
			name: "fallback after successful primary",
			mutate: func(candidate *PreparedCandidate) {
				fallback := candidate.roles[0].attempts[0]
				fallback.id = fallbackID
				fallback.kind = review.AttemptKindFallback
				candidate.roles[0].attempts = append(candidate.roles[0].attempts, fallback)
			},
		},
		{
			name: "more than primary and fallback",
			mutate: func(candidate *PreparedCandidate) {
				candidate.roles[0].attempts[0].state = domain.AttemptFailed
				fallback := candidate.roles[0].attempts[0]
				fallback.id = fallbackID
				fallback.kind = review.AttemptKindFallback
				extra := fallback
				extra.id = extraID
				candidate.roles[0].attempts = append(candidate.roles[0].attempts, fallback, extra)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := publicationTestCandidate(t, false)
			test.mutate(&candidate)
			if candidate.Valid() {
				t.Fatal("candidate accepted a non-canonical attempt sequence")
			}
		})
	}
}
func TestValidatedCandidateSHA256BindsRuntimeInventory(t *testing.T) {
	t.Parallel()

	baseline := publicationRuntimeCandidate(t)
	want := baseline.ValidatedCandidateSHA256()
	if want == "" {
		t.Fatal("runtime candidate has no validated identity")
	}

	cases := []struct {
		name   string
		mutate func(*testing.T, *PreparedCandidate)
	}{
		{"run", func(t *testing.T, candidate *PreparedCandidate) {
			runID, err := domain.ParseRunID("r_019f596a-dfe4-7c9c-b82e-7149158243ba")
			if err != nil {
				t.Fatal(err)
			}
			candidate.runID = runID
		}},
		{"attempt", func(t *testing.T, candidate *PreparedCandidate) {
			attemptID, err := domain.ParseAttemptID("a_019f596a-e048-79e7-b2b7-59822f012273")
			if err != nil {
				t.Fatal(err)
			}
			candidate.roles[0].attempts[0].id = attemptID
		}},
		{"sequence", appendPublicationRuntimeRepairInvocation},
		{"purpose", appendPublicationRuntimeRepairInvocation},
		{"role", func(t *testing.T, candidate *PreparedCandidate) {
			attemptID, err := domain.ParseAttemptID("a_019f596a-e0ac-7c12-8b68-0bd73e911b2e")
			if err != nil {
				t.Fatal(err)
			}
			role := candidate.roles[0]
			role.attempts = append([]preparedAttempt(nil), role.attempts...)
			role.attempts[0].invocations = append([]preparedInvocation(nil), role.attempts[0].invocations...)
			role.role = domain.RoleMaintainability
			role.required = false
			role.attempts[0].id = attemptID
			role.attempts[0].provider = "kimi-maintainability"
			role.attempts[0].invocations[0].runtime = clonePreparedRuntimeArtifact(role.attempts[0].invocations[0].runtime)
			role.attempts[0].invocations[0].runtime.role = role.role
			candidate.roles = append(candidate.roles, role)
		}},
		{"target bytes and digest", func(t *testing.T, candidate *PreparedCandidate) {
			runtime := candidate.roles[0].attempts[0].invocations[0].runtime
			runtime.target = []byte("other target\n")
			candidate.target.sha256 = sha256Identifier(runtime.target)
			runtime.targetSHA256 = strings.TrimPrefix(candidate.target.sha256, "sha256:")
		}},
		{"target identity kind, repository, base, head, tree, and index", func(t *testing.T, candidate *PreparedCandidate) {
			runtime := candidate.roles[0].attempts[0].invocations[0].runtime
			runtime.targetKind = domain.TargetGit
			runtime.targetRepository = "github.com/irootkernel/kkachi-agent-review"
			runtime.targetBaseOID = strings.Repeat("d", 64)
			runtime.targetHeadOID = strings.Repeat("e", 64)
			runtime.targetHeadTreeOID = strings.Repeat("f", 64)
			runtime.targetIndexTreeOID = strings.Repeat("a", 64)
			candidate.target.baseOID = runtime.targetBaseOID
			candidate.target.headOID = runtime.targetHeadOID
		}},
		{"stdin and digest", func(t *testing.T, candidate *PreparedCandidate) {
			runtime := candidate.roles[0].attempts[0].invocations[0].runtime
			runtime.stdin = []byte("other stdin")
			runtime.stdinSHA256 = prompt.CompleteStdinSHA256(runtime.stdin)
		}},
		{"template ID", func(t *testing.T, candidate *PreparedCandidate) {
			candidate.roles[0].attempts[0].invocations[0].runtime.templateID = "other-template"
		}},
		{"template version", func(t *testing.T, candidate *PreparedCandidate) {
			candidate.roles[0].attempts[0].invocations[0].runtime.templateVersion = "v2"
		}},
		{"template hash", func(t *testing.T, candidate *PreparedCandidate) {
			candidate.roles[0].attempts[0].invocations[0].runtime.templateSHA256 = "sha256:" + strings.Repeat("b", 64)
		}},
		{"source invocation ID", func(t *testing.T, candidate *PreparedCandidate) {
			candidate.roles[0].attempts[0].invocations[0].runtime.sourceInvocationID = "source-2"
		}},
		{"execution invocation ID", func(t *testing.T, candidate *PreparedCandidate) {
			candidate.roles[0].attempts[0].invocations[0].runtime.executionInvocationID = "execution-2"
		}},
		{"scope", func(t *testing.T, candidate *PreparedCandidate) {
			candidate.roles[0].attempts[0].invocations[0].runtime.scope = "scope-2"
		}},
		{"adapter profile", func(t *testing.T, candidate *PreparedCandidate) {
			candidate.roles[0].attempts[0].invocations[0].runtime.adapterProfile = "profile-2"
		}},
		{"sorted adapter parameter key and value", func(t *testing.T, candidate *PreparedCandidate) {
			candidate.roles[0].attempts[0].invocations[0].runtime.adapterParameters = map[string]string{
				"model": "other", "temperature": "0.2", "top_p": "0.9",
			}
		}},
		{"capture kind", appendPublicationRuntimeRepairInvocation},
		{"capture security flag and bytes", func(t *testing.T, candidate *PreparedCandidate) {
			artifact := &candidate.roles[0].attempts[0].invocations[0].artifacts[0]
			artifact.securityRejected = true
			artifact.bytes = nil
		}},
		{"capture bytes", func(t *testing.T, candidate *PreparedCandidate) {
			candidate.roles[0].attempts[0].invocations[0].artifacts[0].bytes = []byte("other capture")
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := publicationRuntimeCandidate(t)
			test.mutate(t, &candidate)
			if !candidate.Valid() {
				t.Fatalf("%s produced an invalid candidate", test.name)
			}
			if got := candidate.ValidatedCandidateSHA256(); got == "" || got == want {
				t.Fatalf("%s candidate identity = %q, want nonempty value distinct from baseline", test.name, got)
			}
		})
	}
}
func TestValidatedCandidateSHA256BindsProductionProvenance(t *testing.T) {
	t.Parallel()

	baseline := publicationTestCandidate(t, false)
	want := baseline.ValidatedCandidateSHA256()
	cases := []struct {
		name   string
		mutate func(*PreparedCandidate)
	}{
		{"build product", func(c *PreparedCandidate) { c.production.BuildProduct = "other-kar" }},
		{"build version", func(c *PreparedCandidate) { c.production.BuildVersion, c.kar.version = "0.2.0", "0.2.0" }},
		{"build commit", func(c *PreparedCandidate) {
			c.production.BuildCommit, c.kar.commit = "fedcba9876543210", "fedcba9876543210"
		}},
		{"objective digest", func(c *PreparedCandidate) { c.production.ObjectiveSHA256 = sha256Identifier([]byte("other objective")) }},
		{"objective presence", func(c *PreparedCandidate) { c.production.HasObjective, c.production.ObjectiveSHA256 = false, "" }},
		{"snapshot digest", func(c *PreparedCandidate) {
			c.production.SnapshotManifestSHA256 = sha256Identifier([]byte("other snapshot"))
		}},
		{"workspace receipt", func(c *PreparedCandidate) {
			c.production.WorkspaceTerminalReceipt = sha256Identifier([]byte("other workspace"))
		}},
		{"family", func(c *PreparedCandidate) { c.production.Providers[0].Family = "aaa" }},
		{"instance", func(c *PreparedCandidate) { c.production.Providers[0].Instance = "agy-other" }},
		{"provider version", func(c *PreparedCandidate) { c.production.Providers[0].Version = "2.0.0" }},
		{"executable", func(c *PreparedCandidate) { c.production.Providers[0].Executable = "/private/bin/other-agy" }},
		{"executable digest", func(c *PreparedCandidate) {
			c.production.Providers[0].ExecutableSHA256 = sha256Identifier([]byte("other executable"))
		}},
		{"launcher", func(c *PreparedCandidate) { c.production.Providers[0].Launcher = "/private/bin/other-launcher" }},
		{"launcher digest", func(c *PreparedCandidate) {
			c.production.Providers[0].LauncherSHA256 = sha256Identifier([]byte("other launcher"))
		}},
		{"profile generation", func(c *PreparedCandidate) { c.production.Providers[0].ProfileGeneration = "generation-2" }},
		{"adapter profile", func(c *PreparedCandidate) { c.production.Providers[0].AdapterProfile = "other-profile" }},
		{"qualification receipt", func(c *PreparedCandidate) {
			c.production.Providers[0].QualificationReceiptIDs[0] = sha256Identifier([]byte("other qualification"))
		}},
		{"packet receipt", func(c *PreparedCandidate) {
			c.production.Providers[0].PacketTransportReceiptIDs[0] = sha256Identifier([]byte("other transport"))
		}},
		{"namespace receipt", func(c *PreparedCandidate) {
			c.production.Providers[0].NamespaceTerminalReceipt = sha256Identifier([]byte("other namespace"))
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := publicationTestCandidate(t, false)
			test.mutate(&candidate)
			if !candidate.Valid() {
				t.Fatal("mutation produced an invalid candidate")
			}
			if got := candidate.ValidatedCandidateSHA256(); got == want {
				t.Fatal("production mutation did not change candidate digest")
			}
		})
	}
}

func appendPublicationRuntimeRepairInvocation(t *testing.T, candidate *PreparedCandidate) {
	t.Helper()
	invocation := candidate.roles[0].attempts[0].invocations[0]
	invocation.sequence = 2
	invocation.purpose = domain.InvocationRepair
	invocation.runtime = clonePreparedRuntimeArtifact(invocation.runtime)
	invocation.artifacts = []preparedAttemptArtifact{{
		kind: ports.AttemptArtifactRepairedCandidate, bytes: []byte("repaired capture"),
	}}
	candidate.roles[0].attempts[0].invocations = append(candidate.roles[0].attempts[0].invocations, invocation)
}

func clonePreparedRuntimeArtifact(runtime *preparedRuntimeArtifact) *preparedRuntimeArtifact {
	cloned := *runtime
	cloned.target = append([]byte(nil), runtime.target...)
	cloned.capturedArchive = append([]byte(nil), runtime.capturedArchive...)
	cloned.stdin = append([]byte(nil), runtime.stdin...)
	cloned.adapterParameters = make(map[string]string, len(runtime.adapterParameters))
	for key, value := range runtime.adapterParameters {
		cloned.adapterParameters[key] = value
	}
	return &cloned
}

func publicationRuntimeCandidate(t *testing.T) PreparedCandidate {
	t.Helper()
	candidate := publicationTestCandidate(t, false)
	target := []byte("reviewed line\n")
	for roleIndex := range candidate.roles {
		invocation := &candidate.roles[roleIndex].attempts[0].invocations[0]
		stdin := []byte("provider stdin")
		invocation.runtime = &preparedRuntimeArtifact{
			target: target, targetSHA256: strings.TrimPrefix(candidate.target.sha256, "sha256:"),
			targetKind: domain.TargetPatch, stdin: stdin, stdinSHA256: prompt.CompleteStdinSHA256(stdin),
			templateID: "review", templateVersion: "v1", templateSHA256: "sha256:" + strings.Repeat("c", 64),
			sourceInvocationID: "source-1", executionInvocationID: "execution-1", scope: "repository",
			role: candidate.roles[roleIndex].role, adapterProfile: "default", adapterParameters: map[string]string{"model": "trusted"},
		}
		invocation.artifacts = []preparedAttemptArtifact{{kind: ports.AttemptArtifactInitialCandidate, bytes: []byte("captured candidate")}}
	}
	return candidate
}
func publicationTestCandidate(t *testing.T, withFinding bool) PreparedCandidate {
	t.Helper()
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	logicAttempt, err := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	securityAttempt, err := domain.ParseAttemptID("a_019f596a-d0ac-7c12-8b68-0bd73e911b2e")
	if err != nil {
		t.Fatal(err)
	}
	shaA := sha256Identifier([]byte("reviewed line\n"))
	excerptBytes := []byte("reviewed line\n")
	excerptClaim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: shaA,
		Side:         evidence.SideHead,
		Path:         "internal/app/review.go",
		LineStart:    1,
		LineEnd:      1,
		Quote:        string(excerptBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	excerptSHA256, err := excerptClaim.ExcerptSHA256(excerptBytes)
	if err != nil {
		t.Fatal(err)
	}
	roles := []preparedRole{
		{
			role: domain.RoleLogic, required: true, state: domain.RoleTaskSucceeded, valid: true, outcome: "completed",
			attempts: []preparedAttempt{{
				id: logicAttempt, kind: review.AttemptKindPrimary, provider: "kimi-logic", state: domain.AttemptSucceeded,
				invocations: []preparedInvocation{{sequence: 1, purpose: domain.InvocationInitial, state: domain.InvocationSucceeded}},
			}},
			validFindingIDs: []string{}, limitations: []string{},
		},
		{
			role: domain.RoleSecurity, required: true, state: domain.RoleTaskSucceeded, valid: true, outcome: "completed",
			attempts: []preparedAttempt{{
				id: securityAttempt, kind: review.AttemptKindPrimary, provider: "agy-security", state: domain.AttemptSucceeded,
				invocations: []preparedInvocation{{sequence: 1, purpose: domain.InvocationInitial, state: domain.InvocationSucceeded}},
			}},
			validFindingIDs: []string{}, limitations: []string{},
		},
	}
	candidate := PreparedCandidate{
		sessionID: sessionID,
		runID:     runID,
		runState:  domain.RunCompleted,
		target: preparedTarget{
			sha256: shaA,
		},
		threshold: domain.SeverityHigh,
		kar:       preparedKAR{version: "0.1.0", commit: "0123456789abcdef"},
		production: &ProductionReviewProvenance{
			BuildProduct: "kar", BuildVersion: "0.1.0", BuildCommit: "0123456789abcdef",
			ObjectiveSHA256: sha256Identifier([]byte("objective")), HasObjective: true,
			SnapshotManifestSHA256:   sha256Identifier([]byte("snapshot")),
			WorkspaceTerminalReceipt: sha256Identifier([]byte("workspace-terminal")),
			Providers: []ProductionProviderProvenance{
				{Family: "agy", Instance: "agy-security", Version: "1.1.4", Executable: "/private/bin/agy", ExecutableSHA256: sha256Identifier([]byte("agy")), Launcher: "/private/bin/agy", LauncherSHA256: sha256Identifier([]byte("agy")), ProfileGeneration: "generation-1", AdapterProfile: "agy-default", QualificationReceiptIDs: []string{sha256Identifier([]byte("agy-qualification"))}, PacketTransportReceiptIDs: []string{sha256Identifier([]byte("agy-transport"))}, NamespaceTerminalReceipt: sha256Identifier([]byte("agy-terminal"))},
				{Family: "kimi", Instance: "kimi-logic", Version: "0.23.6", Executable: "/private/bin/kimi", ExecutableSHA256: sha256Identifier([]byte("kimi")), Launcher: "/private/bin/kimi", LauncherSHA256: sha256Identifier([]byte("kimi")), ProfileGeneration: "generation-1", AdapterProfile: "kimi-default", QualificationReceiptIDs: []string{sha256Identifier([]byte("kimi-qualification"))}, PacketTransportReceiptIDs: []string{sha256Identifier([]byte("kimi-transport"))}, NamespaceTerminalReceipt: sha256Identifier([]byte("kimi-terminal"))},
			},
		},
		axes:     preparedAxes{content: domain.ContentNoFindings, coverage: domain.CoverageComplete, ci: domain.CIPass},
		roles:    roles,
		findings: []preparedFinding{},
		failures: []preparedFailure{},
		limits:   []string{},
		reasons:  []string{"policy_evaluated"},
		exitCode: int(domain.ExitCommittedPass),
	}
	if withFinding {
		candidate.axes = preparedAxes{content: domain.ContentRequestChanges, coverage: domain.CoverageComplete, ci: domain.CIFail}
		candidate.reasons = []string{"request_changes_threshold"}
		candidate.exitCode = int(domain.ExitCommittedCIRejected)
		candidate.roles[0].validFindingIDs = []string{"F001"}
		candidate.findings = []preparedFinding{{
			id: "F001", fingerprint: "sha256:" + strings.Repeat("b", 64), role: domain.RoleLogic, provider: "kimi-logic",
			severity: domain.SeverityHigh, title: "Trusted finding", description: "The verifier accepted this evidence.",
			recommendation: "Correct the reviewed implementation.", confidence: domain.ConfidenceHigh, lifecycle: domain.FindingOpen,
			evidence: []preparedEvidence{{
				targetSHA256: shaA, side: evidence.SideHead, path: "internal/app/review.go", lineStart: 1, lineEnd: 1,
				quote: string(excerptBytes), currentExcerptSHA256: excerptSHA256, excerpt: excerptBytes,
			}},
		}}
	}
	if err := candidate.validate(); err != nil {
		t.Fatalf("test candidate is not valid: %v", err)
	}
	return candidate
}

func publicationTestReviewID(t *testing.T) domain.ReviewID {
	t.Helper()
	id, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func publicationTestTime() time.Time {
	return time.Date(2026, time.July, 13, 3, 0, 0, 500000000, time.UTC)
}
