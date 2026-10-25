package publication

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestBuildAbsentLiveRefusalPreservesProloguePrecedence(t *testing.T) {
	live := retainedLiveCandidate(t, false)
	if _, err := live.Build(context.Background(), retainedSchema(t), publicationTestReviewID(t), publicationTestTime(), 1); err != nil {
		t.Fatalf("live positive control: %v", err)
	}
	absent := retainedLiveCandidate(t, false)
	absent.target.live = nil
	if !absent.Valid() {
		t.Fatal("absent-live guard input failed an earlier candidate invariant")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name                                                           string
		ctx                                                            context.Context
		nilValidator, invalidCandidate, invalidID, zeroTime, zeroEpoch bool
		want                                                           string
	}{
		{name: "nil context", want: "context is required"},
		{name: "canceled context", ctx: canceled, want: "context canceled"},
		{name: "nil validator", ctx: context.Background(), nilValidator: true, want: "schema validator is required"},
		{name: "invalid candidate", ctx: context.Background(), invalidCandidate: true, want: "candidate is not prevalidated"},
		{name: "invalid review ID", ctx: context.Background(), invalidID: true, want: "review ID"},
		{name: "zero created time", ctx: context.Background(), zeroTime: true, want: "created time is required"},
		{name: "zero epoch", ctx: context.Background(), zeroEpoch: true, want: "epoch must be positive"},
		{name: "absent live source", ctx: context.Background(), want: "live source is required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, binding := range []string{"Build", "live builder bind"} {
				t.Run(binding, func(t *testing.T) {
					candidate := absent
					if test.invalidCandidate {
						candidate.runID = domain.RunID{}
					}
					id, created, epoch := publicationTestReviewID(t), publicationTestTime(), uint64(1)
					if test.invalidID {
						id = domain.ReviewID{}
					}
					if test.zeroTime {
						created = time.Time{}
					}
					if test.zeroEpoch {
						epoch = 0
					}
					schema := retainedSchema(t)
					var validator SchemaValidator = schema
					if test.nilValidator {
						validator = nil
					}
					var err error
					if binding == "Build" {
						_, err = candidate.Build(test.ctx, validator, id, created, epoch)
					} else {
						// Force the internal boundary directly; the public live
						// wrapper already refuses this absent-live value.
						builder := &livePublicationBuilder{candidate: candidate}
						_, err = builder.bind(test.ctx, validator, id, created, epoch)
					}
					if err == nil || !strings.Contains(publicationErrorChainText(err), test.want) || len(schema.ids) != 0 {
						t.Fatalf("prologue refusal = %v; schemas=%d; want %s", err, len(schema.ids), test.want)
					}
					if test.name == "absent live source" {
						diagnostic, ok := FailureDiagnosticFromError(err)
						if !ok || diagnostic.Phase() != domain.DiagnosticPhasePublicationCandidate || diagnostic.Cause() != domain.DiagnosticCausePublicationCandidateInvalid {
							t.Fatalf("absent-live diagnostic = %#v", diagnostic)
						}
					}
				})
			}
		})
	}
}

// Synthetic shared-validation input, not original-source/provider product proof.
// M_test=1: TASK-065 and contracts retain live validation/publication authority.
func retainedLiveCandidate(t *testing.T, withFinding bool) PreparedCandidate {
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
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	path, err := ports.NewSafeRelativePath("internal/app/review.go")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	shaA := identity.SHA256()
	excerptBytes := []byte("reviewed line\n")
	excerptClaim, err := evidence.NewLiveClaim(identity, evidence.SideWorktree, path.String(), 1, 1, string(excerptBytes))
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
				id: logicAttempt, kind: review.AttemptKindPrimary, provider: "zcode-logic", state: domain.AttemptSucceeded,
				parseState: domain.ParseValid, validationState: domain.ValidationValid,
				invocations: []preparedInvocation{{sequence: 1, purpose: domain.InvocationInitial, state: domain.InvocationSucceeded}},
			}},
			validFindingIDs: []string{}, limitations: []string{},
			reportMarkdown:  []byte("# logic review\n\nStructured provider review accepted.\n"),
			outputTransport: ports.ProviderOutputTransportStdout,
		},
		{
			role: domain.RoleSecurity, required: true, state: domain.RoleTaskSucceeded, valid: true, outcome: "completed",
			attempts: []preparedAttempt{{
				id: securityAttempt, kind: review.AttemptKindPrimary, provider: "grok-security", state: domain.AttemptSucceeded,
				parseState: domain.ParseValid, validationState: domain.ValidationValid,
				invocations: []preparedInvocation{{sequence: 1, purpose: domain.InvocationInitial, state: domain.InvocationSucceeded}},
			}},
			validFindingIDs: []string{}, limitations: []string{},
			reportMarkdown:  []byte("# security review\n\nStructured provider review accepted.\n"),
			outputTransport: ports.ProviderOutputTransportStdout,
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
		mulgae:    preparedMulgae{version: "0.1.0", commit: "0123456789abcdef"},

		axes: preparedAxes{
			content: domain.ContentNoFindings, coverage: domain.CoverageComplete, ci: domain.CIPass,
			structuredExtraction: domain.StructuredExtractionStructured,
		},
		roles:    roles,
		findings: []preparedFinding{},
		failures: []preparedFailure{},
		limits:   []string{},
		reasons:  []string{"policy_evaluated"},
		exitCode: int(domain.ExitCommittedPass),
	}
	provenance := LiveProductionProvenance{BuildProduct: "mulgae", BuildVersion: "0.1.0", BuildCommit: "0123456789abcdef", SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:" + sha256Identifier([]byte("workspace-terminal")), Providers: retainedProviderProvenance()}
	source, err := prepareLiveSource(target, provenance, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate.target.live = source
	if withFinding {
		candidate.axes = preparedAxes{
			content: domain.ContentRequestChanges, coverage: domain.CoverageComplete, ci: domain.CIFail,
			structuredExtraction: domain.StructuredExtractionStructured,
		}
		candidate.reasons = []string{"request_changes_threshold"}
		candidate.exitCode = int(domain.ExitCommittedCIRejected)
		candidate.roles[0].validFindingIDs = []string{"F001"}
		candidate.findings = []preparedFinding{{
			id: "F001", fingerprint: "sha256:" + strings.Repeat("b", 64), role: domain.RoleLogic, provider: "zcode-logic",
			severity: domain.SeverityHigh, title: "Trusted finding", description: "The verifier accepted this evidence.",
			recommendation: "Correct the reviewed implementation.", confidence: domain.ConfidenceHigh, lifecycle: domain.FindingOpen,
			evidence: []preparedEvidence{{
				targetSHA256: shaA, liveSource: identity, side: evidence.SideWorktree, path: "internal/app/review.go", lineStart: 1, lineEnd: 1,
				quote: string(excerptBytes), currentExcerptSHA256: excerptSHA256, excerpt: excerptBytes,
			}},
		}}
	}
	if err := candidate.validate(); err != nil {
		t.Fatalf("test candidate is not valid: %v", err)
	}
	return candidate
}

func retainedProviderProvenance() []ProductionProviderProvenance {
	return []ProductionProviderProvenance{
		{Family: "grok", Instance: "grok-security", Version: "1.0.30", Executable: "/private/bin/grok", ExecutableSHA256: sha256Identifier([]byte("grok")), Launcher: "/private/bin/grok", LauncherSHA256: sha256Identifier([]byte("grok")), ProfileGeneration: "generation-1", AdapterProfile: "grok-default", QualificationReceiptIDs: []string{sha256Identifier([]byte("grok-qualification"))}, PacketTransportReceiptIDs: []string{sha256Identifier([]byte("grok-transport"))}, NamespaceTerminalReceipt: sha256Identifier([]byte("grok-terminal"))},
		{Family: "zcode", Instance: "zcode-logic", Version: "0.16.5", Executable: "/usr/bin/node", ExecutableSHA256: sha256Identifier([]byte("node")), Launcher: "/private/bin/zcode.cjs", LauncherSHA256: sha256Identifier([]byte("zcode")), ProfileGeneration: "generation-1", AdapterProfile: "zcode-default", QualificationReceiptIDs: []string{sha256Identifier([]byte("zcode-qualification"))}, PacketTransportReceiptIDs: []string{sha256Identifier([]byte("zcode-transport"))}, NamespaceTerminalReceipt: sha256Identifier([]byte("zcode-terminal"))},
	}
}

func TestRetainedLivePreparedCandidateRejectsMalformedAndUnvalidatedBuild(t *testing.T) {
	t.Parallel()
	candidate := PreparedCandidate{}
	if candidate.Valid() {
		t.Fatal("zero candidate is valid")
	}
	reviewID := publicationTestReviewID(t)
	validator := retainedSchema(t)
	if _, err := candidate.Build(context.Background(), validator, reviewID, publicationTestTime(), 1); err == nil {
		t.Fatal("Build accepted an unvalidated candidate")
	}
	if len(validator.ids) != 0 {
		t.Fatalf("validator saw %d schemas for invalid candidate", len(validator.ids))
	}

	valid := retainedLiveCandidate(t, false)
	valid.roles[0].validFindingIDs = []string{"F002"}
	if valid.Valid() {
		t.Fatal("candidate with malformed finding binding is valid")
	}
	if _, err := valid.Build(context.Background(), validator, reviewID, publicationTestTime(), 1); err == nil {
		t.Fatal("Build accepted malformed candidate")
	}
}

// TestPreparedCandidateRejectsASecondAttemptForOneRole pins the one-provider
// rule at the publication boundary. A role runs its provider once and may repair
// within that attempt, so a live candidate can never carry a second attempt.
// Manifests written before the rule can, and stay readable; see the manifest
// validation in internal/app/query.
func TestRetainedLivePreparedCandidateRejectsASecondAttemptForOneRole(t *testing.T) {
	t.Parallel()

	candidate := retainedLiveCandidate(t, false)
	secondID, err := domain.ParseAttemptID("a_019f596a-d049-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	first := &candidate.roles[0].attempts[0]
	first.state = domain.AttemptFailed
	first.parseState = domain.ParseNotStarted
	first.validationState = domain.ValidationNotStarted
	first.invocations[0].state = domain.InvocationFailed
	second := *first
	second.id = secondID
	second.provider = "zcode-logic"
	second.state = domain.AttemptSucceeded
	second.parseState = domain.ParseValid
	second.validationState = domain.ValidationValid
	second.invocations = []preparedInvocation{{
		sequence: 1, purpose: domain.InvocationInitial, state: domain.InvocationSucceeded,
	}}
	candidate.roles[0].attempts = append(candidate.roles[0].attempts, second)
	candidate.failures = []preparedFailure{{
		class: domain.FailureInvalidOutput, stage: "review",
		reason: string(review.AttemptConditionInvalidProviderOutput), attemptID: &first.id,
	}}

	if err := candidate.validate(); err == nil {
		t.Fatal("a candidate carrying two attempts for one role was accepted")
	}
}

func TestRetainedLiveRunSupportArtifactIdentityRecognizesOnlyCanonicalPromptManifests(t *testing.T) {
	t.Parallel()

	candidate := retainedLiveCandidate(t, false)
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

func TestRetainedLivePreparedCandidateRejectsMismatchedExcerptIdentity(t *testing.T) {
	t.Parallel()
	candidate := retainedLiveCandidate(t, true)
	candidate.findings[0].evidence[0].currentExcerptSHA256 = "sha256:" + strings.Repeat("c", 64)
	if candidate.Valid() {
		t.Fatal("candidate accepted excerpt bytes that do not match the verified excerpt identity")
	}
}
func TestRetainedLivePublicationBundleRejectsFinalManifestOutcomeMismatch(t *testing.T) {
	t.Parallel()

	candidate := retainedLiveCandidate(t, true)
	bundle, err := candidate.Build(
		context.Background(),
		retainedSchema(t),
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

func TestRetainedLivePreparedCandidateRejectsReportsOnlyFlagMismatch(t *testing.T) {
	t.Parallel()
	candidate := retainedLiveCandidate(t, false)
	candidate.roles[0].reportsOnly = true
	candidate.axes.structuredExtraction = domain.StructuredExtractionMixed
	if candidate.Valid() {
		t.Fatal("candidate accepted reportsOnly that disagrees with terminal attempt extraction")
	}
}

func TestRetainedLivePublicationBundleRejectsStructuredExtractionStatusMismatch(t *testing.T) {
	t.Parallel()
	candidate := retainedLiveCandidate(t, false)
	bundle, err := candidate.Build(
		context.Background(),
		retainedSchema(t),
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
	final.StructuredExtractionStatus = string(domain.StructuredExtractionReportsOnly)
	final.ContentVerdict = string(domain.ContentReportsOnly)
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

	var manifest runManifestWire
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.StructuredExtractionStatus = string(domain.StructuredExtractionReportsOnly)
	manifest.ContentVerdict = string(domain.ContentReportsOnly)
	manifest.FinalReview.SHA256 = finalIdentity.SHA256()
	manifest.RecoveryJournal.ExpectedFinal.SHA256 = finalIdentity.SHA256()
	manifest.RecoveryJournal.ExpectedStaged.SHA256 = finalIdentity.SHA256()
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestArtifact, err := ports.NewImmutablePublicationArtifact(
		bundle.Manifest().Path(), sha256Identifier(manifestBytes), manifestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	epochBytes, err := marshalCanonical(publicationEpochWire{
		SchemaVersion: publicationEpochV1,
		StoreEpoch:    bundle.Epoch().Value(),
		Manifest:      artifactIdentityWire{Path: manifestArtifact.Path().String(), SHA256: manifestArtifact.SHA256()},
		LineageEdge: artifactIdentityWire{
			Path: bundle.LineageEdge().Path().String(), SHA256: bundle.LineageEdge().SHA256(),
		},
		FinalReview: artifactIdentityWire{
			Path: finalIdentity.Path().String(), SHA256: finalIdentity.SHA256(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	epochRecord, err := ports.NewImmutablePublicationArtifact(
		bundle.Epoch().Record().Path(), sha256Identifier(epochBytes), epochBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := ports.NewPublicationEpoch(bundle.Epoch().Value(), epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePublicationCompositeSemantics(
		finalArtifact, manifestArtifact, bundle.LineageEdge(), epoch,
	); err == nil {
		t.Fatal("composite reopen accepted top-level SES that disagrees with terminal attempt extraction")
	}
}

func TestRetainedLivePrepareReportsOnlyRepairExhaustedCandidatePublishes(t *testing.T) {
	t.Parallel()
	candidate := retainedLiveCandidate(t, false)
	primaryReport := []byte("# logic\n\nOriginal free-form assistant report.\n")
	for index := range candidate.roles {
		role := &candidate.roles[index]
		role.reportsOnly = true
		role.validFindingIDs = nil
		role.reportMarkdown = append([]byte(nil), primaryReport...)
		role.attempts[0].parseState = domain.ParseInvalidJSON
		role.attempts[0].validationState = domain.ValidationRepairExhausted
		role.attempts[0].invocations = []preparedInvocation{
			{sequence: 1, purpose: domain.InvocationInitial, state: domain.InvocationSucceeded},
			{sequence: 2, purpose: domain.InvocationRepair, state: domain.InvocationSucceeded},
		}
	}
	candidate.findings = nil
	candidate.axes = preparedAxes{
		content: domain.ContentReportsOnly, coverage: domain.CoverageComplete, ci: domain.CIPass,
		structuredExtraction: domain.StructuredExtractionReportsOnly,
	}
	candidate.reasons = []string{"policy_evaluated"}
	candidate.exitCode = int(domain.ExitCommittedPass)
	if !candidate.Valid() {
		t.Fatal("reports-only repair-exhausted candidate is invalid")
	}
	bundle, err := candidate.Build(
		context.Background(),
		retainedSchema(t),
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !bundle.Valid() {
		t.Fatal("reports-only repair-exhausted bundle failed semantic reopen")
	}
	var final finalReviewWire
	var manifest runManifestWire
	if err := json.Unmarshal(bundle.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if final.Validation.Status != "valid" {
		t.Fatalf("final validation status = %q, want valid", final.Validation.Status)
	}
	if final.StructuredExtractionStatus != string(domain.StructuredExtractionReportsOnly) ||
		manifest.StructuredExtractionStatus != string(domain.StructuredExtractionReportsOnly) ||
		final.ContentVerdict != string(domain.ContentReportsOnly) {
		t.Fatalf("reports-only axes drifted: final=%#v manifest=%#v", final, manifest)
	}
	for _, attempt := range manifest.Attempts {
		if attempt.ValidationState != string(domain.ValidationRepairExhausted) ||
			attempt.ParseState != string(domain.ParseInvalidJSON) {
			t.Fatalf("attempt extraction facts drifted: %#v", attempt)
		}
	}
	for _, report := range manifest.RoleReports {
		if report.ByteLength != len(primaryReport) {
			t.Fatalf("role report did not preserve original assistant bytes: %#v", report)
		}
	}
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/role-reports/"
	for _, excerpt := range bundle.Excerpts() {
		path := excerpt.Path().String()
		if len(path) > len(prefix) && path[:len(prefix)] == prefix {
			if string(excerpt.Bytes()) != string(primaryReport) {
				t.Fatalf("published role report bytes = %q, want original assistant content", excerpt.Bytes())
			}
		}
	}
}
func TestRetainedLivePublicationBundleDerivesValidationStatusFromRepairedAttempts(t *testing.T) {
	t.Parallel()

	repaired := retainedLiveCandidate(t, false)
	repaired.roles[0].repaired = true
	repaired.roles[0].attempts[0].validationState = domain.ValidationRepairedValid
	repairedBundle, err := repaired.Build(
		context.Background(),
		retainedSchema(t),
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

	unrepaired := retainedLiveCandidate(t, false)
	unrepairedBundle, err := unrepaired.Build(
		context.Background(),
		retainedSchema(t),
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

func TestRetainedLivePublicationBundleRejectsUnderivedReportProjections(t *testing.T) {
	t.Parallel()

	candidate := retainedLiveCandidate(t, true)
	bundle, err := candidate.Build(
		context.Background(),
		retainedSchema(t),
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
	if err := validateFinalReportSemantics(final, candidate.axes.content, candidate.axes.coverage, candidate.axes.ci); err != nil {
		t.Fatalf("positive report control: %v", err)
	}
	for _, test := range []struct {
		name, want string
		mutate     func(*finalReviewWire)
	}{
		{"CI reasons", "final review CI reasons do not match publication axes", func(f *finalReviewWire) { f.CIReasonCodes = []string{"policy_evaluated"} }},
		{"evidence verification", `final finding "F001" evidence 0 is invalid`, func(f *finalReviewWire) { f.Findings[0].Evidence[0].Current.Verification = "unverified" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var changed finalReviewWire
			if err := json.Unmarshal(bundle.Final().Bytes(), &changed); err != nil {
				t.Fatal(err)
			}
			test.mutate(&changed)
			if err := validateFinalReportSemantics(changed, candidate.axes.content, candidate.axes.coverage, candidate.axes.ci); err == nil || err.Error() != test.want {
				t.Fatalf("independent guard = %v, want %s", err, test.want)
			}
			raw, err := marshalCanonical(changed)
			if err != nil {
				t.Fatal(err)
			}
			id, err := ports.NewFinalReviewIdentity(bundle.Final().Identity().ReviewID(), bundle.Final().Identity().Path(), sha256Identifier(raw))
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := ports.NewFinalReviewArtifact(id, raw)
			if err != nil {
				t.Fatal(err)
			}
			changedBundle := bundle
			changedBundle.final = artifact
			if changedBundle.Valid() {
				t.Fatal("bundle accepted an underived report projection")
			}
		})
	}

	bundle, err = candidate.Build(
		context.Background(),
		retainedSchema(t),
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
		retainedSchema(t),
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

func TestRetainedLivePreparedCandidateRejectsNonCanonicalAttemptSequences(t *testing.T) {
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
			candidate := retainedLiveCandidate(t, false)
			test.mutate(&candidate)
			if candidate.Valid() {
				t.Fatal("candidate accepted a non-canonical attempt sequence")
			}
		})
	}
}

func TestRetainedLiveTerminalTimeoutPublishesWithoutCapturedInventory(t *testing.T) {
	candidate := retainedLiveCandidate(t, false)
	role := &candidate.roles[1]
	role.state = domain.RoleTaskFailed
	role.valid = false
	role.outcome = "failed"
	role.failureClass = domain.FailureTimeout
	role.failureReason = "provider_timed_out"
	role.limitations = []string{"Role coverage is incomplete due to a terminal provider failure."}
	role.reportMarkdown = nil
	role.outputTransport = ""
	role.attempts[0].state = domain.AttemptTimedOut
	role.attempts[0].parseState = domain.ParseNotStarted
	role.attempts[0].validationState = domain.ValidationNotStarted
	role.attempts[0].invocations[0].state = domain.InvocationTimedOut
	attemptID := role.attempts[0].id
	candidate.failures = []preparedFailure{{
		class: domain.FailureTimeout, stage: "review", reason: "provider_timed_out", attemptID: &attemptID,
	}}
	candidate.runState = domain.RunFailed
	candidate.axes.coverage = domain.CoverageIncomplete
	candidate.axes.ci = domain.CIFail
	candidate.reasons = []string{"required_role_incomplete"}
	candidate.limits = []string{"Required review coverage is incomplete."}
	candidate.exitCode = int(domain.ExitIncompleteCoverage)

	if err := candidate.validate(); err != nil {
		t.Fatalf("terminal provider timeout candidate rejected: %v", err)
	}
	bundle, err := (PreparedLiveCandidate{candidate: candidate}).Build(context.Background(), retainedSchema(t), publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil || !bundle.Valid() {
		t.Fatalf("terminal timeout publication: %v", err)
	}
	assertNoRetiredSupport(t, bundle)
}

func TestRetainedLiveAllTimeoutsPublishWithoutCapturedInventory(t *testing.T) {
	candidate := retainedLiveCandidate(t, false)
	candidate.failures = nil
	for roleIndex := range candidate.roles {
		role := &candidate.roles[roleIndex]
		role.state = domain.RoleTaskFailed
		role.valid = false
		role.outcome = "failed"
		role.failureClass = domain.FailureTimeout
		role.failureReason = "provider_timed_out"
		role.limitations = []string{"Role coverage is incomplete due to a terminal provider failure."}
		role.reportMarkdown = nil
		role.outputTransport = ""
		role.attempts[0].state = domain.AttemptTimedOut
		role.attempts[0].parseState = domain.ParseNotStarted
		role.attempts[0].validationState = domain.ValidationNotStarted
		role.attempts[0].invocations[0].state = domain.InvocationTimedOut
		attemptID := role.attempts[0].id
		candidate.failures = append(candidate.failures, preparedFailure{
			class: domain.FailureTimeout, stage: "review", reason: "provider_timed_out", attemptID: &attemptID,
		})
	}
	candidate.runState = domain.RunFailed
	candidate.axes.coverage = domain.CoverageIncomplete
	candidate.axes.ci = domain.CIFail
	candidate.reasons = []string{"required_role_incomplete"}
	candidate.limits = []string{"Required review coverage is incomplete."}
	candidate.exitCode = int(domain.ExitIncompleteCoverage)

	bundle, err := (PreparedLiveCandidate{candidate: candidate}).Build(context.Background(), retainedSchema(t), publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil || !bundle.Valid() {
		t.Fatalf("all-timeout live publication: %v", err)
	}
	assertNoRetiredSupport(t, bundle)
}
