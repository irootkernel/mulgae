package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRecoveryRejectsTamperedAndUnsafeSources(t *testing.T) {
	document, blobs := recoveryFixture(t)
	if _, err := Restore(context.Background(), recoveryJSON(t, document), blobs); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Document, map[string][]byte){
		"target":               func(d *Document, b map[string][]byte) { b[d.Target.Bytes.SHA256][0] ^= 1 },
		"archive":              func(d *Document, b map[string][]byte) { delete(b, d.Target.CapturedArchive.SHA256) },
		"prompt":               func(d *Document, b map[string][]byte) { b[d.Attempts[0].InitialPrompt.Stdin.SHA256][0] ^= 1 },
		"report":               func(d *Document, b map[string][]byte) { b[d.Roles[0].Report.SHA256][0] ^= 1 },
		"missing queued input": func(d *Document, _ map[string][]byte) { d.Attempts = d.Attempts[:1] },
		"provider binding":     func(d *Document, _ map[string][]byte) { d.Attempts[1].ProviderInstance = "different" },
		"security":             func(d *Document, _ map[string][]byte) { d.Attempts[1].FailureClass = domain.FailureSecurityPolicy },
		"configuration":        func(d *Document, _ map[string][]byte) { d.Attempts[1].FailureClass = domain.FailureConfiguration },
		"artifact":             func(d *Document, _ map[string][]byte) { d.Attempts[1].FailureClass = domain.FailureArtifact },
		"cleanup":              func(d *Document, _ map[string][]byte) { d.WorkspaceTerminalReceipt = "" },
		"successful final":     func(d *Document, _ map[string][]byte) { d.RunState = domain.RunCompleted },
		"scope": func(d *Document, _ map[string][]byte) {
			d.Attempts[1].InitialPrompt.Scope = d.Attempts[0].InitialPrompt.Scope
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate, content := cloneDocument(document), cloneBlobs(blobs)
			mutate(&candidate, content)
			if _, err := Restore(context.Background(), recoveryJSON(t, candidate), content); err == nil {
				t.Fatal("invalid recovery was accepted")
			}
		})
	}
}

func TestRecoveryAcceptsStructuredFindingsAndReportsOnlyWithoutFindings(t *testing.T) {
	document, blobs := recoveryFixture(t)
	attachVerifiedLogicFinding(t, &document, blobs)
	if _, err := Restore(context.Background(), recoveryJSON(t, document), blobs); err != nil {
		t.Fatalf("structured accepted role with verified findings: %v", err)
	}

	document, blobs = recoveryFixture(t)
	document.Roles[0].ReportsOnly = true
	if _, err := Restore(context.Background(), recoveryJSON(t, document), blobs); err != nil {
		t.Fatalf("reports-only accepted role without findings: %v", err)
	}
}

func TestRecoveryRejectsReportsOnlyAcceptedRoleWithFindingIDs(t *testing.T) {
	document, blobs := recoveryFixture(t)
	attachVerifiedLogicFinding(t, &document, blobs)
	document.Roles[0].ReportsOnly = true
	if _, err := Restore(context.Background(), recoveryJSON(t, document), blobs); err == nil {
		t.Fatal("reports-only accepted role with finding IDs was admitted")
	}
}

func TestRecoveryPreparedAndSealHonorCallerContext(t *testing.T) {
	document, blobs := recoveryFixture(t)
	document.WorkspaceTerminalReceipt = ""
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewPrepared(ctx, document, blobs); !errors.Is(err, context.Canceled) {
		t.Fatalf("NewPrepared cancelled context: %v", err)
	}
	prepared, err := NewPrepared(context.Background(), document, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Seal(ctx, ports.WorkspaceTerminalReceipt{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Seal cancelled context: %v", err)
	}
	stepped := &recoveryCancellationContext{Context: context.Background(), remaining: 5}
	stepped.cancel = func() {
		cancelled, stop := context.WithCancel(context.Background())
		stop()
		stepped.Context = cancelled
	}
	if _, err := NewPrepared(stepped, document, blobs); !errors.Is(err, context.Canceled) {
		t.Fatalf("NewPrepared discarded mid-validation cancellation: %v", err)
	}

	receipt := recoveryTestReceipt(t, document)
	stepped = &recoveryCancellationContext{Context: context.Background(), remaining: 5}
	stepped.cancel = func() {
		cancelled, stop := context.WithCancel(context.Background())
		stop()
		stepped.Context = cancelled
	}
	if _, err := prepared.Seal(stepped, receipt); !errors.Is(err, context.Canceled) {
		t.Fatalf("Seal discarded mid-validation cancellation: %v", err)
	}
}

func TestRecoveryPreparedRequiresTerminalProofAndOwnsInputs(t *testing.T) {
	document, blobs := recoveryFixture(t)
	document.WorkspaceTerminalReceipt = ""
	prepared, err := NewPrepared(context.Background(), document, blobs)
	if err != nil {
		t.Fatal(err)
	}
	document.Roles[0].ProviderInstance = "changed"
	blobs[document.Target.Bytes.SHA256][0] ^= 1
	if prepared.document.Roles[0].ProviderInstance == "changed" || Digest(prepared.blobs[document.Target.Bytes.SHA256]) != document.Target.Bytes.SHA256 {
		t.Fatal("prepared input is aliased")
	}
	if _, err := prepared.Seal(context.Background(), ports.WorkspaceTerminalReceipt{}); err == nil {
		t.Fatal("missing terminal proof was accepted")
	}
}

func TestRecoveryStatusSeparatesAcceptedRolesFromRetryAttempts(t *testing.T) {
	document, blobs := recoveryFixture(t)
	snapshot, err := Restore(context.Background(), recoveryJSON(t, document), blobs)
	if err != nil {
		t.Fatal(err)
	}
	status := snapshot.Status()
	if !status.Available || len(status.AcceptedRoles) != 1 || status.AcceptedRoles[0] != domain.RoleLogic || len(status.RetryAttempts) != 1 || status.RetryAttempts[0].Role != domain.RoleSecurity || status.RetryAttempts[0].AttemptID != document.Attempts[1].AttemptID {
		t.Fatalf("wrong status: %+v", status)
	}
	reference, err := snapshot.Reference()
	if err != nil || reference.RecoveryManifestSHA256() != Digest(snapshot.Manifest()) {
		t.Fatal("recovery reference lost manifest binding")
	}
}

func recoveryFixture(t *testing.T) (Document, map[string][]byte) {
	t.Helper()
	session, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewCapturedReviewPatchTarget([]byte("immutable target"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewWorkspaceSnapshotRequest(nil, "recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	blobs := map[string][]byte{}
	document := Document{SchemaVersion: SchemaVersion, SessionID: session.String(), RunID: run.String(), RunType: domain.RunTypeReview, RunState: domain.RunFailed, Threshold: domain.SeverityHigh, SnapshotManifestSHA256: "sha256:" + strings.Repeat("a", 64), WorkspaceTerminalReceipt: "workspace-terminal:v1:sha256:" + strings.Repeat("b", 64), Findings: []Finding{}}
	document.Target = Target{Kind: target.Identity().Kind(), SHA256: "sha256:" + target.Identity().SHA256(), Bytes: AddBlob(blobs, target.Bytes()), CapturedArchive: AddBlob(blobs, archive)}
	for index, role := range []domain.Role{domain.RoleLogic, domain.RoleSecurity} {
		suffix := "000000000021"
		if index == 1 {
			suffix = "000000000022"
		}
		attemptID, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-" + suffix)
		if err != nil {
			t.Fatal(err)
		}
		roleTaskID, err := prompt.ParseRoleTaskID("rt_019f5a09-5eec-7001-8001-" + suffix)
		if err != nil {
			t.Fatal(err)
		}
		coordinates, err := prompt.NewScopeCoordinates(session, run, roleTaskID, attemptID)
		if err != nil {
			t.Fatal(err)
		}
		template, err := prompt.NewTrustedTemplate("recovery-test", "v1", []byte("Return a review."))
		if err != nil {
			t.Fatal(err)
		}
		compiler, err := prompt.NewCompiler(template, recoveryIssuer{suffix})
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := compiler.Compile(prompt.CompileInput{Scope: coordinates, ReviewTarget: prompt.NewPayload(target.Bytes())})
		if err != nil {
			t.Fatal(err)
		}
		input := Prompt{Stdin: AddBlob(blobs, compiled.Stdin()), SourceInvocationID: compiled.Scope().SourceInvocationID().String(), ExecutionInvocationID: compiled.Scope().ExecutionInvocationID().String(), TemplateID: template.ID(), TemplateVersion: template.Version(), TemplateSHA256: "sha256:" + template.SHA256(), AdapterProfile: "test", AdapterParameters: map[string]string{}, Scope: compiled.Scope().FrameScope().String()}
		attempt := Attempt{AttemptID: attemptID.String(), Role: role, ProviderInstance: "test.provider", State: domain.AttemptSucceeded, InitialPrompt: input}
		outcome := Role{Role: role, Required: true, Outcome: "completed", AttemptID: attemptID.String(), ProviderInstance: attempt.ProviderInstance, FindingIDs: []string{}}
		if index == 0 {
			report := AddBlob(blobs, []byte("Accepted logic report."))
			outcome.Report = &report
		} else {
			attempt.State = domain.AttemptCancelled
			attempt.FailureClass = domain.FailureCancelled
			attempt.ReasonCode = "cancelled"
			outcome.Outcome = "failed"
		}
		document.Attempts = append(document.Attempts, attempt)
		document.Roles = append(document.Roles, outcome)
	}
	return document, blobs
}

func recoveryTestReceipt(t *testing.T, document Document) ports.WorkspaceTerminalReceipt {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity("/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef", document.SnapshotManifestSHA256, "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := ports.AcquireWorkspaceSnapshotLease(context.Background(), func(_ context.Context, binding ports.WorkspaceTerminalBinding) (ports.WorkspaceSnapshotLease, error) {
		release, err := binding.Bind(identity, func(ports.WorkspaceCompletionEvidence) error { return nil })
		if err != nil {
			return nil, err
		}
		return recoveryReceiptLease{identity: identity, release: release}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	completion, err := ports.NewWorkspaceCompletionEvidence(identity, document.RunID, ports.NewEmptyProviderRunTerminalReceipt())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := lease.Release(completion)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

type recoveryReceiptLease struct {
	identity ports.WorkspaceSnapshotIdentity
	release  ports.WorkspaceTerminalRelease
}

func (lease recoveryReceiptLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return lease.identity
}
func (recoveryReceiptLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, errors.New("unexpected workspace revalidation")
}
func (lease recoveryReceiptLease) Receipt() ports.WorkspaceSnapshotReceipt {
	return ports.WorkspaceSnapshotReceipt{}
}
func (lease recoveryReceiptLease) Release(completion ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
	return lease.release(completion)
}
func (recoveryReceiptLease) Abort(ports.WorkspaceAbortEvidence) error { return nil }

func attachVerifiedLogicFinding(t *testing.T, document *Document, blobs map[string][]byte) {
	t.Helper()
	delete(blobs, document.Target.CapturedArchive.SHA256)
	target, err := ports.NewCapturedReviewPatchTarget(blobs[document.Target.Bytes.SHA256])
	if err != nil {
		t.Fatal(err)
	}
	path, err := ports.NewSafeRelativePath("source.go")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("line evidence")
	file, err := ports.NewWorkspaceSnapshotFile(path, raw, Digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewWorkspaceSnapshotRequest(nil, "recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	captured, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: {file}})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, nil, captured)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	document.Target.CapturedArchive = AddBlob(blobs, archive)
	claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: document.Target.SHA256,
		Side:         evidence.SideHead,
		Path:         path.String(),
		LineStart:    1,
		LineEnd:      1,
		Quote:        string(raw),
	})
	if err != nil {
		t.Fatal(err)
	}
	excerptHash, err := claim.ExcerptSHA256(raw)
	if err != nil {
		t.Fatal(err)
	}
	document.Roles[0].FindingIDs = []string{"F001"}
	document.Findings = []Finding{{
		ID: "F001", Fingerprint: Digest([]byte("finding")), Role: document.Roles[0].Role,
		ProviderInstance: document.Roles[0].ProviderInstance, Severity: domain.SeverityLow,
		Title: "Title", Description: "Description", Recommendation: "Recommendation",
		Confidence: domain.ConfidenceHigh, Lifecycle: domain.FindingOpen,
		Evidence: []Evidence{{
			TargetSHA256: document.Target.SHA256, Side: evidence.SideHead, Path: path.String(),
			LineStart: 1, LineEnd: 1, Quote: string(raw), ExcerptSHA256: excerptHash,
		}},
	}}
}

type recoveryIssuer struct{ suffix string }

func (issuer recoveryIssuer) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	return prompt.ParseSourceInvocationID("i_019f5a09-5eec-7001-8001-" + issuer.suffix)
}
func (issuer recoveryIssuer) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	return prompt.ParseExecutionInvocationID("019f5a09-5eec-7002-8001-" + issuer.suffix)
}
func recoveryJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRestoreRecoveryHonorsCancellationDuringValidation(t *testing.T) {
	document, blobs := recoveryFixture(t)
	raw := recoveryJSON(t, document)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Restore(ctx, raw, blobs); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled restore: %v", err)
	}
	// The context becomes cancelled only after metadata validation has begun.
	// No goroutine timing or source-sized allocation is needed to reach the gate.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	stepped := &recoveryCancellationContext{Context: ctx, cancel: cancel, remaining: 5}
	if _, err := Restore(stepped, raw, blobs); !errors.Is(err, context.Canceled) {
		t.Fatalf("validation discarded caller cancellation: %v", err)
	}
}

type recoveryCancellationContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (ctx *recoveryCancellationContext) Err() error {
	ctx.remaining--
	if ctx.remaining == 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestRecoveryEvidenceReaderHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path, err := ports.NewSafeRelativePath("source.go")
	if err != nil {
		t.Fatal(err)
	}
	reader := archiveReader{target: "sha256:" + strings.Repeat("a", 64)}
	availability, content, err := reader.ReadImmutableTarget(ctx, reader.target, evidence.SideHead, path)
	if !errors.Is(err, context.Canceled) || availability != evidence.ImmutableTargetUnavailable || len(content) != 0 {
		t.Fatalf("cancelled evidence read returned content or lost cancellation: %v", err)
	}
}

func TestRecoveryEvidenceMismatchHasConcreteError(t *testing.T) {
	document, blobs := recoveryFixture(t)
	document.Roles[0].FindingIDs = []string{"F001"}
	document.Findings = []Finding{{
		ID: "F001", Fingerprint: "sha256:" + strings.Repeat("c", 64), Role: domain.RoleLogic,
		ProviderInstance: document.Roles[0].ProviderInstance, Severity: domain.SeverityLow,
		Title: "Title", Description: "Description", Recommendation: "Recommendation",
		Confidence: domain.ConfidenceHigh, Lifecycle: domain.FindingOpen,
		Evidence: []Evidence{{TargetSHA256: document.Target.SHA256, Side: evidence.SideHead, Path: "missing.go", LineStart: 1, LineEnd: 1, Quote: "missing", ExcerptSHA256: "sha256:" + strings.Repeat("d", 64)}},
	}}
	_, err := Restore(context.Background(), recoveryJSON(t, document), blobs)
	if err == nil || err.Error() != "recovery: evidence receipt mismatch" {
		t.Fatalf("wrong receipt mismatch diagnostic: %v", err)
	}
}
