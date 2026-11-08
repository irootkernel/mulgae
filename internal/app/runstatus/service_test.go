package runstatus

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type publicationFake struct {
	run                 ports.PublicationRun
	status              PublicationStatus
	resolveErr, readErr error
	calls, reads        int
}

func (fake *publicationFake) ResolveRun(context.Context, ports.AnchoredRoot, domain.RunID) (ports.PublicationRun, error) {
	fake.calls++
	return fake.run, fake.resolveErr
}
func (fake *publicationFake) ReadRunStatus(context.Context, ports.PublicationRun) (PublicationStatus, error) {
	fake.reads++
	return fake.status, fake.readErr
}

type diagnosticFake struct {
	status              ports.RuntimeDiagnosticRunStatus
	err                 error
	calls, sessionCalls int
	root                ports.AnchoredRoot
	session             domain.SessionID
	run                 domain.RunID
}

func (fake *diagnosticFake) ReadRunStatus(_ context.Context, root ports.AnchoredRoot, run domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	fake.calls++
	fake.root, fake.run = root, run
	return fake.status, fake.err
}
func (fake *diagnosticFake) ReadSessionRunStatus(_ context.Context, root ports.AnchoredRoot, session domain.SessionID, run domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	fake.sessionCalls++
	fake.root, fake.session, fake.run = root, session, run
	return fake.status, fake.err
}

func TestStatusAcquisitionCompatibility(t *testing.T) {
	root, _ := ports.NewAnchoredRoot("/fixture/.mulgae")
	otherRoot, _ := ports.NewAnchoredRoot("/other/.mulgae")
	session, _ := domain.ParseSessionID("s_019f596a-cfe4-7c9c-b82e-7149158243ba")
	runID, _ := domain.ParseRunID("r_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := ports.NewPublicationRun(root, session, runID)
	otherRun, _ := ports.NewPublicationRun(otherRoot, session, runID)
	otherID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	wrongRun, _ := ports.NewPublicationRun(root, session, otherID)
	summary, err := ports.NewRuntimeDiagnosticSummary(ports.RuntimeDiagnosticSummaryInput{Component: "provider_registry", Phase: "provider_observation"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 23, 6, 0, 0, 0, time.UTC)
	diagnostic, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: session, RunID: runID, State: domain.RunRunning, StartedAt: now, UpdatedAt: now, DiagnosticSummary: summary, HasDiagnosticSummary: true})
	if err != nil {
		t.Fatal(err)
	}
	artifact, _ := domain.NewFailure("test.status", domain.FailureArtifact, "missing", ports.ErrPublicationRunNotFound)
	raw := errors.New("original raw failure")
	mixed := errors.Join(ports.ErrPublicationRunNotFound, raw)
	for _, test := range []struct {
		name                      string
		resolveErr, diagnosticErr error
		want                      Kind
		phase                     Phase
		err                       error
		calls                     int
	}{
		{"sole missing", ports.ErrPublicationRunNotFound, nil, Diagnostic, Resolve, nil, 1},
		{"ordinary wrapper", fmt.Errorf("lookup: %w", ports.ErrPublicationRunNotFound), nil, Diagnostic, Resolve, nil, 1},
		{"typed artifact wrapper", artifact, nil, Diagnostic, Resolve, nil, 1},
		{"single join", errors.Join(ports.ErrPublicationRunNotFound), nil, Diagnostic, Resolve, nil, 1},
		{"missing-only join", errors.Join(ports.ErrPublicationRunNotFound, artifact), nil, Diagnostic, Resolve, nil, 1},
		{"mixed publication", mixed, nil, Publication, Resolve, mixed, 0},
		{"raw publication", raw, nil, Publication, Resolve, raw, 0},
		{"diagnostic missing", artifact, ports.ErrRuntimeDiagnosticRunNotFound, Unavailable, Resolve, artifact, 1},
		{"mixed diagnostic", artifact, errors.Join(ports.ErrRuntimeDiagnosticRunNotFound, raw), Publication, DiagnosticRead, nil, 1},
		{"diagnostic cancellation", artifact, context.Canceled, Publication, DiagnosticRead, context.Canceled, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			pub := &publicationFake{resolveErr: test.resolveErr}
			diag := &diagnosticFake{status: diagnostic, err: test.diagnosticErr}
			got, err := New(pub, diag).Read(context.Background(), root, runID)
			wantErr := test.err
			if test.name == "mixed diagnostic" {
				wantErr = test.diagnosticErr
			}
			if err != wantErr || got.Kind != test.want || got.Phase != test.phase || pub.calls != 1 || pub.reads != 0 || diag.calls != test.calls || diag.sessionCalls != 0 {
				t.Fatalf("result=%+v err=%v calls=%d/%d/%d/%d", got, err, pub.calls, pub.reads, diag.calls, diag.sessionCalls)
			}
			if test.calls == 1 && (diag.root != root || diag.run != runID) {
				t.Fatal("diagnostic fallback scope changed")
			}
			if got.Kind == Diagnostic && got.Diagnostic.State() != domain.RunRunning {
				t.Fatal("application narrowed transport diagnostic eligibility")
			}
		})
	}
	for _, status := range []domain.PublicationStatus{domain.PublicationCommitted, domain.PublicationNotPublished} {
		pub := &publicationFake{run: run, status: PublicationStatus{PublicationState: status}}
		diag := &diagnosticFake{status: diagnostic}
		got, err := New(pub, diag).Read(context.Background(), root, runID)
		wantSession := 1
		wantSummary := status != domain.PublicationCommitted
		if err != nil || got.Kind != Publication || got.Run != run || diag.calls != 0 || diag.sessionCalls != wantSession || got.Status.HasDiagnosticSummary != wantSummary {
			t.Fatalf("publication=%+v err=%v diagnostics=%d/%d", got, err, diag.calls, diag.sessionCalls)
		}
		if diag.root != root || diag.session != session || diag.run != runID || wantSummary && got.Status.DiagnosticSummary != summary {
			t.Fatal("session-bound summary merge changed")
		}
	}
	for _, resolved := range []ports.PublicationRun{{}, otherRun, wrongRun} {
		pub := &publicationFake{run: resolved}
		diag := &diagnosticFake{}
		got, err := New(pub, diag).Read(context.Background(), root, runID)
		if err != ErrInvalidScope || got.Phase != ResolveScope || pub.reads+diag.calls+diag.sessionCalls != 0 {
			t.Fatal("invalid resolved scope admitted")
		}
	}
	pub := &publicationFake{run: run, readErr: raw}
	got, err := New(pub, nil).Read(context.Background(), root, runID)
	if err != raw || got.Phase != PublicationRead {
		t.Fatal("publication read cause changed")
	}
	for _, cause := range []error{raw, context.Canceled, errors.Join(ports.ErrRuntimeDiagnosticRunNotFound, raw)} {
		pub = &publicationFake{run: run, status: PublicationStatus{PublicationState: domain.PublicationNotPublished}}
		got, err = New(pub, &diagnosticFake{err: cause}).Read(context.Background(), root, runID)
		if err != cause || got.Phase != SessionDiagnosticRead {
			t.Fatal("session diagnostic cause changed")
		}
	}
	pub = &publicationFake{resolveErr: artifact}
	got, err = New(pub, nil).Read(context.Background(), root, runID)
	if err != artifact || got.Phase != Resolve {
		t.Fatal("optional diagnostics changed original failure")
	}
}

func TestServiceReadCommittedCoordinationSupplementBestEffort(t *testing.T) {
	root, _ := ports.NewAnchoredRoot("/fixture/.mulgae")
	session, _ := domain.ParseSessionID("s_019f596a-cfe4-7c9c-b82e-7149158243ba")
	runID, _ := domain.ParseRunID("r_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := ports.NewPublicationRun(root, session, runID)
	summary, _ := ports.NewRuntimeDiagnosticSummary(ports.RuntimeDiagnosticSummaryInput{Component: "coordination", Phase: "release", InvariantID: string(domain.DiagnosticCauseCoordinationDispositionFailed)})
	now := time.Now().UTC()
	diagnostic, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: session, RunID: runID, State: domain.RunCompleted, StartedAt: now, UpdatedAt: now, DiagnosticSummary: summary, HasDiagnosticSummary: true})
	if err != nil {
		t.Fatal(err)
	}
	otherSession, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	mismatch, _ := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: otherSession, RunID: runID, State: domain.RunCompleted, StartedAt: now, UpdatedAt: now, DiagnosticSummary: summary, HasDiagnosticSummary: true})
	corrupt := errors.New("corrupt private supplement")
	for _, test := range []struct {
		name       string
		diagnostic ports.RuntimeDiagnosticRunStatus
		err        error
		enrich     bool
	}{
		{"valid", diagnostic, nil, true},
		{"missing", ports.RuntimeDiagnosticRunStatus{}, ports.ErrRuntimeDiagnosticRunNotFound, false},
		{"legacy unsupported", ports.RuntimeDiagnosticRunStatus{}, errors.New("unsupported schema"), false},
		{"corrupt", ports.RuntimeDiagnosticRunStatus{}, corrupt, false},
		{"unreadable", ports.RuntimeDiagnosticRunStatus{}, errors.New("read refused"), false},
		{"mismatch", mismatch, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			axes := PublicationStatus{PublicationState: domain.PublicationCommitted, RunState: domain.RunDegraded, HasRunState: true, ContentVerdict: domain.ContentNoFindings, HasAxes: true}
			pub := &publicationFake{run: run, status: axes}
			diag := &diagnosticFake{status: test.diagnostic, err: test.err}
			got, err := New(pub, diag).Read(context.Background(), root, runID)
			if err != nil || got.Kind != Publication || got.Status.HasDiagnosticSummary != test.enrich || got.Status.RunState != axes.RunState || got.Status.ContentVerdict != axes.ContentVerdict || pub.reads != 1 {
				t.Fatalf("supplement revoked or changed P2: %+v / %v", got, err)
			}
			pub.readErr = corrupt
			before := diag.sessionCalls
			if _, err := New(pub, diag).Read(context.Background(), root, runID); err != corrupt || diag.sessionCalls != before {
				t.Fatal("supplement hid independently corrupt P2")
			}
		})
	}
}
