package reviewcompose

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/domain"
)

type mutationPublisherFunc func(context.Context, Result) (publication.PublicationResult, error)

func (publish mutationPublisherFunc) Publish(ctx context.Context, result Result) (publication.PublicationResult, error) {
	return publish(ctx, result)
}

func TestPublisherRejectsUnavailablePrePublicationStateWithoutReconciliationIdentity(t *testing.T) {
	_, err := (*Publisher)(nil).Publish(context.Background(), Result{})
	var failure *Failure
	if !errors.As(err, &failure) || failure.ReasonCode() != domain.CompositeValidationFailed {
		t.Fatalf("publisher failure = %v", err)
	}
	if _, _, ok := failure.CompositeIdentity(); ok {
		t.Fatal("pre-publication failure exposed a reconciliation identity")
	}
}

func TestMutationServicePreservesDeterministicIdentityForIncompletePublication(t *testing.T) {
	root, security, docs := compositionFixtures(t)
	composer, err := NewService(sourceReader{root.RunID: root, security.RunID: security, docs.RunID: docs})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID, docs.RunID}}
	composed, err := composer.Compose(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	wantRunID, err := composed.Fingerprint.RunID()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		publisher mutationPublisher
	}{
		{
			name: "publisher failure",
			publisher: mutationPublisherFunc(func(context.Context, Result) (publication.PublicationResult, error) {
				return publication.PublicationResult{}, fail(domain.CompositePublicationIncomplete, "private publication failure", errors.New("private"))
			}),
		},
		{
			name: "non P2 result",
			publisher: mutationPublisherFunc(func(context.Context, Result) (publication.PublicationResult, error) {
				return publication.PublicationResult{}, nil
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutation := &MutationService{composer: composer, publisher: test.publisher}
			_, err := mutation.ComposeReview(context.Background(), request)
			var failure *Failure
			if !errors.As(err, &failure) || failure.ReasonCode() != domain.CompositePublicationIncomplete {
				t.Fatalf("ComposeReview() error = %v", err)
			}
			gotSessionID, gotRunID, ok := failure.CompositeIdentity()
			if !ok || gotSessionID != root.SessionID || gotRunID != wantRunID {
				t.Fatalf("ComposeReview() identity = %s/%s, %t; want %s/%s", gotSessionID, gotRunID, ok, root.SessionID, wantRunID)
			}
		})
	}
}

func TestNewPublishedResultRequiresAlignedCIAndTerminalExit(t *testing.T) {
	tests := []struct {
		name    string
		ci      domain.CIDecision
		exit    domain.OperationalExitCode
		reason  string
		wantErr bool
	}{
		{name: "pass", ci: domain.CIPass, exit: domain.ExitCommittedPass, reason: "publication_committed"},
		{name: "request changes", ci: domain.CIFail, exit: domain.ExitCommittedCIRejected, reason: "request_changes_threshold"},
		{name: "pass with policy exit", ci: domain.CIPass, exit: domain.ExitCommittedCIRejected, reason: "request_changes_threshold", wantErr: true},
		{name: "fail with pass exit", ci: domain.CIFail, exit: domain.ExitCommittedPass, reason: "publication_committed", wantErr: true},
		{name: "pass with incomplete coverage exit", ci: domain.CIPass, exit: domain.ExitIncompleteCoverage, reason: "required_role_incomplete", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			terminal := compositeTerminalExit(t, test.exit, test.reason)
			session := sessionID(t)
			run := runID(t, "90")
			_, err := NewPublishedResult(PublishedResultInput{
				SessionID: session, RunID: run, ReviewID: reviewID(t, "91"), RootRunID: runID(t, "92"),
				RecoveryRunIDs: []domain.RunID{runID(t, "93")},
				TargetSHA256:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				RecoveredRoles: []domain.Role{domain.RoleSecurity},
				RoleReportURIs: []RoleReportURI{{
					Role: domain.RoleSecurity,
					URI:  ".mulgae/" + session.String() + "/" + run.String() + "/role-reports/security.md",
				}},
				Coverage: domain.CoverageComplete, Content: domain.ContentNoFindings,
				StructuredExtractionStatus: domain.StructuredExtractionStructured, CIDecision: test.ci,
				PublicationStatus: domain.PublicationCommitted,
				RecoveryAction:    domain.RecoveryActionReconstructCompletedStatus,
				TerminalExit:      terminal, ReconciliationState: "created",
				RunManifestURI:    ".mulgae/" + session.String() + "/" + run.String() + "/manifest.json",
				ReviewArtifactURI: ".mulgae/" + session.String() + "/" + run.String() + "/review_" + reviewID(t, "91").String() + ".json",
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("NewPublishedResult() error = %v, wantErr = %t", err, test.wantErr)
			}
		})
	}
}

func TestNewPublishedResultUsesDomainRoleBound(t *testing.T) {
	recoveryRunIDs := make([]domain.RunID, len(domain.FixedRoleOrder())+1)
	recoveredRoles := make([]domain.Role, len(recoveryRunIDs))
	for index := range recoveryRunIDs {
		recoveryRunIDs[index] = runID(t, fmt.Sprintf("%02x", index+1))
		recoveredRoles[index] = domain.RoleSecurity
	}
	_, err := NewPublishedResult(PublishedResultInput{
		SessionID: sessionID(t), RootRunID: runID(t, "20"),
		RecoveryRunIDs: recoveryRunIDs, RecoveredRoles: recoveredRoles,
	})
	if got, want := fmt.Sprint(err), "published composite result: published composite selection is invalid"; got != want {
		t.Fatalf("NewPublishedResult() error = %q, want %q", got, want)
	}
}

func TestNewPublishedResultRequiresReviewArtifactURIToMatchReviewID(t *testing.T) {
	session := sessionID(t)
	run := runID(t, "90")
	review := reviewID(t, "91")
	_, err := NewPublishedResult(PublishedResultInput{
		SessionID: session, RunID: run, ReviewID: review, RootRunID: runID(t, "92"),
		RecoveryRunIDs: []domain.RunID{runID(t, "93")},
		TargetSHA256:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RecoveredRoles: []domain.Role{domain.RoleSecurity},
		RoleReportURIs: []RoleReportURI{{Role: domain.RoleSecurity, URI: ".mulgae/" + session.String() + "/" + run.String() + "/role-reports/security.md"}},
		Coverage:       domain.CoverageComplete, Content: domain.ContentNoFindings,
		StructuredExtractionStatus: domain.StructuredExtractionStructured, CIDecision: domain.CIPass,
		PublicationStatus: domain.PublicationCommitted, RecoveryAction: domain.RecoveryActionReconstructCompletedStatus,
		TerminalExit: compositeTerminalExit(t, domain.ExitCommittedPass, "publication_committed"), ReconciliationState: domain.CompositionCreated,
		RunManifestURI:    ".mulgae/" + session.String() + "/" + run.String() + "/manifest.json",
		ReviewArtifactURI: ".mulgae/" + session.String() + "/" + run.String() + "/review_" + reviewID(t, "94").String() + ".json",
	})
	if got, want := fmt.Sprint(err), "published composite result: published composite artifact identity is inconsistent"; got != want {
		t.Fatalf("NewPublishedResult() error = %q, want %q", got, want)
	}
}

func compositeTerminalExit(t *testing.T, code domain.OperationalExitCode, reasonCode string) domain.OperationalExitDecision {
	t.Helper()
	reason, err := domain.NewExitReason(code, reasonCode)
	if err != nil {
		t.Fatal(err)
	}
	input, err := domain.NewOperationalExitInput([]domain.ExitReason{reason})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := domain.ReduceOperationalExit(input)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}
