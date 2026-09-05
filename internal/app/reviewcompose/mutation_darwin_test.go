//go:build darwin && arm64

package reviewcompose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type mutationTestClock struct{ now time.Time }

func (clock mutationTestClock) Now() time.Time { return clock.now }

type mutationTestIDs struct{ reviewID domain.ReviewID }

func (ids mutationTestIDs) NewReviewID(time.Time) (domain.ReviewID, error) { return ids.reviewID, nil }

type mutationFailingEpochStore struct{ ports.PublicationStore }

func (mutationFailingEpochStore) WithNextPublicationEpoch(context.Context, ports.AnchoredRoot, func(context.Context, uint64) error) error {
	return errors.New("private epoch failure")
}

func TestMutationServicePublishesAndReconcilesExactComposite(t *testing.T) {
	ctx := context.Background()
	root, security, docs := compositionFixtures(t)
	targetBytes := []byte("diff --git a/main.go b/main.go\n")
	targetDigest := sha256.Sum256(targetBytes)
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind:   domain.TargetPatch,
		SHA256: hex.EncodeToString(targetDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	root.TargetSHA256 = "sha256:" + hex.EncodeToString(targetDigest[:])
	root.TargetIdentity = target
	root.TargetBytes = targetBytes
	security.TargetSHA256 = root.TargetSHA256
	docs.TargetSHA256 = root.TargetSHA256

	for _, source := range []*Source{&root, &security, &docs} {
		for index := range source.RoleReports {
			contents := []byte("# " + string(source.RoleReports[index].Role) + "\n\nVerified report.\n")
			digest := sha256.Sum256(contents)
			source.RoleReports[index].Bytes = contents
			source.RoleReports[index].ByteLength = len(contents)
			source.RoleReports[index].SHA256 = "sha256:" + hex.EncodeToString(digest[:])
		}
	}

	artifactPath := filepath.Join(t.TempDir(), ".mulgae")
	if err := os.Mkdir(artifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	artifactRoot, err := ports.NewAnchoredRoot(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []Source{root, security, docs} {
		for _, report := range source.RoleReports {
			path := filepath.Join(artifactPath, source.SessionID.String(), source.RunID.String(), filepath.FromSlash(report.Path))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, report.Bytes, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	validator, err := jsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	clock := mutationTestClock{now: time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)}
	publishedReviewID := reviewID(t, "31")
	store, err := filesystem.NewPublicationStore(validator, clock, mutationTestIDs{reviewID: publishedReviewID}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	publicationService, err := publication.NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	composer, err := NewService(sourceReader{root.RunID: root, security.RunID: security, docs.RunID: docs})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(artifactRoot, publicationService)
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := NewMutationService(composer, publisher)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{docs.RunID, security.RunID}}
	created, err := mutation.ComposeReview(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if created.ReconciliationState() != "created" || created.ReviewID() != publishedReviewID ||
		created.PublicationStatus() != domain.PublicationCommitted || created.TerminalExit().Code() != domain.ExitCommittedCIRejected {
		t.Fatalf("created result = reconciliation:%s review:%s publication:%s exit:%d", created.ReconciliationState(), created.ReviewID(), created.PublicationStatus(), created.TerminalExit().Code())
	}
	reports := created.RoleReportURIs()
	if len(reports) != 3 {
		t.Fatalf("created role report URIs = %#v", reports)
	}
	for _, report := range reports {
		wantURI := ".mulgae/" + created.SessionID().String() + "/" + created.RunID().String() + "/role-reports/" + string(report.Role) + ".md"
		if report.URI != wantURI {
			t.Fatalf("created role report URI = %q, want %q", report.URI, wantURI)
		}
	}
	reconciled, err := mutation.ComposeReview(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.ReconciliationState() != "reconciled" || reconciled.RunID() != created.RunID() || reconciled.ReviewID() != created.ReviewID() ||
		reconciled.TerminalExit().Code() != created.TerminalExit().Code() {
		t.Fatalf("reconciled result drifted: created=%#v reconciled=%#v", created, reconciled)
	}

	failingService, err := publication.NewService(mutationFailingEpochStore{PublicationStore: store}, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	failingPublisher, err := NewPublisher(artifactRoot, failingService)
	if err != nil {
		t.Fatal(err)
	}
	failingMutation, err := NewMutationService(composer, failingPublisher)
	if err != nil {
		t.Fatal(err)
	}
	_, err = failingMutation.ComposeReview(ctx, request)
	var failure *Failure
	if !errors.As(err, &failure) || failure.ReasonCode() != domain.CompositePublicationIncomplete {
		t.Fatalf("real publisher failure = %v", err)
	}
	failedSessionID, failedRunID, ok := failure.CompositeIdentity()
	if !ok || failedSessionID != created.SessionID() || failedRunID != created.RunID() {
		t.Fatalf("real publisher failure identity = %s/%s, %t; want %s/%s", failedSessionID, failedRunID, ok, created.SessionID(), created.RunID())
	}
}
