package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

var (
	sharedQueryValidatorOnce sync.Once
	sharedQueryValidator     *jsonschema.Validator
	sharedQueryValidatorErr  error
)

func sharedQueryTestValidator() (*jsonschema.Validator, error) {
	sharedQueryValidatorOnce.Do(func() {
		sharedQueryValidator, sharedQueryValidatorErr = jsonschema.New(context.Background(), builtin.NewCatalog())
	})
	return sharedQueryValidator, sharedQueryValidatorErr
}

func mustSharedQueryTestValidator(t *testing.T) *jsonschema.Validator {
	t.Helper()
	validator, err := sharedQueryTestValidator()
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func historicalQueryStore(t *testing.T, c historical.Case) (*queryStore, ports.PublicationRun) {
	t.Helper()
	root, err := ports.NewAnchoredRoot("/private/historical-corpus")
	if err != nil {
		t.Fatal(err)
	}
	session, err := domain.ParseSessionID(c.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := domain.ParseRunID(c.RunID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, session, id)
	if err != nil {
		t.Fatal(err)
	}
	absent, err := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	store := &queryStore{observation: absent, observationsByRun: map[string]ports.PublicationObservation{}, snapshotsByRun: map[string]ports.CommittedPublicationSnapshot{}, resolutionsByRun: map[string]ports.PublicationRun{}, auxiliaryArtifacts: map[string]ports.ImmutablePublicationArtifact{}}
	files := c.Artifacts()
	for path, raw := range files {
		var document recovery.Document
		if json.Unmarshal(raw, &document) == nil && document.SchemaVersion == recovery.SchemaVersion {
			session, err := domain.ParseSessionID(document.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			id, err := domain.ParseRunID(document.RunID)
			if err != nil {
				t.Fatal(err)
			}
			parent, err := ports.NewPublicationRun(root, session, id)
			if err != nil {
				t.Fatal(err)
			}
			store.resolutionsByRun[id.String()] = parent
		}
		store.auxiliaryArtifacts[path] = mustQueryArtifact(t, mustQueryPath(t, path), raw)
	}
	for path, raw := range files {
		// Use only metadata to present fixed snapshots. The real service validates
		// the untouched full bytes, including schema and semantic relationships.
		var m manifestDTO
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		if !strings.HasPrefix(m.SchemaVersion, "mulgae-run-manifest.") && !strings.HasPrefix(m.SchemaVersion, "mulgae-composite-run-manifest.") {
			continue
		}
		s, err := domain.ParseSessionID(m.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		r, err := domain.ParseRunID(m.RunID)
		if err != nil {
			t.Fatal(err)
		}
		current, err := ports.NewPublicationRun(root, s, r)
		if err != nil {
			t.Fatal(err)
		}
		review, err := domain.ParseReviewID(m.FinalReview.ReviewID)
		if err != nil {
			t.Fatal(err)
		}
		finalIdentity, err := ports.NewFinalReviewIdentity(review, mustQueryPath(t, m.FinalReview.Path), querySHA(files[m.FinalReview.Path]))
		if err != nil {
			t.Fatal(err)
		}
		final, err := ports.NewFinalReviewArtifact(finalIdentity, files[m.FinalReview.Path])
		if err != nil {
			t.Fatal(err)
		}
		var e struct {
			Value uint64 `json:"store_epoch"`
		}
		epochArtifact := store.auxiliaryArtifacts[m.CompositeIdentity.Epoch.Path]
		if err := json.Unmarshal(epochArtifact.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		epoch, err := ports.NewPublicationEpoch(e.Value, epochArtifact)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := ports.NewCommittedPublicationSnapshot(final, store.auxiliaryArtifacts[path], store.auxiliaryArtifacts[m.CompositeIdentity.LineageEdge.Path], epoch)
		if err != nil {
			t.Fatal(err)
		}
		store.snapshotsByRun[r.String()] = snapshot
		store.observationsByRun[r.String()] = queryP2Observation(t, current, snapshot, domain.JournalCompleted, domain.OperationalExitCode(m.ExitCode), e.Value)
		store.resolutionsByRun[r.String()] = current
	}
	store.resolutionsByRun[c.RunID] = run
	return store, run
}

func TestHistoricalCorpusRead(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := mustSharedQueryTestValidator(t)
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			store, run := historicalQueryStore(t, c)
			service := mustQueryService(t, store, validator, nil)
			got, err := service.ReadCommitted(context.Background(), run)
			reason := c.Expected.ReadReason
			if c.Family == "failed-recovery" {
				reason = "committed review is unavailable without P2 authority"
			}
			if c.ID == "composite-mixed-v1" {
				reason = retiredProviderArtifactReason
			}
			if reason != "" {
				historicalReason(t, err, reason)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got.ContentVerdict()) != c.Expected.Content || string(got.CoverageStatus()) != c.Expected.Coverage || string(got.CIDecision()) != c.Expected.CI || len(got.Findings()) != c.Expected.Findings {
				t.Fatalf("preserved result changed: %s/%s/%s findings=%d", got.ContentVerdict(), got.CoverageStatus(), got.CIDecision(), len(got.Findings()))
			}
			var envelope struct {
				Exit int `json:"exit_code"`
			}
			if err := json.Unmarshal(got.ManifestBytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Exit != c.Expected.Exit {
				t.Fatal("stored operational exit changed")
			}
			status, err := service.ReadRunStatus(context.Background(), run)
			if err != nil {
				t.Fatal(err)
			}
			if string(status.PublicationStatus()) != c.Expected.Publication {
				t.Fatal("publication authority changed")
			}
			if c.ID == "no-change" {
				return
			}
			target, err := service.ReadRuntimeTarget(context.Background(), run)
			if c.Expected.RuntimeReason != "" {
				historicalReason(t, err, c.Expected.RuntimeReason)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.ID == "ordinary-v1-nonminified" {
				path := c.SessionID + "/" + c.RunID + "/target/captured-review.json"
				raw := c.Artifacts()[path]
				if !bytes.Contains(raw, []byte("\n  ")) || !bytes.Equal(target.CapturedArchive(), raw) {
					t.Fatal("legacy archive was re-encoded")
				}
			}
			if c.ID == "artist" {
				brief, present := target.ArtistBrief()
				if !present || !bytes.Equal(brief, c.Artifacts()[c.SessionID+"/"+c.RunID+"/inputs/artist-brief.md"]) {
					t.Fatal("artist brief bytes changed")
				}
				visual, present := target.ArtistVisualAssets()
				if !present || !bytes.Equal(visual, c.Artifacts()[c.SessionID+"/"+c.RunID+"/inputs/artist-visual-assets.json"]) {
					t.Fatal("artist visual bytes changed")
				}
			}
		})
	}
}
func historicalReason(t *testing.T, err error, reason string) {
	t.Helper()
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || failure.Reason() != reason {
		t.Fatalf("failure=%v; want artifact reason %q", err, reason)
	}
}

func TestHistoricalCorpusAttempts(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := mustSharedQueryTestValidator(t)
	required := map[string]bool{}
	for _, id := range []string{"ordinary-v1-nonminified", "ordinary-v2", "artist", "rerun-exact", "rerun-recompose", "delta", "recovery-child-v2", "followup-resolved", "followup-partially_resolved", "followup-still_open", "followup-unclear", "retired-kimi"} {
		required[id] = true
	}
	for _, c := range corpus.Cases {
		if len(c.Attempts) == 0 {
			if required[c.ID] {
				t.Errorf("%s lacks frozen committed-attempt expectations", c.ID)
			}
			continue
		}
		delete(required, c.ID)
		t.Run(c.ID, func(t *testing.T) {
			store, run := historicalQueryStore(t, c)
			service := mustQueryService(t, store, validator, nil)
			files := c.Artifacts()
			var manifest manifestDTO
			if err := json.Unmarshal(files[c.SessionID+"/"+c.RunID+"/manifest.json"], &manifest); err != nil {
				t.Fatal(err)
			}
			if len(manifest.Attempts) != len(c.Attempts) {
				t.Fatal("frozen expectations do not cover every manifest attempt")
			}
			for i, want := range c.Attempts {
				if manifest.Attempts[i].AttemptID != want.AttemptID {
					t.Fatal("frozen attempt inventory changed")
				}
			}
			for _, want := range c.Attempts {
				t.Run(want.AttemptID, func(t *testing.T) {
					id, err := domain.ParseAttemptID(want.AttemptID)
					if err != nil {
						t.Fatal(err)
					}
					got, err := service.ReadCommittedAttempt(context.Background(), run, id)
					if want.Reason != "" {
						historicalReason(t, err, want.Reason)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					historicalAttempt(t, got, want, files)
				})
			}
			for _, selector := range c.AttemptSelectors {
				t.Run("selector/"+selector.Role+"/"+selector.Provider, func(t *testing.T) {
					got, err := service.ResolveCommittedAttempt(context.Background(), run, domain.Role(selector.Role), selector.Provider)
					if selector.Reason != "" {
						historicalReason(t, err, selector.Reason)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range c.Attempts {
						if want.AttemptID == selector.AttemptID {
							historicalAttempt(t, got, want, files)
							return
						}
					}
					t.Fatal("selector lacks a frozen attempt expectation")
				})
			}
		})
	}
	for id := range required {
		t.Errorf("missing committed-attempt fixture %s", id)
	}
}

func historicalAttempt(t *testing.T, got CommittedAttempt, want historical.Attempt, files map[string][]byte) {
	t.Helper()
	prompt := got.Prompt()
	identity := historical.Attempt{
		SessionID: got.SessionID().String(), RunID: got.RunID().String(), ReviewID: got.ReviewID().String(),
		AttemptID: got.AttemptID().String(), Role: string(got.Role()), Provider: got.Provider(),
		PromptManifestPath: prompt.ManifestPath().String(), PromptManifestSHA256: prompt.ManifestSHA256(),
		StdinPath: want.StdinPath, StdinSHA256: prompt.StdinSHA256(), CompleteStdinSHA256: prompt.CompleteStdinSHA256(),
		TemplateID: prompt.TemplateID(), TemplateVersion: prompt.TemplateVersion(), TemplateSHA256: prompt.TemplateSHA256(),
	}
	if identity != want {
		t.Fatalf("committed attempt changed: got %+v; want %+v", identity, want)
	}
	stdin, present := files[want.StdinPath]
	if !present || !bytes.Equal(prompt.Stdin(), stdin) {
		t.Fatal("committed attempt stdin differs from frozen member")
	}
}

func TestHistoricalCorpusRecovery(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := mustSharedQueryTestValidator(t)
	for _, c := range corpus.Cases {
		if c.Family != "failed-recovery" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			store, run := historicalQueryStore(t, c)
			service := mustQueryService(t, store, validator, nil)
			if c.Expected.RecoveryReason != "" {
				status, err := service.ReadRunStatus(context.Background(), run)
				if c.Expected.RecoveryReason == "source_not_retained" {
					if err != nil {
						t.Fatal(err)
					}
					recovery := status.FailedRunRecovery()
					if recovery.Available || recovery.UnavailableReason == nil || *recovery.UnavailableReason != "source_not_retained" {
						t.Fatal("missing manifest was not explicit unavailability")
					}
				} else {
					historicalReason(t, err, c.Expected.RecoveryReason)
					recovery := status.FailedRunRecovery()
					if recovery.Available || recovery.UnavailableReason == nil || *recovery.UnavailableReason != "source_invalid" {
						t.Fatal("corrupt source projected recovery authority")
					}
				}
				return
			}
			snapshot, err := service.ReadFailedRunRecovery(context.Background(), run)
			if err != nil {
				t.Fatal(err)
			}
			if !snapshot.Status().Available {
				t.Fatal("recovery unavailable")
			}
			status, err := service.ReadRunStatus(context.Background(), run)
			if err != nil {
				t.Fatal(err)
			}
			if status.PublicationStatus() != domain.PublicationNotPublished || !status.FailedRunRecovery().Available {
				t.Fatal("recovery acquired final authority")
			}
		})
	}
}
