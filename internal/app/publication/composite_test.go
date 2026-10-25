//go:build darwin && arm64

package publication

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type compositeTestIDs struct{ reviewID domain.ReviewID }

func (ids compositeTestIDs) NewReviewID(time.Time) (domain.ReviewID, error) { return ids.reviewID, nil }

type compositeInterruptedStore struct {
	*filesystem.PublicationStore
	after  int
	writes int
}

func (store *compositeInterruptedStore) ReplaceMutable(ctx context.Context, request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
	result, err := store.PublicationStore.ReplaceMutable(ctx, request)
	if err == nil && store.after == -1 && request.Document() == ports.MutablePublicationJournal {
		os.Exit(73)
	}
	return result, err
}

func (store *compositeInterruptedStore) InstallFinal(ctx context.Context, request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
	result, err := store.PublicationStore.InstallFinal(ctx, request)
	if err == nil && store.after == -2 {
		os.Exit(73)
	}
	return result, err
}

func (store *compositeInterruptedStore) PersistValidatedCandidate(ctx context.Context, request ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
	result, err := store.PublicationStore.PersistValidatedCandidate(ctx, request)
	if err == nil && store.after == 0 {
		return ports.PersistValidatedCandidateResult{}, errors.New("interrupted after candidate installation")
	}
	return result, err
}

func (store *compositeInterruptedStore) PersistAuxiliaryArtifact(ctx context.Context, request ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	result, err := store.PublicationStore.PersistAuxiliaryArtifact(ctx, request)
	store.writes++
	if err == nil && store.writes == store.after {
		return ports.PersistAuxiliaryArtifactResult{}, errors.New("interrupted after support installation")
	}
	return result, err
}

func checkCompositeVersionPairs(t *testing.T, original PublicationBundle) {
	t.Helper()
	for _, pair := range []struct{ final, manifest string }{{"v1", "v1"}, {"v2", "v2"}, {"v1", "v2"}, {"v2", "v1"}} {
		t.Run("versions-"+pair.final+"-"+pair.manifest, func(t *testing.T) {
			bundle := original
			var final, manifest, epoch map[string]any
			for _, item := range []struct {
				raw   []byte
				value *map[string]any
			}{{bundle.final.Bytes(), &final}, {bundle.manifest.Bytes(), &manifest}, {bundle.epoch.Record().Bytes(), &epoch}} {
				if err := json.Unmarshal(item.raw, item.value); err != nil {
					t.Fatal(err)
				}
			}
			final["schema_version"] = "mulgae-composite-review-artifact." + pair.final
			finalBytes, err := marshalCanonical(final)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := ports.NewFinalReviewIdentity(bundle.final.Identity().ReviewID(), bundle.final.Identity().Path(), sha256Identifier(finalBytes))
			if err != nil {
				t.Fatal(err)
			}
			bundle.final, err = ports.NewFinalReviewArtifact(identity, finalBytes)
			if err != nil {
				t.Fatal(err)
			}
			bundle.staged, err = immutableArtifact(bundle.staged.Path(), finalBytes)
			if err != nil {
				t.Fatal(err)
			}
			manifest["schema_version"] = "mulgae-composite-run-manifest." + pair.manifest
			manifest["final_review"].(map[string]any)["sha256"] = identity.SHA256()
			manifestBytes, err := marshalCanonical(manifest)
			if err != nil {
				t.Fatal(err)
			}
			bundle.manifest, err = immutableArtifact(bundle.manifest.Path(), manifestBytes)
			if err != nil {
				t.Fatal(err)
			}
			epoch["manifest"].(map[string]any)["sha256"] = bundle.manifest.SHA256()
			epoch["final_review"].(map[string]any)["sha256"] = identity.SHA256()
			epochBytes, err := marshalCanonical(epoch)
			if err != nil {
				t.Fatal(err)
			}
			record, err := immutableArtifact(bundle.epoch.Record().Path(), epochBytes)
			if err != nil {
				t.Fatal(err)
			}
			bundle.epoch, err = ports.NewPublicationEpoch(bundle.epoch.Value(), record)
			if err != nil {
				t.Fatal(err)
			}
			root, err := ports.NewAnchoredRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			session, err := domain.ParseSessionID(final["session_id"].(string))
			if err != nil {
				t.Fatal(err)
			}
			runID, err := domain.ParseRunID(final["run_id"].(string))
			if err != nil {
				t.Fatal(err)
			}
			run, err := ports.NewPublicationRun(root, session, runID)
			if err != nil {
				t.Fatal(err)
			}
			matching := pair.final == pair.manifest
			if err := validateCompositeBundleSemantics(bundle); (err == nil) != matching {
				t.Errorf("bundle pair accepted=%t, want %t: %v", err == nil, matching, err)
			}
			if _, err := validateCompositeMaterial(run, bundle.final, bundle.manifest, bundle.lineageEdge, bundle.epoch); (err == nil) != matching {
				t.Errorf("material pair accepted=%t, want %t: %v", err == nil, matching, err)
			}
		})
	}
}

func TestHistoricalCompositeVersionPairs(t *testing.T) {
	for _, family := range []string{"composite-legacy-v1", "composite-copied-v1", "composite-mixed-v1", "composite-copied-v2"} {
		t.Run(family, func(t *testing.T) {
			bundle := retainedHistoricalFixture(t, family).bundle
			checkCompositeVersionPairs(t, bundle)
			checkHistoricalCompositeSchemas(t, bundle)
		})
	}
}

// Preserve the original schema refusals independently of retired construction.
func checkHistoricalCompositeSchemas(t *testing.T, bundle PublicationBundle) {
	t.Helper()
	validator := retainedSchema(t)
	members := [][]byte{bundle.Final().Bytes(), bundle.Manifest().Bytes()}
	ids := make([]ports.AssetID, len(members))
	for i, raw := range members {
		var envelope struct {
			SchemaVersion string `json:"schema_version"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		id, err := ports.ParseAssetID("https://mulgae.local/schemas/" + envelope.SchemaVersion + ".schema.json")
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
		if err := validator.Validate(context.Background(), id, raw); err != nil {
			t.Fatalf("fixed composite schema positive control: %v", err)
		}
	}
	for _, test := range []struct {
		name   string
		index  int
		mutate func(map[string]any)
	}{
		{"degraded run", 1, func(value map[string]any) { value["state"] = "degraded" }},
		{"empty role report", 1, func(value map[string]any) { value["role_reports"].([]any)[0].(map[string]any)["byte_length"] = 0 }},
		{"not applicable role", 0, func(value map[string]any) {
			value["role_outcomes"].([]any)[0].(map[string]any)["outcome"] = "not_applicable"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(members[test.index], &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			invalid, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := validator.Validate(context.Background(), ids[test.index], invalid); err == nil {
				t.Errorf("composite schema accepted unpublishable %s", test.name)
			}
		})
	}
}
