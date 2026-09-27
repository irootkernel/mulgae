package query

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ReadCompositionSupport captures portable source provenance and verified
// evidence, then confirms the same publication supplied all copied material.
func (service *Service) ReadCompositionSupport(ctx context.Context, run ports.PublicationRun) (compositesupport.Material, error) {
	observation, err := service.observe(ctx, run, "query.composition_support")
	if err != nil {
		return compositesupport.Material{}, err
	}
	review, err := service.ReadCommitted(ctx, run)
	if err != nil {
		return compositesupport.Material{}, err
	}
	if review.RunType() == domain.RunTypeComposite {
		return compositesupport.Material{}, fmt.Errorf("composite source is unsupported")
	}
	index, err := service.readRuntimeSupportIndex(ctx, run, review)
	if err != nil {
		return compositesupport.Material{}, err
	}
	var manifest manifestDTO
	if err := decodeStrictDTO(review.ManifestBytes(), &manifest); err != nil {
		return compositesupport.Material{}, err
	}
	material := compositesupport.Material{Source: compositesupport.Source{SessionID: run.SessionID().String(), RunID: run.RunID().String(), ReviewID: review.ReviewID().String(), FinalSHA256: review.FinalSHA256(), ManifestSHA256: review.ManifestSHA256(), SupportSHA256: manifest.CompositeIdentity.SupportIndex.SHA256, LineageSHA256: review.LineageEdgeSHA256(), Epoch: review.Epoch(), TargetSHA256: review.TargetSHA256(), CaptureAvailability: "capture_identity_unavailable"}}
	providers := map[string]bool{}
	if err := service.compositionProviders(ctx, run, review, providers, map[string]bool{}); err != nil {
		return material, err
	}
	for provider := range providers {
		material.Source.ProviderIdentities = append(material.Source.ProviderIdentities, provider)
	}
	sort.Strings(material.Source.ProviderIdentities)
	target, err := service.ReadRuntimeTarget(ctx, run)
	if err != nil {
		return material, err
	}
	if err := compositesupport.RetainCapture(&material, target.CapturedArchive()); err != nil {
		return material, err
	}
	var body struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(review.FinalBytes(), &body); err != nil {
		return material, err
	}
	originals := map[string]json.RawMessage{}
	for _, raw := range body.Findings {
		var id struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &id); err != nil {
			return material, err
		}
		originals[id.ID] = raw
	}
	for _, finding := range review.Findings() {
		raw, ok := originals[finding.ID()]
		if !ok {
			return material, fmt.Errorf("source finding absent")
		}
		item := compositesupport.FindingMaterial{Finding: compositesupport.Finding{ID: finding.ID(), Role: finding.Role(), SourceFindingID: finding.ID(), OriginalSHA256: compositesupport.SHA256(raw), Evidence: []compositesupport.Evidence{}}, Original: raw, Excerpts: [][]byte{}}
		for i, e := range finding.Evidence() {
			ref := compositesupport.Evidence{Index: i, Availability: "evidence_unavailable", TargetSHA256: e.TargetSHA256(), Side: e.Side(), Path: e.Path().String(), LineStart: e.LineStart(), LineEnd: e.LineEnd(), ExcerptSHA256: e.CurrentExcerptSHA256()}
			path, err := excerptArtifactPath(run, finding.ID(), i+1)
			if err != nil {
				return material, err
			}
			var content []byte
			if _, ok := index[path.String()]; ok {
				content, err = service.readCommittedFindingExcerpt(ctx, run, review, finding.ID(), i+1, e, index)
				if err != nil {
					return material, err
				}
				ref.Availability = "verified"
				ref.ContentSHA256 = compositesupport.SHA256(content)
			}
			item.Finding.Evidence = append(item.Finding.Evidence, ref)
			item.Excerpts = append(item.Excerpts, content)
		}
		material.Findings = append(material.Findings, item)
	}
	if err := service.confirmStableP2Observation(ctx, run, observation, "query.composition_support"); err != nil {
		return material, err
	}
	return material, nil
}

// Preserve the provider identities inspected by the existing retirement policy
// before detaching a composite from its source lineage.
func (service *Service) compositionProviders(ctx context.Context, run ports.PublicationRun, review CommittedReview, providers map[string]bool, seen map[string]bool) error {
	if seen[run.RunID().String()] {
		return nil
	}
	seen[run.RunID().String()] = true
	for _, r := range review.Roles() {
		if p, ok := r.ProviderInstance(); ok {
			providers[p] = true
		}
	}
	for _, a := range review.Attempts() {
		providers[a.ProviderInstance()] = true
	}
	for _, r := range review.RoleReports() {
		providers[r.ProviderInstance()] = true
	}
	final, err := decodeFinalDTO(review.FinalBytes())
	if err != nil {
		return err
	}
	if final.Provenance.Production != nil {
		for _, p := range final.Provenance.Production.Providers {
			providers[p.Family] = true
			providers[p.Instance] = true
		}
	}
	delete(providers, "")
	if final.ImmutableLineage.SourceRunID == nil {
		return nil
	}
	return service.compositionSourceProviders(ctx, run.Root(), *final.ImmutableLineage.SourceRunID, final.ImmutableLineage.SourceKind, providers, seen)
}
func (service *Service) compositionSourceProviders(ctx context.Context, root ports.AnchoredRoot, id, kind string, providers map[string]bool, seen map[string]bool) error {
	sourceID, err := domain.ParseRunID(id)
	if err != nil {
		return err
	}
	run, err := service.ResolveRun(ctx, root, sourceID)
	if err != nil {
		return nil
	}
	if kind == "failed_run_recovery" {
		if seen[id] {
			return nil
		}
		seen[id] = true
		snapshot, err := recovery.Read(ctx, service.store, service.validator, run, service.maxReadBytes)
		if err != nil {
			return err
		}
		doc := snapshot.Document()
		for _, a := range doc.Attempts {
			providers[a.ProviderInstance] = true
		}
		for _, r := range doc.Roles {
			providers[r.ProviderInstance] = true
		}
		for _, f := range doc.Findings {
			providers[f.ProviderInstance] = true
		}
		delete(providers, "")
		if doc.Source != nil {
			return service.compositionSourceProviders(ctx, root, doc.Source.RunID, doc.Source.Kind, providers, seen)
		}
		return nil
	}
	review, err := service.readCommittedUnfiltered(ctx, run)
	if err != nil {
		return err
	}
	return service.compositionProviders(ctx, run, review, providers, seen)
}

// ReadRecoveryCompositionProviders retains the same ancestry retirement policy
// used when admitting a failed-run recovery source.
func (service *Service) ReadRecoveryCompositionProviders(ctx context.Context, run ports.PublicationRun) ([]string, error) {
	providers := map[string]bool{}
	if err := service.compositionSourceProviders(ctx, run.Root(), run.RunID().String(), "failed_run_recovery", providers, map[string]bool{}); err != nil {
		return nil, err
	}
	values := []string{}
	for value := range providers {
		values = append(values, value)
	}
	sort.Strings(values)
	return values, nil
}
