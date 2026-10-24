package query

import (
	"context"
	"math"

	"github.com/irootkernel/mulgae/internal/app/capture"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// readContext is the query-owned per-call verified read state. One public
// entry-point invocation owns exactly one context: it records the initial P2
// binding of every consumed publication, its verified support index, and the
// dependency graph between them, so the call performs each publication's
// snapshot read and whole-support verification at most once within that
// context while every served artifact is still read digest-bound. The
// context stores no support-artifact bodies of its own; what it retains
// until the call returns is each consumed publication's verified review —
// the structured final and manifest view, plus a composite's bound support —
// and that publication's initial binding. It never survives the call, is
// never attached to the Service, and a new request, including an MCP
// continuation, verifies freshly.
type readContext struct {
	service      *Service
	byRun        map[string]*contextRun
	order        []*contextRun
	walking      *contextRun
	recoverySeen map[string]struct{}
}

// contextRun is one publication consumed inside a read context.
type contextRun struct {
	run     ports.PublicationRun
	stage   string
	binding observedRun

	review        CommittedReview
	hasReview     bool
	retireChecked bool
	retired       bool

	index     map[string]string
	deps      []*contextRun
	confirmed bool
}

func (service *Service) newReadContext() *readContext {
	return &readContext{service: service, byRun: map[string]*contextRun{}}
}

// ensureRun returns the context node for run, creating it with a fresh
// initial observation on first consumption. A publication first consumed
// while another publication's retirement or composition walk is in progress
// becomes a dependency of that publication.
func (context *readContext) ensureRun(ctx context.Context, run ports.PublicationRun, stage string) (*contextRun, error) {
	if node, ok := context.byRun[run.RunID().String()]; ok {
		return node, nil
	}
	observation, err := context.service.observe(ctx, run, stage)
	if err != nil {
		return nil, err
	}
	node := &contextRun{run: run, stage: stage, binding: observation}
	context.byRun[run.RunID().String()] = node
	context.order = append(context.order, node)
	if context.walking != nil {
		context.walking.deps = append(context.walking.deps, node)
	}
	return node, nil
}

// finish re-observes every consumed publication in dependency postorder:
// each publication is confirmed only after all of its dependencies, and the
// requested publication, consumed first, is confirmed last. Every
// publication-identity change still observable at a confirmation is
// detected, while every artifact read stays digest-bound to the initially
// verified index, so a transient state with different bytes fails its digest
// check and one with identical bytes cannot change the returned data.
func (context *readContext) finish(ctx context.Context) error {
	for _, node := range context.order {
		if err := context.confirm(ctx, node); err != nil {
			return err
		}
	}
	return nil
}

func (context *readContext) confirm(ctx context.Context, node *contextRun) error {
	if node.confirmed {
		return nil
	}
	node.confirmed = true
	for _, dependency := range node.deps {
		if err := context.confirm(ctx, dependency); err != nil {
			return err
		}
	}
	// Only a consumed committed publication claims P2 stability; a bare
	// observation (P0, P1, not published) projects status without one.
	if !node.hasReview {
		return nil
	}
	return context.service.confirmStableP2Observation(ctx, node.run, node.binding, node.stage)
}

// snapshotReview verifies run's committed snapshot and whole support once,
// returning its context node. It is the read-context form of the unfiltered
// committed read: no retirement walk and no confirmation run here.
func (context *readContext) snapshotReview(ctx context.Context, run ports.PublicationRun, stage string) (*contextRun, error) {
	node, err := context.ensureRun(ctx, run, stage)
	if err != nil {
		return nil, err
	}
	if node.binding.decision.Status() != domain.PublicationCommitted ||
		node.binding.decision.Authority() != domain.PublicationAuthorityP2 {
		return nil, typedFailure(stage, domain.FailureArtifact, "committed review is unavailable without P2 authority", nil)
	}
	if err := context.verifySnapshot(ctx, node); err != nil {
		return nil, err
	}
	return node, nil
}

// readCommitted is the read-context form of ReadCommitted. The whole-support
// verification inside the snapshot read completes before the retirement walk
// starts, so a support failure keeps precedence over a retired ancestor.
func (context *readContext) readCommitted(ctx context.Context, run ports.PublicationRun, stage string) (*contextRun, error) {
	node, err := context.snapshotReview(ctx, run, stage)
	if err != nil {
		return nil, err
	}
	retired, err := context.committedRetired(ctx, node)
	if err != nil {
		return nil, err
	}
	if retired {
		return nil, typedFailure(readCommittedStage, domain.FailureArtifact, retiredProviderArtifactReason, nil)
	}
	return node, nil
}

// verifySnapshot performs the store snapshot read, schema and semantic
// validation, and — when the manifest binds one — the whole-support
// verification of node's publication, at most once per node. A node without
// P2 authority is rejected before any snapshot read. It deliberately performs
// no confirmation; the owning call's finish does that.
func (context *readContext) verifySnapshot(ctx context.Context, node *contextRun) error {
	if node.hasReview {
		return nil
	}
	service := context.service
	if missingDependency(service) || missingDependency(service.store) || missingDependency(service.validator) {
		return typedFailure(node.stage, domain.FailureArtifact, "committed read dependency is unavailable", nil)
	}
	if err := contextFailure(ctx, node.stage); err != nil {
		return err
	}
	if node.binding.decision.Status() != domain.PublicationCommitted ||
		node.binding.decision.Authority() != domain.PublicationAuthorityP2 {
		return typedFailure(node.stage, domain.FailureArtifact, "committed snapshot was requested without P2 authority", nil)
	}
	request, err := ports.NewReadCommittedSnapshotRequest(node.run, service.maxReadBytes)
	if err != nil {
		return typedFailure(node.stage, domain.FailureConfiguration, "committed snapshot request is invalid", err)
	}
	snapshot, err := service.store.ReadCommittedSnapshot(ctx, request)
	if err != nil {
		return dependencyFailure(ctx, node.stage, domain.FailureArtifact, "committed snapshot read failed", err)
	}
	if !snapshot.Valid() {
		return typedFailure(node.stage, domain.FailureArtifact, "committed snapshot is invalid", nil)
	}
	final, manifest := snapshot.Final(), snapshot.Manifest()
	if !final.Valid() || !manifest.Valid() || !snapshot.LineageEdge().Valid() || !snapshot.Epoch().Valid() {
		return typedFailure(node.stage, domain.FailureArtifact, "committed snapshot members are invalid", nil)
	}
	if !sameCommittedSnapshot(node.binding.snapshot, snapshot) {
		return typedFailure(node.stage, domain.FailureArtifact, "committed snapshot identities do not match the observed P2 authority", nil)
	}
	if node.binding.storeEpoch != snapshot.Epoch().Value() {
		return typedFailure(node.stage, domain.FailureArtifact, "committed snapshot epoch does not match the observed P2 authority", nil)
	}
	review, err := service.buildSnapshotReview(ctx, context, node, snapshot, final.Bytes(), manifest.Bytes())
	if err != nil {
		return err
	}
	node.review, node.hasReview = review, true
	return nil
}

// supportIndex returns node's manifest-bound support index, verifying every
// contract-required support artifact exactly once per call. Live
// publications read and verify every indexed artifact; historical v2
// publications verify their capture support; composite and v1 publications
// verify the index identities. Artifact bodies are dropped after
// verification, as before.
func (context *readContext) supportIndex(ctx context.Context, node *contextRun, review CommittedReview) (map[string]string, error) {
	if node.index != nil {
		return node.index, nil
	}
	run := node.run
	var ref *artifactIdentityDTO
	if review.RunType() == domain.RunTypeComposite {
		var manifest compositeManifestDTO
		if err := decodeStrictDTO(review.ManifestBytes(), &manifest); err != nil {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed composite manifest decode failed", err)
		}
		ref = manifest.CompositeIdentity.SupportIndex
	} else {
		manifest, err := decodeManifestDTO(review.ManifestBytes())
		if err != nil {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed manifest decode failed", err)
		}
		ref = manifest.CompositeIdentity.SupportIndex
	}
	if ref == nil || !validSHA256(ref.SHA256) {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "manifest-bound support index is absent", nil)
	}
	path, err := ports.NewSafeRelativePath(ref.Path)
	if err != nil {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index path is invalid", err)
	}
	kind, err := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
	if err != nil || kind != ports.RunSupportArtifactSupportIndex {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index path is not canonical", err)
	}
	artifact, err := context.boundArtifact(ctx, node, path, ref.SHA256, context.service.maxReadBytes)
	if err != nil {
		return nil, err
	}
	var index runtimeSupportIndexDTO
	if err := decodeStrictDTO(artifact.Bytes(), &index); err != nil {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index decode failed", err)
	}
	live := review.liveSource != nil
	if live && index.SchemaVersion != artifactwire.SupportIndexV3 || !live && index.SchemaVersion != artifactwire.SupportIndexV1 && index.SchemaVersion != artifactwire.SupportIndexV2 {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index is invalid", nil)
	}
	// Empty artifacts is schema-valid for provider-free no-change publications.
	identities := make(map[string]string, len(index.Artifacts))
	for _, item := range index.Artifacts {
		path, pathErr := ports.NewSafeRelativePath(item.Path)
		if pathErr != nil || !validSHA256(item.SHA256) {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index artifact identity is invalid", pathErr)
		}
		kind, classifyErr := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
		if classifyErr != nil {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index artifact path is invalid", classifyErr)
		}
		if (kind == ports.RunSupportArtifactCaptureManifest || kind == ports.RunSupportArtifactCompositeMetadata || kind == ports.RunSupportArtifactSourceFinding) && index.SchemaVersion != artifactwire.SupportIndexV2 {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "capture manifest requires support index v2", nil)
		}
		if !live && (kind == ports.RunSupportArtifactLiveSource || kind == ports.RunSupportArtifactSourceImage) {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "historical support contains live source authority", nil)
		}
		if _, duplicate := identities[item.Path]; duplicate {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index artifact is ambiguous", nil)
		}
		identities[item.Path] = item.SHA256
	}
	if live {
		artifacts := make(map[string]ports.ImmutablePublicationArtifact, len(identities))
		for name, digest := range identities {
			path, _ := ports.NewSafeRelativePath(name)
			kind, _ := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
			maximum := context.service.maxReadBytes
			if kind.IsVariableSized() {
				maximum = math.MaxInt64 - 1
			}
			artifact, err := context.boundArtifact(ctx, node, path, digest, maximum)
			if err != nil {
				return nil, err
			}
			artifacts[name] = artifact
		}
		if err := verifyLiveReadSupport(run, review, artifacts); err != nil {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed source support is invalid", err)
		}
		node.index = identities
		return identities, nil
	}
	if index.SchemaVersion == artifactwire.SupportIndexV2 && review.RunType() == domain.RunTypeComposite {
		if _, ok := identities[run.SessionID().String()+"/"+run.RunID().String()+"/support/composite.json"]; !ok {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "composite support metadata absent", nil)
		}
		// The committed snapshot reader verifies every copied artifact and final binding.
		node.index = identities
		return identities, nil
	}
	if index.SchemaVersion == artifactwire.SupportIndexV2 {
		artifacts := make(map[string]ports.ImmutablePublicationArtifact)
		for name, digest := range identities {
			path, _ := ports.NewSafeRelativePath(name)
			kind, _ := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
			if kind != ports.RunSupportArtifactCaptureManifest && kind != ports.RunSupportArtifactCapturedArchive && kind != ports.RunSupportArtifactCapturedBlob {
				continue
			}
			artifact, err := context.boundArtifact(ctx, node, path, digest, math.MaxInt64-1)
			if err != nil {
				return nil, err
			}
			artifacts[name] = artifact
		}
		final, err := decodeFinalDTO(review.FinalBytes())
		if err != nil {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed final decode failed", err)
		}
		if _, err := capture.VerifySupport(run.SessionID(), run.RunID(), review.TargetSHA256(), final.Target.BaseOID, final.Target.HeadOID, artifacts); err != nil {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed capture support is invalid", err)
		}
	}
	node.index = identities
	return identities, nil
}

// boundArtifact reads one support artifact digest-bound to the initially
// verified index, with the full path/kind/digest identity checks. It performs
// no observation of its own; the owning call's finish confirms the
// publication identity.
func (context *readContext) boundArtifact(ctx context.Context, node *contextRun, path ports.SafeRelativePath, digest string, maximum int64) (ports.ImmutablePublicationArtifact, error) {
	if !validSHA256(digest) {
		return ports.ImmutablePublicationArtifact{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact digest is absent", nil)
	}
	request, err := ports.NewReadAuxiliaryArtifactRequest(node.run, path, digest, maximum)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact request is invalid", err)
	}
	artifact, err := context.service.store.ReadAuxiliaryArtifact(ctx, request)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, dependencyFailure(ctx, readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact read failed", err)
	}
	if !artifact.Valid() || artifact.Path() != path || artifact.SHA256() != digest {
		return ports.ImmutablePublicationArtifact{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact identity drifted", nil)
	}
	return artifact, nil
}

// indexedArtifact reads one artifact named by the verified support index.
func (context *readContext) indexedArtifact(ctx context.Context, node *contextRun, path ports.SafeRelativePath) (ports.ImmutablePublicationArtifact, error) {
	digest, ok := node.index[path.String()]
	if !ok || !validSHA256(digest) {
		return ports.ImmutablePublicationArtifact{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact is absent from support index", nil)
	}
	if kind, err := ports.ClassifyRunSupportArtifactPath(node.run.SessionID(), node.run.RunID(), path); err == nil && kind == ports.RunSupportArtifactSourceImage {
		return context.boundArtifact(ctx, node, path, digest, math.MaxInt64-1)
	}
	return context.boundArtifact(ctx, node, path, digest, context.service.maxReadBytes)
}

// roleReportURIs verifies role-report support against the manifest inventory
// and returns the projected report URIs. Role-report bodies are served with
// one digest-bound read each; the owning call's finish confirms the
// publication identity.
func (context *readContext) roleReportURIs(ctx context.Context, node *contextRun) ([]RoleReportURI, error) {
	run, review := node.run, node.review
	reports := review.RoleReports()
	index, err := context.supportIndex(ctx, node, node.review)
	if err != nil {
		return nil, err
	}
	roleReportIndex := make(map[string]string)
	for pathValue, digest := range index {
		path, pathErr := ports.NewSafeRelativePath(pathValue)
		if pathErr != nil {
			return nil, typedFailure(readStatusStage, domain.FailureArtifact, "support index path is invalid", pathErr)
		}
		kind, classifyErr := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
		if classifyErr != nil {
			return nil, typedFailure(readStatusStage, domain.FailureArtifact, "support index path is not canonical", classifyErr)
		}
		if kind != ports.RunSupportArtifactRoleReport {
			continue
		}
		roleReportIndex[pathValue] = digest
	}
	if len(reports) == 0 {
		if len(roleReportIndex) != 0 {
			return nil, typedFailure(readStatusStage, domain.FailureArtifact, "support index has unbound role reports", nil)
		}
		return nil, nil
	}
	uris := make([]RoleReportURI, 0, len(reports))
	for _, report := range reports {
		pathValue := run.SessionID().String() + "/" + run.RunID().String() + "/" + report.Path()
		path, pathErr := ports.NewSafeRelativePath(pathValue)
		if pathErr != nil {
			return nil, typedFailure(readStatusStage, domain.FailureArtifact, "role report path is invalid", pathErr)
		}
		kind, classifyErr := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
		if classifyErr != nil || kind != ports.RunSupportArtifactRoleReport {
			return nil, typedFailure(readStatusStage, domain.FailureArtifact, "role report path is not canonical", classifyErr)
		}
		digest, ok := roleReportIndex[path.String()]
		if !ok || digest != report.SHA256() {
			return nil, typedFailure(readStatusStage, domain.FailureArtifact, "role report is absent from support index", nil)
		}
		artifact, readErr := context.boundArtifact(ctx, node, path, digest, int64(report.ByteLength()))
		if readErr != nil {
			return nil, readErr
		}
		content := artifact.Bytes()
		if artifact.SHA256() != report.SHA256() || len(content) != report.ByteLength() {
			return nil, typedFailure(readStatusStage, domain.FailureArtifact, "role report artifact identity mismatch", nil)
		}
		if !validRoleReportMarkdown(content) {
			return nil, typedFailure(readStatusStage, domain.FailureArtifact, "role report markdown is invalid", nil)
		}
		delete(roleReportIndex, path.String())
		uris = append(uris, RoleReportURI{
			Role: report.Role(),
			URI:  ".mulgae/" + path.String(),
		})
	}
	if len(roleReportIndex) != 0 {
		return nil, typedFailure(readStatusStage, domain.FailureArtifact, "support index has unbound role reports", nil)
	}
	return uris, nil
}
