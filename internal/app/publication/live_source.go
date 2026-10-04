package publication

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const liveSourceManifestPath = "source/source.json"

type publicationEvidenceTarget struct {
	captured domain.TargetIdentity
	source   evidence.LiveSourceIdentity
}

func (target publicationEvidenceTarget) matchesClaim(claim evidence.CurrentClaim) bool {
	if target.source.Valid() {
		return claim.IsLiveSource() && claim.SourceIdentitySHA256() == target.source.SHA256()
	}
	return !claim.IsLiveSource() && claim.TargetSHA256() == "sha256:"+target.captured.SHA256()
}

func (target publicationEvidenceTarget) allowsUnavailable() bool {
	if target.source.Valid() {
		return false
	}
	kind := target.captured.Kind()
	return kind == domain.TargetWorkspace || kind == domain.TargetPatch || kind == domain.TargetStdin
}

// LiveProductionProvenance records source-directory and provider closure. It
// carries no snapshot, source-content fingerprint, or source replay claim.
type LiveProductionProvenance struct {
	BuildProduct          string
	BuildVersion          string
	BuildCommit           string
	ObjectiveSHA256       string
	HasObjective          bool
	SourceIdentitySHA256  string
	SourceTerminalReceipt string
	Providers             []ProductionProviderProvenance
}

type preparedLiveSource struct {
	target     ports.LiveSourceTarget
	identity   evidence.LiveSourceIdentity
	provenance LiveProductionProvenance
	binary     []evidence.LiveBinaryReceipt
}

// PreparedLiveCandidate shares terminal validation and the P2 transaction with
// captured results while keeping live source authority explicit at admission.
type PreparedLiveCandidate struct{ candidate PreparedCandidate }

func (candidate PreparedLiveCandidate) Valid() bool {
	return candidate.candidate.target.live != nil && candidate.candidate.Valid()
}
func (candidate PreparedLiveCandidate) SessionID() domain.SessionID {
	return candidate.candidate.SessionID()
}
func (candidate PreparedLiveCandidate) RunID() domain.RunID { return candidate.candidate.RunID() }
func (candidate PreparedLiveCandidate) ValidatedCandidateSHA256() string {
	return candidate.candidate.ValidatedCandidateSHA256()
}
func (candidate PreparedLiveCandidate) Build(ctx context.Context, validator SchemaValidator, id domain.ReviewID, createdAt time.Time, epoch uint64) (PublicationBundle, error) {
	if !candidate.Valid() {
		return PublicationBundle{}, fmt.Errorf("live publication: invalid candidate")
	}
	return candidate.candidate.Build(ctx, validator, id, createdAt, epoch)
}

// LiveCandidateInput contains trusted coordination output and verifier-owned
// selected evidence. Provider transcripts remain in their attempt locations.
type LiveCandidateInput struct {
	Result            review.CoordinatorResult
	Target            ports.LiveSourceTarget
	SeverityThreshold domain.Severity
	Provenance        LiveProductionProvenance
	AttemptArtifacts  []AttemptArtifactInput
	BinaryEvidence    []evidence.LiveBinaryReceipt
}

func PrepareLiveCandidate(input LiveCandidateInput) (PreparedLiveCandidate, error) {
	if input.Target.NoChange() {
		return PreparedLiveCandidate{}, fmt.Errorf("live publication: empty selection requires provider-free no-change preparation")
	}
	source, err := prepareLiveSource(input.Target, input.Provenance, input.BinaryEvidence)
	if err != nil {
		return PreparedLiveCandidate{}, err
	}
	if "sha256:"+input.Result.SourceIdentitySHA256() != source.identity.SHA256() {
		return PreparedLiveCandidate{}, fmt.Errorf("live publication: coordination source identity mismatch")
	}
	candidate, err := prepareTerminalCandidate(input.Result, preparedTarget{
		sha256: source.identity.SHA256(), baseOID: input.Target.Base().String(), headOID: input.Target.Head().String(), live: source,
	}, publicationEvidenceTarget{source: source.identity}, input.SeverityThreshold, input.Provenance.BuildVersion, input.Provenance.BuildCommit, rootPublicationContext())
	if err != nil {
		return PreparedLiveCandidate{}, err
	}
	if err := candidate.bindAttemptArtifacts(input.AttemptArtifacts); err != nil {
		return PreparedLiveCandidate{}, err
	}
	return PreparedLiveCandidate{candidate: candidate}, nil
}

func PrepareLiveNoChangeCandidate(sessionID domain.SessionID, runID domain.RunID, target ports.LiveSourceTarget, selectedRoles []domain.Role, threshold domain.Severity, provenance LiveProductionProvenance) (PreparedLiveCandidate, error) {
	if !target.NoChange() || len(provenance.Providers) != 0 {
		return PreparedLiveCandidate{}, fmt.Errorf("live no-change publication: provider-free empty selection is required")
	}
	source, err := prepareLiveSource(target, provenance, nil)
	if err != nil {
		return PreparedLiveCandidate{}, err
	}
	if threshold == "" {
		threshold = domain.SeverityHigh
	}
	roles := make([]preparedRole, len(selectedRoles))
	for index, role := range selectedRoles {
		roles[index] = preparedRole{role: role, required: role == domain.RoleLogic, state: domain.RoleTaskSucceeded, valid: true, outcome: "not_applicable", limitations: []string{evidence.LiveNoChangeLimitation}}
	}
	candidate := PreparedCandidate{
		sessionID: sessionID, runID: runID, runState: domain.RunCompleted,
		target:    preparedTarget{sha256: source.identity.SHA256(), baseOID: target.Base().String(), headOID: target.Head().String(), live: source},
		threshold: threshold, mulgae: preparedMulgae{version: provenance.BuildVersion, commit: provenance.BuildCommit},
		axes:  preparedAxes{content: domain.ContentNoFindings, coverage: domain.CoverageComplete, ci: domain.CIPass, structuredExtraction: domain.StructuredExtractionStructured},
		roles: roles, findings: []preparedFinding{}, failures: []preparedFailure{}, limits: []string{}, reasons: []string{"policy_evaluated"}, exitCode: int(domain.ExitCommittedPass), lineage: rootPublicationContext().lineage, noChange: true,
	}
	if err := candidate.validate(); err != nil {
		return PreparedLiveCandidate{}, err
	}
	return PreparedLiveCandidate{candidate: candidate}, nil
}

func prepareLiveSource(target ports.LiveSourceTarget, provenance LiveProductionProvenance, binary []evidence.LiveBinaryReceipt) (*preparedLiveSource, error) {
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		return nil, err
	}
	if err := validateLiveProvenance(provenance, identity, target.NoChange()); err != nil {
		return nil, err
	}
	provenance.Providers = cloneProductionReviewProvenance(ProductionReviewProvenance{Providers: provenance.Providers}).Providers
	selected := append([]evidence.LiveBinaryReceipt(nil), binary...)
	sort.SliceStable(selected, func(i, j int) bool {
		return string(selected[i].Side())+"\x00"+selected[i].Path().String() < string(selected[j].Side())+"\x00"+selected[j].Path().String()
	})
	for index, receipt := range selected {
		if !receipt.Valid() || receipt.Source().SHA256() != identity.SHA256() || index > 0 && receipt.Side() == selected[index-1].Side() && receipt.Path() == selected[index-1].Path() {
			return nil, fmt.Errorf("live publication: invalid, rebound or duplicate binary observation")
		}
	}
	return &preparedLiveSource{target: target, identity: identity, provenance: provenance, binary: selected}, nil
}

func validateLiveProvenance(value LiveProductionProvenance, identity evidence.LiveSourceIdentity, noChange bool) error {
	if !identity.Valid() || value.SourceIdentitySHA256 != identity.SHA256() || value.BuildProduct != "mulgae" || !safeText(value.BuildCommit, 128, true) || validateBuildMetadata(value.BuildVersion, value.BuildCommit) != nil ||
		!validReceiptID(value.SourceTerminalReceipt) || value.HasObjective != (value.ObjectiveSHA256 != "") || value.HasObjective && !validSHA256(value.ObjectiveSHA256) ||
		noChange != (len(value.Providers) == 0) {
		return fmt.Errorf("live publication: invalid source, build, objective or terminal provenance")
	}
	return validateProductionProviders(value.Providers)
}

func (candidate PreparedCandidate) validateLiveSource() error {
	source := candidate.target.live
	if source == nil {
		return nil
	}
	if candidate.publicationLineage().runType != domain.RunTypeReview || candidate.production != nil || candidate.noChangeProvenance != nil || len(candidate.capturedArchive) != 0 ||
		candidate.target.sha256 != source.identity.SHA256() || candidate.target.baseOID != source.target.Base().String() || candidate.target.headOID != source.target.Head().String() ||
		candidate.mulgae.version != source.provenance.BuildVersion || candidate.mulgae.commit != source.provenance.BuildCommit || candidate.noChange != source.target.NoChange() {
		return fmt.Errorf("live publication: source authority is inconsistent or contains captured material")
	}
	if err := validateLiveProvenance(source.provenance, source.identity, candidate.noChange); err != nil {
		return err
	}
	for _, role := range candidate.roles {
		for _, attempt := range role.attempts {
			for _, invocation := range attempt.invocations {
				if invocation.runtime != nil {
					return fmt.Errorf("live publication: captured runtime inventory is forbidden")
				}
			}
		}
	}
	for _, finding := range candidate.findings {
		for _, item := range finding.evidence {
			if item.liveSource.SHA256() != source.identity.SHA256() {
				return fmt.Errorf("live publication: mixed source evidence")
			}
		}
	}
	return nil
}

func (candidate PreparedCandidate) validateLiveNoChange() error {
	if candidate.runState != domain.RunCompleted || candidate.axes != (preparedAxes{content: domain.ContentNoFindings, coverage: domain.CoverageComplete, ci: domain.CIPass, structuredExtraction: domain.StructuredExtractionStructured}) ||
		len(candidate.roles) == 0 || len(candidate.findings) != 0 || len(candidate.failures) != 0 || len(candidate.limits) != 0 || candidate.exitCode != int(domain.ExitCommittedPass) || !reflect.DeepEqual(candidate.reasons, []string{"policy_evaluated"}) {
		return fmt.Errorf("live no-change publication: inconsistent outcomes")
	}
	for index, role := range candidate.roles {
		if !role.role.Valid() || index > 0 && roleOrdinal(candidate.roles[index-1].role) >= roleOrdinal(role.role) || role.required != (role.role == domain.RoleLogic) ||
			role.state != domain.RoleTaskSucceeded || !role.valid || role.degraded || role.repaired || role.failureClass != "" || role.failureReason != "" || role.outcome != "not_applicable" ||
			len(role.attempts) != 0 || len(role.validFindingIDs) != 0 || role.outputTransport != "" || len(role.reportMarkdown) != 0 || !reflect.DeepEqual(role.limitations, []string{evidence.LiveNoChangeLimitation}) {
			return fmt.Errorf("live no-change publication: inconsistent selected roles")
		}
	}
	return nil
}

func (service *Service) PublishLiveNext(ctx context.Context, root ports.AnchoredRoot, candidate PreparedLiveCandidate) (PublicationResult, error) {
	return service.publishNextCandidate(ctx, root, candidate, nil)
}

func (service *Service) PublishLiveNextObserved(ctx context.Context, root ports.AnchoredRoot, candidate PreparedLiveCandidate, observer LifecycleObserver) (PublicationResult, error) {
	if observer == nil {
		return PublicationResult{}, fmt.Errorf("live publication: lifecycle observer unavailable")
	}
	return service.publishNextCandidate(ctx, root, candidate, observer)
}
