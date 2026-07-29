package providers

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/doctor"
)

// Diagnoser supplies the redacted environment diagnosis consumed by this
// read-only service.
type Diagnoser interface {
	DiagnoseEnvironment(context.Context) (doctor.DoctorResult, error)
}

// Service lists fixed provider profiles from doctor evidence. It neither probes
// providers nor promotes evidence.
type Service struct {
	diagnoser Diagnoser
}

// NewService constructs a provider-profile listing service.
func NewService(diagnoser Diagnoser) (*Service, error) {
	if nilInterface(diagnoser) {
		return nil, fmt.Errorf("providers: nil diagnoser")
	}
	return &Service{diagnoser: diagnoser}, nil
}

// ListProviderProfiles returns the exact trusted family inventory in canonical
// order. When includeUnverified is false, only unverified profiles are omitted;
// failed and inconclusive profiles remain visible as unsupported.
func (service *Service) ListProviderProfiles(ctx context.Context, includeUnverified bool) (Result, error) {
	var zero Result
	if ctx == nil {
		return zero, fmt.Errorf("providers: nil context")
	}
	if service == nil || nilInterface(service.diagnoser) {
		return zero, fmt.Errorf("providers: invalid service dependencies")
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("providers: context: %w", err)
	}

	diagnosis, err := service.diagnoser.DiagnoseEnvironment(ctx)
	if err != nil {
		return zero, fmt.Errorf("providers: diagnose environment: %w", err)
	}
	if err := diagnosis.Validate(); err != nil {
		return zero, fmt.Errorf("providers: invalid doctor result: %w", err)
	}
	evidence, err := canonicalEvidence(diagnosis)
	if err != nil {
		return zero, err
	}

	profiles := make([]Profile, 0, len(trustedProfiles))
	for _, definition := range trustedProfiles {
		row, found := evidence[definition.family]
		profile := definition.profile(row, found)
		if !includeUnverified && profile.support == SupportUnverified {
			continue
		}
		profiles = append(profiles, profile)
	}
	return Result{profiles: profiles}, nil
}

type profileDefinition struct {
	family          Family
	id              string
	promptTransport PromptTransport
	resultTransport ResultTransport
}

var trustedProfiles = []profileDefinition{
	{family: FamilyKimi, id: "kimi-default", promptTransport: PromptTransportArgv, resultTransport: ResultTransportKimiStreamJSONAssistantContent},
	{family: FamilyZCode, id: "zcode-default", promptTransport: PromptTransportArgv, resultTransport: ResultTransportStrictJSON},
	{family: FamilyAGY, id: "agy-default", promptTransport: PromptTransportArgv, resultTransport: ResultTransportStrictJSON},
}

func (definition profileDefinition) profile(evidence doctor.ProviderEvidence, found bool) Profile {
	profile := Profile{
		family:          definition.family,
		id:              definition.id,
		promptTransport: definition.promptTransport,
		resultTransport: definition.resultTransport,
		support:         SupportUnverified,
		evidenceState:   doctor.EvidenceStateUnverified,
		assignmentState: doctor.AssignmentIntendedButUnverified,
	}
	if !found {
		return profile
	}
	profile.evidenceState = evidence.EvidenceState
	profile.assignmentState = evidence.AssignmentState
	if evidence.EvidenceURI != nil {
		profile.evidenceURI = *evidence.EvidenceURI
	}
	if evidence.EvidenceSHA256 != nil {
		profile.evidenceSHA256 = *evidence.EvidenceSHA256
	}
	switch evidence.EvidenceState {
	case doctor.EvidenceStatePass:
		if evidence.Intended && evidence.AssignmentState == doctor.AssignmentEligible {
			profile.support = SupportSupported
		}
	case doctor.EvidenceStateFail, doctor.EvidenceStateInconclusive:
		profile.support = SupportUnsupported
	}
	return profile
}

func canonicalEvidence(diagnosis doctor.DoctorResult) (map[Family]doctor.ProviderEvidence, error) {
	if err := validateProviderIDOrder("intended_provider_ids", diagnosis.IntendedProviderIDs); err != nil {
		return nil, err
	}
	if err := validateProviderIDOrder("unverified_provider_ids", diagnosis.UnverifiedProviderIDs); err != nil {
		return nil, err
	}

	rows := make(map[Family]doctor.ProviderEvidence, len(diagnosis.ProviderEvidence))
	last := -1
	for _, row := range diagnosis.ProviderEvidence {
		family, index, ok := trustedFamily(row.ProviderID)
		if !ok {
			return nil, fmt.Errorf("providers: unexpected provider evidence family %q", row.ProviderID)
		}
		if _, duplicate := rows[family]; duplicate {
			return nil, fmt.Errorf("providers: duplicate provider evidence for %q", row.ProviderID)
		}
		if index <= last {
			return nil, fmt.Errorf("providers: provider evidence is not in canonical order")
		}
		if !validEvidenceState(row.EvidenceState) || !validAssignmentState(row.AssignmentState) {
			return nil, fmt.Errorf("providers: provider evidence %q has invalid state", row.ProviderID)
		}
		last = index
		rows[family] = copyEvidence(row)
	}
	return rows, nil
}

func validateProviderIDOrder(field string, ids []string) error {
	last := -1
	seen := make(map[Family]struct{}, len(ids))
	for _, id := range ids {
		family, index, ok := trustedFamily(id)
		if !ok {
			return fmt.Errorf("providers: %s contains unexpected family %q", field, id)
		}
		if _, duplicate := seen[family]; duplicate {
			return fmt.Errorf("providers: %s contains duplicate family %q", field, id)
		}
		if index <= last {
			return fmt.Errorf("providers: %s is not in canonical order", field)
		}
		seen[family] = struct{}{}
		last = index
	}
	return nil
}

func trustedFamily(id string) (Family, int, bool) {
	for index, definition := range trustedProfiles {
		if string(definition.family) == id {
			return definition.family, index, true
		}
	}
	return "", 0, false
}

func validEvidenceState(state doctor.EvidenceState) bool {
	switch state {
	case doctor.EvidenceStatePass, doctor.EvidenceStateFail, doctor.EvidenceStateInconclusive, doctor.EvidenceStateUnverified:
		return true
	default:
		return false
	}
}

func validAssignmentState(state doctor.AssignmentState) bool {
	switch state {
	case doctor.AssignmentEligible, doctor.AssignmentIneligible, doctor.AssignmentIntendedButUnverified:
		return true
	default:
		return false
	}
}

func copyEvidence(row doctor.ProviderEvidence) doctor.ProviderEvidence {
	copy := row
	if row.EvidenceURI != nil {
		value := *row.EvidenceURI
		copy.EvidenceURI = &value
	}
	if row.EvidenceSHA256 != nil {
		value := *row.EvidenceSHA256
		copy.EvidenceSHA256 = &value
	}
	copy.ReasonCodes = append([]string(nil), row.ReasonCodes...)
	return copy
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	switch kind {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}

// RenderHuman deterministically renders only JSON-safe profile fields.
func RenderHuman(result Result) string {
	var output bytes.Buffer
	for _, profile := range result.profiles {
		fmt.Fprintf(&output, "family=%s profile=%s support=%s evidence=%s assignment=%s", profile.family, profile.id, profile.support, profile.evidenceState, profile.assignmentState)
		if profile.evidenceURI != "" {
			fmt.Fprintf(&output, " evidence_uri=%s", profile.evidenceURI)
		}
		if profile.evidenceSHA256 != "" {
			fmt.Fprintf(&output, " evidence_sha256=%s", profile.evidenceSHA256)
		}
		output.WriteByte('\n')
	}
	return output.String()
}

// RenderHuman deterministically renders only JSON-safe profile fields.
func (result Result) RenderHuman() string {
	return RenderHuman(result)
}

// String renders the JSON-safe human view.
func (result Result) String() string {
	return strings.TrimSuffix(RenderHuman(result), "\n")
}
