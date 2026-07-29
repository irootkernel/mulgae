// Package providers lists the fixed, trusted provider profiles without invoking them.
package providers

import "github.com/irootkernel/mulgae/internal/app/doctor"

// Family identifies one provider family in canonical runtime order.
type Family string

const (
	FamilyKimi  Family = "kimi"
	FamilyZCode Family = "zcode"
	FamilyAGY   Family = "agy"
)

// SupportState is the non-authoritative availability projection of doctor evidence.
type SupportState string

const (
	SupportSupported   SupportState = "supported"
	SupportUnsupported SupportState = "unsupported"
	SupportUnverified  SupportState = "unverified"
)

// PromptTransport identifies the fixed provider prompt transport.
type PromptTransport string

const (
	PromptTransportArgv PromptTransport = "argv"
)

// ResultTransport identifies the fixed provider result transport.
type ResultTransport string

const (
	ResultTransportKimiStreamJSONAssistantContent ResultTransport = "kimi_stream_json_assistant_content"
	ResultTransportStrictJSON                     ResultTransport = "strict_json"
)

// Profile is the immutable application view of a trusted provider profile.
type Profile struct {
	family          Family
	id              string
	promptTransport PromptTransport
	resultTransport ResultTransport
	support         SupportState
	evidenceState   doctor.EvidenceState
	assignmentState doctor.AssignmentState
	evidenceURI     string
	evidenceSHA256  string
}

func (profile Profile) Family() Family                          { return profile.family }
func (profile Profile) ID() string                              { return profile.id }
func (profile Profile) PromptTransport() PromptTransport        { return profile.promptTransport }
func (profile Profile) ResultTransport() ResultTransport        { return profile.resultTransport }
func (profile Profile) Support() SupportState                   { return profile.support }
func (profile Profile) EvidenceState() doctor.EvidenceState     { return profile.evidenceState }
func (profile Profile) AssignmentState() doctor.AssignmentState { return profile.assignmentState }

// EvidenceURI returns the redacted authority evidence URI, when doctor supplied one.
func (profile Profile) EvidenceURI() (string, bool) {
	return profile.evidenceURI, profile.evidenceURI != ""
}

// EvidenceSHA256 returns the redacted authority evidence digest, when doctor supplied one.
func (profile Profile) EvidenceSHA256() (string, bool) {
	return profile.evidenceSHA256, profile.evidenceSHA256 != ""
}

// Result is a caller-safe list of profiles in canonical family order.
type Result struct {
	profiles []Profile
}

// Profiles returns a defensive copy in canonical family order.
func (result Result) Profiles() []Profile {
	return append([]Profile(nil), result.profiles...)
}

// JSONResult is the JSON-safe public projection. It excludes executable paths,
// environment values, credentials, prompt bytes, and arbitrary diagnostic errors.
type JSONResult struct {
	Profiles []JSONProfile `json:"profiles"`
}

// JSONProfile is the JSON-safe projection for one fixed provider profile.
type JSONProfile struct {
	Family          Family                 `json:"family"`
	ProfileID       string                 `json:"profile_id"`
	PromptTransport PromptTransport        `json:"prompt_transport"`
	ResultTransport ResultTransport        `json:"result_transport"`
	Support         SupportState           `json:"support"`
	EvidenceState   doctor.EvidenceState   `json:"evidence_state"`
	AssignmentState doctor.AssignmentState `json:"assignment_state"`
	EvidenceURI     *string                `json:"evidence_uri,omitempty"`
	EvidenceSHA256  *string                `json:"evidence_sha256,omitempty"`
}

// JSON returns a defensive JSON-safe projection of the result.
func (result Result) JSON() JSONResult {
	profiles := make([]JSONProfile, 0, len(result.profiles))
	for _, profile := range result.profiles {
		row := JSONProfile{
			Family:          profile.family,
			ProfileID:       profile.id,
			PromptTransport: profile.promptTransport,
			ResultTransport: profile.resultTransport,
			Support:         profile.support,
			EvidenceState:   profile.evidenceState,
			AssignmentState: profile.assignmentState,
		}
		if profile.evidenceURI != "" {
			value := profile.evidenceURI
			row.EvidenceURI = &value
		}
		if profile.evidenceSHA256 != "" {
			value := profile.evidenceSHA256
			row.EvidenceSHA256 = &value
		}
		profiles = append(profiles, row)
	}
	return JSONResult{Profiles: profiles}
}
