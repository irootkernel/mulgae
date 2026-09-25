package providercli

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// protocolInvocationPurpose is the adapter-owned purpose used to construct a
// provider conversation. Qualification is intentionally separate from review
// invocation purposes even though both use the same process runner.
type protocolInvocationPurpose string

const (
	protocolPurposeReview        protocolInvocationPurpose = "review"
	protocolPurposeExtraction    protocolInvocationPurpose = "extraction"
	protocolPurposeQualification protocolInvocationPurpose = "qualification"
)

// providerProtocolSession is the common result of a protocol driver
// constructor. The registry consumes only these protocol-neutral facts.
type providerProtocolSession interface {
	ports.ProviderSessionDriver
	AssistantEvidenceText() []byte
	SessionObservation() (ports.ProviderSessionObservation, bool)
}

type protocolWriteAuthority interface {
	Destination() (ports.StagedOutputDestination, error)
	AuthorizeWriteOnce(candidate string) error
}

// providerProtocolDriverConstructor owns the wire-protocol choice for a
// runtime definition. A protocol channel without this authority is invalid.
type providerProtocolDriverConstructor interface {
	NewSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, writeAuthority protocolWriteAuthority, configuration protocolSessionConfiguration) (providerProtocolSession, error)
}

type protocolSessionConfiguration struct {
	zcodeSelection *zcodeModelSelection
	zcodeEffort    string
	zcodeAccount   *zcodeAccountRuntime
	grokSettings   grokInvocationSettings
}

type zcodeAccountRuntimeAuthority interface {
	zcodeAccountRuntime(string, string) (*zcodeAccountRuntime, error)
}

func protocolConfigurationForNamespace(definition RuntimeDefinition, namespace any) (protocolSessionConfiguration, error) {
	configuration := protocolSessionConfiguration{
		grokSettings: grokInvocationSettings{
			model: definition.grokModel, reasoningEffort: definition.grokReasoningEffort,
		},
	}
	if definition.family != FamilyZcode {
		return configuration, nil
	}
	selection, err := parseZCodeModelSelection(definition.zcodeModel)
	if err != nil {
		return protocolSessionConfiguration{}, err
	}
	configuration.zcodeSelection = selection
	configuration.zcodeEffort = definition.zcodeReasoningEffort
	authority, ok := namespace.(zcodeAccountRuntimeAuthority)
	if !ok || authority == nil {
		// Provider-neutral qualification doubles carry no native account authority.
		return configuration, nil
	}
	account, err := authority.zcodeAccountRuntime(definition.zcodeProviderConfig, definition.zcodeModel)
	if err != nil {
		return protocolSessionConfiguration{}, err
	}
	configuration.zcodeAccount = account
	return configuration, nil
}

type zcodeProtocolDriverConstructor struct{}

func (zcodeProtocolDriverConstructor) NewSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, _ protocolWriteAuthority, configuration protocolSessionConfiguration) (providerProtocolSession, error) {
	var session *zcodeProtocolSession
	var err error
	switch purpose {
	case protocolPurposeReview:
		session, err = newZcodeReviewProtocolSession(workspacePath, prompt, configuration.zcodeSelection)
	case protocolPurposeExtraction:
		session, err = newZcodeExtractionProtocolSession(workspacePath, prompt, configuration.zcodeSelection)
	case protocolPurposeQualification:
		session, err = newZcodeCapabilityProtocolSession(workspacePath, prompt, configuration.zcodeSelection)
	default:
		return nil, fmt.Errorf("zcode protocol: unsupported invocation purpose")
	}
	if err != nil {
		return nil, err
	}
	session.reasoningEffort = configuration.zcodeEffort
	session.account = configuration.zcodeAccount
	return session, nil
}

type grokACPProtocolDriverConstructor struct{}

func (grokACPProtocolDriverConstructor) NewSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, writeAuthority protocolWriteAuthority, configuration protocolSessionConfiguration) (providerProtocolSession, error) {
	return newGrokACPProtocolSession(workspacePath, prompt, purpose, writeAuthority, configuration.grokSettings)
}

type codexProtocolDriverConstructor struct{}

func (codexProtocolDriverConstructor) NewSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, writeAuthority protocolWriteAuthority, _ protocolSessionConfiguration) (providerProtocolSession, error) {
	return newCodexProtocolSession(workspacePath, prompt, purpose, writeAuthority)
}

// providerAdapterAuthority is the single family-to-transport-and-driver
// registry. Other family switches may shape native argv or output, but they do
// not select whether or how a protocol conversation is driven.
type providerAdapterAuthority struct {
	defaultChannel       ports.ProviderPacketChannel
	qualificationChannel ports.ProviderPacketChannel
	protocolDriver       providerProtocolDriverConstructor
}

func adapterAuthorityForFamily(family string) (providerAdapterAuthority, error) {
	switch family {
	case FamilyZcode:
		return providerAdapterAuthority{defaultChannel: ports.ProviderPacketChannelProtocol, qualificationChannel: ports.ProviderPacketChannelProtocol, protocolDriver: zcodeProtocolDriverConstructor{}}, nil
	case FamilyGrok:
		return providerAdapterAuthority{defaultChannel: ports.ProviderPacketChannelProtocol, qualificationChannel: ports.ProviderPacketChannelProtocol, protocolDriver: grokACPProtocolDriverConstructor{}}, nil
	case FamilyCodex:
		return providerAdapterAuthority{defaultChannel: ports.ProviderPacketChannelProtocol, qualificationChannel: ports.ProviderPacketChannelProtocol, protocolDriver: codexProtocolDriverConstructor{}}, nil
	default:
		return providerAdapterAuthority{}, fmt.Errorf("unsupported family")
	}
}

type protocolDiagnosticFailure interface {
	error
	ProtocolFailureCause() domain.RuntimeDiagnosticCause
}

func protocolPurposeForReview(purpose ports.ProviderInvocationPurpose) protocolInvocationPurpose {
	if purpose == ports.ProviderInvocationExtract {
		return protocolPurposeExtraction
	}
	return protocolPurposeReview
}

func releaseProtocolTranscript(observation ports.ProcessObservation) error {
	artifact, ok := observation.StdoutArtifact()
	if !ok {
		return nil
	}
	lease, ok := artifact.(ports.ContentLease)
	if !ok || lease == nil {
		return fmt.Errorf("protocol transcript: missing cleanup authority")
	}
	if err := lease.Close(); err != nil {
		return fmt.Errorf("protocol transcript: cleanup: %w", err)
	}
	return nil
}
