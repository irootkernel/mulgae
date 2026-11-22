package providercli

import (
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// protocolInvocationPurpose is the adapter-owned purpose used to construct a
// provider conversation. Qualification is intentionally separate from review
// invocation purposes even though both use the same process runner.
type protocolInvocationPurpose string

const (
	protocolPurposeReview         protocolInvocationPurpose = "review"
	protocolPurposeExtraction     protocolInvocationPurpose = "extraction"
	protocolPurposeQualification  protocolInvocationPurpose = "qualification"
	protocolPurposeLiveReview     protocolInvocationPurpose = "live-review"
	protocolPurposeLiveExtraction protocolInvocationPurpose = "live-extraction"
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
	zcodeSelection  *zcodeModelSelection
	zcodeEffort     string
	zcodeAccount    *zcodeAccountRuntime
	liveSourceScope domain.LiveSourceScope
	agySettings     agyInvocationSettings
	agyLiveReads    *agyLiveReadAuthority
	agyAgentName    string
}

type zcodeAccountRuntimeAuthority interface {
	zcodeAccountRuntime(context.Context, RuntimeDefinition) (*zcodeAccountRuntime, error)
}

func protocolConfigurationForNamespace(ctx context.Context, definition RuntimeDefinition, namespace any) (protocolSessionConfiguration, error) {
	configuration := protocolSessionConfiguration{}
	if definition.family == FamilyAgy {
		settings, err := newAgyInvocationSettings(definition.agyModel, definition.agyReasoningEffort)
		if err != nil {
			return protocolSessionConfiguration{}, err
		}
		configuration.agySettings = settings
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
	account, err := authority.zcodeAccountRuntime(ctx, definition)
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
	case protocolPurposeLiveReview:
		if configuration.liveSourceScope != "" && !configuration.liveSourceScope.Valid() {
			return nil, fmt.Errorf("zcode protocol: invalid live source scope")
		}
		session, err = newZcodeProtocolSession(workspacePath, "plan", zcodeLiveReviewProtocolDenylist, prompt, configuration.zcodeSelection)
		if err == nil {
			session.captureAssistantText = true
			session.liveSource = true
			session.liveReadTools = true
			session.liveSourceScope = configuration.liveSourceScope
		}
	case protocolPurposeLiveExtraction:
		session, err = newZcodeCapabilityProtocolSession(workspacePath, prompt, configuration.zcodeSelection)
		if err == nil {
			session.liveSource = true
			session.extraction = true
		}
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

type agyProtocolDriverConstructor struct{}

func (agyProtocolDriverConstructor) NewSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, writeAuthority protocolWriteAuthority, configuration protocolSessionConfiguration) (providerProtocolSession, error) {
	return newAgyProtocolSession(workspacePath, prompt, purpose, writeAuthority, configuration)
}

type codexProtocolDriverConstructor struct{}

func (codexProtocolDriverConstructor) NewSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, writeAuthority protocolWriteAuthority, _ protocolSessionConfiguration) (providerProtocolSession, error) {
	return newCodexProtocolSession(workspacePath, prompt, purpose, writeAuthority)
}

// providerAdapterAuthority is the single family-to-transport-and-driver
// registry. Other family switches may shape native argv or output, but they do
// not select whether or how a protocol or terminal conversation is driven.
type providerAdapterAuthority struct {
	defaultChannel       ports.ProviderPacketChannel
	qualificationChannel ports.ProviderPacketChannel
	protocolDriver       providerProtocolDriverConstructor
	terminalProfile      terminalProviderProfile
}

func adapterAuthorityForFamily(family string) (providerAdapterAuthority, error) {
	switch family {
	case FamilyZcode:
		return providerAdapterAuthority{defaultChannel: ports.ProviderPacketChannelProtocol, qualificationChannel: ports.ProviderPacketChannelProtocol, protocolDriver: zcodeProtocolDriverConstructor{}}, nil
	case FamilyGrok:
		return providerAdapterAuthority{defaultChannel: ports.ProviderPacketChannelTerminal, qualificationChannel: ports.ProviderPacketChannelTerminal, terminalProfile: grokTerminalProfile{}}, nil
	case FamilyCodex:
		return providerAdapterAuthority{defaultChannel: ports.ProviderPacketChannelProtocol, qualificationChannel: ports.ProviderPacketChannelProtocol, protocolDriver: codexProtocolDriverConstructor{}}, nil
	case FamilyAgy:
		return providerAdapterAuthority{defaultChannel: ports.ProviderPacketChannelProtocol, qualificationChannel: ports.ProviderPacketChannelProtocol, protocolDriver: agyProtocolDriverConstructor{}}, nil
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
