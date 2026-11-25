package providercli

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// providerAdapterAuthority is the single family-to-transport-and-driver
// registry. Other family switches may shape native argv or output, but they do
// not select whether or how a protocol or terminal conversation is driven.
type providerAdapterAuthority struct {
	defaultChannel       ports.ProviderPacketChannel
	qualificationChannel ports.ProviderPacketChannel
	terminalProfile      terminalProviderProfile
}

func adapterAuthorityForFamily(family string) (providerAdapterAuthority, error) {
	switch family {
	case FamilyZcode:
		return providerAdapterAuthority{defaultChannel: ports.ProviderPacketChannelTerminal, qualificationChannel: ports.ProviderPacketChannelTerminal, terminalProfile: zcodeTerminalProfile{}}, nil
	case FamilyGrok:
		return providerAdapterAuthority{defaultChannel: ports.ProviderPacketChannelTerminal, qualificationChannel: ports.ProviderPacketChannelTerminal, terminalProfile: grokTerminalProfile{}}, nil
	default:
		return providerAdapterAuthority{}, fmt.Errorf("unsupported family")
	}
}

type protocolDiagnosticFailure interface {
	error
	ProtocolFailureCause() domain.RuntimeDiagnosticCause
}
