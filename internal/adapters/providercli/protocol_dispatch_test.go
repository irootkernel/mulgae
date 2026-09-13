package providercli

import (
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestProtocolAuthorityBindsChannelAndDriverAtConstruction(t *testing.T) {
	for _, test := range []struct {
		family  string
		channel ports.ProviderPacketChannel
		driver  any
	}{
		{FamilyKimi, ports.ProviderPacketChannelArgvLiteral, nil},
		{FamilyZcode, ports.ProviderPacketChannelProtocol, zcodeProtocolDriverConstructor{}},
		{FamilyAgy, ports.ProviderPacketChannelArgvLiteral, nil},
		{FamilyCodex, ports.ProviderPacketChannelStdin, nil},
	} {
		authority, err := adapterAuthorityForFamily(test.family)
		if err != nil {
			t.Fatalf("%s authority: %v", test.family, err)
		}
		if authority.defaultChannel != test.channel || reflect.TypeOf(authority.protocolDriver) != reflect.TypeOf(test.driver) {
			t.Fatalf("%s authority = %#v", test.family, authority)
		}
		if authority.qualificationChannel != test.channel {
			t.Fatalf("%s qualification channel = %q", test.family, authority.qualificationChannel)
		}
	}
}

func TestRuntimeDefinitionRejectsCrossFamilyProtocolMutation(t *testing.T) {
	definition := testProfile(t, FamilyKimi, "kimi_default", "", "")
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelProtocol, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	definition.transport = transport
	definition.protocolDriver = zcodeProtocolDriverConstructor{}
	if err := definition.validate(); err == nil {
		t.Fatal("Kimi definition accepted the ZCode protocol authority")
	}

	zcode := testProfile(t, FamilyZcode, "zcode_default", "", "")
	zcode.protocolDriver = nil
	if err := zcode.validate(); err == nil {
		t.Fatal("ZCode definition accepted a missing protocol driver")
	}
}

func TestZCodeProtocolConstructorOwnsPurposeSelection(t *testing.T) {
	constructor := zcodeProtocolDriverConstructor{}
	for _, test := range []struct {
		purpose protocolInvocationPurpose
		capture bool
	}{
		{protocolPurposeReview, false},
		{protocolPurposeExtraction, true},
		{protocolPurposeQualification, true},
	} {
		driver, err := constructor.NewSession("/private/work", []byte("packet"), test.purpose, nil)
		if err != nil {
			t.Fatal(err)
		}
		session, ok := driver.(*zcodeProtocolSession)
		if !ok || session.captureAssistantText != test.capture {
			t.Fatalf("purpose %q driver = %#v", test.purpose, driver)
		}
	}
	if _, err := constructor.NewSession("/private/work", []byte("packet"), protocolInvocationPurpose("other"), nil); err == nil {
		t.Fatal("constructor accepted an unknown purpose")
	}
}

func TestExplicitProtocolTransportRequiresCanonicalDriverAuthority(t *testing.T) {
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelProtocol, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntimeDefinitionWithTransport(
		FamilyKimi, "kimi_default", "", "/private/bin/kimi", "", "profile",
		[]string{"/private/bin/kimi"}, transport, nil, "/private/work", time.Second,
	); err == nil {
		t.Fatal("non-protocol family accepted the protocol channel")
	}
}
