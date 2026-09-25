package providercli

import "testing"

type zcodeAccountRuntimeStub struct {
	runtime *zcodeAccountRuntime
	err     error
}

func (stub zcodeAccountRuntimeStub) zcodeAccountRuntime(string, string) (*zcodeAccountRuntime, error) {
	return stub.runtime, stub.err
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
		driver, err := constructor.NewSession("/private/work", []byte("packet"), test.purpose, nil, protocolSessionConfiguration{})
		if err != nil {
			t.Fatal(err)
		}
		session, ok := driver.(*zcodeProtocolSession)
		if !ok || session.captureAssistantText != test.capture {
			t.Fatalf("purpose %q driver = %#v", test.purpose, driver)
		}
	}
	if _, err := constructor.NewSession("/private/work", []byte("packet"), protocolInvocationPurpose("other"), nil, protocolSessionConfiguration{}); err == nil {
		t.Fatal("constructor accepted an unknown purpose")
	}
}

func TestZCodeProtocolConfigurationPreservesAppServerDefaultModel(t *testing.T) {
	definition := RuntimeDefinition{family: FamilyZcode}
	account := &zcodeAccountRuntime{}
	configuration, err := protocolConfigurationForNamespace(definition, zcodeAccountRuntimeStub{runtime: account})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.zcodeSelection != nil || configuration.zcodeAccount != account {
		t.Fatalf("app-server default configuration = %#v", configuration)
	}
}
