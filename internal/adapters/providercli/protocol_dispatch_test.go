package providercli

import "testing"

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
