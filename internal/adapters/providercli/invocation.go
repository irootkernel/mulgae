package providercli

import (
	"fmt"
	"reflect"
)

// NativeProbeInvocation builds the sole family-policy probe argv. Approved
// permission bypasses are emitted only by their owning family policy.
type NativeProbeInvocation struct{}

// VersionArgv builds the sole family-closed argv admitted for a version probe.
func (NativeProbeInvocation) VersionArgv(definition RuntimeDefinition) ([]string, error) {
	if err := safeProbeDefinition(definition); err != nil {
		return nil, err
	}
	baseArgv, err := canonicalProbeBaseArgv(definition)
	if err != nil {
		return nil, err
	}
	argv := append(baseArgv, "--version")
	if definition.Family() == FamilyZcode {
		argv = append(argv, "--json")
		if bundle := definition.zcodeCompanion.BundleOverride; bundle != "" {
			argv = append(argv, "--app-bundle", bundle)
		}
	}
	return argv, nil
}
func (NativeProbeInvocation) CapabilityArgv(definition RuntimeDefinition, fixture ProbeFixture) ([]string, error) {
	if err := safeProbeDefinition(definition); err != nil {
		return nil, err
	}
	if fixture == nil || fixture.Validate() != nil || !validRelativeNativeReference(fixture.Reference()) {
		return nil, fmt.Errorf("native probe invocation: invalid fixture")
	}
	return nativeProbeArgv(definition, fixture)
}

func (NativeProbeInvocation) Validate(definition RuntimeDefinition, fixture ProbeFixture, argv []string) error {
	if fixture == nil || fixture.Validate() != nil {
		return fmt.Errorf("native probe invocation: invalid fixture")
	}
	want, err := nativeProbeArgv(definition, fixture)
	if err != nil || !reflect.DeepEqual(argv, want) {
		return fmt.Errorf("native probe invocation: argv violates family policy")
	}
	return nil
}

func nativeProbeArgv(definition RuntimeDefinition, fixture ProbeFixture) ([]string, error) {
	if err := safeProbeDefinition(definition); err != nil {
		return nil, err
	}
	if fixture == nil || !validRelativeNativeReference(fixture.Reference()) {
		return nil, fmt.Errorf("native probe invocation: invalid native reference")
	}
	baseArgv, err := canonicalProbeBaseArgv(definition)
	if err != nil {
		return nil, err
	}
	packet := fixture.Packet()
	if len(packet) == 0 {
		return nil, fmt.Errorf("native probe invocation: invalid fixture packet")
	}
	switch definition.Family() {
	case FamilyZcode:
		// The real argv is assembled after descriptor-bound host preparation.
		return baseArgv, nil
	case FamilyGrok:
		return grokTerminalBaseArgv(definition, terminalPurposeQualification, "", false)
	default:
		return nil, fmt.Errorf("native probe invocation: unsupported family")
	}
}

func canonicalProbeBaseArgv(definition RuntimeDefinition) ([]string, error) {
	baseArgv := definition.BaseArgv()
	executable := definition.Executable()
	if !reflect.DeepEqual(baseArgv, []string{executable}) {
		return nil, fmt.Errorf("native probe invocation: unsupported %s base argv", definition.Family())
	}
	return baseArgv, nil
}
