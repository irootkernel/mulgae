package providercli

import (
	"fmt"
	"reflect"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
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
	return append(baseArgv, "--version"), nil
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
	nativeReference := "@" + fixture.Reference()
	switch definition.Family() {
	case FamilyKimi:
		return appendKimiInvocation(baseArgv, definition.KimiModel(), nativeReference), nil
	case FamilyZcode:
		return append(baseArgv, "--mode", "plan", "--no-color", "--prompt", nativeReference), nil
	case FamilyAgy:
		return canonicalAGYExecutionArgv(definition, fixture.WorkspaceSnapshotIdentity(), fixture.Reference())
	default:
		return nil, fmt.Errorf("native probe invocation: unsupported family")
	}
}

func appendKimiInvocation(argv []string, model, prompt string) []string {
	result := append([]string(nil), argv...)
	if model == "" {
		model = "kimi-code/k3"
	}
	result = append(result, "--model", model)
	return append(result, "--prompt", prompt, "--output-format", "stream-json")
}
func canonicalProbeBaseArgv(definition RuntimeDefinition) ([]string, error) {
	baseArgv := definition.BaseArgv()
	executable := definition.Executable()
	switch definition.Family() {
	case FamilyKimi, FamilyAgy:
		if !reflect.DeepEqual(baseArgv, []string{executable}) {
			return nil, fmt.Errorf("native probe invocation: unsupported %s base argv", definition.Family())
		}
	case FamilyZcode:
		launcher := definition.Launcher()
		if !reflect.DeepEqual(baseArgv, []string{executable}) &&
			(launcher == "" || !reflect.DeepEqual(baseArgv, []string{executable, launcher})) {
			return nil, fmt.Errorf("native probe invocation: unsupported zcode base argv")
		}
	default:
		return nil, fmt.Errorf("native probe invocation: unsupported family")
	}
	return baseArgv, nil
}

func canonicalAGYExecutionArgv(definition RuntimeDefinition, snapshot ports.WorkspaceSnapshotIdentity, nativeReference string) ([]string, error) {
	if !validAGYNativeReference(nativeReference) {
		return nil, fmt.Errorf("native probe invocation: invalid native reference")
	}
	baseArgv, err := canonicalProbeBaseArgv(definition)
	if err != nil {
		return nil, err
	}
	snapshotPath, err := immutableSnapshotPath(snapshot)
	if err != nil {
		return nil, err
	}
	controls := []string{"--new-project", "--sandbox"}
	if definition.Transport().ArgvIndex() == 11 {
		controls = append(controls, "--dangerously-skip-permissions")
	}
	controls = append(controls, "--add-dir", snapshotPath, "--mode", "plan", "--print-timeout", "2m", "--print", "@"+nativeReference)
	return append(baseArgv, controls...), nil
}
func immutableSnapshotPath(identity ports.WorkspaceSnapshotIdentity) (string, error) {
	if !identity.Valid() {
		return "", fmt.Errorf("native probe invocation: invalid immutable snapshot identity")
	}
	return identity.SnapshotPath(), nil
}
