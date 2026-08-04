package providercli

import (
	"fmt"
	"reflect"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

// NativeProbeInvocation builds the sole family-policy probe argv. Approved
// permission bypasses are emitted only by their owning family policy.
type NativeProbeInvocation struct{}

const agyPrintTimeoutCleanupGrace = 5 * time.Second

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
	packet := fixture.Packet()
	if len(packet) == 0 {
		return nil, fmt.Errorf("native probe invocation: invalid fixture packet")
	}
	switch definition.Family() {
	case FamilyKimi:
		return appendKimiInvocation(baseArgv, definition.KimiModel(), string(packet)), nil
	case FamilyZcode:
		return appendZcodeInvocation(baseArgv, string(packet)), nil
	case FamilyAgy:
		return canonicalAGYExecutionArgv(definition, fixture.WorkspaceSnapshotIdentity(), fixture.Reference())
	default:
		return nil, fmt.Errorf("native probe invocation: unsupported family")
	}
}

func appendZcodeInvocation(argv []string, prompt string) []string {
	result := append([]string(nil), argv...)
	return append(result, "--mode", "build", "--no-color", "--prompt", prompt, "--json", "--disallowed-tools", "*")
}

func appendKimiInvocation(argv []string, model, prompt string) []string {
	result := append([]string(nil), argv...)
	if model == "" {
		model = "kimi-code/kimi-for-coding"
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
	if definition.Transport().ArgvIndex() == 13 {
		controls = append(controls, "--dangerously-skip-permissions")
	}
	controls = append(controls, "--add-dir", snapshotPath, "--mode", "plan", "--effort", "low", "--print-timeout", agyPrintTimeout(definition.Timeout()).String(), "--print", "@"+nativeReference)
	return append(baseArgv, controls...), nil
}

func agyPrintTimeout(runtimeTimeout time.Duration) time.Duration {
	// Keep AGY's own timeout inside the enclosing process deadline so Mulgae
	// retains time to collect output and complete bounded lifecycle cleanup.
	grace := min(agyPrintTimeoutCleanupGrace, runtimeTimeout/2)
	return runtimeTimeout - grace
}

func immutableSnapshotPath(identity ports.WorkspaceSnapshotIdentity) (string, error) {
	if !identity.Valid() {
		return "", fmt.Errorf("native probe invocation: invalid immutable snapshot identity")
	}
	return identity.SnapshotPath(), nil
}
