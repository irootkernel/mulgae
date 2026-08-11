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
const agyQualificationJSONSchema = `{"additionalProperties":false,"properties":{"link":{"minLength":1,"type":"string"},"role":{"minLength":1,"type":"string"},"root":{"minLength":1,"type":"string"}},"required":["root","link","role"],"type":"object"}`

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
		// Kimi has no adapter-owned workspace read tools; capability remains
		// prompt-bound to the fixture packet while the process cwd stays the
		// immutable snapshot.
		return appendKimiInvocation(baseArgv, definition.KimiModel(), string(packet)), nil
	case FamilyZcode:
		// Capability stays tool-denied so qualification remains bounded. Review
		// invocations use appendZcodeInvocation's read-oriented denylist.
		return appendZcodeCapabilityInvocation(baseArgv, string(packet)), nil
	case FamilyAgy:
		argv, err := canonicalAGYExecutionArgv(definition, fixture.WorkspaceSnapshotIdentity(), fixture.Reference())
		if err != nil {
			return nil, err
		}
		return append(argv, "--output-format", "json", "--json-schema", agyQualificationJSONSchema), nil
	default:
		return nil, fmt.Errorf("native probe invocation: unsupported family")
	}
}

// zcodeWorkspaceReadOnlyDisallowedTools is the adapter-owned ZCode denylist for
// workspace-first reviews. Local ZCode 0.16.1 rejects --allowed-tools at
// runtime, so Mulgae uses an explicit shell/edit/network denylist instead.
//
// Write is deliberately absent: it is the single authority a staged_file review
// needs to place its role report at the Mulgae-chosen staging path. The
// workspace itself stays read-only regardless, because Bash, Edit and
// NotebookEdit remain denied, the snapshot the process is launched in is
// immutable, and post-execution drift detection revalidates it. Every byte the
// grant produces is bounded by the staged-output validation that reads it back.
const zcodeWorkspaceReadOnlyDisallowedTools = "Bash,Edit,NotebookEdit,WebSearch,WebFetch"

// zcodeCapabilityDisallowedTools keeps qualification prompt-bound and latency
// bounded. Workspace-selective read is exercised on review invocations.
const zcodeCapabilityDisallowedTools = "*"

// appendZcodeInvocation builds the ZCode REVIEW argv only. Qualification keeps
// its own fully tool-denied plan-mode profile in appendZcodeCapabilityInvocation.
//
// yolo is the headless auto-approve mode for the non-denied toolset: plan mode
// suppresses the write authority the staged_file transport depends on. Write
// authority is granted deliberately here and bounded by the staged-output
// validation, snapshot immutability and workspace drift detection (owner
// decision recorded on live capability evidence).
func appendZcodeInvocation(argv []string, prompt string) []string {
	result := append([]string(nil), argv...)
	return append(result, "--mode", "yolo", "--no-color", "--prompt", prompt, "--json", "--disallowed-tools", zcodeWorkspaceReadOnlyDisallowedTools)
}

func appendZcodeCapabilityInvocation(argv []string, prompt string) []string {
	result := append([]string(nil), argv...)
	return append(result, "--mode", "plan", "--no-color", "--prompt", prompt, "--json", "--disallowed-tools", zcodeCapabilityDisallowedTools)
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
	if agyPermissionBypassEnabled(definition.BaseArgv(), definition.Transport()) {
		controls = append(controls, "--dangerously-skip-permissions")
	}
	controls = append(controls, "--add-dir", snapshotPath, "--mode", "plan", "--effort", "low", "--print-timeout", agyProbePrintTimeout(definition.Timeout()).String(), "--print", "@"+nativeReference)
	return append(baseArgv, controls...), nil
}

func agyPermissionBypassEnabled(baseArgv []string, transport RuntimeTransport) bool {
	return transport.ArgvIndex() == len(baseArgv)+12
}

func agyPrintTimeout(runtimeTimeout time.Duration) time.Duration {
	// Keep AGY's own timeout inside the enclosing process deadline so Mulgae
	// retains time to collect output and complete bounded lifecycle cleanup.
	grace := min(agyPrintTimeoutCleanupGrace, runtimeTimeout/2)
	return runtimeTimeout - grace
}

// agyProbePrintTimeout keeps AGY's own print deadline inside the bounded
// qualification process deadline. canonicalAGYExecutionArgv builds capability
// probe argv only; review invocations keep deriving their print deadline from
// the full configured runtime timeout in buildArgv.
func agyProbePrintTimeout(runtimeTimeout time.Duration) time.Duration {
	return agyPrintTimeout(boundedProbeTimeout(runtimeTimeout))
}

func immutableSnapshotPath(identity ports.WorkspaceSnapshotIdentity) (string, error) {
	if !identity.Valid() {
		return "", fmt.Errorf("native probe invocation: invalid immutable snapshot identity")
	}
	return identity.SnapshotPath(), nil
}
