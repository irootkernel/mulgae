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
	case FamilyZcode:
		// Capability stays tool-denied so qualification remains bounded. The
		// conversation runs in plan mode with every tool denied; review
		// conversations use zcodeReviewProtocolDenylist instead.
		return appendZcodeProtocolServerArgv(baseArgv), nil
	case FamilyGrok:
		return grokACPArgv(definition.Executable(), protocolPurposeQualification)
	case FamilyCodex:
		return appendCodexProtocolServerArgv(baseArgv, definition.CodexModel(), definition.CodexReasoningEffort()), nil
	default:
		return nil, fmt.Errorf("native probe invocation: unsupported family")
	}
}

// zcodeReviewProtocolDenylist is the adapter-owned ZCode tool denylist for
// workspace-first reviews on the app-server protocol session.
//
// Write is deliberately absent: it is the single authority a staged_file review
// needs to place its role report at the Mulgae-chosen staging path. The
// workspace itself stays read-only regardless, because Bash, Edit and
// NotebookEdit remain denied, the snapshot the process is launched in is
// immutable, and post-execution drift detection revalidates it. Every byte the
// grant produces is bounded by the staged-output validation that reads it back.
// The plan tools stay denied because the protocol's plan flow persists
// plan-<session>.md files inside the workspace, which the sealed snapshot's
// drift detection must continue to reject.
var zcodeReviewProtocolDenylist = []string{"Bash", "Edit", "NotebookEdit", "WebSearch", "WebFetch", "EnterPlanMode", "ExitPlanMode"}

// zcodeCapabilityProtocolDenylist keeps qualification prompt-bound and latency
// bounded. Workspace-selective read is exercised on review invocations.
var zcodeCapabilityProtocolDenylist = []string{"*"}

// zcodeProtocolServerArgv is the complete argv of the ZCode app-server: the
// protocol needs no stdio flags because the server speaks newline-delimited
// JSON on its standard pipes by default.
const zcodeProtocolServerArgument = "app-server"

// appendZcodeProtocolServerArgv builds the ZCode review and qualification
// argv. Every ZCode packet travels inside the protocol conversation, so the
// argv never carries the prompt or tool policy.
func appendZcodeProtocolServerArgv(argv []string) []string {
	result := append([]string(nil), argv...)
	return append(result, zcodeProtocolServerArgument)
}

func canonicalProbeBaseArgv(definition RuntimeDefinition) ([]string, error) {
	baseArgv := definition.BaseArgv()
	executable := definition.Executable()
	switch definition.Family() {
	case FamilyGrok, FamilyCodex:
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

func appendCodexProtocolServerArgv(argv []string, model, reasoningEffort string) []string {
	result := append([]string(nil), argv...)
	result = append(result, "app-server", "--strict-config")
	for _, feature := range []string{"apps", "browser_use", "computer_use", "hooks", "image_generation", "multi_agent", "plugins", "skill_search"} {
		result = append(result, "--disable", feature)
	}
	result = append(result,
		"-c", `permissions.mulgae={extends=":read-only",filesystem={"~/.codex"="deny"}}`,
		"-c", `default_permissions="mulgae"`,
		"-c", "project_doc_max_bytes=0",
		"-c", "shell_environment_policy.inherit=none",
	)
	if model != "" {
		result = append(result, "-c", fmt.Sprintf("model=%q", model))
	}
	if reasoningEffort != "" {
		result = append(result, "-c", fmt.Sprintf("model_reasoning_effort=%q", reasoningEffort))
	}
	return result
}

func validCodexReasoningEffort(value string) bool {
	switch value {
	case "minimal", "low", "medium", "high", "xhigh":
		return true
	default:
		return false
	}
}
