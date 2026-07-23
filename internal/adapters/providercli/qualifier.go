package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const currentProbeTimeout = 30 * time.Second
const currentProbeOutputLimit int64 = 64 << 10

// QualificationNamespace is the retained provider namespace authority. Workspace
// authority belongs exclusively to the ProbeFixtureLease used for each spawn.
type QualificationNamespace = ports.ProviderQualificationNamespace

// SafeProbeInvocation supplies family-closed capability argv.
type SafeProbeInvocation interface {
	VersionArgv(RuntimeDefinition) ([]string, error)
	CapabilityArgv(RuntimeDefinition, ProbeFixture) ([]string, error)
	Validate(RuntimeDefinition, ProbeFixture, []string) error
}

// CurrentProbe performs current version and capability qualification.
type CurrentProbe struct {
	runner   ports.ProcessRunner
	verifier SpawnVerifier
}

func NewCurrentProbe(runner ports.ProcessRunner, verifier SpawnVerifier) (*CurrentProbe, error) {
	if runner == nil || nilSpawnVerifier(verifier) {
		return nil, fmt.Errorf("provider current probe: runner and spawn verifier are required")
	}
	return &CurrentProbe{runner: runner, verifier: verifier}, nil
}

type CurrentProbeRequest struct {
	Definition   RuntimeDefinition
	Namespace    QualificationNamespace
	Fixture      ProbeFixtureLease
	RoleFixtures []ProbeFixtureLease
	Invocation   SafeProbeInvocation
	Now          time.Time
	TTL          time.Duration
}

// CurrentProbeDirectExecutionAuthorityReceipt is descriptor-bound execution
// authority for the complete current-probe role set. It is minted only after
// every role has succeeded and its post-execution fixture, transport, and
// lifecycle evidence has been revalidated.
type CurrentProbeDirectExecutionAuthorityReceipt struct {
	authorityID               string
	runtimeDefinitionIdentity string
	proofs                    []currentProbeDirectExecutionRoleProof
	expiresAt                 time.Time
}

func (receipt CurrentProbeDirectExecutionAuthorityReceipt) AuthorityID() string {
	return receipt.authorityID
}
func (receipt CurrentProbeDirectExecutionAuthorityReceipt) ExpiresAt() time.Time {
	return receipt.expiresAt
}
func (receipt CurrentProbeDirectExecutionAuthorityReceipt) Valid() bool {
	if validateCurrentProbeDirectExecutionProofSnapshots(receipt.proofs) != nil {
		return false
	}
	proofAuthorityID, err := currentProbeDirectExecutionAuthorityID(receipt.proofs, receipt.expiresAt)
	if err != nil || receipt.authorityID == "" {
		return false
	}
	if receipt.runtimeDefinitionIdentity == "" {
		return receipt.authorityID == proofAuthorityID
	}
	return receipt.authorityID == currentProbeAuthorityID(proofAuthorityID, receipt.runtimeDefinitionIdentity)
}

// Matches reports whether this receipt is valid for one exact runtime definition,
// observed version, namespace generation, and unique role set.
func (receipt CurrentProbeDirectExecutionAuthorityReceipt) Matches(candidate ports.ProviderRuntimeDefinition, observedVersion, namespaceGeneration string, roles []domain.Role) bool {
	definition, ok := candidate.(RuntimeDefinition)
	if !ok {
		return false
	}
	runtimeDefinitionIdentity, identityErr := currentProbeRuntimeDefinitionIdentity(definition)
	if !receipt.Valid() || identityErr != nil || receipt.runtimeDefinitionIdentity != runtimeDefinitionIdentity ||
		!semverOutput.MatchString(observedVersion) || namespaceGeneration == "" || len(roles) != len(receipt.proofs) {
		return false
	}
	wantRoles := make(map[domain.Role]struct{}, len(roles))
	for _, role := range roles {
		if !role.Valid() {
			return false
		}
		if _, exists := wantRoles[role]; exists {
			return false
		}
		wantRoles[role] = struct{}{}
	}
	for _, proof := range receipt.proofs {
		if proof.Family != definition.Family() || proof.ProviderInstance != definition.Instance() || proof.ProviderVersion != definition.Version() ||
			proof.Executable != definition.Executable() || proof.ExecutableSHA256 != definition.ExecutableSHA256() ||
			proof.Launcher != definition.Launcher() || proof.LauncherSHA256 != definition.LauncherSHA256() ||
			proof.ProfileID != definition.ProfileID() || proof.ProfileGeneration != definition.ProfileGeneration() ||
			proof.ObservedVersion != observedVersion || proof.NamespaceGeneration != namespaceGeneration {
			return false
		}
		role := domain.Role(proof.Role)
		if _, exists := wantRoles[role]; !exists {
			return false
		}
		delete(wantRoles, role)
	}
	return len(wantRoles) == 0
}

func newCurrentProbeDirectExecutionAuthorityReceiptForDefinition(
	proofs []currentProbeDirectExecutionRoleProof,
	expiresAt time.Time,
	definition RuntimeDefinition,
) (CurrentProbeDirectExecutionAuthorityReceipt, error) {
	receipt, err := newCurrentProbeDirectExecutionAuthorityReceipt(proofs, expiresAt)
	if err != nil {
		return CurrentProbeDirectExecutionAuthorityReceipt{}, err
	}
	identity, err := currentProbeRuntimeDefinitionIdentity(definition)
	if err != nil {
		return CurrentProbeDirectExecutionAuthorityReceipt{}, err
	}
	receipt.runtimeDefinitionIdentity = identity
	receipt.authorityID = currentProbeAuthorityID(receipt.authorityID, identity)
	if !receipt.Valid() {
		return CurrentProbeDirectExecutionAuthorityReceipt{}, fmt.Errorf("runtime-bound direct-execution authority receipt is invalid")
	}
	return receipt, nil
}

type CurrentProbeReceipt struct {
	Kind                     string
	EvidenceID               string
	ExpiresAt                time.Time
	DirectExecutionAuthority *CurrentProbeDirectExecutionAuthorityReceipt
}

type currentProbeEnvironmentReceiptEvidence struct {
	NamespaceGeneration string   `json:"namespace_generation"`
	Values              []string `json:"values"`
}

type CurrentProbeResult struct {
	VersionArgv []string
	Version     string
	Receipts    []CurrentProbeReceipt
}

func (probe *CurrentProbe) QualifyCurrent(ctx context.Context, request CurrentProbeRequest) (CurrentProbeResult, error) {
	if probe == nil || probe.runner == nil || nilSpawnVerifier(probe.verifier) || ctx == nil || request.Now.IsZero() || request.TTL <= 0 || request.Namespace == nil || request.Fixture == nil || request.Invocation == nil {
		return CurrentProbeResult{}, probeFailure("authority", domain.FailureInternal, "missing isolated qualification authority", nil)
	}
	if err := ctx.Err(); err != nil {
		return CurrentProbeResult{}, err
	}
	definition, namespace, fixture := request.Definition, request.Namespace, request.Fixture
	if err := safeProbeDefinition(definition); err != nil {
		return CurrentProbeResult{}, securityProbeFailure("definition", "unsafe provider definition", err)
	}
	if namespace.ProviderInstance() != definition.Instance() || namespace.Generation() == "" || namespace.RuntimeSafetyPolicyIdentity() != definition.RuntimeSafetyPolicyIdentity() {
		return CurrentProbeResult{}, securityProbeFailure("namespace", "namespace binding drift", nil)
	}
	fixtures, err := validateCurrentProbeFixtures(fixture, request.RoleFixtures)
	if err != nil {
		return CurrentProbeResult{}, securityProbeFailure("fixture", "role fixtures are not independently bound", err)
	}
	namespaceEnvironment := namespace.Environment()
	environment, err := isolatedProcessEnvironment(definition.Environment(), namespaceEnvironment)
	if err != nil {
		return CurrentProbeResult{}, securityProbeFailure("environment", "isolated environment rejected", err)
	}
	timeout := boundedProbeTimeout(definition.Timeout())
	versionArgv, err := request.Invocation.VersionArgv(definition)
	if err != nil {
		return CurrentProbeResult{}, securityProbeFailure("invocation", "safe version invocation unavailable", err)
	}
	versionObservation, err := probe.runBound(ctx, definition, namespace, fixture, versionArgv, environment, timeout, nil, nil)
	if err != nil {
		return CurrentProbeResult{}, err
	}
	version, err := plainSemver(versionObservation)
	if err != nil {
		return CurrentProbeResult{}, classifyProbeFailure(ctx, definition.Family(), err, versionObservation.Stderr(), versionObservation.Stdout())
	}
	expires := request.Now.Add(request.TTL)
	directExecutionProofs := make([]currentProbeDirectExecutionRoleProof, 0, len(fixtures))
	transportEvidence := make([]string, 0, len(fixtures))
	for _, roleFixture := range fixtures {
		packet, packetErr := ports.NewProviderPacketFromBytes(roleFixture.Packet())
		if packetErr != nil {
			return CurrentProbeResult{}, securityProbeFailure("fixture", "invalid immutable fixture packet", packetErr)
		}
		argv, invokeErr := request.Invocation.CapabilityArgv(definition, roleFixture)
		if invokeErr != nil {
			return CurrentProbeResult{}, securityProbeFailure("invocation", "safe invocation unavailable", invokeErr)
		}
		if invokeErr := request.Invocation.Validate(definition, roleFixture, argv); invokeErr != nil {
			return CurrentProbeResult{}, securityProbeFailure("invocation", "safe invocation rejected", invokeErr)
		}
		var executionPolicy *AGYExecutionPolicy
		if definition.Family() == FamilyAgy {
			policy, policyErr := NewAGYExecutionPolicy(definition, roleFixture.WorkspaceSnapshotIdentity(), argv, roleFixture.Reference())
			if policyErr != nil {
				return CurrentProbeResult{}, securityProbeFailure("direct-execution-authority", "AGY execution policy unavailable", policyErr)
			}
			executionPolicy = &policy
		}
		capabilityObservation, runErr := probe.runBound(ctx, definition, namespace, roleFixture, argv, environment, timeout, &packet, executionPolicy)
		if runErr != nil {
			return CurrentProbeResult{}, runErr
		}
		if evidenceErr := validateProbeTransportAndLifecycle(definition, packet, capabilityObservation); evidenceErr != nil {
			return CurrentProbeResult{}, securityProbeFailure("capability", "provider transport or lifecycle evidence mismatch: "+evidenceErr.Error(), evidenceErr)
		}
		if !capabilityObservation.Succeeded() {
			return CurrentProbeResult{}, classifyProbeFailure(ctx, definition.Family(), fmt.Errorf("capability probe failed"), capabilityObservation.Stderr(), capabilityObservation.Stdout())
		}
		output := capabilityObservation.Stdout()
		if definition.Family() == FamilyKimi {
			output, runErr = kimiContent(output)
			if runErr != nil {
				return CurrentProbeResult{}, probeFailure("capability", domain.FailureInvalidOutput, "invalid Kimi stream JSON", runErr)
			}
		} else if definition.Family() == FamilyAgy {
			output, runErr = agyContent(output)
			if runErr != nil {
				return CurrentProbeResult{}, probeFailure("capability", domain.FailureInvalidOutput, "invalid AGY terminal JSON", runErr)
			}
		} else if definition.Family() == FamilyZcode {
			output, runErr = zcodeContent(output)
			if runErr != nil {
				return CurrentProbeResult{}, probeFailure("capability", domain.FailureInvalidOutput, "invalid ZCode terminal JSON", runErr)
			}
		}
		if definition.Family() != FamilyAgy {
			output, runErr = controlledProbeJSON(output)
			if runErr != nil {
				return CurrentProbeResult{}, probeFailure("capability", domain.FailureInvalidOutput, "invalid controlled JSON envelope", runErr)
			}
		}
		if runErr := validateProbeEvidence(output, roleFixture); runErr != nil {
			return CurrentProbeResult{}, securityProbeFailure("capability", "controlled evidence mismatch", runErr)
		}
		transport, _ := capabilityObservation.ProviderPacketTransportReceipt()
		transportIdentity := transport.PacketIdentity()
		preStart := transport.PreStartIdentity()
		postEnd := transport.PostTerminationIdentity()
		transportEvidence = append(transportEvidence, fmt.Sprintf("%s|%s|%s|%s|%d|%s|%d|%s|%d",
			transport.Channel(), transport.PromptFileReference(), transport.SnapshotCWD(),
			transportIdentity.CompleteSHA256(), transportIdentity.ByteLength(),
			preStart.CompleteSHA256(), preStart.ByteLength(), postEnd.CompleteSHA256(), postEnd.ByteLength()))
		proof, proofErr := newCurrentProbeDirectExecutionRoleProof(definition, version, namespace.Generation(), namespace, namespaceEnvironment, environment, roleFixture, argv, packet, capabilityObservation, executionPolicy)
		if proofErr != nil {
			return CurrentProbeResult{}, securityProbeFailure("direct-execution-authority", "direct role execution proof invalid", proofErr)
		}
		directExecutionProofs = append(directExecutionProofs, proof)
	}
	if err := validateCurrentProbeDirectExecutionProofSnapshots(directExecutionProofs); err != nil {
		return CurrentProbeResult{}, securityProbeFailure("direct-execution-authority", "direct-execution role workspaces are not independent", err)
	}
	receipt, receiptErr := newCurrentProbeDirectExecutionAuthorityReceiptForDefinition(directExecutionProofs, expires, definition)
	if receiptErr != nil {
		return CurrentProbeResult{}, securityProbeFailure("direct-execution-authority", "direct-execution authority receipt invalid", receiptErr)
	}
	receipts, receiptErr := currentProbeValidatedReceipts(definition, fixtures, version, directExecutionProofs, transportEvidence, environment, namespace.Generation(), expires)
	if receiptErr != nil {
		return CurrentProbeResult{}, securityProbeFailure("receipt", "qualification receipt evidence unavailable", receiptErr)
	}
	receipts = append(receipts, CurrentProbeReceipt{
		Kind:                     "direct-execution-authority",
		EvidenceID:               receipt.AuthorityID(),
		ExpiresAt:                expires,
		DirectExecutionAuthority: &receipt,
	})
	return CurrentProbeResult{VersionArgv: versionArgv, Version: version, Receipts: receipts}, nil
}

// runBound makes exactly one descriptor-bound launch. Every return path validates
// the namespace and fixture before launch and the fixture guard after launch.
func (probe *CurrentProbe) runBound(ctx context.Context, definition RuntimeDefinition, namespace QualificationNamespace, fixture ProbeFixtureLease, argv []string, environment []ports.EnvironmentVariable, timeout time.Duration, packet *ports.ProviderPacket, executionPolicy *AGYExecutionPolicy) (observation ports.ProcessObservation, err error) {
	if err := namespace.ValidateForSpawn(); err != nil {
		return ports.ProcessObservation{}, securityProbeFailure("namespace", "namespace validation failed", err)
	}
	guard, guardErr := fixture.RevalidateForExecution()
	if guardErr != nil || nilWorkspaceExecutionGuard(guard) {
		return ports.ProcessObservation{}, securityProbeFailure("fixture", "fixture execution guard unavailable", guardErr)
	}
	defer func() {
		if closeErr := guard.Close(); closeErr != nil {
			err = securityProbeFailure("fixture", "fixture guard close failed", closeErr)
		}
	}()
	root := guard.WorkspaceRoot()
	if !root.Valid() || guard.WorkspaceSnapshotIdentity() != fixture.WorkspaceSnapshotIdentity() || root.SnapshotIdentity() != fixture.WorkspaceSnapshotIdentity() {
		return ports.ProcessObservation{}, securityProbeFailure("fixture", "fixture descriptor binding drift", nil)
	}
	if definition.Family() == FamilyAgy && packet != nil {
		if executionPolicy == nil || executionPolicy.Validate() != nil ||
			executionPolicy.SnapshotIdentity() != fixture.WorkspaceSnapshotIdentity() ||
			!reflect.DeepEqual(executionPolicy.Argv(), argv) || executionPolicy.NativeReference() != fixture.Reference() {
			return ports.ProcessObservation{}, securityProbeFailure("direct-execution-authority", "AGY execution policy drift", nil)
		}
	} else if executionPolicy != nil {
		return ports.ProcessObservation{}, securityProbeFailure("direct-execution-authority", "unexpected execution policy", nil)
	}
	var request ports.ProcessRequest
	var requestErr error
	if packet == nil {
		request, requestErr = ports.NewProcessRequest(definition.Executable(), argv, environment, root.Path(), nil, timeout, boundedProbeOutput(definition.MaxStdoutBytes()), boundedProbeOutput(definition.MaxStderrBytes()), definition.ConcurrencyKey())
	} else {
		request, requestErr = boundProbeProviderRequest(definition, *packet, argv, "@"+fixture.Reference(), environment, root.Path(), timeout)
	}
	if requestErr != nil {
		return ports.ProcessObservation{}, securityProbeFailure("process", "bound process request rejected", requestErr)
	}
	launchDirectory, duplicateErr := guard.DuplicateLaunchDirectory()
	if duplicateErr != nil {
		return ports.ProcessObservation{}, securityProbeFailure("fixture", "launch descriptor unavailable", duplicateErr)
	}
	if definition.Family() == FamilyAgy {
		authority, ok := namespace.NativeHomeLaunchAuthority()
		if !ok || !authority.Valid() {
			_ = launchDirectory.Close()
			return ports.ProcessObservation{}, securityProbeFailure("namespace", "AGY native home authority unavailable", nil)
		}
		request, requestErr = ports.NewBoundProcessRequestWithNativeHomeAuthority(request, root, launchDirectory, authority)
	} else {
		request, requestErr = ports.NewBoundProcessRequest(request, root, launchDirectory)
	}
	if requestErr != nil {
		_ = launchDirectory.Close()
		return ports.ProcessObservation{}, securityProbeFailure("process", "bound process descriptor rejected", requestErr)
	}
	if err := probe.verifier.VerifyProviderSpawn(ctx, definition); err != nil {
		launchDirectory, _, _ := request.BoundLaunchDirectory()
		if launchDirectory != nil {
			_ = launchDirectory.Close()
		}
		return ports.ProcessObservation{}, securityProbeFailure("spawn", "spawn verification failed", err)
	}
	observation, err = probe.runner.Run(ctx, request)
	if postErr := guard.RevalidateAfterExecution(); postErr != nil {
		return observation, securityProbeFailure("fixture", "post-execution fixture drift", postErr)
	}
	if err != nil {
		return observation, classifyProbeFailure(ctx, definition.Family(), err, nil)
	}
	return observation, nil
}

var semverOutput = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

func currentProbeValidatedReceipts(
	definition RuntimeDefinition,
	fixtures []ProbeFixtureLease,
	version string,
	proofs []currentProbeDirectExecutionRoleProof,
	transportEvidence []string,
	effectiveEnvironment []ports.EnvironmentVariable,
	namespaceGeneration string,
	expires time.Time,
) ([]CurrentProbeReceipt, error) {
	runtimeDefinitionIdentity, err := currentProbeRuntimeDefinitionIdentity(definition)
	if err != nil || len(fixtures) == 0 || len(proofs) != len(fixtures) || len(transportEvidence) != len(fixtures) ||
		len(effectiveEnvironment) == 0 || namespaceGeneration == "" || !semverOutput.MatchString(version) {
		return nil, fmt.Errorf("incomplete validated qualification evidence")
	}
	snapshots := make([]string, 0, len(fixtures))
	manifests := make([]string, 0, len(fixtures))
	roles := make([]string, 0, len(fixtures))
	references := make([]string, 0, len(fixtures))
	outputs := make([]string, 0, len(proofs))
	for index, fixture := range fixtures {
		if validateProbeFixtureLease(fixture) != nil || proofs[index].Role != string(fixture.Role()) {
			return nil, fmt.Errorf("fixture evidence drift")
		}
		snapshot := fixture.WorkspaceSnapshotIdentity()
		snapshots = append(snapshots, snapshot.SnapshotPath())
		manifests = append(manifests, snapshot.ManifestSHA256())
		roles = append(roles, string(fixture.Role()))
		references = append(references, "@"+fixture.Reference())
		outputs = append(outputs, proofs[index].OutputSHA256)
	}
	environmentValues := make([]string, len(effectiveEnvironment))
	for index, variable := range effectiveEnvironment {
		if !variable.Valid() {
			return nil, fmt.Errorf("effective environment evidence drift")
		}
		environmentValues[index] = variable.Name() + "=" + variable.Value()
	}
	sort.Strings(environmentValues)
	evidence := func(kind string, values any) (CurrentProbeReceipt, error) {
		id, evidenceErr := currentProbeEvidenceID(kind, runtimeDefinitionIdentity, values)
		if evidenceErr != nil {
			return CurrentProbeReceipt{}, evidenceErr
		}
		return CurrentProbeReceipt{Kind: kind, EvidenceID: id, ExpiresAt: expires}, nil
	}
	items := []struct {
		kind   string
		values any
	}{
		{"workspace", snapshots},
		{"manifest", manifests},
		{"namespace", []string{definition.Instance(), definition.RuntimeSafetyPolicyIdentity(), namespaceGeneration}},
		{"environment", currentProbeEnvironmentReceiptEvidence{NamespaceGeneration: namespaceGeneration, Values: environmentValues}},
		{"transport", transportEvidence},
		{"native-reference", references},
		{"version", version},
		{"capability", outputs},
		{"base-role", roles},
		{"assignment", append(append([]string(nil), roles...), snapshots...)},
	}
	receipts := make([]CurrentProbeReceipt, 0, len(items))
	for _, item := range items {
		itemReceipt, evidenceErr := evidence(item.kind, item.values)
		if evidenceErr != nil {
			return nil, evidenceErr
		}
		receipts = append(receipts, itemReceipt)
	}
	return receipts, nil
}

func currentProbeEvidenceID(kind, runtimeDefinitionIdentity string, values any) (string, error) {
	bytes, err := json.Marshal(struct {
		Domain                    string `json:"domain"`
		RuntimeDefinitionIdentity string `json:"runtime_definition_identity"`
		Values                    any    `json:"values"`
	}{Domain: "KAR-CURRENT-PROBE-RECEIPT/" + kind + "/1", RuntimeDefinitionIdentity: runtimeDefinitionIdentity, Values: values})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// currentProbeRuntimeDefinitionIdentity canonically binds every RuntimeDefinition
// field. RuntimeDefinition has no non-authoritative metadata, so none is excluded.
func currentProbeRuntimeDefinitionIdentity(definition RuntimeDefinition) (string, error) {
	environment := definition.Environment()
	environmentValues := make([]string, len(environment))
	for index, variable := range environment {
		if !variable.Valid() {
			return "", fmt.Errorf("invalid runtime environment")
		}
		environmentValues[index] = variable.Name() + "=" + variable.Value()
	}
	lifecycle, hasLifecycle := definition.PostOutputLifecycle()
	bytes, err := json.Marshal(struct {
		Family, Instance, Version, Executable, ExecutableSHA256                  string
		Launcher, LauncherSHA256, ProfileGeneration, RuntimeSafetyPolicyIdentity string
		ConcurrencyKey, ProfileID                                                string
		BaseArgv, Environment                                                    []string
		TransportChannel, TransportReference                                     string
		TransportArgvIndex                                                       int
		WorkingDirectory                                                         string
		TimeoutNanoseconds                                                       int64
		MaxStdoutBytes, MaxStderrBytes                                           int64
		HasPostOutputLifecycle                                                   bool
		LifecycleFraming                                                         string
		LifecycleStabilityNanoseconds, LifecycleTerminationNanoseconds           int64
		RequiresWorkspaceAuthority, RequiresSpawnVerification                    bool
		ProductionExplicitTransport                                              bool
	}{
		Family: definition.family, Instance: definition.instance, Version: definition.version,
		Executable: definition.executable, ExecutableSHA256: definition.executableSHA256,
		Launcher: definition.launcher, LauncherSHA256: definition.launcherSHA256,
		ProfileGeneration: definition.profileGeneration, RuntimeSafetyPolicyIdentity: definition.runtimeSafetyPolicyIdentity,
		ConcurrencyKey: definition.concurrencyKey.String(), ProfileID: definition.profileID,
		BaseArgv: append([]string(nil), definition.baseArgv...), Environment: environmentValues,
		TransportChannel: string(definition.transport.channel), TransportReference: definition.transport.reference,
		TransportArgvIndex: definition.transport.argvIndex, WorkingDirectory: definition.workingDirectory,
		TimeoutNanoseconds: definition.timeout.Nanoseconds(), MaxStdoutBytes: definition.maxStdoutBytes,
		MaxStderrBytes: definition.maxStderrBytes, HasPostOutputLifecycle: hasLifecycle,
		LifecycleFraming: string(lifecycle.Framing()), LifecycleStabilityNanoseconds: lifecycle.StabilityGrace().Nanoseconds(),
		LifecycleTerminationNanoseconds: lifecycle.TerminationGrace().Nanoseconds(),
		RequiresWorkspaceAuthority:      definition.requiresWorkspaceAuthority,
		RequiresSpawnVerification:       definition.requiresSpawnVerification,
		ProductionExplicitTransport:     definition.productionExplicitTransport,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func currentProbeAuthorityID(proofAuthorityID, runtimeDefinitionIdentity string) string {
	sum := sha256.Sum256([]byte("KAR-CURRENT-PROBE-DIRECT-EXECUTION-AUTHORITY/2\x00" + proofAuthorityID + "\x00" + runtimeDefinitionIdentity))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateProbeTransportAndLifecycle(definition RuntimeDefinition, packet ports.ProviderPacket, observation ports.ProcessObservation) error {
	transport, ok := observation.ProviderPacketTransportReceipt()
	expectedChannel := ports.ProviderPacketChannelArgvLiteral
	if definition.Family() == FamilyAgy {
		expectedChannel = ports.ProviderPacketChannelPromptFile
	}
	if !ok || !transport.Valid() || transport.Channel() != expectedChannel || transport.PacketIdentity() != packet.Identity() {
		return fmt.Errorf("missing or mismatched provider packet transport receipt")
	}
	lifecyclePolicy, requiresLifecycle := definition.PostOutputLifecycle()
	if !requiresLifecycle {
		return nil
	}
	lifecycle, ok := observation.LifecycleReceipt()
	if !ok || !lifecycle.Valid() || !lifecycle.ProcessGroupAbsent() {
		return fmt.Errorf("missing post-output lifecycle receipt")
	}
	frame, frameOK := lifecycle.OutputFrame()
	if !observation.Succeeded() && !frameOK {
		if len(lifecycle.SignalRequests()) != 0 {
			return fmt.Errorf("failed launch carried post-output signal receipts without a frame")
		}
		return nil
	}
	if !frameOK || !frame.Valid() {
		return fmt.Errorf("missing valid post-output frame receipt")
	}
	if frame.Framing() != lifecyclePolicy.Framing() || lifecyclePolicy.Framing() != ports.ProcessOutputFramingTerminalJSONObject {
		return fmt.Errorf("mismatched post-output frame policy")
	}
	if frame.StabilityGrace() != lifecyclePolicy.StabilityGrace() || lifecyclePolicy.TerminationGrace() <= 0 {
		return fmt.Errorf("mismatched post-output lifecycle timing")
	}
	if frame.ByteLength() != int64(len(observation.Stdout())) {
		return fmt.Errorf("post-output frame length %d does not match stdout length %d", frame.ByteLength(), len(observation.Stdout()))
	}
	sum := sha256.New()
	_, _ = sum.Write([]byte("KAR-PROCESS-STDOUT-FRAME/1"))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write(observation.Stdout())
	if frame.SHA256() != hex.EncodeToString(sum.Sum(nil)) {
		return fmt.Errorf("trailing or mismatched post-output stdout")
	}
	requests := lifecycle.SignalRequests()
	if len(requests) == 0 {
		final := lifecycle.FinalTermination()
		exitCode, exited := final.ExitCode()
		if final.Kind() != ports.ProcessFinalTerminationExited || !exited || exitCode != 0 {
			return fmt.Errorf("invalid natural post-output termination receipt")
		}
		return nil
	}
	if len(requests) > 2 {
		return fmt.Errorf("invalid post-output signal receipt count")
	}
	validateSignal := func(request ports.ProcessGroupSignalRequestReceipt, reason ports.ProcessGroupSignalRequestReason, number int, name string) error {
		identity, identityOK := request.PacketIdentity()
		frameSHA256, frameOK := request.FrameSHA256()
		if !request.Valid() || request.Reason() != reason || request.Signal().Number() != number || request.Signal().Name() != name ||
			!identityOK || identity != packet.Identity() || !frameOK || frameSHA256 != frame.SHA256() {
			return fmt.Errorf("mismatched post-output signal receipt")
		}
		return nil
	}
	if err := validateSignal(requests[0], ports.ProcessGroupSignalRequestPostOutput, 15, "SIGTERM"); err != nil {
		return err
	}
	if len(requests) == 2 {
		if err := validateSignal(requests[1], ports.ProcessGroupSignalRequestPostOutputEscalation, 9, "SIGKILL"); err != nil {
			return err
		}
	}
	return nil
}
func boundProbeProviderRequest(def RuntimeDefinition, packet ports.ProviderPacket, argv []string, reference string, environment []ports.EnvironmentVariable, workingDirectory string, timeout time.Duration) (ports.ProcessRequest, error) {
	channel := ports.ProviderPacketChannelArgvLiteral
	needle := string(packet.Bytes())
	if def.Family() == FamilyAgy {
		channel = ports.ProviderPacketChannelPromptFile
		needle = reference
	}
	index := -1
	for candidate, argument := range argv {
		if argument == needle {
			if index >= 0 {
				return ports.ProcessRequest{}, fmt.Errorf("duplicate provider packet argv")
			}
			index = candidate
		}
	}
	if index < 0 {
		return ports.ProcessRequest{}, fmt.Errorf("missing provider packet argv")
	}
	var binding ports.ProviderPacketBinding
	var err error
	if channel == ports.ProviderPacketChannelPromptFile {
		binding, err = ports.NewPromptFileProviderPacketBinding(packet, index, reference, workingDirectory)
	} else {
		binding, err = ports.NewArgvLiteralProviderPacketBinding(packet, index)
	}
	if err != nil {
		return ports.ProcessRequest{}, err
	}
	if lifecycle, ok := def.PostOutputLifecycle(); ok {
		return ports.NewProviderProcessRequestWithPostOutputLifecycle(def.Executable(), argv, environment, workingDirectory, binding, lifecycle, timeout, boundedProbeOutput(def.MaxStdoutBytes()), boundedProbeOutput(def.MaxStderrBytes()), def.ConcurrencyKey())
	}
	return ports.NewProviderProcessRequest(def.Executable(), argv, environment, workingDirectory, binding, timeout, boundedProbeOutput(def.MaxStdoutBytes()), boundedProbeOutput(def.MaxStderrBytes()), def.ConcurrencyKey())
}

func safeProbeDefinition(definition RuntimeDefinition) error {
	if !validFamily(definition.Family()) || definition.Instance() == "" || definition.Executable() == "" || len(definition.BaseArgv()) == 0 {
		return fmt.Errorf("unsupported definition")
	}
	for _, arg := range definition.BaseArgv()[1:] {
		lower := strings.ToLower(arg)
		if strings.HasPrefix(lower, "--danger") || strings.Contains(lower, "permission") || strings.Contains(lower, "approve") || strings.Contains(lower, "yolo") || strings.Contains(lower, "shell") || strings.Contains(lower, "write") {
			return fmt.Errorf("unsafe provider permission")
		}
	}
	return nil
}

func validateProbeFixtureLease(fixture ProbeFixtureLease) error {
	if fixture.Validate() != nil || !fixture.Role().Valid() || !fixture.WorkspaceSnapshotIdentity().Valid() || fixture.Workspace() == nil || !validRelativeNativeReference(fixture.Reference()) {
		return fmt.Errorf("invalid fixture lease")
	}
	return nil
}

func validRelativeNativeReference(reference string) bool {
	return reference != "" && !strings.HasPrefix(reference, "@") && !strings.HasPrefix(reference, "/") && !strings.Contains(reference, "\\") && !strings.Contains(reference, "..")
}

// VersionAtLeast compares validated semantic versions, including prerelease precedence.
func VersionAtLeast(value string, wantMajor, wantMinor, wantPatch int) bool {
	if !semverOutput.MatchString(value) {
		return false
	}
	core, prerelease, hasPrerelease := strings.Cut(strings.SplitN(value, "+", 2)[0], "-")
	var major, minor, patch int
	if _, err := fmt.Sscanf(core, "%d.%d.%d", &major, &minor, &patch); err != nil {
		return false
	}
	if major != wantMajor {
		return major > wantMajor
	}
	if minor != wantMinor {
		return minor > wantMinor
	}
	if patch != wantPatch {
		return patch > wantPatch
	}
	return !hasPrerelease || prerelease == ""
}
func validateCurrentProbeFixtures(base ProbeFixtureLease, roleFixtures []ProbeFixtureLease) ([]ProbeFixtureLease, error) {
	fixtures := append([]ProbeFixtureLease{base}, roleFixtures...)
	roles := make(map[domain.Role]struct{}, len(fixtures))
	workspaces := make(map[ports.WorkspaceSnapshotIdentity]struct{}, len(fixtures))
	for _, fixture := range fixtures {
		if err := validateProbeFixtureLease(fixture); err != nil {
			return nil, err
		}
		if _, exists := roles[fixture.Role()]; exists {
			return nil, fmt.Errorf("duplicate role fixture")
		}
		roles[fixture.Role()] = struct{}{}
		identity := fixture.WorkspaceSnapshotIdentity()
		if _, exists := workspaces[identity]; exists {
			return nil, fmt.Errorf("duplicate fixture workspace")
		}
		workspaces[identity] = struct{}{}
	}
	return fixtures, nil
}
func validateCurrentProbeDirectExecutionProofSnapshots(proofs []currentProbeDirectExecutionRoleProof) error {
	type snapshotIdentity struct {
		manifest, name, path, policy                         string
		snapshotDevice, snapshotInode, rootDevice, rootInode uint64
	}
	seen := make(map[snapshotIdentity]struct{}, len(proofs))
	for _, proof := range proofs {
		identity := snapshotIdentity{
			manifest: proof.SnapshotManifestSHA256, name: proof.SnapshotName, path: proof.SnapshotPath, policy: proof.SnapshotPolicyIdentity,
			snapshotDevice: proof.SnapshotDevice, snapshotInode: proof.SnapshotInode, rootDevice: proof.RootDevice, rootInode: proof.RootInode,
		}
		if _, exists := seen[identity]; exists {
			return fmt.Errorf("duplicate direct-execution proof workspace")
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func boundedProbeTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > currentProbeTimeout {
		return currentProbeTimeout
	}
	return timeout
}
func boundedProbeOutput(limit int64) int64 {
	if limit <= 0 || limit > currentProbeOutputLimit {
		return currentProbeOutputLimit
	}
	return limit
}

func plainSemver(observation ports.ProcessObservation) (string, error) {
	version := strings.TrimSpace(string(observation.Stdout()))
	if !observation.Succeeded() || !semverOutput.MatchString(version) {
		return "", fmt.Errorf("invalid plain semver version output")
	}
	return version, nil
}

func strictKimiProbeContent(stdout []byte) ([]byte, error) {
	var content string
	found := false
	for _, line := range bytes.Split(stdout, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return nil, err
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("trailing Kimi stream JSON")
		}
		if event.Role != "assistant" || found {
			return nil, fmt.Errorf("expected exactly one assistant content event")
		}
		content, found = event.Content, true
	}
	if !found {
		return nil, fmt.Errorf("expected exactly one assistant content event")
	}
	return []byte(content), nil
}
func validateProbeEvidence(output []byte, fixture ProbeFixtureLease) error {
	var evidence struct {
		Root string `json:"root"`
		Link string `json:"link"`
		Role string `json:"role"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return fmt.Errorf("invalid controlled probe evidence")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF ||
		evidence.Root != fixture.Nonce() || evidence.Link != fixture.Link() ||
		evidence.Role != string(fixture.Role()) {
		return fmt.Errorf("invalid controlled probe evidence")
	}
	return nil
}

func controlledProbeJSON(output []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(output)
	const fenceStart = "```json\n"
	const fenceEnd = "\n```"
	if bytes.HasPrefix(trimmed, []byte(fenceStart)) && bytes.HasSuffix(trimmed, []byte(fenceEnd)) {
		trimmed = trimmed[len(fenceStart) : len(trimmed)-len(fenceEnd)]
	}
	var object map[string]json.RawMessage
	if len(trimmed) == 0 || json.Unmarshal(trimmed, &object) != nil || object == nil {
		return nil, fmt.Errorf("controlled probe output is not one JSON object")
	}
	return append([]byte(nil), trimmed...), nil
}

func classifyProbeFailure(ctx context.Context, family string, err error, stderr []byte, additionalDiagnostics ...[]byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	stdout := bytes.Join(additionalDiagnostics, []byte{'\n'})
	if status, _, _, ok := nativeProviderOutcome(family, stdout, stderr); ok {
		switch status {
		case ports.ProviderExecutionStatusAuthentication:
			if errors.Is(err, ports.ErrProviderLoginRequired) || providerLoginRequired(bytes.Join([][]byte{stdout, stderr}, []byte{'\n'})) {
				return probeFailure("capability", domain.FailureAuthentication, "provider login required", errors.Join(ports.ErrProviderLoginRequired, err))
			}
			return probeFailure("capability", domain.FailureAuthentication, "provider authentication unavailable", err)
		case ports.ProviderExecutionStatusTimedOut:
			return probeFailure("capability", domain.FailureTimeout, "provider timed out", err)
		case ports.ProviderExecutionStatusQuota:
			return probeFailure("capability", domain.FailureQuota, "provider quota unavailable", err)
		case ports.ProviderExecutionStatusRateLimit:
			return probeFailure("capability", domain.FailureRateLimit, "provider rate limited", err)
		}
	}
	message := strings.ToLower(string(stderr))
	loginRequired := providerLoginRequired(stderr)
	for _, diagnostic := range additionalDiagnostics {
		loginRequired = loginRequired || providerLoginRequired(diagnostic)
	}
	switch {
	case loginRequired:
		return probeFailure("capability", domain.FailureAuthentication, "provider login required", errors.Join(ports.ErrProviderLoginRequired, err))
	case strings.Contains(message, "auth"), strings.Contains(message, "login"), strings.Contains(message, "sign in"):
		return probeFailure("capability", domain.FailureAuthentication, "provider authentication unavailable", err)
	case strings.Contains(message, "not found"), strings.Contains(message, "unavailable"):
		return probeFailure("capability", domain.FailureProviderUnavailable, "provider unavailable", err)
	default:
		return probeFailure("capability", domain.FailureInvalidOutput, "provider capability failed", err)
	}
}

func probeFailure(stage string, class domain.FailureClass, reason string, cause error) error {
	failure, err := domain.NewFailure(stage, class, reason, cause)
	if err != nil {
		return fmt.Errorf("provider current probe: %w", err)
	}
	return failure
}
func securityProbeFailure(stage, reason string, cause error) error {
	return probeFailure(stage, domain.FailureSecurityPolicy, reason, cause)
}
