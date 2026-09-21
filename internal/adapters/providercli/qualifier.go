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

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const currentProbeTimeout = 3 * time.Minute

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
			proof.ApplicationVersion != definition.ApplicationVersion() || proof.ApplicationMetadata != definition.ApplicationMetadata() || proof.ApplicationMetadataSHA256 != definition.ApplicationMetadataSHA256() ||
			proof.ZCodeProviderConfig != definition.ZCodeProviderConfig() || proof.ZCodeProviderConfigSHA256 != definition.ZCodeProviderConfigSHA256() ||
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

func currentProbeDirectExecutionAuthorityReceiptFrom(
	source ports.ProviderDirectExecutionAuthority,
) (CurrentProbeDirectExecutionAuthorityReceipt, bool) {
	if source == nil {
		return CurrentProbeDirectExecutionAuthorityReceipt{}, false
	}
	if receipt, ok := source.(CurrentProbeDirectExecutionAuthorityReceipt); ok {
		return receipt, true
	}
	if receipt, ok := source.(*CurrentProbeDirectExecutionAuthorityReceipt); ok && receipt != nil {
		return *receipt, true
	}
	return CurrentProbeDirectExecutionAuthorityReceipt{}, false
}

// DeriveEquivalentRouteDirectExecutionAuthority mints a new exact-runtime
// authority for one sibling definition after proving shareable family-profile
// equivalence with the live source authority. It never reuses the source
// authority ID. Destination proofs are rewritten to the destination role set so
// Matches binds those roles, not the source-proved roles alone.
func DeriveEquivalentRouteDirectExecutionAuthority(
	source ports.ProviderDirectExecutionAuthority,
	sourceDefinition ports.ProviderRuntimeDefinition,
	destinationDefinition ports.ProviderRuntimeDefinition,
	observedVersion string,
	sourceNamespaceGeneration string,
	destinationNamespaceGeneration string,
	sourceProvedRoles []domain.Role,
	destinationRoles []domain.Role,
) (ports.ProviderDirectExecutionAuthority, error) {
	sourceReceipt, ok := currentProbeDirectExecutionAuthorityReceiptFrom(source)
	if !ok || !sourceReceipt.Valid() {
		return nil, fmt.Errorf("equivalent route authority: source authority unavailable")
	}
	sourceRuntime, ok := sourceDefinition.(RuntimeDefinition)
	if !ok {
		return nil, fmt.Errorf("equivalent route authority: source runtime unavailable")
	}
	destinationRuntime, ok := destinationDefinition.(RuntimeDefinition)
	if !ok {
		return nil, fmt.Errorf("equivalent route authority: destination runtime unavailable")
	}
	if len(sourceProvedRoles) == 0 || len(destinationRoles) == 0 {
		return nil, fmt.Errorf("equivalent route authority: source and destination roles are required")
	}
	if !sourceReceipt.Matches(sourceRuntime, observedVersion, sourceNamespaceGeneration, sourceProvedRoles) {
		return nil, fmt.Errorf("equivalent route authority: source authority does not match source runtime")
	}
	if !equivalentFamilyRuntimeProfiles(sourceRuntime, destinationRuntime) {
		return nil, fmt.Errorf("equivalent route authority: family runtime profiles are not shareable")
	}
	if destinationNamespaceGeneration == "" {
		return nil, fmt.Errorf("equivalent route authority: destination namespace generation required")
	}
	baseProof := sourceReceipt.proofs[0]
	rewritten := make([]currentProbeDirectExecutionRoleProof, 0, len(destinationRoles))
	seen := make(map[domain.Role]struct{}, len(destinationRoles))
	for _, role := range destinationRoles {
		if !role.Valid() {
			return nil, fmt.Errorf("equivalent route authority: invalid destination role")
		}
		if _, exists := seen[role]; exists {
			return nil, fmt.Errorf("equivalent route authority: duplicate destination role")
		}
		seen[role] = struct{}{}
		proof := baseProof
		proof.ProviderInstance = destinationRuntime.Instance()
		proof.ProviderVersion = destinationRuntime.Version()
		proof.ProfileID = destinationRuntime.ProfileID()
		proof.NamespaceGeneration = destinationNamespaceGeneration
		proof.Role = string(role)
		rewritten = append(rewritten, proof)
	}
	derived, err := newCurrentProbeDirectExecutionAuthorityReceiptForDefinition(rewritten, sourceReceipt.ExpiresAt(), destinationRuntime)
	if err != nil {
		return nil, fmt.Errorf("equivalent route authority: %w", err)
	}
	if derived.AuthorityID() == sourceReceipt.AuthorityID() {
		return nil, fmt.Errorf("equivalent route authority: destination authority must not reuse source authority id")
	}
	if !derived.Matches(destinationRuntime, observedVersion, destinationNamespaceGeneration, destinationRoles) {
		return nil, fmt.Errorf("equivalent route authority: derived authority does not match destination runtime")
	}
	if !sameRoleSet(sourceProvedRoles, destinationRoles) &&
		derived.Matches(destinationRuntime, observedVersion, destinationNamespaceGeneration, sourceProvedRoles) {
		return nil, fmt.Errorf("equivalent route authority: derived authority still matches source-only roles")
	}
	return derived, nil
}

func sameRoleSet(left, right []domain.Role) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[domain.Role]int, len(left))
	for _, role := range left {
		counts[role]++
	}
	for _, role := range right {
		counts[role]--
		if counts[role] < 0 {
			return false
		}
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func equivalentFamilyRuntimeProfiles(left, right RuntimeDefinition) bool {
	if left.Family() != right.Family() ||
		left.Executable() != right.Executable() ||
		left.ExecutableSHA256() != right.ExecutableSHA256() ||
		left.Launcher() != right.Launcher() ||
		left.LauncherSHA256() != right.LauncherSHA256() ||
		left.ZCodeProviderConfig() != right.ZCodeProviderConfig() ||
		left.ZCodeProviderConfigSHA256() != right.ZCodeProviderConfigSHA256() ||
		left.ProfileGeneration() != right.ProfileGeneration() ||
		left.RuntimeSafetyPolicyIdentity() != right.RuntimeSafetyPolicyIdentity() ||
		left.WorkingDirectory() != right.WorkingDirectory() ||
		left.TransportChannel() != right.TransportChannel() ||
		left.TransportArgvIndex() != right.TransportArgvIndex() ||
		left.TransportReference() != right.TransportReference() {
		return false
	}
	if left.grokModel != right.grokModel || left.grokReasoningEffort != right.grokReasoningEffort || left.grokSettingsIdentity != right.grokSettingsIdentity {
		return false
	}
	if left.Family() == FamilyCodex {
		leftNamed := left.ProfileID() != left.Instance()
		rightNamed := right.ProfileID() != right.Instance()
		if leftNamed != rightNamed || leftNamed && left.ProfileID() != right.ProfileID() {
			return false
		}
	}
	if !reflect.DeepEqual(left.BaseArgv(), right.BaseArgv()) {
		return false
	}
	leftEnv := environmentIdentityValues(left.Environment())
	rightEnv := environmentIdentityValues(right.Environment())
	if leftEnv == nil || rightEnv == nil || !reflect.DeepEqual(leftEnv, rightEnv) {
		return false
	}
	leftLifecycle, leftHas := left.PostOutputLifecycle()
	rightLifecycle, rightHas := right.PostOutputLifecycle()
	if leftHas != rightHas {
		return false
	}
	if leftHas && (leftLifecycle.Framing() != rightLifecycle.Framing() ||
		leftLifecycle.StabilityGrace() != rightLifecycle.StabilityGrace() ||
		leftLifecycle.TerminationGrace() != rightLifecycle.TerminationGrace()) {
		return false
	}
	return true
}

func environmentIdentityValues(environment []ports.EnvironmentVariable) []string {
	values := make([]string, len(environment))
	for index, variable := range environment {
		if !variable.Valid() {
			return nil
		}
		values[index] = variable.Name() + "=" + variable.Value()
	}
	sort.Strings(values)
	return values
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

func (probe *CurrentProbe) QualifyCurrent(ctx context.Context, request CurrentProbeRequest) (result CurrentProbeResult, retErr error) {
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
	if _, err := validateCurrentProbeFixtures(fixture, request.RoleFixtures); err != nil {
		return CurrentProbeResult{}, securityProbeFailure("fixture", "role fixtures are not independently bound", err)
	}
	var versionObservation, capabilityObservation ports.ProcessObservation
	var versionError, capabilityError error
	defer func() {
		if err := ports.ObserveQualificationProbe(context.WithoutCancel(ctx), ports.QualificationProbeObservation{
			Provider: definition.Instance(), Role: fixture.Role(), Packet: fixture.Packet(),
			Version: versionObservation, Capability: capabilityObservation, VersionError: versionError, CapabilityError: capabilityError, Err: retErr,
		}); err != nil {
			result = CurrentProbeResult{}
			retErr = errors.Join(probeFailure("diagnostics", domain.FailureArtifact, "qualification diagnostics persistence failed", err), retErr)
		}
	}()
	namespaceEnvironment := namespace.Environment()
	environment, err := isolatedProcessEnvironment(definition.Family(), definition.Environment(), namespaceEnvironment)
	if err != nil {
		return CurrentProbeResult{}, securityProbeFailure("environment", "isolated environment rejected", err)
	}
	timeout := boundedProbeTimeout(definition.Timeout())
	versionArgv, err := request.Invocation.VersionArgv(definition)
	if err != nil {
		return CurrentProbeResult{}, securityProbeFailure("invocation", "safe version invocation unavailable", err)
	}
	versionObservation, _, versionError = probe.runBound(ctx, definition, namespace, fixture, versionArgv, environment, timeout, nil)
	if versionError != nil {
		return CurrentProbeResult{}, versionError
	}
	version, err := plainSemver(definition.Family(), versionObservation)
	if err != nil {
		return CurrentProbeResult{}, classifyProbeFailure(ctx, definition.Family(), err, versionObservation.Stderr(), versionObservation.Stdout())
	}
	expires := request.Now.Add(request.TTL)
	// Family/runtime readiness uses one capability probe on the base fixture.
	// Additional requested roles are admitted by derivation from that proof.
	roleFixture := fixture
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
	var capabilityEvidence []byte
	capabilityObservation, capabilityEvidence, capabilityError = probe.runBound(ctx, definition, namespace, roleFixture, argv, environment, timeout, &packet)
	if capabilityError != nil {
		return CurrentProbeResult{}, capabilityError
	}
	if evidenceErr := validateProbeTransportAndLifecycle(definition, packet, capabilityObservation); evidenceErr != nil {
		return CurrentProbeResult{}, securityProbeFailure("capability", "provider transport or lifecycle evidence mismatch", evidenceErr)
	}
	// A protocol conversation succeeds through its driver: the bounded
	// teardown that ends a live app-server classifies as signaled, so the
	// one-shot Succeeded() frame contract does not apply to it.
	protocolConversation := definition.Transport().Channel() == ports.ProviderPacketChannelProtocol
	if !protocolConversation && !capabilityObservation.Succeeded() {
		processErr := qualificationProcessFailure(definition.Family(), capabilityObservation, fmt.Errorf("capability probe failed"))
		return CurrentProbeResult{}, classifyProbeFailure(ctx, definition.Family(), processErr, capabilityObservation.Stderr(), capabilityObservation.Stdout())
	}
	output := capabilityObservation.Stdout()
	if protocolConversation {
		// Protocol capability evidence is the conversation's captured assistant
		// text; the protocol transcript on stdout is never evidence.
		output = capabilityEvidence
	}
	if evidenceErr := acceptCapabilityResponse(ctx, definition.Family(), output, capabilityObservation.Stderr(), roleFixture); evidenceErr != nil {
		return CurrentProbeResult{}, evidenceErr
	}
	transport, _ := capabilityObservation.ProviderPacketTransportReceipt()
	transportIdentity := transport.PacketIdentity()
	preStart := transport.PreStartIdentity()
	postEnd := transport.PostTerminationIdentity()
	transportEvidence := []string{fmt.Sprintf("%s|%s|%s|%s|%d|%s|%d|%s|%d",
		transport.Channel(), transport.PromptFileReference(), transport.SnapshotCWD(),
		transportIdentity.CompleteSHA256(), transportIdentity.ByteLength(),
		preStart.CompleteSHA256(), preStart.ByteLength(), postEnd.CompleteSHA256(), postEnd.ByteLength())}
	proof, proofErr := newCurrentProbeDirectExecutionRoleProof(definition, version, namespace.Generation(), namespace, namespaceEnvironment, environment, roleFixture, argv, capabilityObservation)
	if proofErr != nil {
		return CurrentProbeResult{}, securityProbeFailure("direct-execution-authority", "direct role execution proof invalid", proofErr)
	}
	directExecutionProofs := []currentProbeDirectExecutionRoleProof{proof}
	capabilityFixtures := []ProbeFixtureLease{roleFixture}
	receipt, receiptErr := newCurrentProbeDirectExecutionAuthorityReceiptForDefinition(directExecutionProofs, expires, definition)
	if receiptErr != nil {
		return CurrentProbeResult{}, securityProbeFailure("direct-execution-authority", "direct-execution authority receipt invalid", receiptErr)
	}
	receipts, receiptErr := currentProbeValidatedReceipts(definition, capabilityFixtures, version, directExecutionProofs, transportEvidence, environment, namespace.Generation(), expires)
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

func qualificationFamilyOutputCause(family string, err error) domain.RuntimeDiagnosticCause {
	switch family {
	case FamilyZcode:
		return domain.DiagnosticCauseOutputEnvelopeInvalid
	default:
		return domain.DiagnosticCauseObservationInvalid
	}
}

// runBound makes exactly one descriptor-bound launch. Every return path validates
// the namespace and fixture before launch and the fixture guard after launch.
// A protocol capability probe converses the packet through its bound driver
// and returns the captured assistant evidence text alongside the observation.
func (probe *CurrentProbe) runBound(ctx context.Context, definition RuntimeDefinition, namespace QualificationNamespace, fixture ProbeFixtureLease, argv []string, environment []ports.EnvironmentVariable, timeout time.Duration, packet *ports.ProviderPacket) (observation ports.ProcessObservation, protocolEvidence []byte, err error) {
	if err := namespace.ValidateForSpawn(); err != nil {
		return ports.ProcessObservation{}, nil, securityProbeFailure("namespace", "namespace validation failed", err)
	}
	guard, guardErr := fixture.RevalidateForExecution()
	if guardErr != nil || nilWorkspaceExecutionGuard(guard) {
		return ports.ProcessObservation{}, nil, securityProbeFailure("fixture", "fixture execution guard unavailable", guardErr)
	}
	defer func() {
		if closeErr := guard.Close(); closeErr != nil {
			err = securityProbeFailure("fixture", "fixture guard close failed", closeErr)
		}
	}()
	root := guard.WorkspaceRoot()
	if !root.Valid() || guard.WorkspaceSnapshotIdentity() != fixture.WorkspaceSnapshotIdentity() || root.SnapshotIdentity() != fixture.WorkspaceSnapshotIdentity() {
		return ports.ProcessObservation{}, nil, securityProbeFailure("fixture", "fixture descriptor binding drift", nil)
	}
	var request ports.ProcessRequest
	var requestErr error
	var protocolSession providerProtocolSession
	authority, authorityErr := adapterAuthorityForFamily(definition.Family())
	if authorityErr != nil {
		return ports.ProcessObservation{}, nil, securityProbeFailure("process", "protocol authority unavailable", authorityErr)
	}
	if packet == nil {
		request, requestErr = ports.NewProcessRequest(definition.Executable(), argv, environment, root.Path(), nil, timeout)
	} else if authority.qualificationChannel == ports.ProviderPacketChannelProtocol && authority.protocolDriver != nil {
		binding, bindingErr := ports.NewProtocolProviderPacketBinding(*packet)
		if bindingErr != nil {
			requestErr = bindingErr
		} else {
			request, requestErr = ports.NewProviderProtocolProcessRequest(definition.Executable(), argv, environment, root.Path(), binding, timeout)
		}
		if requestErr == nil {
			configuration, configurationErr := protocolConfigurationForNamespace(definition.family, definition.grokModel, definition.grokReasoningEffort, namespace)
			if configurationErr != nil {
				return ports.ProcessObservation{}, nil, configurationErr
			}
			protocolSession, requestErr = authority.protocolDriver.NewSession(root.Path(), packet.Bytes(), protocolPurposeQualification, nil, configuration)
		}
	} else {
		request, requestErr = boundProbeProviderRequest(definition, *packet, argv, "@"+fixture.Reference(), environment, root.Path(), timeout)
	}
	if requestErr != nil {
		return ports.ProcessObservation{}, nil, securityProbeFailure("process", "bound process request rejected", requestErr)
	}
	launchDirectory, duplicateErr := guard.DuplicateLaunchDirectory()
	if duplicateErr != nil {
		return ports.ProcessObservation{}, nil, securityProbeFailure("fixture", "launch descriptor unavailable", duplicateErr)
	}
	request, requestErr = ports.NewBoundProcessRequest(request, root, launchDirectory)
	if requestErr != nil {
		_ = launchDirectory.Close()
		return ports.ProcessObservation{}, nil, securityProbeFailure("process", "bound process descriptor rejected", requestErr)
	}
	if err := probe.verifier.VerifyProviderSpawn(ctx, definition); err != nil {
		launchDirectory, _, _ := request.BoundLaunchDirectory()
		if launchDirectory != nil {
			_ = launchDirectory.Close()
		}
		return ports.ProcessObservation{}, nil, securityProbeFailure("spawn", "spawn verification failed", err)
	}
	if protocolSession != nil {
		conversationRunner, ok := probe.runner.(ports.ProviderConversationRunner)
		if !ok {
			return ports.ProcessObservation{}, nil, securityProbeFailure("process", "process runner cannot converse", nil)
		}
		observation, err = conversationRunner.Converse(ctx, request, protocolSession)
	} else {
		observation, err = probe.runner.Run(ctx, request)
	}
	var transcriptCleanupErr error
	if protocolSession != nil {
		protocolEvidence = protocolSession.AssistantEvidenceText()
		transcriptCleanupErr = releaseProtocolTranscript(observation)
	}
	if postErr := guard.RevalidateAfterExecution(); postErr != nil {
		return observation, nil, errors.Join(securityProbeFailure("fixture", "post-execution fixture drift", postErr), transcriptCleanupErr)
	}
	if err != nil {
		err = errors.Join(err, transcriptCleanupErr)
		if interruption := qualificationInterruptionFailure(observation, err); interruption != nil {
			if errors.Is(interruption, context.Canceled) {
				return observation, nil, interruption
			}
			err = interruption
		}
		return observation, nil, classifyProbeFailure(ctx, definition.Family(), qualificationProcessFailure(definition.Family(), observation, err), observation.Stderr(), observation.Stdout())
	}
	if transcriptCleanupErr != nil {
		return observation, nil, probeFailure("process", domain.FailureArtifact, "protocol transcript cleanup failed", transcriptCleanupErr)
	}
	return observation, protocolEvidence, nil
}

func qualificationInterruptionFailure(observation ports.ProcessObservation, err error) error {
	if !observation.Valid() || err == nil {
		return nil
	}
	switch observation.Termination() {
	case ports.ProcessTerminationCancelled:
		return errors.Join(context.Canceled, err)
	case ports.ProcessTerminationTimedOut:
		// A process-local timeout is retryable while the enclosing qualification
		// context still has budget. Do not make it indistinguishable from exhaustion
		// of that enclosing context by wrapping context.DeadlineExceeded here.
		return newProviderOutputFailure(domain.DiagnosticCauseTimedOut, errors.New("provider process timed out"))
	default:
		return nil
	}
}

func qualificationProcessFailure(family string, observation ports.ProcessObservation, err error) error {
	var failure *domain.Failure
	if errors.As(err, &failure) {
		return failure
	}
	if cause, ok := providerDiagnosticCause(err); ok {
		return newProviderOutputFailure(cause, err)
	}
	_, _, cause := classifyProviderFailure(family, observation)
	return newProviderOutputFailure(cause, err)
}

func providerDiagnosticCause(err error) (domain.RuntimeDiagnosticCause, bool) {
	var process interface {
		PrimaryCause() domain.RuntimeDiagnosticCause
	}
	if errors.As(err, &process) && process.PrimaryCause().Valid() {
		return process.PrimaryCause(), true
	}
	var source interface {
		Cause() domain.RuntimeDiagnosticCause
	}
	if !errors.As(err, &source) || !source.Cause().Valid() {
		return "", false
	}
	return source.Cause(), true
}

var semverOutput = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var grokVersionOutput = regexp.MustCompile(`^grok ([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?) \([0-9a-f]+\)$`)

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
	}{Domain: "Mulgae-CURRENT-PROBE-RECEIPT/" + kind + "/1", RuntimeDefinitionIdentity: runtimeDefinitionIdentity, Values: values})
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
		Family, Instance, Version, Executable, ExecutableSHA256                   string
		Launcher, LauncherSHA256, ApplicationVersion, ApplicationMetadata         string
		ApplicationMetadataSHA256, ZCodeProviderConfig, ZCodeProviderConfigSHA256 string
		ProfileGeneration, RuntimeSafetyPolicyIdentity, ProfileID                 string
		GrokModel, GrokReasoningEffort, GrokSettingsIdentity                      string
		BaseArgv, Environment                                                     []string
		TransportChannel, TransportReference                                      string
		TransportArgvIndex                                                        int
		WorkingDirectory                                                          string
		TimeoutNanoseconds                                                        int64
		HasPostOutputLifecycle                                                    bool
		LifecycleFraming                                                          string
		LifecycleStabilityNanoseconds, LifecycleTerminationNanoseconds            int64
		RequiresWorkspaceAuthority, RequiresSpawnVerification                     bool
		ProductionExplicitTransport                                               bool
	}{
		Family: definition.family, Instance: definition.instance, Version: definition.version,
		Executable: definition.executable, ExecutableSHA256: definition.executableSHA256,
		Launcher: definition.launcher, LauncherSHA256: definition.launcherSHA256,
		ApplicationVersion: definition.applicationVersion, ApplicationMetadata: definition.applicationMetadata,
		ApplicationMetadataSHA256: definition.applicationMetadataSHA256,
		ZCodeProviderConfig:       definition.zcodeProviderConfig, ZCodeProviderConfigSHA256: definition.zcodeProviderConfigSHA256,
		ProfileGeneration: definition.profileGeneration, RuntimeSafetyPolicyIdentity: definition.runtimeSafetyPolicyIdentity,
		ProfileID: definition.profileID,
		GrokModel: definition.grokModel, GrokReasoningEffort: definition.grokReasoningEffort,
		GrokSettingsIdentity: definition.grokSettingsIdentity,
		BaseArgv:             append([]string(nil), definition.baseArgv...), Environment: environmentValues,
		TransportChannel: string(definition.transport.channel), TransportReference: definition.transport.reference,
		TransportArgvIndex: definition.transport.argvIndex, WorkingDirectory: definition.workingDirectory,
		TimeoutNanoseconds: definition.timeout.Nanoseconds(), HasPostOutputLifecycle: hasLifecycle,
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
	sum := sha256.Sum256([]byte("Mulgae-CURRENT-PROBE-DIRECT-EXECUTION-AUTHORITY/4\x00" + proofAuthorityID + "\x00" + runtimeDefinitionIdentity))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateProbeTransportAndLifecycle(definition RuntimeDefinition, packet ports.ProviderPacket, observation ports.ProcessObservation) error {
	transport, ok := observation.ProviderPacketTransportReceipt()
	authority, err := adapterAuthorityForFamily(definition.Family())
	if err != nil {
		return probeEvidenceFailure(domain.DiagnosticCauseTransportReceiptMismatch, "provider protocol authority unavailable")
	}
	expectedChannel := authority.qualificationChannel
	if !ok || !transport.Valid() || transport.Channel() != expectedChannel || transport.PacketIdentity() != packet.Identity() {
		return probeEvidenceFailure(domain.DiagnosticCauseTransportReceiptMismatch, "missing or mismatched provider packet transport receipt")
	}
	lifecyclePolicy, requiresLifecycle := definition.PostOutputLifecycle()
	if !requiresLifecycle {
		return nil
	}
	lifecycle, ok := observation.LifecycleReceipt()
	if !ok || !lifecycle.Valid() || !lifecycle.ProcessGroupAbsent() {
		return probeEvidenceFailure(domain.DiagnosticCauseLifecycleReceiptInvalid, "missing post-output lifecycle receipt")
	}
	frame, frameOK := lifecycle.OutputFrame()
	requests := lifecycle.SignalRequests()
	if !frameOK {
		// A terminal JSON frame is optional metadata, not the result transport.
		// With no frame there is no frame-integrity claim to verify, so capability
		// acceptance is decided by bound fixture evidence instead. This cannot hide
		// a forged post-output signal claim: ProcessLifecycleReceipt.Valid rejects
		// any post-output signal receipt that is not bound to a present frame.
		return nil
	}
	if !frame.Valid() {
		return probeEvidenceFailure(domain.DiagnosticCauseOutputFrameMissing, "missing valid post-output frame receipt")
	}
	if frame.Framing() != lifecyclePolicy.Framing() || lifecyclePolicy.Framing() != ports.ProcessOutputFramingTerminalJSONObject {
		return probeEvidenceFailure(domain.DiagnosticCauseOutputFrameMismatch, "mismatched post-output frame policy")
	}
	if frame.StabilityGrace() != lifecyclePolicy.StabilityGrace() || lifecyclePolicy.TerminationGrace() <= 0 {
		return probeEvidenceFailure(domain.DiagnosticCauseLifecycleReceiptInvalid, "mismatched post-output lifecycle timing")
	}
	if frame.ByteLength() != int64(len(observation.Stdout())) {
		return probeEvidenceFailure(domain.DiagnosticCauseOutputFrameMismatch, "post-output frame length does not match stdout length")
	}
	sum := sha256.New()
	_, _ = sum.Write([]byte("Mulgae-PROCESS-STDOUT-FRAME/1"))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write(observation.Stdout())
	if frame.SHA256() != hex.EncodeToString(sum.Sum(nil)) {
		return probeEvidenceFailure(domain.DiagnosticCauseOutputFrameMismatch, "trailing or mismatched post-output stdout")
	}
	hasPostOutput, hasNonPostOutput := false, false
	for _, request := range requests {
		switch request.Reason() {
		case ports.ProcessGroupSignalRequestPostOutput, ports.ProcessGroupSignalRequestPostOutputEscalation:
			hasPostOutput = true
		default:
			hasNonPostOutput = true
		}
	}
	if hasPostOutput && hasNonPostOutput {
		return probeEvidenceFailure(domain.DiagnosticCauseSignalReceiptMismatch, "mixed post-output and failure signal receipts")
	}
	// Timeout, cancellation, incomplete stdin, and other process failures may
	// retain a valid frame observed before their internal teardown signal. That
	// signal is not a post-output success claim; leave its typed process cause to
	// qualificationProcessFailure instead of relabeling it as a receipt mismatch.
	if hasNonPostOutput || (!observation.Succeeded() && !hasPostOutput) {
		return nil
	}
	if len(requests) == 0 {
		final := lifecycle.FinalTermination()
		exitCode, exited := final.ExitCode()
		if final.Kind() != ports.ProcessFinalTerminationExited || !exited || exitCode != 0 {
			return probeEvidenceFailure(domain.DiagnosticCauseLifecycleReceiptInvalid, "invalid natural post-output termination receipt")
		}
		return nil
	}
	if len(requests) > 2 {
		return probeEvidenceFailure(domain.DiagnosticCauseSignalReceiptMismatch, "invalid post-output signal receipt count")
	}
	validateSignal := func(request ports.ProcessGroupSignalRequestReceipt, reason ports.ProcessGroupSignalRequestReason, number int, name string) error {
		identity, identityOK := request.PacketIdentity()
		frameSHA256, frameOK := request.FrameSHA256()
		if !request.Valid() || request.Reason() != reason || request.Signal().Number() != number || request.Signal().Name() != name ||
			!identityOK || identity != packet.Identity() || !frameOK || frameSHA256 != frame.SHA256() {
			return probeEvidenceFailure(domain.DiagnosticCauseSignalReceiptMismatch, "mismatched post-output signal receipt")
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

func probeEvidenceFailure(cause domain.RuntimeDiagnosticCause, message string) error {
	return newProviderOutputFailure(cause, errors.New(message))
}
func boundProbeProviderRequest(def RuntimeDefinition, packet ports.ProviderPacket, argv []string, reference string, environment []ports.EnvironmentVariable, workingDirectory string, timeout time.Duration) (ports.ProcessRequest, error) {
	authority, err := adapterAuthorityForFamily(def.Family())
	if err != nil {
		return ports.ProcessRequest{}, err
	}
	channel := authority.qualificationChannel
	needle := string(packet.Bytes())
	if channel == ports.ProviderPacketChannelPromptFile {
		needle = reference
	}
	index := -1
	if channel != ports.ProviderPacketChannelStdin {
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
	}
	var binding ports.ProviderPacketBinding
	switch channel {
	case ports.ProviderPacketChannelPromptFile:
		binding, err = ports.NewPromptFileProviderPacketBinding(packet, index, reference, workingDirectory)
	case ports.ProviderPacketChannelArgvLiteral:
		binding, err = ports.NewArgvLiteralProviderPacketBinding(packet, index)
	case ports.ProviderPacketChannelStdin:
		binding, err = ports.NewStdinProviderPacketBinding(packet)
	default:
		return ports.ProcessRequest{}, fmt.Errorf("unsupported provider packet transport")
	}
	if err != nil {
		return ports.ProcessRequest{}, err
	}
	if lifecycle, ok := def.PostOutputLifecycle(); ok {
		return ports.NewProviderProcessRequestWithPostOutputLifecycle(def.Executable(), argv, environment, workingDirectory, binding, lifecycle, timeout)
	}
	return ports.NewProviderProcessRequest(def.Executable(), argv, environment, workingDirectory, binding, timeout)
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
func plainSemver(family string, observation ports.ProcessObservation) (string, error) {
	version := strings.TrimSpace(string(observation.Stdout()))
	if family == FamilyCodex {
		version = strings.TrimPrefix(version, "codex-cli ")
	} else if family == FamilyGrok {
		match := grokVersionOutput.FindStringSubmatch(version)
		if len(match) != 2 {
			return "", fmt.Errorf("invalid Grok version output")
		}
		version = match[1]
	}
	if !observation.Succeeded() || !semverOutput.MatchString(version) {
		return "", fmt.Errorf("invalid plain semver version output")
	}
	return version, nil
}

func acceptCapabilityResponse(ctx context.Context, family string, output, stderr []byte, fixture ProbeFixtureLease) error {
	err := acceptCapabilityEvidence(family, output, fixture)
	if err == nil {
		return nil
	}
	// A zero exit code does not erase native failure evidence. Classify it only
	// after proof validation fails, so valid narrated proofs keep their meaning.
	if _, _, cause, known := nativeProviderOutcome(family, output, stderr); known {
		return classifyProbeFailure(ctx, family, newProviderOutputFailure(cause, errors.New("capability response failed")), stderr, output)
	}
	return err
}

func acceptCapabilityEvidence(family string, output []byte, fixture ProbeFixtureLease) error {
	candidates, err := capabilityEvidenceCandidates(family, output)
	if err != nil {
		return probeFailure("capability", domain.FailureInvalidOutput, "capability evidence unavailable", newProviderOutputFailure(qualificationFamilyOutputCause(family, err), err))
	}
	var mismatch error
	for _, candidate := range candidates {
		if err := validateProbeEvidence(candidate, fixture); err == nil {
			return nil
		} else {
			mismatch = err
		}
	}
	if mismatch == nil {
		mismatch = fmt.Errorf("invalid controlled probe evidence")
	}
	// Fixture-binding failure is an operational capability rejection. Security
	// classification stays reserved for transport, lifecycle, and frame-integrity
	// receipt violations, which are proved before this point.
	return probeFailure("capability", domain.FailureInvalidOutput, "controlled evidence mismatch", newProviderOutputFailure(domain.DiagnosticCauseObservationMismatch, mismatch))
}

func capabilityEvidenceCandidates(family string, output []byte) ([][]byte, error) {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty capability output")
	}
	candidates := make([][]byte, 0, 2)
	// Protocol capability evidence arrives as the conversation's captured
	// assistant text, so its candidates are the controlled probe JSON and the
	// trimmed text itself.
	if content, err := controlledProbeJSON(trimmed); err == nil {
		candidates = append(candidates, content)
	}
	candidates = append(candidates, trimmed)
	return candidates, nil
}

// capabilityEvidencePayload remains for tests that inspect joined candidate text.
func capabilityEvidencePayload(family string, output []byte) ([]byte, error) {
	candidates, err := capabilityEvidenceCandidates(family, output)
	if err != nil {
		return nil, err
	}
	return bytes.Join(candidates, []byte{'\n'}), nil
}

func validateProbeEvidence(output []byte, fixture ProbeFixtureLease) error {
	if fixture == nil {
		return fmt.Errorf("invalid controlled probe evidence")
	}
	nonce, link, role := fixture.Nonce(), fixture.Link(), string(fixture.Role())
	if nonce == "" || link == "" || role == "" || nonce == link || nonce == role || link == role {
		return fmt.Errorf("invalid controlled probe evidence")
	}
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return fmt.Errorf("invalid controlled probe evidence")
	}
	packet := bytes.TrimSpace(fixture.Packet())
	if len(packet) > 0 && bytes.Equal(trimmed, packet) {
		return fmt.Errorf("capability evidence is prompt echo")
	}
	if looksLikeJSONObject(trimmed) {
		evidence, err := parseProbeEvidenceJSON(trimmed)
		if err != nil {
			return fmt.Errorf("invalid controlled probe evidence")
		}
		if evidence.Root == nonce && evidence.Link == link && evidence.Role == role {
			return nil
		}
		return fmt.Errorf("invalid controlled probe evidence")
	}
	for _, candidate := range bytes.Split(trimmed, []byte{'\n'}) {
		candidate = bytes.TrimSpace(candidate)
		if !looksLikeJSONObject(candidate) {
			continue
		}
		if evidence, err := parseProbeEvidenceJSON(candidate); err == nil {
			if evidence.Root == nonce && evidence.Link == link && evidence.Role == role {
				return nil
			}
		}
	}
	// Narrated proof must bind values outside a pure prompt copy.
	remainder := trimmed
	if len(packet) > 0 {
		remainder = bytes.ReplaceAll(remainder, packet, nil)
	}
	remainder = bytes.TrimSpace(remainder)
	if len(remainder) == 0 {
		return fmt.Errorf("capability evidence is prompt echo")
	}
	text := string(remainder)
	if containsDistinctBinding(text, nonce) && containsDistinctBinding(text, link) && containsDistinctBinding(text, role) {
		return nil
	}
	return fmt.Errorf("invalid controlled probe evidence")
}

func looksLikeJSONArray(output []byte) bool {
	trimmed := bytes.TrimSpace(output)
	return len(trimmed) > 0 && trimmed[0] == '['
}

func looksLikeJSONObject(output []byte) bool {
	trimmed := bytes.TrimSpace(output)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func parseProbeEvidenceJSON(output []byte) (struct {
	Root string `json:"root"`
	Link string `json:"link"`
	Role string `json:"role"`
}, error) {
	var evidence struct {
		Root string `json:"root"`
		Link string `json:"link"`
		Role string `json:"role"`
	}
	if err := rejectDuplicateJSONKeys(output); err != nil {
		return evidence, err
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	if err := decoder.Decode(&evidence); err != nil {
		return evidence, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return evidence, fmt.Errorf("trailing probe evidence")
	}
	return evidence, nil
}

func rejectDuplicateJSONKeys(output []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(output))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return fmt.Errorf("invalid JSON object key")
				}
				if _, duplicate := seen[name]; duplicate {
					return fmt.Errorf("duplicate JSON key %q", name)
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return fmt.Errorf("invalid JSON object terminator")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return fmt.Errorf("invalid JSON array terminator")
			}
		default:
			return fmt.Errorf("invalid JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func containsDistinctBinding(text, value string) bool {
	if value == "" || !strings.Contains(text, value) {
		return false
	}
	return true
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
	var failure *domain.Failure
	if errors.As(err, &failure) {
		return failure
	}
	if cause, ok := providerDiagnosticCause(err); ok {
		switch cause {
		case domain.DiagnosticCauseTimedOut:
			return probeFailure("capability", domain.FailureTimeout, "provider timed out", err)
		case domain.DiagnosticCauseRateLimited:
			return probeFailure("capability", domain.FailureRateLimit, "provider rate limited", err)
		case domain.DiagnosticCauseQuotaExceeded:
			return probeFailure("capability", domain.FailureQuota, "provider quota unavailable", err)
		case domain.DiagnosticCauseLoginRequired, domain.DiagnosticCauseAuthenticationFailed, domain.DiagnosticCausePermissionDenied:
			return probeFailure("capability", domain.FailureAuthentication, "provider authentication unavailable", err)
		case domain.DiagnosticCauseProviderSpawnFailed, domain.DiagnosticCauseProviderExecutionFailed,
			domain.DiagnosticCauseProviderTurnFailed, domain.DiagnosticCauseProviderProcessWaitFailed:
			return probeFailure("capability", domain.FailureProviderUnavailable, "provider unavailable", err)
		}
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
		case ports.ProviderExecutionStatusUnavailable:
			return probeFailure("capability", domain.FailureProviderUnavailable, "provider unavailable", err)
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
