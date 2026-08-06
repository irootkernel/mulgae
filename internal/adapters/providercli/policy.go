package providercli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// RuntimeSafetyPolicy records retained namespace configuration provenance. It
// is not execution or security authority and is excluded from AGY authority
// preimages.
type RuntimeSafetyPolicy struct {
	family   CredentialSourceFamily
	identity string
	path     string
	bytes    []byte
}

type agySafetyContract struct {
	AuthenticationContext string `json:"authentication_context"`
	PolicyScope           string `json:"policy_scope"`
}

// AGYExecutionPolicy is the exact, immutable description of one native AGY
// qualification execution. Mulgae receives no native-HOME mutation capability:
// the typed authority supplies only identity-checked launch context. The child
// provider retains its normal installed-user authentication behavior, so this
// policy deliberately does not claim that AGY itself cannot refresh auth state.
type AGYExecutionPolicy struct {
	definition      RuntimeDefinition
	snapshot        ports.WorkspaceSnapshotIdentity
	argv            []string
	nativeReference string
	identity        string
}

type agyExecutionPolicyContract struct {
	Argv                         []string `json:"argv"`
	MaxStderrBytes               int64    `json:"max_stderr_bytes"`
	MaxStdoutBytes               int64    `json:"max_stdout_bytes"`
	NativeReference              string   `json:"native_reference"`
	PostOutputFraming            string   `json:"post_output_framing"`
	PostOutputStabilityNanosec   int64    `json:"post_output_stability_nanoseconds"`
	PostOutputTerminationNanosec int64    `json:"post_output_termination_nanoseconds"`
	ProfileGeneration            string   `json:"profile_generation"`
	ProfileID                    string   `json:"profile_id"`
	ProtectionGuarantee          string   `json:"protection_guarantee"`
	ProviderInstance             string   `json:"provider_instance"`
	ProviderVersion              string   `json:"provider_version"`
	SnapshotManifestSHA256       string   `json:"snapshot_manifest_sha256"`
	SnapshotName                 string   `json:"snapshot_name"`
	SnapshotPath                 string   `json:"snapshot_path"`
	SnapshotPolicyIdentity       string   `json:"snapshot_policy_identity"`
	SnapshotDevice               uint64   `json:"snapshot_device"`
	SnapshotInode                uint64   `json:"snapshot_inode"`
	RootDevice                   uint64   `json:"root_device"`
	RootInode                    uint64   `json:"root_inode"`
	TimeoutNanoseconds           int64    `json:"timeout_nanoseconds"`
}

var runtimeSafetyPolicies = func() map[CredentialSourceFamily]RuntimeSafetyPolicy {
	values := map[CredentialSourceFamily]RuntimeSafetyPolicy{
		CredentialSourceKimi:  {family: CredentialSourceKimi, bytes: []byte("{\"family\":\"kimi\",\"permissions\":{\"allow\":[],\"ask\":[],\"deny\":[\"*\"]}}\n")},
		CredentialSourceZCode: {family: CredentialSourceZCode, bytes: []byte("{\"family\":\"zcode\",\"permissions\":{\"allow\":[],\"ask\":[],\"deny\":[\"*\"]}}\n")},
		CredentialSourceAGY:   {family: CredentialSourceAGY, bytes: []byte("{\"authentication_context\":\"installed_user_home\",\"policy_scope\":\"namespace_auth_only\"}\n")},
	}
	for family, policy := range values {
		values[family] = runtimeSafetyPolicyWithIdentity(policy)
	}
	return values
}()

// RuntimeSafetyPolicyForFamily returns a copy of the canonical retained policy.
func RuntimeSafetyPolicyForFamily(family CredentialSourceFamily) (RuntimeSafetyPolicy, error) {
	policy, ok := runtimeSafetyPolicies[family]
	if !ok {
		return RuntimeSafetyPolicy{}, fmt.Errorf("runtime safety policy: unsupported family")
	}
	return cloneRuntimeSafetyPolicy(policy), nil
}

// RuntimeSafetyPolicyForFamilyAndWorkspaceRoot is retained for production
// composition callers while their workspace-bound construction is migrated. The
// workspace root is deliberately not authority for the retained policy.
//
// Deprecated: use RuntimeSafetyPolicyForFamily. The workspace root is validated
// only to reject malformed legacy callers and never contributes authority.
func RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(family CredentialSourceFamily, workspaceRoot string) (RuntimeSafetyPolicy, error) {
	if family == CredentialSourceAGY && workspaceRoot != "" && (workspaceRoot == string(filepath.Separator) || !canonicalAbsolutePath(workspaceRoot)) {
		return RuntimeSafetyPolicy{}, fmt.Errorf("runtime safety policy: invalid workspace root")
	}
	return RuntimeSafetyPolicyForFamily(family)
}

// NewAGYExecutionPolicy binds the only native AGY prompt-file execution shape
// to the exact descriptor-backed snapshot.
func NewAGYExecutionPolicy(definition RuntimeDefinition, snapshot ports.WorkspaceSnapshotIdentity, argv []string, nativeReference string) (AGYExecutionPolicy, error) {
	if safeProbeDefinition(definition) != nil || definition.Family() != FamilyAgy || !snapshot.Valid() || !validAGYNativeReference(nativeReference) ||
		definition.Timeout() <= 0 || definition.MaxStdoutBytes() <= 0 || definition.MaxStderrBytes() <= 0 {
		return AGYExecutionPolicy{}, fmt.Errorf("AGY execution policy: invalid authority")
	}
	lifecycle, ok := definition.PostOutputLifecycle()
	if !ok || !lifecycle.Valid() || lifecycle.Framing() != ports.ProcessOutputFramingTerminalJSONObject {
		return AGYExecutionPolicy{}, fmt.Errorf("AGY execution policy: invalid lifecycle")
	}
	want, err := canonicalAGYExecutionArgv(definition, snapshot, nativeReference)
	if err != nil || !reflect.DeepEqual(argv, want) {
		return AGYExecutionPolicy{}, fmt.Errorf("AGY execution policy: argv drift")
	}
	policy := AGYExecutionPolicy{definition: definition, snapshot: snapshot, argv: append([]string(nil), argv...), nativeReference: nativeReference}
	bytes, err := agyExecutionPolicyBytes(policy)
	if err != nil {
		return AGYExecutionPolicy{}, fmt.Errorf("AGY execution policy: encode")
	}
	sum := sha256.Sum256(bytes)
	policy.identity = "sha256:" + hex.EncodeToString(sum[:])
	return policy, nil
}

func (policy AGYExecutionPolicy) Identity() string { return policy.identity }
func (policy AGYExecutionPolicy) SnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return policy.snapshot
}
func (policy AGYExecutionPolicy) Argv() []string          { return append([]string(nil), policy.argv...) }
func (policy AGYExecutionPolicy) NativeReference() string { return policy.nativeReference }

func (policy AGYExecutionPolicy) Validate() error {
	canonical, err := NewAGYExecutionPolicy(policy.definition, policy.snapshot, policy.argv, policy.nativeReference)
	if err != nil || policy.identity == "" || canonical.identity != policy.identity {
		return fmt.Errorf("AGY execution policy: drift")
	}
	return nil
}

func (policy AGYExecutionPolicy) ArgvSHA256() string {
	bytes, err := json.Marshal(policy.argv)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type currentProbeDirectExecutionRoleProof struct {
	Family                      string `json:"family"`
	ProviderInstance            string `json:"provider_instance"`
	ProviderVersion             string `json:"provider_version"`
	ObservedVersion             string `json:"observed_version"`
	Executable                  string `json:"executable"`
	ExecutableSHA256            string `json:"executable_sha256"`
	Launcher                    string `json:"launcher"`
	LauncherSHA256              string `json:"launcher_sha256"`
	ProfileID                   string `json:"profile_id"`
	ProfileGeneration           string `json:"profile_generation"`
	NamespaceGeneration         string `json:"namespace_generation"`
	Role                        string `json:"role"`
	SnapshotManifestSHA256      string `json:"snapshot_manifest_sha256"`
	SnapshotName                string `json:"snapshot_name"`
	SnapshotPath                string `json:"snapshot_path"`
	SnapshotPolicyIdentity      string `json:"snapshot_policy_identity"`
	SnapshotDevice              uint64 `json:"snapshot_device"`
	SnapshotInode               uint64 `json:"snapshot_inode"`
	RootDevice                  uint64 `json:"root_device"`
	RootInode                   uint64 `json:"root_inode"`
	ArgvSHA256                  string `json:"argv_sha256"`
	NativeReference             string `json:"native_reference"`
	OutputSHA256                string `json:"output_sha256"`
	Termination                 string `json:"termination"`
	HasExitCode                 bool   `json:"has_exit_code"`
	ExitCode                    int    `json:"exit_code"`
	HasSignal                   bool   `json:"has_signal"`
	SignalNumber                int    `json:"signal_number"`
	SignalName                  string `json:"signal_name"`
	TransportChannel            string `json:"transport_channel"`
	TransportPacketSHA256       string `json:"transport_packet_sha256"`
	TransportPacketLength       int    `json:"transport_packet_length"`
	TransportPreStartSHA256     string `json:"transport_pre_start_sha256"`
	TransportPreStartLength     int    `json:"transport_pre_start_length"`
	TransportPostEndSHA256      string `json:"transport_post_end_sha256"`
	TransportPostEndLength      int    `json:"transport_post_end_length"`
	TransportReference          string `json:"transport_reference"`
	TransportSnapshotCWD        string `json:"transport_snapshot_cwd"`
	LifecycleFrameSHA256        string `json:"lifecycle_frame_sha256"`
	LifecycleFrameLength        int64  `json:"lifecycle_frame_length"`
	LifecycleFraming            string `json:"lifecycle_framing"`
	LifecycleProcessGroupAbsent bool   `json:"lifecycle_process_group_absent"`
	AGYExecutionPolicy          string `json:"agy_execution_policy"`
	NamespaceEnvironmentSHA256  string `json:"namespace_environment_sha256"`
	EffectiveEnvironmentSHA256  string `json:"effective_environment_sha256"`
	NativeHomePath              string `json:"native_home_path"`
	NativeHomeDevice            uint64 `json:"native_home_device"`
	NativeHomeInode             uint64 `json:"native_home_inode"`
	NativeHomeEffectiveUID      uint32 `json:"native_home_effective_uid"`
}

type currentProbeDirectExecutionAuthorityContract struct {
	Domain          string                                 `json:"domain"`
	ExpiresUnixNano int64                                  `json:"expires_unix_nano"`
	Proofs          []currentProbeDirectExecutionRoleProof `json:"proofs"`
}
type currentProbeAGYControlAuthorityContract struct {
	Domain          string                                 `json:"domain"`
	ExpiresUnixNano int64                                  `json:"expires_unix_nano"`
	Proofs          []currentProbeDirectExecutionRoleProof `json:"proofs"`
}

func (receipt CurrentProbeDirectExecutionAuthorityReceipt) AGYControlAuthorityID() (string, bool) {
	if !receipt.Valid() || len(receipt.proofs) == 0 {
		return "", false
	}
	proofs := append([]currentProbeDirectExecutionRoleProof(nil), receipt.proofs...)
	for index := range proofs {
		if proofs[index].Family != FamilyAgy {
			return "", false
		}
		proofs[index].OutputSHA256 = ""
		proofs[index].LifecycleFrameSHA256 = ""
		proofs[index].LifecycleFrameLength = 0
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].Role < proofs[j].Role })
	bytes, err := json.Marshal(currentProbeAGYControlAuthorityContract{
		Domain:          "Mulgae-CURRENT-PROBE-AGY-CONTROL-AUTHORITY/1",
		ExpiresUnixNano: receipt.expiresAt.UTC().UnixNano(),
		Proofs:          proofs,
	})
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), true
}
func disposableNamespaceEnvironmentID(environment []ports.EnvironmentVariable) (string, error) {
	values, err := validatedDisposableNamespaceEnvironment(environment)
	if err != nil {
		return "", err
	}
	bytes, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validatedDisposableNamespaceEnvironment(environment []ports.EnvironmentVariable) ([]string, error) {
	paths := make(map[string]string, 8)
	for _, variable := range environment {
		if !variable.Valid() || !namespaceEnvironmentName(variable.Name()) || !validCanonicalAbsolute(variable.Value()) {
			return nil, fmt.Errorf("invalid namespace environment")
		}
		if _, exists := paths[variable.Name()]; exists {
			return nil, fmt.Errorf("duplicate namespace environment")
		}
		paths[variable.Name()] = variable.Value()
	}
	if len(paths) != 8 {
		return nil, fmt.Errorf("incomplete namespace environment")
	}
	root := filepath.Dir(paths["XDG_CONFIG_HOME"])
	if root == string(filepath.Separator) || !validCanonicalAbsolute(root) ||
		paths["XDG_CONFIG_HOME"] != filepath.Join(root, "settings") ||
		paths["XDG_DATA_HOME"] != filepath.Join(root, "auth") ||
		paths["XDG_CACHE_HOME"] != filepath.Join(root, "cache") ||
		paths["TMPDIR"] != filepath.Join(root, "tmp") ||
		paths["TMP"] != filepath.Join(root, "tmp") ||
		paths["TEMP"] != filepath.Join(root, "tmp") ||
		paths["MULGAE_PROVIDER_SCRATCH"] != filepath.Join(root, "scratch") {
		return nil, fmt.Errorf("namespace environment escapes Mulgae-owned root")
	}
	values := make([]string, 0, len(paths))
	for name, value := range paths {
		values = append(values, name+"="+value)
	}
	sort.Strings(values)
	return values, nil
}

func validateDirectExecutionEnvironmentAuthority(family string, namespace QualificationNamespace, namespaceEnvironment, environment []ports.EnvironmentVariable) error {
	if _, err := disposableNamespaceEnvironmentID(namespaceEnvironment); err != nil || !containsNamespaceEnvironment(namespace.Environment(), namespaceEnvironment) ||
		!containsNamespaceEnvironment(namespaceEnvironment, namespace.Environment()) || !containsNamespaceEnvironment(environment, namespaceEnvironment) {
		return fmt.Errorf("namespace environment")
	}
	home := ""
	for _, variable := range namespaceEnvironment {
		if variable.Name() == "HOME" {
			home = variable.Value()
			break
		}
	}
	authority, hasAuthority := namespace.NativeHomeLaunchAuthority()
	if family == FamilyAgy {
		if !hasAuthority || !authority.Valid() || !validCanonicalAbsolute(authority.Path()) || home != authority.Path() {
			return fmt.Errorf("AGY native home authority")
		}
		return nil
	}
	if hasAuthority {
		return fmt.Errorf("non-AGY native home authority")
	}
	root := filepath.Dir(home)
	if root == string(filepath.Separator) || home != filepath.Join(root, "home") {
		return fmt.Errorf("non-AGY HOME escapes Mulgae-owned root")
	}
	return nil
}

func containsNamespaceEnvironment(environment, namespace []ports.EnvironmentVariable) bool {
	wanted := make(map[string]string, len(namespace))
	for _, variable := range namespace {
		if !variable.Valid() || !namespaceEnvironmentName(variable.Name()) {
			return false
		}
		if _, exists := wanted[variable.Name()]; exists {
			return false
		}
		wanted[variable.Name()] = variable.Value()
	}
	actual := make(map[string]string, len(wanted))
	for _, variable := range environment {
		if !namespaceEnvironmentName(variable.Name()) {
			continue
		}
		if !variable.Valid() {
			return false
		}
		if _, exists := actual[variable.Name()]; exists {
			return false
		}
		actual[variable.Name()] = variable.Value()
	}
	if len(actual) != len(wanted) {
		return false
	}
	for name, value := range wanted {
		if actual[name] != value {
			return false
		}
	}
	return true
}

func newCurrentProbeDirectExecutionRoleProof(definition RuntimeDefinition, observedVersion, namespaceGeneration string, namespace QualificationNamespace, namespaceEnvironment, environment []ports.EnvironmentVariable, fixture ProbeFixtureLease, argv []string, packet ports.ProviderPacket, observation ports.ProcessObservation, executionPolicy *AGYExecutionPolicy) (currentProbeDirectExecutionRoleProof, error) {
	if safeProbeDefinition(definition) != nil || namespace == nil || fixture == nil || validateProbeFixtureLease(fixture) != nil ||
		namespaceGeneration == "" || !semverOutput.MatchString(observedVersion) || !fixture.Role().Valid() || !observation.Valid() || !observation.Succeeded() ||
		!validRelativeNativeReference(fixture.Reference()) {
		return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: invalid direct execution")
	}
	argvBytes, err := json.Marshal(argv)
	if err != nil {
		return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: argv")
	}
	argvSum := sha256.Sum256(argvBytes)
	snapshot := fixture.WorkspaceSnapshotIdentity()
	rootDevice, rootInode := snapshot.RootIdentity()
	snapshotDevice, snapshotInode := snapshot.SnapshotFSIdentity()
	proof := currentProbeDirectExecutionRoleProof{
		Family: definition.Family(), ProviderInstance: definition.Instance(), ProviderVersion: definition.Version(), ObservedVersion: observedVersion,
		Executable: definition.Executable(), ExecutableSHA256: definition.ExecutableSHA256(), Launcher: definition.Launcher(), LauncherSHA256: definition.LauncherSHA256(),
		ProfileID: definition.ProfileID(), ProfileGeneration: definition.ProfileGeneration(), NamespaceGeneration: namespaceGeneration, Role: string(fixture.Role()),
		SnapshotManifestSHA256: snapshot.ManifestSHA256(), SnapshotName: snapshot.SnapshotName(), SnapshotPath: snapshot.SnapshotPath(), SnapshotPolicyIdentity: snapshot.PolicyIdentity(),
		SnapshotDevice: snapshotDevice, SnapshotInode: snapshotInode, RootDevice: rootDevice, RootInode: rootInode,
		ArgvSHA256: "sha256:" + hex.EncodeToString(argvSum[:]), NativeReference: "@" + fixture.Reference(),
		Termination: string(observation.Termination()),
	}
	outputSum := sha256.Sum256(observation.Stdout())
	proof.OutputSHA256 = "sha256:" + hex.EncodeToString(outputSum[:])
	proof.ExitCode, proof.HasExitCode = observation.ExitCode()
	proof.SignalNumber, proof.SignalName, proof.HasSignal = observation.Signal()
	if environmentErr := validateDirectExecutionEnvironmentAuthority(definition.Family(), namespace, namespaceEnvironment, environment); environmentErr != nil {
		return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: namespace environment")
	}
	environmentID, environmentErr := effectiveEnvironmentIdentity(environment)
	if environmentErr != nil {
		return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: effective environment")
	}
	proof.EffectiveEnvironmentSHA256 = environmentID
	if definition.Family() != FamilyAgy {
		if executionPolicy != nil {
			return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: unexpected AGY policy")
		}
		return proof, nil
	}
	if executionPolicy == nil || executionPolicy.Validate() != nil || executionPolicy.Identity() == "" ||
		executionPolicy.SnapshotIdentity() != snapshot || !reflect.DeepEqual(executionPolicy.Argv(), argv) ||
		executionPolicy.NativeReference() != fixture.Reference() || !packet.Valid() ||
		validateProbeTransportAndLifecycle(definition, packet, observation) != nil {
		return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: AGY evidence drift")
	}
	transport, _ := observation.ProviderPacketTransportReceipt()
	lifecycle, _ := observation.LifecycleReceipt()
	frame, frameOK := lifecycle.OutputFrame()
	identity := transport.PacketIdentity()
	proof.TransportChannel = string(transport.Channel())
	proof.TransportPacketSHA256 = identity.CompleteSHA256()
	proof.TransportPacketLength = identity.ByteLength()
	preStart := transport.PreStartIdentity()
	postEnd := transport.PostTerminationIdentity()
	proof.TransportPreStartSHA256 = preStart.CompleteSHA256()
	proof.TransportPreStartLength = preStart.ByteLength()
	proof.TransportPostEndSHA256 = postEnd.CompleteSHA256()
	proof.TransportPostEndLength = postEnd.ByteLength()
	proof.TransportReference = transport.PromptFileReference()
	proof.TransportSnapshotCWD = transport.SnapshotCWD()
	// Every frame-derived field is sourced from the frame receipt itself, never
	// from the definition's lifecycle policy. A terminal JSON frame is optional
	// metadata, so a frameless observation binds no frame claim and leaves all
	// three fields at exactly their zero values.
	if frameOK {
		proof.LifecycleFrameSHA256 = frame.SHA256()
		proof.LifecycleFrameLength = frame.ByteLength()
		proof.LifecycleFraming = string(frame.Framing())
	}
	proof.LifecycleProcessGroupAbsent = lifecycle.ProcessGroupAbsent()
	proof.AGYExecutionPolicy = executionPolicy.Identity()
	namespaceEnvironmentID, environmentErr := disposableNamespaceEnvironmentID(namespaceEnvironment)
	if environmentErr != nil {
		return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: namespace environment")
	}
	authority, authorityOK := namespace.NativeHomeLaunchAuthority()
	if !authorityOK || !authority.Valid() {
		return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: AGY native home authority")
	}
	proof.NamespaceEnvironmentSHA256 = namespaceEnvironmentID
	proof.NativeHomePath = authority.Path()
	proof.NativeHomeDevice = authority.Device()
	proof.NativeHomeInode = authority.Inode()
	proof.NativeHomeEffectiveUID = authority.EffectiveUID()
	return proof, nil
}

func newCurrentProbeDirectExecutionAuthorityReceipt(proofs []currentProbeDirectExecutionRoleProof, expiresAt time.Time) (CurrentProbeDirectExecutionAuthorityReceipt, error) {
	authorityID, err := currentProbeDirectExecutionAuthorityID(proofs, expiresAt)
	if err != nil {
		return CurrentProbeDirectExecutionAuthorityReceipt{}, err
	}
	copied := append([]currentProbeDirectExecutionRoleProof(nil), proofs...)
	return CurrentProbeDirectExecutionAuthorityReceipt{authorityID: authorityID, proofs: copied, expiresAt: expiresAt}, nil
}

func effectiveEnvironmentIdentity(environment []ports.EnvironmentVariable) (string, error) {
	values := make([]string, len(environment))
	seen := make(map[string]struct{}, len(environment))
	for index, variable := range environment {
		if !variable.Valid() {
			return "", fmt.Errorf("invalid environment variable")
		}
		if _, exists := seen[variable.Name()]; exists {
			return "", fmt.Errorf("duplicate environment variable")
		}
		seen[variable.Name()] = struct{}{}
		values[index] = variable.Name() + "=" + variable.Value()
	}
	sort.Strings(values)
	bytes, err := json.Marshal(struct {
		Domain string   `json:"domain"`
		Values []string `json:"values"`
	}{Domain: "Mulgae-CURRENT-PROBE-EFFECTIVE-ENVIRONMENT/1", Values: values})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// wholeAGYProofFrameEvidence reports whether one AGY proof carries frame
// evidence that is either wholly absent or wholly complete. A terminal JSON
// frame is optional metadata, not the result transport, so a frameless probe
// binds no frame claim at all; forgery resistance then rests on the fixture
// nonce evidence, the prompt-file transport receipt, the workspace guard, and
// the process-group-absent lifecycle receipt, every one of which stays
// mandatory. Partial frame evidence is never a real observation, so a proof
// that sets some frame-derived fields and zeroes others is always rejected.
func wholeAGYProofFrameEvidence(proof currentProbeDirectExecutionRoleProof) bool {
	if proof.LifecycleFrameSHA256 == "" && proof.LifecycleFrameLength == 0 && proof.LifecycleFraming == "" {
		return true
	}
	return proof.LifecycleFrameSHA256 != "" && proof.LifecycleFrameLength > 0 &&
		proof.LifecycleFraming == string(ports.ProcessOutputFramingTerminalJSONObject)
}

func currentProbeDirectExecutionAuthorityID(proofs []currentProbeDirectExecutionRoleProof, expiresAt time.Time) (string, error) {
	if expiresAt.IsZero() || len(proofs) == 0 {
		return "", fmt.Errorf("current probe direct-execution authority: missing expiry or proofs")
	}
	canonical := append([]currentProbeDirectExecutionRoleProof(nil), proofs...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Role < canonical[j].Role })
	for index, proof := range canonical {
		if !validFamily(proof.Family) || proof.ProviderInstance == "" || !semverOutput.MatchString(proof.ObservedVersion) ||
			!validCanonicalAbsolute(proof.Executable) || proof.ExecutableSHA256 == "" || !validCanonicalAbsolute(proof.Launcher) || proof.LauncherSHA256 == "" ||
			!domain.Role(proof.Role).Valid() || proof.NamespaceGeneration == "" || proof.SnapshotManifestSHA256 == "" ||
			proof.SnapshotName == "" || proof.SnapshotPath == "" || proof.SnapshotPolicyIdentity == "" || proof.ArgvSHA256 == "" ||
			proof.NativeReference == "" || !strings.HasPrefix(proof.NativeReference, "@") || !validRelativeNativeReference(strings.TrimPrefix(proof.NativeReference, "@")) ||
			proof.OutputSHA256 == "" || proof.EffectiveEnvironmentSHA256 == "" || proof.Termination == "" ||
			(index > 0 && proof.Role == canonical[index-1].Role) {
			return "", fmt.Errorf("current probe direct-execution authority: invalid or replayed role proof")
		}
		if proof.Family == FamilyAgy && (proof.AGYExecutionPolicy == "" || proof.NamespaceEnvironmentSHA256 == "" ||
			proof.NativeHomePath == "" || proof.NativeHomeDevice == 0 || proof.NativeHomeInode == 0 ||
			proof.TransportChannel != string(ports.ProviderPacketChannelPromptFile) ||
			proof.TransportPacketSHA256 == "" || proof.TransportPacketLength <= 0 || proof.TransportPreStartSHA256 == "" ||
			proof.TransportPreStartLength <= 0 || proof.TransportPostEndSHA256 == "" || proof.TransportPostEndLength <= 0 ||
			proof.TransportReference != proof.NativeReference ||
			proof.TransportSnapshotCWD != proof.SnapshotPath || !proof.LifecycleProcessGroupAbsent ||
			!wholeAGYProofFrameEvidence(proof)) {
			return "", fmt.Errorf("current probe direct-execution authority: incomplete AGY proof")
		}
		if proof.Family != FamilyAgy && proof.AGYExecutionPolicy != "" {
			return "", fmt.Errorf("current probe direct-execution authority: non-AGY policy")
		}
	}
	bytes, err := json.Marshal(currentProbeDirectExecutionAuthorityContract{
		Domain: "Mulgae-CURRENT-PROBE-DIRECT-EXECUTION-AUTHORITY/1", ExpiresUnixNano: expiresAt.UTC().UnixNano(), Proofs: canonical,
	})
	if err != nil {
		return "", fmt.Errorf("current probe direct-execution authority: encode")
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func agyExecutionPolicyBytes(policy AGYExecutionPolicy) ([]byte, error) {
	lifecycle, _ := policy.definition.PostOutputLifecycle()
	rootDevice, rootInode := policy.snapshot.RootIdentity()
	snapshotDevice, snapshotInode := policy.snapshot.SnapshotFSIdentity()
	return json.Marshal(agyExecutionPolicyContract{
		Argv: append([]string(nil), policy.argv...), MaxStderrBytes: boundedProbeOutput(policy.definition.MaxStderrBytes()), MaxStdoutBytes: boundedProbeOutput(policy.definition.MaxStdoutBytes()), NativeReference: policy.nativeReference,
		PostOutputFraming: string(lifecycle.Framing()), PostOutputStabilityNanosec: lifecycle.StabilityGrace().Nanoseconds(), PostOutputTerminationNanosec: lifecycle.TerminationGrace().Nanoseconds(),
		ProfileGeneration: policy.definition.ProfileGeneration(), ProfileID: policy.definition.ProfileID(), ProtectionGuarantee: "descriptor_bound_pre_post_drift_detection", ProviderInstance: policy.definition.Instance(), ProviderVersion: policy.definition.Version(),
		SnapshotManifestSHA256: policy.snapshot.ManifestSHA256(), SnapshotName: policy.snapshot.SnapshotName(), SnapshotPath: policy.snapshot.SnapshotPath(), SnapshotPolicyIdentity: policy.snapshot.PolicyIdentity(), SnapshotDevice: snapshotDevice, SnapshotInode: snapshotInode, RootDevice: rootDevice, RootInode: rootInode, TimeoutNanoseconds: boundedProbeTimeout(policy.definition.Timeout()).Nanoseconds(),
	})
}

func validAGYNativeReference(reference string) bool {
	if !validRelativeNativeReference(reference) {
		return false
	}
	for _, segment := range stringsSplitPath(reference) {
		if segment == ".git" || segment == ".mulgae" {
			return false
		}
	}
	return true
}

func stringsSplitPath(value string) []string { return strings.Split(value, "/") }

func runtimeSafetyPolicyWithIdentity(policy RuntimeSafetyPolicy) RuntimeSafetyPolicy {
	sum := sha256.Sum256(policy.bytes)
	policy.identity = "sha256:" + hex.EncodeToString(sum[:])
	return policy
}

func cloneRuntimeSafetyPolicy(policy RuntimeSafetyPolicy) RuntimeSafetyPolicy {
	policy.bytes = append([]byte(nil), policy.bytes...)
	return policy
}

func validRuntimeSafetyPolicy(policy RuntimeSafetyPolicy) bool {
	if policy.identity == "" || !validCredentialSourceFamily(policy.family) || len(policy.bytes) == 0 || policy.path != "" {
		return false
	}
	if policy.family == CredentialSourceAGY {
		var contract agySafetyContract
		if err := json.Unmarshal(policy.bytes, &contract); err != nil ||
			contract.AuthenticationContext != "installed_user_home" ||
			contract.PolicyScope != "namespace_auth_only" ||
			string(policy.bytes) != "{\"authentication_context\":\"installed_user_home\",\"policy_scope\":\"namespace_auth_only\"}\n" {
			return false
		}
	}
	return policy.identity == runtimeSafetyPolicyWithIdentity(policy).identity
}

func (policy RuntimeSafetyPolicy) Identity() string { return policy.identity }

func (lease *namespaceLease) RuntimeSafetyPolicyIdentity() string {
	lease.policyMu.RLock()
	defer lease.policyMu.RUnlock()
	return lease.policy.identity
}

func (lease *namespaceLease) installRuntimeSafetyPolicy(policy RuntimeSafetyPolicy) error {
	if lease == nil || !validRuntimeSafetyPolicy(policy) {
		return fmt.Errorf("runtime safety policy: invalid policy")
	}
	lease.policyMu.Lock()
	defer lease.policyMu.Unlock()
	if lease.policy.identity != "" {
		return fmt.Errorf("runtime safety policy: already installed")
	}
	if policy.path == "" {
		lease.policy = policy
		lease.policy.bytes = append([]byte(nil), policy.bytes...)
		return nil
	}
	parent, err := lease.validateCredentialDirectory(policy.path)
	if err != nil {
		return fmt.Errorf("runtime safety policy: namespace drift")
	}
	path := filepath.Join(parent, filepath.Base(policy.path))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("runtime safety policy: install")
	}
	if count, err := file.Write(policy.bytes); err != nil || count != len(policy.bytes) || file.Sync() != nil || file.Close() != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("runtime safety policy: install")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(len(policy.bytes)) {
		_ = os.Remove(path)
		return fmt.Errorf("runtime safety policy: install")
	}
	lease.policy = policy
	lease.policy.bytes = append([]byte(nil), policy.bytes...)
	lease.policyInfo = info
	return nil
}

func (lease *namespaceLease) validateRuntimeSafetyPolicy() error {
	lease.policyMu.RLock()
	defer lease.policyMu.RUnlock()
	policy := lease.policy
	if !validRuntimeSafetyPolicy(policy) {
		return fmt.Errorf("runtime safety policy drift")
	}
	if policy.path == "" {
		return nil
	}
	parent, err := lease.validateCredentialDirectory(policy.path)
	if err != nil {
		return fmt.Errorf("runtime safety policy drift")
	}
	path := filepath.Join(parent, filepath.Base(policy.path))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(len(policy.bytes)) || !os.SameFile(lease.policyInfo, info) {
		return fmt.Errorf("runtime safety policy drift")
	}
	bytes, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(bytes) != sha256.Sum256(policy.bytes) {
		return fmt.Errorf("runtime safety policy drift")
	}
	return nil
}

func (lease *namespaceLease) zeroAndUnlinkRuntimeSafetyPolicy() error {
	lease.policyMu.Lock()
	defer lease.policyMu.Unlock()
	if lease.policy.path == "" || lease.policyCleaned {
		return nil
	}
	parent, err := lease.validateCredentialDirectory(lease.policy.path)
	if err != nil {
		return fmt.Errorf("runtime safety policy cleanup failed")
	}
	path := filepath.Join(parent, filepath.Base(lease.policy.path))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(lease.policyInfo, info) {
		return fmt.Errorf("runtime safety policy cleanup failed")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("runtime safety policy cleanup failed")
	}
	zeros := make([]byte, len(lease.policy.bytes))
	_, writeErr := file.Write(zeros)
	zeroBytes(zeros)
	if writeErr != nil || file.Sync() != nil || file.Close() != nil || os.Remove(path) != nil {
		_ = file.Close()
		return fmt.Errorf("runtime safety policy cleanup failed")
	}
	lease.policyCleaned = true
	return nil
}
