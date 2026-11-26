package providercli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// RuntimeSafetyPolicy records retained namespace configuration provenance.
type RuntimeSafetyPolicy struct {
	family   CredentialSourceFamily
	identity string
	bytes    []byte
}

var runtimeSafetyPolicies = func() map[CredentialSourceFamily]RuntimeSafetyPolicy {
	values := map[CredentialSourceFamily]RuntimeSafetyPolicy{
		CredentialSourceZCode: {family: CredentialSourceZCode, bytes: []byte("{\"family\":\"zcode\",\"transport\":\"isolated-zcode-terminal-v1\",\"pane_mode\":\"PaneTTY\",\"interaction_policy\":\"block\",\"profile_scope\":\"managed_namespace\"}\n")},
		CredentialSourceGrok:  {family: CredentialSourceGrok, bytes: []byte("{\"family\":\"grok\",\"transport\":\"herdr-core-terminal-v1\",\"policy_scope\":\"isolated_namespace\",\"home_mode\":\"disposable_home_and_grok_home\",\"requirements_toml\":\"minimal-disposable-v1\",\"tty_mode\":\"pane-tty-only\",\"output_delivery\":\"post-esrch-staged-file-v1\",\"bash_gate\":\"index-commit-b1-v1\"}\n")},
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
	return RuntimeSafetyPolicyForFamily(family)
}

// RuntimeSafetyPolicyForGrokTerminal binds the verified isolated herdr-core
// binary path, SHA-256 digest, and hello version into Grok's immutable runtime
// safety policy identity once the isolated terminal runtime is active.
func RuntimeSafetyPolicyForGrokTerminal(identity ports.TerminalRuntimeIdentity) (RuntimeSafetyPolicy, error) {
	if !identity.Valid() {
		return RuntimeSafetyPolicy{}, fmt.Errorf("runtime safety policy: invalid terminal runtime identity")
	}
	payload, err := json.Marshal(struct {
		Family                          string `json:"family"`
		Transport                       string `json:"transport"`
		PolicyScope                     string `json:"policy_scope"`
		HomeMode                        string `json:"home_mode"`
		RequirementsTOML                string `json:"requirements_toml"`
		TTYMode                         string `json:"tty_mode"`
		OutputDelivery                  string `json:"output_delivery"`
		BashGate                        string `json:"bash_gate"`
		TerminalRuntimeExecutable       string `json:"terminal_runtime_executable"`
		TerminalRuntimeExecutableSHA256 string `json:"terminal_runtime_executable_sha256"`
		TerminalRuntimeVersion          string `json:"terminal_runtime_version"`
	}{
		Family:                          FamilyGrok,
		Transport:                       "herdr-core-terminal-v1",
		PolicyScope:                     "isolated_namespace",
		HomeMode:                        "disposable_home_and_grok_home",
		RequirementsTOML:                "minimal-disposable-v1",
		TTYMode:                         "pane-tty-only",
		OutputDelivery:                  "post-esrch-staged-file-v1",
		BashGate:                        "index-commit-b1-v1",
		TerminalRuntimeExecutable:       identity.Executable(),
		TerminalRuntimeExecutableSHA256: identity.ExecutableSHA256(),
		TerminalRuntimeVersion:          identity.Version(),
	})
	if err != nil {
		return RuntimeSafetyPolicy{}, fmt.Errorf("runtime safety policy: encode grok terminal policy: %w", err)
	}
	payload = append(payload, '\n')
	return runtimeSafetyPolicyWithIdentity(RuntimeSafetyPolicy{
		family: CredentialSourceGrok,
		bytes:  payload,
	}), nil
}

type currentProbeDirectExecutionRoleProof struct {
	TerminalRuntimeExecutable       string                    `json:"terminal_runtime_executable,omitempty"`
	TerminalRuntimeExecutableSHA256 string                    `json:"terminal_runtime_executable_sha256,omitempty"`
	TerminalRuntimeVersion          string                    `json:"terminal_runtime_version,omitempty"`
	TerminalRuntimePolicyIdentity   string                    `json:"terminal_runtime_policy_identity,omitempty"`
	TerminalRuntimeGeneration       int                       `json:"terminal_runtime_generation,omitempty"`
	ZCodePreparation                *ZCodeTerminalObservation `json:"zcode_preparation,omitempty"`
	Family                          string                    `json:"family"`
	ProviderInstance                string                    `json:"provider_instance"`
	ProviderVersion                 string                    `json:"provider_version"`
	ObservedVersion                 string                    `json:"observed_version"`
	Executable                      string                    `json:"executable"`
	ExecutableSHA256                string                    `json:"executable_sha256"`
	Launcher                        string                    `json:"launcher"`
	LauncherSHA256                  string                    `json:"launcher_sha256"`
	ApplicationVersion              string                    `json:"application_version,omitempty"`
	ApplicationMetadata             string                    `json:"application_metadata,omitempty"`
	ApplicationMetadataSHA256       string                    `json:"application_metadata_sha256,omitempty"`
	ZCodeProviderConfig             string                    `json:"zcode_provider_config,omitempty"`
	ZCodeProviderConfigSHA256       string                    `json:"zcode_provider_config_sha256,omitempty"`
	ProfileID                       string                    `json:"profile_id"`
	ProfileGeneration               string                    `json:"profile_generation"`
	NamespaceGeneration             string                    `json:"namespace_generation"`
	Role                            string                    `json:"role"`
	SnapshotManifestSHA256          string                    `json:"snapshot_manifest_sha256"`
	SnapshotName                    string                    `json:"snapshot_name"`
	SnapshotPath                    string                    `json:"snapshot_path"`
	SnapshotPolicyIdentity          string                    `json:"snapshot_policy_identity"`
	SnapshotDevice                  uint64                    `json:"snapshot_device"`
	SnapshotInode                   uint64                    `json:"snapshot_inode"`
	RootDevice                      uint64                    `json:"root_device"`
	RootInode                       uint64                    `json:"root_inode"`
	ArgvSHA256                      string                    `json:"argv_sha256"`
	NativeReference                 string                    `json:"native_reference"`
	OutputSHA256                    string                    `json:"output_sha256"`
	Termination                     string                    `json:"termination"`
	HasExitCode                     bool                      `json:"has_exit_code"`
	ExitCode                        int                       `json:"exit_code"`
	HasSignal                       bool                      `json:"has_signal"`
	SignalNumber                    int                       `json:"signal_number"`
	SignalName                      string                    `json:"signal_name"`
	TransportChannel                string                    `json:"transport_channel"`
	TransportPacketSHA256           string                    `json:"transport_packet_sha256"`
	TransportPacketLength           int                       `json:"transport_packet_length"`
	TransportPreStartSHA256         string                    `json:"transport_pre_start_sha256"`
	TransportPreStartLength         int                       `json:"transport_pre_start_length"`
	TransportPostEndSHA256          string                    `json:"transport_post_end_sha256"`
	TransportPostEndLength          int                       `json:"transport_post_end_length"`
	TransportReference              string                    `json:"transport_reference"`
	TransportSnapshotCWD            string                    `json:"transport_snapshot_cwd"`
	EffectiveEnvironmentSHA256      string                    `json:"effective_environment_sha256"`
}

type currentProbeDirectExecutionAuthorityContract struct {
	Domain          string                                 `json:"domain"`
	ExpiresUnixNano int64                                  `json:"expires_unix_nano"`
	Proofs          []currentProbeDirectExecutionRoleProof `json:"proofs"`
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
		paths["MULGAE_PROVIDER_SCRATCH"] != filepath.Join(root, "scratch") {
		return nil, fmt.Errorf("namespace environment escapes Mulgae-owned root")
	}
	// ZCode's Desktop bridge uses a short, generation-owned socket path.
	// Other providers keep temp state inside their namespace.
	namespaceTemp := filepath.Join(root, "tmp")
	name := filepath.Base(root)
	generation := name[strings.LastIndexByte(name, '-')+1:]
	if paths["TMPDIR"] != namespaceTemp && paths["TMPDIR"] != zcodeRuntimeTempPath(generation) {
		return nil, fmt.Errorf("namespace environment escapes Mulgae-owned root")
	}
	if paths["TMP"] != paths["TMPDIR"] || paths["TEMP"] != paths["TMPDIR"] {
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
	_, hasAuthority := namespace.NativeHomeLaunchAuthority()
	if hasAuthority {
		return fmt.Errorf("native home authority is unsupported")
	}
	root := filepath.Dir(home)
	if root == string(filepath.Separator) || home != filepath.Join(root, "home") {
		return fmt.Errorf("HOME escapes Mulgae-owned root")
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

func newCurrentProbeDirectExecutionRoleProof(definition RuntimeDefinition, observedVersion, namespaceGeneration string, namespace QualificationNamespace, namespaceEnvironment, environment []ports.EnvironmentVariable, fixture ProbeFixtureLease, argv []string, observation ports.ProcessObservation) (currentProbeDirectExecutionRoleProof, error) {
	return newCurrentProbeDirectExecutionRoleProofWithEvidence(definition, observedVersion, namespaceGeneration, namespace, namespaceEnvironment, environment, fixture, argv, observation, nil, ports.TerminalRuntimeIdentity{})
}

func newCurrentProbeDirectExecutionRoleProofWithEvidence(definition RuntimeDefinition, observedVersion, namespaceGeneration string, namespace QualificationNamespace, namespaceEnvironment, environment []ports.EnvironmentVariable, fixture ProbeFixtureLease, argv []string, observation ports.ProcessObservation, stagedOutput []byte, terminalIdentity ports.TerminalRuntimeIdentity) (currentProbeDirectExecutionRoleProof, error) {
	if safeProbeDefinition(definition) != nil || namespace == nil || fixture == nil || validateProbeFixtureLease(fixture) != nil ||
		namespaceGeneration == "" || !acceptedObservedVersion(observedVersion) || !fixture.Role().Valid() || !observation.Valid() ||
		// Protocol conversations and managed terminal sessions succeed through
		// their drivers; the shared process-level completion predicates replace
		// the one-shot Succeeded() frame contract for them.
		(!observation.Succeeded() && !observation.ProtocolConversationCompleted() && !observation.TerminalSessionCompleted()) ||
		!validRelativeNativeReference(fixture.Reference()) {
		return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: invalid direct execution")
	}
	var terminalExec, terminalSHA, terminalVersion, terminalPolicyID string
	var zcodePreparation *ZCodeTerminalObservation
	isTerminalChannel := definition.Transport().Channel() == ports.ProviderPacketChannelTerminal
	if definition.Family() == FamilyGrok || isTerminalChannel {
		if !observation.TerminalSessionCompleted() || !terminalIdentity.Valid() || len(stagedOutput) == 0 {
			return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: missing terminal runtime identity or staged output")
		}
		var terminalPolicy RuntimeSafetyPolicy
		var policyErr error
		if definition.Family() == FamilyZcode {
			retained, ok := namespace.(interface{ concreteNamespace() *namespaceLease })
			if !ok || retained.concreteNamespace() == nil {
				return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: missing ZCode namespace")
			}
			lease := retained.concreteNamespace()
			lease.policyMu.RLock()
			prepared, runtime := lease.zcodePrepared, lease.zcodeTerminal
			lease.policyMu.RUnlock()
			if runtime != terminalIdentity {
				return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: ZCode runtime drift")
			}
			profile, err := zcodeProfileForDefinition(definition)
			if err != nil {
				return currentProbeDirectExecutionRoleProof{}, err
			}
			terminalPolicy, policyErr = RuntimeSafetyPolicyForZCodeTerminal(runtime, profile.pkg, profile.appBundle, prepared, definition.ZCodeModel(), definition.ZCodeReasoningEffort())
			zcodePreparation = &prepared
		} else {
			terminalPolicy, policyErr = RuntimeSafetyPolicyForGrokTerminal(terminalIdentity)
		}
		if policyErr != nil {
			return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: %w", policyErr)
		}
		terminalExec = terminalIdentity.Executable()
		terminalSHA = terminalIdentity.ExecutableSHA256()
		terminalVersion = terminalIdentity.Version()
		terminalPolicyID = terminalPolicy.Identity()
	} else if terminalIdentity.Valid() {
		return currentProbeDirectExecutionRoleProof{}, fmt.Errorf("current probe direct execution proof: unexpected terminal runtime identity")
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
		TerminalRuntimeExecutable:       terminalExec,
		TerminalRuntimeExecutableSHA256: terminalSHA,
		TerminalRuntimeVersion:          terminalVersion,
		TerminalRuntimePolicyIdentity:   terminalPolicyID,
		TerminalRuntimeGeneration:       terminalIdentity.Generation(),
		ZCodePreparation:                zcodePreparation,
		Family:                          definition.Family(), ProviderInstance: definition.Instance(), ProviderVersion: definition.Version(), ObservedVersion: observedVersion,
		Executable: definition.Executable(), ExecutableSHA256: definition.ExecutableSHA256(), Launcher: definition.Launcher(), LauncherSHA256: definition.LauncherSHA256(),
		ApplicationVersion: definition.ApplicationVersion(), ApplicationMetadata: definition.ApplicationMetadata(), ApplicationMetadataSHA256: definition.ApplicationMetadataSHA256(),
		ZCodeProviderConfig: definition.ZCodeProviderConfig(), ZCodeProviderConfigSHA256: definition.ZCodeProviderConfigSHA256(),
		ProfileID: definition.ProfileID(), ProfileGeneration: definition.ProfileGeneration(), NamespaceGeneration: namespaceGeneration, Role: string(fixture.Role()),
		SnapshotManifestSHA256: snapshot.ManifestSHA256(), SnapshotName: snapshot.SnapshotName(), SnapshotPath: snapshot.SnapshotPath(), SnapshotPolicyIdentity: snapshot.PolicyIdentity(),
		SnapshotDevice: snapshotDevice, SnapshotInode: snapshotInode, RootDevice: rootDevice, RootInode: rootInode,
		ArgvSHA256: "sha256:" + hex.EncodeToString(argvSum[:]), NativeReference: "@" + fixture.Reference(),
		Termination: string(observation.Termination()),
	}
	outputBytes := observation.Stdout()
	if definition.Family() == FamilyGrok || isTerminalChannel {
		// Terminal qualification proofs bind OutputSHA256 strictly to accepted
		// staged probe.json bytes, never post-kill screen capture text.
		outputBytes = stagedOutput
	}
	outputSum := sha256.Sum256(outputBytes)
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

func currentProbeDirectExecutionAuthorityID(proofs []currentProbeDirectExecutionRoleProof, expiresAt time.Time) (string, error) {
	if expiresAt.IsZero() || len(proofs) == 0 {
		return "", fmt.Errorf("current probe direct-execution authority: missing expiry or proofs")
	}
	canonical := append([]currentProbeDirectExecutionRoleProof(nil), proofs...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Role < canonical[j].Role })
	for index, proof := range canonical {
		if !validFamily(proof.Family) || proof.ProviderInstance == "" || !acceptedObservedVersion(proof.ObservedVersion) ||
			!validCanonicalAbsolute(proof.Executable) || proof.ExecutableSHA256 == "" || !validCanonicalAbsolute(proof.Launcher) || proof.LauncherSHA256 == "" ||
			!domain.Role(proof.Role).Valid() || proof.NamespaceGeneration == "" || proof.SnapshotManifestSHA256 == "" ||
			proof.SnapshotName == "" || proof.SnapshotPath == "" || proof.SnapshotPolicyIdentity == "" || proof.ArgvSHA256 == "" ||
			proof.OutputSHA256 == "" || proof.EffectiveEnvironmentSHA256 == "" || proof.Termination == "" ||
			(index > 0 && proof.Role == canonical[index-1].Role) {
			return "", fmt.Errorf("current probe direct-execution authority: invalid or replayed role proof")
		}
		if proof.Family == FamilyZcode {
			if proof.ZCodePreparation == nil || !proof.ZCodePreparation.valid() || proof.ApplicationVersion != proof.ZCodePreparation.AppVersion {
				return "", fmt.Errorf("current probe direct-execution authority: invalid ZCode preparation proof")
			}
		} else if proof.ZCodePreparation != nil || proof.ApplicationVersion != "" {
			return "", fmt.Errorf("current probe direct-execution authority: unexpected ZCode preparation proof")
		}
		if !validCanonicalAbsolute(proof.TerminalRuntimeExecutable) || !validSHA256Identity(proof.TerminalRuntimeExecutableSHA256) ||
			proof.TerminalRuntimeVersion == "" || proof.TerminalRuntimeGeneration < 1 || !validSHA256Identity(proof.TerminalRuntimePolicyIdentity) {
			return "", fmt.Errorf("current probe direct-execution authority: invalid terminal runtime proof")
		}
		if proof.NativeReference == "" || !strings.HasPrefix(proof.NativeReference, "@") ||
			!validRelativeNativeReference(strings.TrimPrefix(proof.NativeReference, "@")) {
			return "", fmt.Errorf("current probe direct-execution authority: invalid native reference")
		}
	}
	bytes, err := json.Marshal(currentProbeDirectExecutionAuthorityContract{
		Domain: "Mulgae-CURRENT-PROBE-DIRECT-EXECUTION-AUTHORITY/3", ExpiresUnixNano: expiresAt.UTC().UnixNano(), Proofs: canonical,
	})
	if err != nil {
		return "", fmt.Errorf("current probe direct-execution authority: encode")
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

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
	if policy.identity == "" || !validCredentialSourceFamily(policy.family) || len(policy.bytes) == 0 {
		return false
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
	lease.policy = policy
	lease.policy.bytes = append([]byte(nil), policy.bytes...)
	return nil
}

func (lease *namespaceLease) validateRuntimeSafetyPolicy() error {
	lease.policyMu.RLock()
	defer lease.policyMu.RUnlock()
	policy := lease.policy
	if !validRuntimeSafetyPolicy(policy) {
		return fmt.Errorf("runtime safety policy drift")
	}
	return nil
}
