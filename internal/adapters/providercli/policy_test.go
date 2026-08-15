package providercli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestAGYSafetyContractIsDeterministicAndNotMaterialized(t *testing.T) {
	const want = "{\"authentication_context\":\"installed_user_home\",\"policy_scope\":\"namespace_auth_only\"}\n"
	policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceAGY)
	if err != nil {
		t.Fatal(err)
	}
	again, err := RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(CredentialSourceAGY, "/private/immutable-workspace")
	if err != nil || policy.Identity() != again.Identity() || string(policy.bytes) != string(again.bytes) {
		t.Fatalf("AGY contract was not deterministic: %#v, %v", again, err)
	}
	if policy.path != "" || string(policy.bytes) != want || policy.Identity() != "sha256:"+sha256Hex(policy.bytes) {
		t.Fatalf("AGY contract = %#v", policy)
	}
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "agy_primary")
	if err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	if err := concrete.installRuntimeSafetyPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(concrete.root, "home", ".gemini", "antigravity-cli", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("AGY safety contract materialized: %v", err)
	}
	if err := concrete.ValidateForSpawn(); err != nil {
		t.Fatal(err)
	}
	if _, err := concrete.DrainTerminal(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAGYSafetyContractRejectsNonCanonicalPolicies(t *testing.T) {
	policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceAGY)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutated := range []RuntimeSafetyPolicy{
		{family: CredentialSourceAGY, path: "settings.json", bytes: policy.bytes},
		{family: CredentialSourceAGY, bytes: []byte("{}\n")},
	} {
		mutated = runtimeSafetyPolicyWithIdentity(mutated)
		if validRuntimeSafetyPolicy(mutated) {
			t.Fatalf("non-canonical AGY contract accepted: %#v", mutated)
		}
	}
}

func TestRuntimeSafetyPolicyForFamilyAndWorkspaceRootRejectsInvalidRoots(t *testing.T) {
	for _, root := range []string{"/", "workspace", "/private/../workspace", "/private/workspace/"} {
		if _, err := RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(CredentialSourceAGY, root); err == nil {
			t.Fatalf("invalid workspace root %q accepted", root)
		}
	}
	if _, err := RuntimeSafetyPolicyForFamily(CredentialSourceAGY); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return fmt.Sprintf("%x", sum[:])
}
func TestDirectExecutionEnvironmentAuthorityFailsClosed(t *testing.T) {
	root := "/private/mulgae-owned-namespace"
	namespaceEnvironment := directExecutionNamespaceEnvironment(t, root, filepath.Join(root, "home"))
	namespace := currentProbeNamespace{environment: namespaceEnvironment}
	if err := validateDirectExecutionEnvironmentAuthority(FamilyKimi, namespace, namespaceEnvironment, namespaceEnvironment); err != nil {
		t.Fatalf("valid Kimi namespace rejected: %v", err)
	}
	if err := validateDirectExecutionEnvironmentAuthority(FamilyZcode, namespace, namespaceEnvironment, namespaceEnvironment); err != nil {
		t.Fatalf("valid ZCode namespace rejected: %v", err)
	}

	nativeHome := currentProbeNativeHome(t)
	agyEnvironment := directExecutionNamespaceEnvironment(t, root, nativeHome.Path())
	agyNamespace := currentProbeNamespace{environment: agyEnvironment, nativeHome: nativeHome}
	if err := validateDirectExecutionEnvironmentAuthority(FamilyAgy, agyNamespace, agyEnvironment, agyEnvironment); err != nil {
		t.Fatalf("valid AGY namespace rejected: %v", err)
	}

	pathEscape := append([]ports.EnvironmentVariable(nil), agyEnvironment...)
	pathEscape[1] = mustEnvironment(t, "XDG_CONFIG_HOME", root+"/../escape")
	if err := validateDirectExecutionEnvironmentAuthority(FamilyAgy, agyNamespace, pathEscape, pathEscape); err == nil {
		t.Fatal("path-escaping namespace environment accepted")
	}

	wrongRoot := directExecutionNamespaceEnvironment(t, "/private/not-mulgae-owned", nativeHome.Path())
	if err := validateDirectExecutionEnvironmentAuthority(FamilyAgy, agyNamespace, wrongRoot, wrongRoot); err == nil {
		t.Fatal("same-shape wrong-root namespace environment accepted")
	}

	homeMismatch := directExecutionNamespaceEnvironment(t, root, "/private/other-native-home")
	homeMismatchNamespace := currentProbeNamespace{environment: homeMismatch, nativeHome: nativeHome}
	if err := validateDirectExecutionEnvironmentAuthority(FamilyAgy, homeMismatchNamespace, homeMismatch, homeMismatch); err == nil {
		t.Fatal("AGY HOME mismatch accepted")
	}

	injectedAuthority := currentProbeNamespace{environment: namespaceEnvironment, nativeHome: nativeHome}
	if err := validateDirectExecutionEnvironmentAuthority(FamilyKimi, injectedAuthority, namespaceEnvironment, namespaceEnvironment); err == nil {
		t.Fatal("Kimi native-home authority injection accepted")
	}
	if err := validateDirectExecutionEnvironmentAuthority(FamilyZcode, injectedAuthority, namespaceEnvironment, namespaceEnvironment); err == nil {
		t.Fatal("ZCode native-home authority injection accepted")
	}
}

func TestCodexProcessEnvironmentPinsDisposableCodexHome(t *testing.T) {
	root := "/private/mulgae-owned-namespace"
	namespaceEnvironment := directExecutionNamespaceEnvironment(t, root, filepath.Join(root, "home"))
	configured := []ports.EnvironmentVariable{mustEnvironment(t, "CODEX_HOME", "/Users/operator/.codex")}
	environment, err := isolatedProcessEnvironment(FamilyCodex, configured, namespaceEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string, len(environment))
	for _, variable := range environment {
		values[variable.Name()] = variable.Value()
	}
	want := filepath.Join(root, "home", ".codex")
	if values["CODEX_HOME"] != want {
		t.Fatalf("CODEX_HOME = %q, want %q", values["CODEX_HOME"], want)
	}
}

func directExecutionNamespaceEnvironment(t *testing.T, root, home string) []ports.EnvironmentVariable {
	t.Helper()
	return []ports.EnvironmentVariable{
		mustEnvironment(t, "HOME", home),
		mustEnvironment(t, "XDG_CONFIG_HOME", filepath.Join(root, "settings")),
		mustEnvironment(t, "XDG_DATA_HOME", filepath.Join(root, "auth")),
		mustEnvironment(t, "XDG_CACHE_HOME", filepath.Join(root, "cache")),
		mustEnvironment(t, "TMPDIR", filepath.Join(root, "tmp")),
		mustEnvironment(t, "TMP", filepath.Join(root, "tmp")),
		mustEnvironment(t, "TEMP", filepath.Join(root, "tmp")),
		mustEnvironment(t, "MULGAE_PROVIDER_SCRATCH", filepath.Join(root, "scratch")),
	}
}

func TestCurrentProbeDirectExecutionAuthorityBindsDirectRoleProofs(t *testing.T) {
	expires := time.Unix(1_000, 0).UTC()
	proof := currentProbeDirectExecutionTestProof()
	receipt, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{proof}, expires)
	if err != nil || !receipt.Valid() || receipt.AuthorityID() == "" {
		t.Fatalf("typed authority = %#v, %v", receipt, err)
	}
	for name, mutate := range map[string]func(*currentProbeDirectExecutionRoleProof){
		"family":               func(proof *currentProbeDirectExecutionRoleProof) { proof.Family = FamilyZcode },
		"instance":             func(proof *currentProbeDirectExecutionRoleProof) { proof.ProviderInstance = "other" },
		"version":              func(proof *currentProbeDirectExecutionRoleProof) { proof.ObservedVersion = "2.0.0" },
		"executable":           func(proof *currentProbeDirectExecutionRoleProof) { proof.Executable = "/private/bin/other" },
		"executable SHA":       func(proof *currentProbeDirectExecutionRoleProof) { proof.ExecutableSHA256 = "sha256:other-executable" },
		"launcher":             func(proof *currentProbeDirectExecutionRoleProof) { proof.Launcher = "/private/bin/other-launcher" },
		"launcher SHA":         func(proof *currentProbeDirectExecutionRoleProof) { proof.LauncherSHA256 = "sha256:other-launcher" },
		"profile version":      func(proof *currentProbeDirectExecutionRoleProof) { proof.ProviderVersion = "2.0.0" },
		"profile":              func(proof *currentProbeDirectExecutionRoleProof) { proof.ProfileID = "other-profile" },
		"namespace generation": func(proof *currentProbeDirectExecutionRoleProof) { proof.NamespaceGeneration = "other-generation" },
		"snapshot":             func(proof *currentProbeDirectExecutionRoleProof) { proof.SnapshotPath = "/snapshot/other" },
		"argv":                 func(proof *currentProbeDirectExecutionRoleProof) { proof.ArgvSHA256 = "sha256:other" },
		"native reference":     func(proof *currentProbeDirectExecutionRoleProof) { proof.NativeReference = "@other.md" },
		"role outcome":         func(proof *currentProbeDirectExecutionRoleProof) { proof.OutputSHA256 = "sha256:other" },
		"effective environment": func(proof *currentProbeDirectExecutionRoleProof) {
			proof.EffectiveEnvironmentSHA256 = "sha256:other-environment"
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := proof
			mutate(&mutated)
			changed, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{mutated}, expires)
			if err != nil || changed.AuthorityID() == receipt.AuthorityID() {
				t.Fatalf("bound fact did not change authority: %#v, %v", changed, err)
			}
		})
	}
	forged := receipt
	forged.authorityID = "sha256:forged"
	if forged.Valid() {
		t.Fatal("forged authority ID accepted")
	}
	forgedProof := proof
	forgedProof.Family = "forged"
	if _, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{forgedProof}, expires); err == nil {
		t.Fatal("forged role proof accepted")
	}
	for _, mutate := range []func(*currentProbeDirectExecutionRoleProof){
		func(proof *currentProbeDirectExecutionRoleProof) { proof.Executable = "" },
		func(proof *currentProbeDirectExecutionRoleProof) { proof.ExecutableSHA256 = "" },
		func(proof *currentProbeDirectExecutionRoleProof) { proof.Launcher = "" },
		func(proof *currentProbeDirectExecutionRoleProof) { proof.LauncherSHA256 = "" },
	} {
		invalid := proof
		mutate(&invalid)
		if _, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{invalid}, expires); err == nil {
			t.Fatal("incomplete executable identity accepted")
		}
	}
	if _, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{proof, proof}, expires); err == nil {
		t.Fatal("replayed role proof accepted")
	}
	if _, err := newCurrentProbeDirectExecutionAuthorityReceipt(nil, expires); err == nil {
		t.Fatal("missing role proof accepted")
	}
}

func currentProbeDirectExecutionTestProof() currentProbeDirectExecutionRoleProof {
	return currentProbeDirectExecutionRoleProof{
		Family: FamilyKimi, ProviderInstance: "kimi_current", ProviderVersion: "1.2.3", ObservedVersion: "1.2.3",
		Executable: "/private/bin/kimi", ExecutableSHA256: "sha256:executable", Launcher: "/private/bin/kimi", LauncherSHA256: "sha256:executable",
		ProfileID: "profile", ProfileGeneration: "generation", NamespaceGeneration: "namespace", Role: string(domain.RoleLogic),
		SnapshotManifestSHA256: "sha256:snapshot", SnapshotName: "snapshot", SnapshotPath: "/snapshot/path", SnapshotPolicyIdentity: "sha256:snapshot-policy",
		SnapshotDevice: 1, SnapshotInode: 2, RootDevice: 3, RootInode: 4, ArgvSHA256: "sha256:argv", NativeReference: "@roadmap.md",
		OutputSHA256: "sha256:output", EffectiveEnvironmentSHA256: "sha256:environment", Termination: string(ports.ProcessTerminationExited), HasExitCode: true, ExitCode: 0,
	}
}
func TestCurrentProbeDirectExecutionAuthorityMatchesExactRuntimeAndRoles(t *testing.T) {
	definition := testProfile(t, FamilyKimi, "kimi_current", "1.2.3", "sha256:executable")
	definition.launcher = definition.Executable()
	definition.launcherSHA256 = definition.ExecutableSHA256()
	definition.profileID = "profile"
	definition.profileGeneration = "generation"

	proof := currentProbeDirectExecutionTestProof()
	receipt, err := newCurrentProbeDirectExecutionAuthorityReceiptForDefinition([]currentProbeDirectExecutionRoleProof{proof}, time.Unix(1_000, 0).UTC(), definition)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Matches(definition, "1.2.3", "namespace", []domain.Role{domain.RoleLogic}) {
		t.Fatal("direct execution authority did not match its runtime")
	}
	if receipt.Matches(definition, "1.2.3", "namespace", []domain.Role{domain.RoleLogic, domain.RoleLogic}) {
		t.Fatal("direct execution authority accepted duplicate roles")
	}
	if receipt.Matches(definition, "1.2.3", "namespace", []domain.Role{domain.RoleSecurity}) {
		t.Fatal("direct execution authority accepted a role set it did not prove")
	}

	replayedDefinition := definition
	replayedDefinition.executable = "/private/bin/kimi-other"
	replayedDefinition.baseArgv = []string{replayedDefinition.executable}
	if receipt.Matches(replayedDefinition, "1.2.3", "namespace", []domain.Role{domain.RoleLogic}) {
		t.Fatal("direct execution authority replayed across executable paths")
	}
	replayedDefinition = definition
	replayedDefinition.executableSHA256 = "sha256:other-executable"
	if receipt.Matches(replayedDefinition, "1.2.3", "namespace", []domain.Role{domain.RoleLogic}) {
		t.Fatal("direct execution authority replayed across executable hashes")
	}
	replayedDefinition = definition
	replayedDefinition.launcher = "/private/bin/kimi-launcher"
	if receipt.Matches(replayedDefinition, "1.2.3", "namespace", []domain.Role{domain.RoleLogic}) {
		t.Fatal("direct execution authority replayed across launcher paths")
	}
	replayedDefinition = definition
	replayedDefinition.launcherSHA256 = "sha256:other-launcher"
	if receipt.Matches(replayedDefinition, "1.2.3", "namespace", []domain.Role{domain.RoleLogic}) {
		t.Fatal("direct execution authority replayed across launcher hashes")
	}

	tampered := receipt
	tampered.proofs = append([]currentProbeDirectExecutionRoleProof(nil), receipt.proofs...)
	tampered.proofs[0].ExecutableSHA256 = "sha256:tampered"
	if tampered.Matches(definition, "1.2.3", "namespace", []domain.Role{domain.RoleLogic}) {
		t.Fatal("tampered direct execution authority matched")
	}
}

// currentProbeAGYDirectExecutionTestProof returns one complete AGY role proof
// whose frame-derived fields describe a present terminal JSON frame.
func currentProbeAGYDirectExecutionTestProof() currentProbeDirectExecutionRoleProof {
	proof := currentProbeDirectExecutionTestProof()
	proof.Family = FamilyAgy
	proof.AGYExecutionPolicy = "sha256:execution"
	proof.TransportChannel = string(ports.ProviderPacketChannelPromptFile)
	proof.TransportPacketSHA256 = "sha256:packet"
	proof.TransportPacketLength = 1
	proof.TransportPreStartSHA256 = "sha256:pre"
	proof.TransportPreStartLength = 1
	proof.TransportPostEndSHA256 = "sha256:post"
	proof.TransportPostEndLength = 1
	proof.TransportReference = proof.NativeReference
	proof.TransportSnapshotCWD = proof.SnapshotPath
	proof.LifecycleFrameSHA256 = "sha256:frame"
	proof.LifecycleFrameLength = 1
	proof.LifecycleFraming = string(ports.ProcessOutputFramingTerminalJSONObject)
	proof.LifecycleProcessGroupAbsent = true
	proof.NamespaceEnvironmentSHA256 = "sha256:namespace-environment"
	proof.NativeHomePath = "/private/home"
	proof.NativeHomeDevice = 1
	proof.NativeHomeInode = 1
	proof.NativeHomeEffectiveUID = 1
	return proof
}

// A terminal JSON frame is optional metadata, so an AGY proof that binds no
// frame at all still mints direct-execution authority once every non-frame
// control holds.
func TestAGYDirectExecutionProofAcceptsFramelessLifecycle(t *testing.T) {
	expires := time.Unix(1_000, 0).UTC()
	framed := currentProbeAGYDirectExecutionTestProof()
	frameless := framed
	frameless.LifecycleFrameSHA256 = ""
	frameless.LifecycleFrameLength = 0
	frameless.LifecycleFraming = ""
	receipt, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{frameless}, expires)
	if err != nil {
		t.Fatalf("frameless AGY proof rejected: %v", err)
	}
	if !receipt.Valid() || receipt.AuthorityID() == "" {
		t.Fatalf("frameless AGY authority invalid: %#v", receipt)
	}
	controlID, ok := receipt.AGYControlAuthorityID()
	if !ok || controlID == "" {
		t.Fatal("frameless AGY authority omitted control authority")
	}
	framedReceipt, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{framed}, expires)
	if err != nil {
		t.Fatal(err)
	}
	// The frame is still bound evidence when it is present, so the two
	// observations must never share one authority identity.
	if receipt.AuthorityID() == framedReceipt.AuthorityID() {
		t.Fatal("frameless and framed AGY proofs shared a direct-execution authority ID")
	}
	// Every non-frame AGY control stays mandatory.
	for _, test := range []struct {
		name   string
		mutate func(*currentProbeDirectExecutionRoleProof)
	}{
		{name: "execution policy", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.AGYExecutionPolicy = "" }},
		{name: "namespace environment", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.NamespaceEnvironmentSHA256 = "" }},
		{name: "native home path", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.NativeHomePath = "" }},
		{name: "native home device", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.NativeHomeDevice = 0 }},
		{name: "native home inode", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.NativeHomeInode = 0 }},
		{name: "transport channel", mutate: func(p *currentProbeDirectExecutionRoleProof) {
			p.TransportChannel = string(ports.ProviderPacketChannelArgvLiteral)
		}},
		{name: "transport packet sha", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.TransportPacketSHA256 = "" }},
		{name: "transport packet length", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.TransportPacketLength = 0 }},
		{name: "transport pre-start sha", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.TransportPreStartSHA256 = "" }},
		{name: "transport pre-start length", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.TransportPreStartLength = 0 }},
		{name: "transport post-end sha", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.TransportPostEndSHA256 = "" }},
		{name: "transport post-end length", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.TransportPostEndLength = 0 }},
		{name: "transport reference", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.TransportReference = "@other.md" }},
		{name: "transport snapshot cwd", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.TransportSnapshotCWD = "/other/path" }},
		{name: "process group absent", mutate: func(p *currentProbeDirectExecutionRoleProof) { p.LifecycleProcessGroupAbsent = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := frameless
			test.mutate(&mutated)
			if _, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{mutated}, expires); err == nil {
				t.Fatal("frameless AGY proof accepted a missing non-frame control")
			}
		})
	}
}

// Frame evidence is all-or-nothing: a proof that sets some frame-derived fields
// and zeroes others never described a real observation.
func TestAGYDirectExecutionProofRejectsPartialFrameEvidence(t *testing.T) {
	expires := time.Unix(1_000, 0).UTC()
	for _, test := range []struct {
		name    string
		sha256  string
		length  int64
		framing string
	}{
		{name: "sha without length", sha256: "sha256:frame", framing: string(ports.ProcessOutputFramingTerminalJSONObject)},
		{name: "length without sha", length: 1, framing: string(ports.ProcessOutputFramingTerminalJSONObject)},
		{name: "sha and length without framing", sha256: "sha256:frame", length: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := currentProbeAGYDirectExecutionTestProof()
			proof.LifecycleFrameSHA256 = test.sha256
			proof.LifecycleFrameLength = test.length
			proof.LifecycleFraming = test.framing
			_, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{proof}, expires)
			if err == nil || !strings.Contains(err.Error(), "incomplete AGY proof") {
				t.Fatalf("partial frame evidence accepted: err=%v", err)
			}
		})
	}
}

func TestAGYControlAuthorityExcludesOutputAndRequiresAGYControls(t *testing.T) {
	expires := time.Unix(1_000, 0).UTC()
	proof := currentProbeDirectExecutionTestProof()
	proof.Family = FamilyAgy
	proof.AGYExecutionPolicy = "sha256:execution"
	proof.TransportChannel = string(ports.ProviderPacketChannelPromptFile)
	proof.TransportPacketSHA256 = "sha256:packet"
	proof.TransportPacketLength = 1
	proof.TransportPreStartSHA256 = "sha256:pre"
	proof.TransportPreStartLength = 1
	proof.TransportPostEndSHA256 = "sha256:post"
	proof.TransportPostEndLength = 1
	proof.TransportReference = proof.NativeReference
	proof.TransportSnapshotCWD = proof.SnapshotPath
	proof.LifecycleFrameSHA256 = "sha256:frame"
	proof.LifecycleFrameLength = 1
	proof.LifecycleFraming = string(ports.ProcessOutputFramingTerminalJSONObject)
	proof.LifecycleProcessGroupAbsent = true
	proof.NamespaceEnvironmentSHA256 = "sha256:namespace-environment"
	proof.NativeHomePath = "/private/home"
	proof.NativeHomeDevice = 1
	proof.NativeHomeInode = 1
	proof.NativeHomeEffectiveUID = 1
	receipt, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{proof}, expires)
	if err != nil {
		t.Fatal(err)
	}
	controlID, ok := receipt.AGYControlAuthorityID()
	if !ok || controlID == "" {
		t.Fatal("missing AGY control authority")
	}
	changedOutput := proof
	changedOutput.OutputSHA256 = "sha256:other-output"
	outputReceipt, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{changedOutput}, expires)
	if err != nil {
		t.Fatal(err)
	}
	if outputID, ok := outputReceipt.AGYControlAuthorityID(); !ok || outputID != controlID {
		t.Fatalf("output changed AGY control authority: %q, %t", outputID, ok)
	}
	changedControls := proof
	changedControls.AGYExecutionPolicy = "sha256:other-execution-controls"
	lifecycleReceipt, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{changedControls}, expires)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycleID, ok := lifecycleReceipt.AGYControlAuthorityID(); !ok || lifecycleID == controlID {
		t.Fatalf("lifecycle did not change AGY control authority: %q, %t", lifecycleID, ok)
	}
	kimi, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{currentProbeDirectExecutionTestProof()}, expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kimi.AGYControlAuthorityID(); ok {
		t.Fatal("non-AGY direct authority exposed AGY control authority")
	}
}
