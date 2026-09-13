package providercli

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func sha256Hex(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return fmt.Sprintf("%x", sum[:])
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
		"family":               func(proof *currentProbeDirectExecutionRoleProof) { proof.Family = FamilyGrok },
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
		Family: FamilyZcode, ProviderInstance: "zcode_current", ProviderVersion: "1.2.3", ObservedVersion: "1.2.3",
		Executable: "/private/bin/zcode", ExecutableSHA256: "sha256:executable", Launcher: "/private/bin/zcode", LauncherSHA256: "sha256:executable",
		ProfileID: "profile", ProfileGeneration: "generation", NamespaceGeneration: "namespace", Role: string(domain.RoleLogic),
		SnapshotManifestSHA256: "sha256:snapshot", SnapshotName: "snapshot", SnapshotPath: "/snapshot/path", SnapshotPolicyIdentity: "sha256:snapshot-policy",
		SnapshotDevice: 1, SnapshotInode: 2, RootDevice: 3, RootInode: 4, ArgvSHA256: "sha256:argv", NativeReference: "@roadmap.md",
		OutputSHA256: "sha256:output", EffectiveEnvironmentSHA256: "sha256:environment", Termination: string(ports.ProcessTerminationExited), HasExitCode: true, ExitCode: 0,
	}
}
