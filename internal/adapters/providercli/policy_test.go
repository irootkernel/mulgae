package providercli

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func sha256Hex(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return fmt.Sprintf("%x", sum[:])
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
		"family": func(proof *currentProbeDirectExecutionRoleProof) {
			proof.Family = FamilyGrok
			proof.ZCodePreparation = nil
			proof.ZCodeProviderConfig = ""
			proof.ZCodeProviderConfigSHA256 = ""
			proof.ApplicationVersion = ""
			proof.ApplicationMetadata = ""
			proof.ApplicationMetadataSHA256 = ""
			proof.TerminalRuntimeExecutable = "/private/bin/herdr-core"
			proof.TerminalRuntimeExecutableSHA256 = "sha256:" + strings.Repeat("d", 64)
			proof.TerminalRuntimeVersion = "0.1.0"
			proof.TerminalRuntimePolicyIdentity = "sha256:" + strings.Repeat("e", 64)
		},
		"instance":       func(proof *currentProbeDirectExecutionRoleProof) { proof.ProviderInstance = "other" },
		"version":        func(proof *currentProbeDirectExecutionRoleProof) { proof.ObservedVersion = "2.0.0" },
		"executable":     func(proof *currentProbeDirectExecutionRoleProof) { proof.Executable = "/private/bin/other" },
		"executable SHA": func(proof *currentProbeDirectExecutionRoleProof) { proof.ExecutableSHA256 = "sha256:other-executable" },
		"launcher":       func(proof *currentProbeDirectExecutionRoleProof) { proof.Launcher = "/private/bin/other-launcher" },
		"launcher SHA":   func(proof *currentProbeDirectExecutionRoleProof) { proof.LauncherSHA256 = "sha256:other-launcher" },
		"provider config": func(proof *currentProbeDirectExecutionRoleProof) {
			proof.ZCodeProviderConfig = "/private/config/other.json"
		},
		"provider config SHA": func(proof *currentProbeDirectExecutionRoleProof) {
			proof.ZCodeProviderConfigSHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		"application version": func(proof *currentProbeDirectExecutionRoleProof) {
			prepared := *proof.ZCodePreparation
			prepared.AppVersion, proof.ApplicationVersion = "4.1.0", "4.1.0"
			proof.ZCodePreparation = &prepared
		},
		"application metadata": func(proof *currentProbeDirectExecutionRoleProof) {
			proof.ApplicationMetadata = "/Applications/Other.app/Contents/Info.plist"
		},
		"application metadata SHA": func(proof *currentProbeDirectExecutionRoleProof) {
			proof.ApplicationMetadataSHA256 = "sha256:" + strings.Repeat("c", 64)
		},
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

	// Verify every Grok terminal runtime identity field is bound and required.
	grokProof := proof
	grokProof.Family = FamilyGrok
	grokProof.ZCodePreparation = nil
	grokProof.ProviderInstance = "grok_current"
	grokProof.Executable = "/private/bin/grok"
	grokProof.Launcher = "/private/bin/grok"
	grokProof.ZCodeProviderConfig = ""
	grokProof.ZCodeProviderConfigSHA256 = ""
	grokProof.ApplicationVersion = ""
	grokProof.ApplicationMetadata = ""
	grokProof.ApplicationMetadataSHA256 = ""
	grokProof.TerminalRuntimeExecutable = "/private/bin/herdr-core"
	grokProof.TerminalRuntimeExecutableSHA256 = "sha256:" + strings.Repeat("d", 64)
	grokProof.TerminalRuntimeVersion = "0.1.0"
	grokProof.TerminalRuntimePolicyIdentity = "sha256:" + strings.Repeat("e", 64)
	grokReceipt, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{grokProof}, expires)
	if err != nil || !grokReceipt.Valid() {
		t.Fatalf("grok terminal receipt = %#v, %v", grokReceipt, err)
	}
	for name, mutate := range map[string]func(*currentProbeDirectExecutionRoleProof){
		"grok terminal executable": func(p *currentProbeDirectExecutionRoleProof) { p.TerminalRuntimeExecutable = "/private/bin/hc-other" },
		"grok terminal sha256": func(p *currentProbeDirectExecutionRoleProof) {
			p.TerminalRuntimeExecutableSHA256 = "sha256:" + strings.Repeat("f", 64)
		},
		"grok terminal version": func(p *currentProbeDirectExecutionRoleProof) { p.TerminalRuntimeVersion = "0.2.0" },
		"grok terminal policy": func(p *currentProbeDirectExecutionRoleProof) {
			p.TerminalRuntimePolicyIdentity = "sha256:" + strings.Repeat("9", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := grokProof
			mutate(&mutated)
			changed, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{mutated}, expires)
			if err != nil || changed.AuthorityID() == grokReceipt.AuthorityID() {
				t.Fatalf("bound grok terminal fact %q did not change authority: %#v, %v", name, changed, err)
			}
		})
	}
	for _, clearField := range []func(*currentProbeDirectExecutionRoleProof){
		func(p *currentProbeDirectExecutionRoleProof) { p.TerminalRuntimeExecutable = "" },
		func(p *currentProbeDirectExecutionRoleProof) { p.TerminalRuntimeExecutableSHA256 = "" },
		func(p *currentProbeDirectExecutionRoleProof) { p.TerminalRuntimeVersion = "" },
		func(p *currentProbeDirectExecutionRoleProof) { p.TerminalRuntimePolicyIdentity = "" },
	} {
		invalid := grokProof
		clearField(&invalid)
		if _, err := newCurrentProbeDirectExecutionAuthorityReceipt([]currentProbeDirectExecutionRoleProof{invalid}, expires); err == nil {
			t.Fatal("incomplete Grok terminal runtime proof accepted")
		}
	}
}

func currentProbeDirectExecutionTestProof() currentProbeDirectExecutionRoleProof {
	return currentProbeDirectExecutionRoleProof{
		Family: FamilyZcode, ProviderInstance: "zcode_current", ProviderVersion: "1.2.3", ObservedVersion: "1.2.3",
		Executable: "/private/bin/zcode", ExecutableSHA256: "sha256:executable", Launcher: "/private/bin/zcode", LauncherSHA256: "sha256:executable",
		TerminalRuntimeExecutable: "/private/bin/hc", TerminalRuntimeExecutableSHA256: "sha256:" + strings.Repeat("a", 64),
		TerminalRuntimeVersion: "0.1.0", TerminalRuntimeGeneration: 1, TerminalRuntimePolicyIdentity: "sha256:" + strings.Repeat("b", 64),
		ApplicationVersion: "4.0.0",
		ZCodePreparation:   &ZCodeTerminalObservation{AppVersion: "4.0.0", CatalogRevision: 1, CatalogSHA256: strings.Repeat("a", 64), AccountIdentitySHA256: strings.Repeat("b", 64)},
		ProfileID:          "profile", ProfileGeneration: "generation", NamespaceGeneration: "namespace", Role: string(domain.RoleLogic),
		SnapshotManifestSHA256: "sha256:snapshot", SnapshotName: "snapshot", SnapshotPath: "/snapshot/path", SnapshotPolicyIdentity: "sha256:snapshot-policy",
		SnapshotDevice: 1, SnapshotInode: 2, RootDevice: 3, RootInode: 4, ArgvSHA256: "sha256:argv", NativeReference: "@roadmap.md",
		OutputSHA256: "sha256:output", EffectiveEnvironmentSHA256: "sha256:environment", Termination: string(ports.ProcessTerminationExited), HasExitCode: true, ExitCode: 0,
	}
}
