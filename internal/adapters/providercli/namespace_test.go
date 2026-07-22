package providercli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

func TestNamespaceFactoryIsolatesInstancesAndRetainsGeneration(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	second, err := factory.AcquireProviderNamespace(context.Background(), "kimi_secondary")
	if err != nil {
		t.Fatal(err)
	}
	if first.Generation() == second.Generation() {
		t.Fatal("distinct instances share a namespace generation")
	}
	firstEnvironment := namespaceEnvironmentMap(t, first.Environment())
	secondEnvironment := namespaceEnvironmentMap(t, second.Environment())
	if firstEnvironment["HOME"] == secondEnvironment["HOME"] {
		t.Fatal("provider namespace inherited host HOME")
	}
	if firstEnvironment["XDG_CONFIG_HOME"] == "" || firstEnvironment["XDG_DATA_HOME"] == "" ||
		firstEnvironment["XDG_CACHE_HOME"] == "" || firstEnvironment["TMPDIR"] == "" ||
		firstEnvironment["KAR_PROVIDER_SCRATCH"] == "" {
		t.Fatal("provider namespace omitted required isolated directories")
	}
	if err := first.ValidateForSpawn(); err != nil {
		t.Fatal(err)
	}
	if first.Generation() != first.Generation() {
		t.Fatal("repeated namespace access changed generation")
	}
}

func TestNamespaceLeaseRejectsDriftAndDrainsExactlyOnce(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	environment := namespaceEnvironmentMap(t, lease.Environment())
	if err := os.Remove(environment["XDG_CACHE_HOME"]); err != nil {
		t.Fatal(err)
	}
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("namespace drift reached spawn validation")
	}
	receipt, err := lease.DrainTerminal(context.Background())
	if err != nil || !receipt.Valid() || !receipt.Drained() || !receipt.CredentialsZeroed() || !receipt.Unlinked() || !receipt.TornDown() {
		t.Fatalf("terminal drain = %#v, %v", receipt, err)
	}
	repeated, err := lease.DrainTerminal(context.Background())
	if err != nil || repeated != receipt {
		t.Fatalf("repeated terminal drain = %#v, %v", repeated, err)
	}
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("closed namespace reached spawn validation")
	}
}
func TestCredentialProjectionSafeAndTerminallyZeroesAndUnlinks(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	_, request := declaredCredentialRequest(t, lease, "token=super-secret-value", ports.CredentialProjectionKimiCredentials)
	if _, err := lease.ProjectCredential(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	destination := filepath.Join(concrete.root, "home", ".kimi-code", "credentials", "kimi-code.json")
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != "token=super-secret-value" {
		t.Fatal("projected credential mismatch")
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credential permissions = %v, %v", info.Mode(), err)
	}
	retained := filepath.Join(t.TempDir(), "retained")
	if err := os.Link(destination, retained); err != nil {
		t.Fatal(err)
	}
	if err := lease.ValidateForSpawn(); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.DrainTerminal(context.Background()); err != nil {
		t.Fatal(err)
	}
	zeroed, err := os.ReadFile(retained)
	if err != nil || string(zeroed) != strings.Repeat("\x00", len("token=super-secret-value")) {
		t.Fatalf("retained credential was not zeroed: %v", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("seed destination remains after drain: %v", err)
	}
}

func TestCredentialProjectionDrainAcceptsProviderOwnedAtomicRefresh(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	secret := "projected-secret"
	_, request := declaredCredentialRequest(t, lease, secret, ports.CredentialProjectionKimiCredentials)
	if _, err := lease.ProjectCredential(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	destination := filepath.Join(concrete.root, "home", ".kimi-code", "credentials", "kimi-code.json")
	retained := filepath.Join(t.TempDir(), "retained")
	if err := os.Link(destination, retained); err != nil {
		t.Fatal(err)
	}
	replacement := destination + ".refresh"
	if err := os.WriteFile(replacement, []byte("provider-refreshed-state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, destination); err != nil {
		t.Fatal(err)
	}
	if err := lease.ValidateForSpawn(); err != nil {
		t.Fatalf("safe provider-owned refresh was rejected: %v", err)
	}
	if _, err := lease.DrainTerminal(context.Background()); err != nil {
		t.Fatal(err)
	}
	zeroed, err := os.ReadFile(retained)
	if err != nil || string(zeroed) != strings.Repeat("\x00", len(secret)) {
		t.Fatalf("original projected credential was not zeroed: %v", err)
	}
	if _, err := os.Lstat(concrete.root); !os.IsNotExist(err) {
		t.Fatalf("refreshed provider namespace remains after drain: %v", err)
	}
}

func TestCredentialProjectionRejectsSymlinkRefreshAndStillDrains(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	_, request := declaredCredentialRequest(t, lease, "projected-secret", ports.CredentialProjectionKimiCredentials)
	if _, err := lease.ProjectCredential(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	destination := filepath.Join(concrete.root, "home", ".kimi-code", "credentials", "kimi-code.json")
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(request.SourcePath(), destination); err != nil {
		t.Fatal(err)
	}
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("symlink refresh reached spawn authority")
	}
	if _, err := lease.DrainTerminal(context.Background()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(request.SourcePath())
	if err != nil || string(contents) != "projected-secret" {
		t.Fatalf("drain followed refreshed symlink: %q, %v", contents, err)
	}
}

func TestCredentialProjectionRejectsUnsafeSourcesAndDestinationsWithoutSecrets(t *testing.T) {
	secret := "never-print-this-secret"
	tests := []struct {
		name  string
		setup func(t *testing.T, lease ports.ProviderNamespaceLease, request ports.CredentialProjectionRequest)
	}{
		{"source_swap", func(t *testing.T, lease ports.ProviderNamespaceLease, request ports.CredentialProjectionRequest) {
			if err := os.Remove(request.SourcePath()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(request.SourcePath(), []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"destination_parent_symlink", func(t *testing.T, lease ports.ProviderNamespaceLease, request ports.CredentialProjectionRequest) {
			parent := filepath.Join(lease.(*namespaceLease).root, "home", ".kimi-code", "credentials")
			if err := os.Remove(parent); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), parent); err != nil {
				t.Fatal(err)
			}
		}},
		{"source_symlink", func(t *testing.T, lease ports.ProviderNamespaceLease, request ports.CredentialProjectionRequest) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(request.SourcePath()); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, request.SourcePath()); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewNamespaceFactory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
			if err != nil {
				t.Fatal(err)
			}
			_, request := declaredCredentialRequest(t, lease, secret, ports.CredentialProjectionKimiCredentials)
			test.setup(t, lease, request)
			_, err = lease.ProjectCredential(context.Background(), request)
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("unsafe projection error exposed secret or succeeded: %v", err)
			}
		})
	}
}

func TestCredentialProjectionRejectsHashDriftDuplicateAndSpawnSourceDrift(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	_, badHash := declaredCredentialRequest(t, lease, "credential-value", ports.CredentialProjectionKimiConfig)
	badHash, err = ports.NewCredentialProjectionRequest(badHash.ProviderInstance(), badHash.Generation(), badHash.SourcePath(), badHash.Source(), strings.Repeat("0", 64), badHash.Size(), badHash.Mode(), badHash.Destination())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lease.ProjectCredential(context.Background(), badHash); err == nil {
		t.Fatal("hash drift projected")
	}
	_, request := declaredCredentialRequest(t, lease, "credential-value", ports.CredentialProjectionKimiConfig)
	if _, err := lease.ProjectCredential(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	_, duplicate := declaredCredentialRequest(t, lease, "different", ports.CredentialProjectionKimiConfig)
	if _, err := lease.ProjectCredential(context.Background(), duplicate); err == nil {
		t.Fatal("duplicate destination projected")
	}
	if err := os.WriteFile(request.SourcePath(), []byte("changed-credential"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("source drift reached spawn")
	}
}

func TestNamespaceDoesNotSeedCredentialsWithoutDescriptor(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	root := lease.(*namespaceLease).root
	for _, path := range []string{
		filepath.Join(root, "home", ".kimi-code", "config.toml"),
		filepath.Join(root, "home", ".kimi-code", "credentials", "kimi-code.json"),
		filepath.Join(root, "home", ".kimi", "config.toml"),
		filepath.Join(root, "home", ".kimi", "credentials", "kimi-code.json"),
		filepath.Join(root, "home", ".zcode", "cli", "config.json"),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("unexpected seeded file %q: %v", path, err)
		}
	}
}

func TestCredentialProjectionUsesOnlyProviderHomePaths(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	paths := []struct {
		destination ports.CredentialProjectionDestination
		path        string
	}{
		{ports.CredentialProjectionKimiConfig, ".kimi-code/config.toml"},
		{ports.CredentialProjectionKimiCredentials, ".kimi-code/credentials/kimi-code.json"},
		{ports.CredentialProjectionZCodeConfig, ".zcode/cli/config.json"},
	}
	home := namespaceEnvironmentMap(t, lease.Environment())["HOME"]
	stub := filepath.Join(t.TempDir(), "provider-cli")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexec /bin/cat \"$HOME/$1\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, test := range paths {
		t.Run(string(test.destination), func(t *testing.T) {
			contents := "declared-" + string(test.destination)
			_, request := declaredCredentialRequest(t, lease, contents, test.destination)
			if _, err := lease.ProjectCredential(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(home, test.path)); err != nil {
				t.Fatalf("credential not projected to standard HOME path: %v", err)
			}
			command := exec.Command(stub, test.path)
			command.Env = []string{"HOME=" + home}
			got, err := command.Output()
			if err != nil || string(got) != contents {
				t.Fatalf("stub CLI did not read projected credential: %q, %v", got, err)
			}
		})
	}
	if _, ok := credentialDestination(ports.CredentialProjectionDestination("settings/undeclared.json")); ok {
		t.Fatal("undeclared destination is accepted")
	}
	if _, err := lease.DrainTerminal(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, test := range paths {
		if _, err := os.Lstat(filepath.Join(home, test.path)); !os.IsNotExist(err) {
			t.Fatalf("credential remains after terminal drain: %q, %v", test.path, err)
		}
	}
}

func declaredCredentialRequest(t *testing.T, lease ports.ProviderNamespaceLease, contents string, destination ports.CredentialProjectionDestination) (string, ports.CredentialProjectionRequest) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "declared")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(contents))
	request, err := ports.NewCredentialProjectionRequest(lease.ProviderInstance(), lease.Generation(), path, source, fmt.Sprintf("%x", hash), info.Size(), info.Mode(), destination)
	if err != nil {
		t.Fatal(err)
	}
	return path, request
}

func namespaceEnvironmentMap(t *testing.T, environment []ports.EnvironmentVariable) map[string]string {
	t.Helper()
	result := make(map[string]string, len(environment))
	for _, variable := range environment {
		result[variable.Name()] = variable.Value()
	}
	return result
}
func TestNamespaceDrainCancellationCanRetry(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if receipt, err := lease.DrainTerminal(canceled); err == nil || receipt.Valid() {
		t.Fatalf("canceled drain = %#v, %v", receipt, err)
	}
	if err := lease.ValidateForSpawn(); err != nil {
		t.Fatalf("canceled drain closed namespace: %v", err)
	}
	receipt, err := lease.DrainTerminal(context.Background())
	if err != nil || !receipt.Valid() {
		t.Fatalf("retried drain = %#v, %v", receipt, err)
	}
	if _, err := os.Lstat(lease.(*namespaceLease).root); !os.IsNotExist(err) {
		t.Fatalf("receipt issued before namespace absence: %v", err)
	}
	repeated, err := lease.DrainTerminal(context.Background())
	if err != nil || repeated != receipt {
		t.Fatalf("idempotent drain = %#v, %v", repeated, err)
	}
}

func TestNamespaceDrainRecoversRenamedAcquiredRoot(t *testing.T) {
	for _, test := range []struct {
		name    string
		replace bool
	}{
		{name: "without_replacement"},
		{name: "with_replacement", replace: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewNamespaceFactory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
			if err != nil {
				t.Fatal(err)
			}
			concrete := lease.(*namespaceLease)
			moved := concrete.root + ".moved"
			if err := os.Rename(concrete.root, moved); err != nil {
				t.Fatal(err)
			}
			if test.replace {
				if err := os.Mkdir(concrete.root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			receipt, err := lease.DrainTerminal(context.Background())
			if err != nil || !receipt.Valid() {
				t.Fatalf("renamed root drain = %#v, %v", receipt, err)
			}
			if _, err := os.Lstat(moved); !os.IsNotExist(err) {
				t.Fatalf("retained inode survives drain: %v", err)
			}
			if test.replace {
				if info, err := os.Lstat(concrete.root); err != nil || !info.IsDir() {
					t.Fatalf("replacement root was removed: %v", err)
				}
			}
		})
	}
}
func TestNamespaceDrainFinalQuarantineRestoresSubstitution(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	moved := concrete.root + ".moved"
	var replacementRoot string
	var replacementSentinel string
	concrete.afterFinalCheckHook = func(candidate *namespaceLease) {
		replacementRoot = filepath.Join(filepath.Dir(concrete.root), candidate.rootName)
		replacementSentinel = filepath.Join(replacementRoot, "replacement")
		if err := os.Rename(replacementRoot, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(replacementRoot, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(replacementSentinel, []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	receipt, err := lease.DrainTerminal(context.Background())
	if err != nil || !receipt.Valid() {
		t.Fatalf("substituted root drain = %#v, %v", receipt, err)
	}
	if contents, err := os.ReadFile(replacementSentinel); err != nil || string(contents) != "replacement" {
		t.Fatalf("replacement was not preserved intact: %q, %v", contents, err)
	}
	if _, err := os.Lstat(moved); !os.IsNotExist(err) {
		t.Fatalf("retained inode survives final cleanup: %v", err)
	}
	if concrete.rootDirectory != nil || concrete.parentDirectory != nil {
		t.Fatal("terminal cleanup retained descriptors")
	}
}

func TestNamespaceDrainRetriesAfterQuarantineFailure(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	concrete.afterQuarantineHook = func(*namespaceLease) error {
		return fmt.Errorf("test quarantine failure")
	}

	receipt, err := lease.DrainTerminal(context.Background())
	if err == nil || receipt.Valid() {
		t.Fatalf("quarantine failure drain = %#v, %v", receipt, err)
	}
	tombPath := filepath.Join(filepath.Dir(concrete.root), concrete.rootName)
	tombInfo, err := os.Lstat(tombPath)
	if err != nil || !tombInfo.IsDir() {
		t.Fatalf("quarantined root missing after failed drain: %v", err)
	}
	descriptorInfo, err := concrete.rootDirectory.Stat()
	if err != nil || !os.SameFile(tombInfo, descriptorInfo) {
		t.Fatalf("quarantine state lost acquired root identity: %v", err)
	}
	if _, err := os.Lstat(concrete.root); !os.IsNotExist(err) {
		t.Fatalf("original root remains after quarantine: %v", err)
	}

	concrete.afterQuarantineHook = nil
	receipt, err = lease.DrainTerminal(context.Background())
	if err != nil || !receipt.Valid() || concrete.rootDirectory != nil || concrete.parentDirectory != nil {
		t.Fatalf("quarantine retry drain = %#v, %v", receipt, err)
	}
}

func TestNamespaceDrainRetriesAfterPartialSeedCleanup(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	_, config := declaredCredentialRequest(t, lease, "first", ports.CredentialProjectionKimiConfig)
	if _, err := lease.ProjectCredential(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	_, credentials := declaredCredentialRequest(t, lease, "second", ports.CredentialProjectionKimiCredentials)
	if _, err := lease.ProjectCredential(context.Background(), credentials); err != nil {
		t.Fatal(err)
	}
	credentialsDirectory := filepath.Join(concrete.root, "home", ".kimi-code", "credentials")
	movedCredentialsDirectory := credentialsDirectory + ".moved"
	if err := os.Rename(credentialsDirectory, movedCredentialsDirectory); err != nil {
		t.Fatal(err)
	}
	receipt, err := lease.DrainTerminal(context.Background())
	if err == nil || receipt.Valid() {
		t.Fatalf("partial seed cleanup drain = %#v, %v", receipt, err)
	}
	configPath := filepath.Join(concrete.root, "home", ".kimi-code", "config.toml")
	if _, err := os.Lstat(configPath); !os.IsNotExist(err) {
		t.Fatalf("completed seed was not removed: %v", err)
	}
	if _, exists := concrete.seeds[ports.CredentialProjectionKimiConfig]; exists {
		t.Fatal("completed seed remained pending")
	}
	if err := os.Rename(movedCredentialsDirectory, credentialsDirectory); err != nil {
		t.Fatal(err)
	}
	receipt, err = lease.DrainTerminal(context.Background())
	if err != nil || !receipt.Valid() {
		t.Fatalf("repaired seed cleanup drain = %#v, %v", receipt, err)
	}
}
func TestNamespaceDrainResumesDescriptorOwnedLateStages(t *testing.T) {
	tests := []struct {
		name  string
		stage namespaceCleanupStage
		set   func(*namespaceLease)
	}{
		{
			name:  "contents_deleted",
			stage: namespaceCleanupContentsDeleted,
			set: func(lease *namespaceLease) {
				lease.afterContentsDeletedHook = func(*namespaceLease) error { return errors.New("contents deleted") }
			},
		},
		{
			name:  "unlinked",
			stage: namespaceCleanupDetached,
			set: func(lease *namespaceLease) {
				lease.afterUnlinkHook = func(*namespaceLease) error { return errors.New("unlinked") }
			},
		},
		{
			name:  "detached",
			stage: namespaceCleanupDetached,
			set: func(lease *namespaceLease) {
				lease.afterDetachedHook = func(*namespaceLease) error { return errors.New("detached") }
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewNamespaceFactory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
			if err != nil {
				t.Fatal(err)
			}
			concrete := lease.(*namespaceLease)
			test.set(concrete)

			receipt, err := lease.DrainTerminal(context.Background())
			if err == nil || receipt.Valid() || concrete.cleanupStage != test.stage || concrete.drained {
				t.Fatalf("late failure drain = %#v, %v, stage %d, drained %t", receipt, err, concrete.cleanupStage, concrete.drained)
			}
			var replacementPath string
			if test.stage >= namespaceCleanupUnlinked {
				if _, err := os.Lstat(concrete.root); !os.IsNotExist(err) {
					t.Fatalf("unlinked namespace was reacquired by pathname: %v", err)
				}
				if err := os.Mkdir(concrete.root, 0700); err != nil {
					t.Fatal(err)
				}
				replacementPath = filepath.Join(concrete.root, "replacement")
				if err := os.WriteFile(replacementPath, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			receipt, err = lease.DrainTerminal(context.Background())
			if err != nil || !receipt.Valid() || !concrete.drained || concrete.rootDirectory != nil || concrete.parentDirectory != nil {
				t.Fatalf("late failure retry = %#v, %v", receipt, err)
			}
			if replacementPath != "" {
				if contents, err := os.ReadFile(replacementPath); err != nil || string(contents) != "replacement" {
					t.Fatalf("replacement pathname was affected by descriptor retry: %q, %v", contents, err)
				}
			}
		})
	}
}

func TestNamespaceDrainCloseFailureRetainsOwnerAndAggregatesFailures(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	rootFailure := errors.New("root close failure")
	parentFailure := errors.New("parent close failure")
	concrete.closeRootDirectory = func(*os.File) error { return rootFailure }
	concrete.closeParentDirectory = func(*os.File) error { return parentFailure }

	receipt, err := lease.DrainTerminal(context.Background())
	if err == nil || receipt.Valid() || concrete.drained || concrete.cleanupStage != namespaceCleanupDetached ||
		concrete.rootDirectory == nil || concrete.parentDirectory == nil || !errors.Is(err, rootFailure) || !errors.Is(err, parentFailure) {
		t.Fatalf("close failure drain = %#v, %v", receipt, err)
	}
	if _, err := os.Lstat(concrete.root); !os.IsNotExist(err) {
		t.Fatalf("unlink was not retained before close retry: %v", err)
	}

	concrete.closeRootDirectory = (*os.File).Close
	concrete.closeParentDirectory = (*os.File).Close
	receipt, err = lease.DrainTerminal(context.Background())
	if err != nil || !receipt.Valid() || !concrete.drained || concrete.rootDirectory != nil || concrete.parentDirectory != nil {
		t.Fatalf("close retry = %#v, %v", receipt, err)
	}
}
func TestNamespaceDrainRetriesAfterPartialDescriptorClose(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	closeFailure := errors.New("root close failure")
	concrete.closeRootDirectory = func(*os.File) error { return closeFailure }

	receipt, err := lease.DrainTerminal(context.Background())
	if err == nil || receipt.Valid() || concrete.drained || concrete.cleanupStage != namespaceCleanupDetached ||
		concrete.rootDirectory == nil || concrete.parentDirectory != nil || !errors.Is(err, closeFailure) {
		t.Fatalf("partial close failure drain = %#v, %v", receipt, err)
	}

	concrete.closeRootDirectory = (*os.File).Close
	receipt, err = lease.DrainTerminal(context.Background())
	if err != nil || !receipt.Valid() || !concrete.drained || concrete.rootDirectory != nil || concrete.parentDirectory != nil {
		t.Fatalf("partial close retry = %#v, %v", receipt, err)
	}
}
func TestNamespaceSetupFailureReturnsAllDescriptorCloseFailures(t *testing.T) {
	root := t.TempDir()
	otherInfo, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	originalClose := closeNamespaceDescriptor
	t.Cleanup(func() { closeNamespaceDescriptor = originalClose })
	rootCloseFailure := errors.New("root setup close failure")
	parentCloseFailure := errors.New("parent setup close failure")
	closeCalls := 0
	closeNamespaceDescriptor = func(file *os.File) error {
		closeErr := file.Close()
		if closeErr != nil {
			return closeErr
		}
		closeCalls++
		if closeCalls == 1 {
			return rootCloseFailure
		}
		return parentCloseFailure
	}

	parent, directory, _, err := openNamespaceDescriptors(root, otherInfo)
	if parent != nil || directory != nil || err == nil || !errors.Is(err, rootCloseFailure) || !errors.Is(err, parentCloseFailure) {
		t.Fatalf("identity setup = parent %v, directory %v, error %v", parent, directory, err)
	}
	if closeCalls != 2 {
		t.Fatalf("setup close calls = %d, want 2", closeCalls)
	}

	originalOpen := openNamespaceRootDescriptor
	t.Cleanup(func() { openNamespaceRootDescriptor = originalOpen })
	openFailure := errors.New("root setup failure")
	openNamespaceRootDescriptor = func(int, string, int, uint32) (int, error) {
		return -1, openFailure
	}
	closeCalls = 1
	factoryRoot := t.TempDir()
	lease, err := NewNamespaceFactory(factoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := lease.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if acquired != nil || err == nil || !errors.Is(err, openFailure) {
		t.Fatalf("failed setup returned lease %v, error %v", acquired, err)
	}
	entries, readErr := os.ReadDir(factoryRoot)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("failed setup retained namespace entry: %v, %d", readErr, len(entries))
	}
	if closeCalls != 2 {
		t.Fatalf("failed setup close calls = %d, want 2", closeCalls)
	}
}

func TestRemoveNamespaceContentsReturnsRecursiveCloseFailureForRetry(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	originalClose := closeNamespaceChildDescriptor
	t.Cleanup(func() { closeNamespaceChildDescriptor = originalClose })
	closeFailure := errors.New("recursive child close failure")
	failClose := true
	closeNamespaceChildDescriptor = func(fd int) error {
		if failClose {
			failClose = false
			return closeFailure
		}
		return originalClose(fd)
	}

	traversal, err := newNamespaceTraversal(int(directory.Fd()))
	if err != nil || traversal == nil {
		t.Fatalf("recursive traversal setup = %v, traversal=%#v", err, traversal)
	}
	if err := traversal.advance(); !errors.Is(err, closeFailure) {
		t.Fatalf("recursive traversal close = %v", err)
	}
	if len(traversal.frames) != 2 {
		t.Fatalf("child descriptor was discarded after close failure: %#v", traversal.frames)
	}
	if _, statErr := os.Stat(child); !os.IsNotExist(statErr) {
		t.Fatalf("child was not unlinked before close retry: %v", statErr)
	}

	closeNamespaceChildDescriptor = originalClose
	if err := traversal.advance(); err != nil {
		t.Fatalf("recursive traversal retry = %v", err)
	}
	if _, err := os.Stat(child); !os.IsNotExist(err) {
		t.Fatalf("child remains after retry: %v", err)
	}
}

func TestNamespaceLocateScanCloseFailureRetainsEnumerationDescriptor(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	lease := acquired.(*namespaceLease)
	parentFD := int(lease.parentDirectory.Fd())
	movedName := "retained-generation"
	if err := unix.Renameat(parentFD, lease.rootName, parentFD, movedName); err != nil {
		t.Fatal(err)
	}

	originalClose := closeNamespaceDescriptor
	t.Cleanup(func() { closeNamespaceDescriptor = originalClose })
	closeFailure := errors.New("parent scan close failure")
	closeNamespaceDescriptor = func(file *os.File) error {
		if file.Name() == "provider namespace parent scan" {
			return closeFailure
		}
		return originalClose(file)
	}
	if err := lease.removeNamespaceRoot(); !errors.Is(err, closeFailure) {
		t.Fatalf("scan close failure = %v", err)
	}
	if len(lease.pendingDescriptors) != 1 || lease.pendingDescriptors[0].Name() != "provider namespace parent scan" {
		t.Fatalf("scan descriptor was not retained: %#v", lease.pendingDescriptors)
	}

	closeNamespaceDescriptor = originalClose
	if err := lease.removeNamespaceRoot(); err != nil {
		t.Fatalf("scan retry root cleanup = %v", err)
	}
	if err := lease.closeNamespaceDescriptors(); err != nil {
		t.Fatalf("scan retry descriptor cleanup = %v", err)
	}
	if _, err := os.Stat(filepath.Join(factory.root, movedName)); !os.IsNotExist(err) {
		t.Fatalf("retained root remains after retry: %v", err)
	}
}

func TestNamespaceConstructionOpenFailureRetainsExactRootForRetry(t *testing.T) {
	factoryRoot := t.TempDir()
	factory, err := NewNamespaceFactory(factoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	originalOpen := openNamespaceRootDescriptor
	t.Cleanup(func() { openNamespaceRootDescriptor = originalOpen })
	openFailure := errors.New("root setup failure")
	openNamespaceRootDescriptor = func(parentFD int, name string, flags int, mode uint32) (int, error) {
		if err := unix.Mkdirat(parentFD, name+"/block", 0700); err != nil {
			t.Fatalf("block construction cleanup: %v", err)
		}
		return -1, openFailure
	}

	acquired, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if acquired != nil || !errors.Is(err, openFailure) {
		t.Fatalf("construction failure = lease %v, error %v", acquired, err)
	}
	owner, ok := NamespaceFromConstructionError(err)
	if !ok || owner.rootDirectory != nil || owner.parentDirectory == nil {
		t.Fatalf("construction cleanup owner = %#v, %v", owner, err)
	}
	parentFD := int(owner.parentDirectory.Fd())
	originalName := owner.rootName
	movedName := "retained-construction-root"
	if err := unix.Renameat(parentFD, originalName, parentFD, movedName); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkdirat(parentFD, originalName, 0700); err != nil {
		t.Fatal(err)
	}

	openNamespaceRootDescriptor = originalOpen
	if err := owner.RetryConstructionCleanup(); err != nil {
		t.Fatalf("construction cleanup retry = %v", err)
	}
	if _, err := os.Stat(filepath.Join(factoryRoot, movedName)); !os.IsNotExist(err) {
		t.Fatalf("retained construction root remains after retry: %v", err)
	}
	replacement, statErr := os.Stat(filepath.Join(factoryRoot, originalName))
	if statErr != nil || !replacement.IsDir() {
		t.Fatalf("replacement was not preserved: %v", statErr)
	}
}
func TestNamespaceRootUnlinkRetryRelocatesRetainedIdentity(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	lease := acquired.(*namespaceLease)
	parentFD := int(lease.parentDirectory.Fd())

	originalUnlink := unlinkNamespaceEntry
	t.Cleanup(func() { unlinkNamespaceEntry = originalUnlink })
	var replacementName string
	unlinkNamespaceEntry = func(directoryFD int, name string, flags int) error {
		if directoryFD != parentFD || flags != unix.AT_REMOVEDIR {
			return originalUnlink(directoryFD, name, flags)
		}
		replacementName = name
		if err := unix.Renameat(directoryFD, name, directoryFD, "retained-root"); err != nil {
			return err
		}
		if err := unix.Mkdirat(directoryFD, name, 0700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(factory.root, name, "replacement"), []byte("replacement"), 0600)
	}

	if err := lease.removeNamespaceRoot(); err == nil ||
		lease.cleanupStage != namespaceCleanupFinalIdentityChecked {
		t.Fatalf("root unlink substitution = %v, stage %d", err, lease.cleanupStage)
	}
	unlinkNamespaceEntry = originalUnlink
	if err := lease.removeNamespaceRoot(); err != nil {
		t.Fatalf("root unlink retry = %v", err)
	}
	if err := lease.closeNamespaceDescriptors(); err != nil {
		t.Fatalf("root descriptor cleanup = %v", err)
	}
	if _, err := os.Stat(filepath.Join(factory.root, "retained-root")); !os.IsNotExist(err) {
		t.Fatalf("retained root remains after retry: %v", err)
	}
	replacement, err := os.Stat(filepath.Join(factory.root, replacementName))
	if err != nil || !replacement.IsDir() {
		t.Fatalf("root replacement was not preserved: %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(factory.root, replacementName, "replacement")); err != nil || string(contents) != "replacement" {
		t.Fatalf("root replacement contents = %q, %v", contents, err)
	}
}

func TestNamespaceChildUnlinkRetryRelocatesRetainedIdentity(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	traversal, err := newNamespaceTraversal(int(directory.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	originalUnlink := unlinkNamespaceEntry
	t.Cleanup(func() { unlinkNamespaceEntry = originalUnlink })
	injected := false
	unlinkNamespaceEntry = func(parentFD int, name string, flags int) error {
		if injected || name != "child" || flags != unix.AT_REMOVEDIR {
			return originalUnlink(parentFD, name, flags)
		}
		injected = true
		if err := unix.Renameat(parentFD, name, parentFD, "retained-child"); err != nil {
			return err
		}
		if err := unix.Mkdirat(parentFD, name, 0700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, name, "replacement"), []byte("replacement"), 0600)
	}
	if err := traversal.advance(); err == nil || len(traversal.frames) != 2 {
		t.Fatalf("child unlink substitution = %v, frames %#v", err, traversal.frames)
	}
	unlinkNamespaceEntry = originalUnlink
	if err := traversal.advance(); err != nil {
		t.Fatalf("child unlink retry = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "retained-child")); !os.IsNotExist(err) {
		t.Fatalf("retained child remains after retry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "child")); !os.IsNotExist(err) {
		t.Fatalf("in-parent replacement was not processed after refresh: %v", err)
	}
}
func TestNamespaceDrainRefreshesParentAfterChildDetach(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := factory.AcquireProviderNamespace(context.Background(), "kimi_primary")
	if err != nil {
		t.Fatal(err)
	}
	lease := acquired.(*namespaceLease)
	child := filepath.Join(lease.root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}

	originalUnlink := unlinkNamespaceEntry
	t.Cleanup(func() { unlinkNamespaceEntry = originalUnlink })
	injected := false
	unlinkNamespaceEntry = func(parentFD int, name string, flags int) error {
		if injected || name != "child" || flags != unix.AT_REMOVEDIR {
			return originalUnlink(parentFD, name, flags)
		}
		injected = true
		if err := originalUnlink(parentFD, name, flags); err != nil {
			return err
		}
		if err := unix.Mkdirat(parentFD, name, 0700); err != nil {
			return err
		}
		childFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(childFD)
		fileFD, err := unix.Openat(childFD, "replacement", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
		if err != nil {
			return err
		}
		if _, err := unix.Write(fileFD, []byte("replacement")); err != nil {
			_ = unix.Close(fileFD)
			return err
		}
		return unix.Close(fileFD)
	}

	receipt, err := lease.DrainTerminal(context.Background())
	if err != nil || !receipt.Valid() || !receipt.Drained() || !receipt.Unlinked() || !receipt.TornDown() {
		t.Fatalf("terminal drain = %#v, %v", receipt, err)
	}
	if _, err := os.Stat(child); !os.IsNotExist(err) {
		t.Fatalf("replacement left in namespace after parent refresh: %v", err)
	}
	if _, err := os.Stat(lease.root); !os.IsNotExist(err) {
		t.Fatalf("namespace root remains after terminal drain: %v", err)
	}
}
