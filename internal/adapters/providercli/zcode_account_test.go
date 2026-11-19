package providercli

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDecryptZCodeCredentialAcceptsDesktopCiphertext(t *testing.T) {
	const secret = "test-desktop-secret"
	t.Setenv("ZCODE_CREDENTIAL_SECRET", secret)
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := []byte("0123456789ab")
	sealed := gcm.Seal(nil, iv, []byte("coding-plan-key"), nil)
	ciphertext, tag := sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():]
	encoded := zcodeCredentialPrefix + base64.RawURLEncoding.EncodeToString(iv) + "." + base64.RawURLEncoding.EncodeToString(tag) + "." + base64.RawURLEncoding.EncodeToString(ciphertext)
	plain, err := decryptZCodeCredential(encoded, "/Users/test")
	if err != nil || plain != "coding-plan-key" {
		t.Fatalf("decrypt = %q, %v", plain, err)
	}
}

func TestLoadZCodeAccountRuntimeUsesV2DesktopState(t *testing.T) {
	home, builtin := writeZCodeAccountFixture(t, "account-one", "key-one")
	runtime, err := loadZCodeAccountRuntime(home, builtin, zcodeIndividualPlanProviderID+"/GLM-5.3")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.providerID != zcodeIndividualPlanProviderID || runtime.accountIdentity != "account-one" || runtime.builtinRevision == "" || runtime.revision == "" {
		t.Fatalf("runtime = %#v", runtime)
	}
	if key, err := runtime.apiKey(t.Context(), zcodeIndividualPlanProviderID); err != nil || key != "key-one" {
		t.Fatalf("api key rotation read = %q, %v", key, err)
	}
	writeZCodeCredentialsFixture(t, home, "account-one", "key-two")
	if key, err := runtime.apiKey(t.Context(), zcodeIndividualPlanProviderID); err != nil || key != "key-two" {
		t.Fatalf("rotated api key = %q, %v", key, err)
	}
}

func TestZCodeOSCredentialReadsOnlyTheBoundProfileAndCodingPlanKey(t *testing.T) {
	home, builtin := writeZCodeAccountFixture(t, "account-one", "key-one")
	path := filepath.Join(home, ".zcode", "v2", "credentials.json")
	const profile = zcodeOSCredentialPrefix + "profile-fixture"
	const firstKey = zcodeOSCredentialPrefix + "coding-plan-fixture"
	const otherKey = zcodeOSCredentialPrefix + "unrelated-fixture"
	credentials := map[string]string{
		"oauth:zai:user_info": profile,
		"account-provider:coding-plan:account:zai-individual-coding-plan:account:account-one:api-key": firstKey,
		"account-provider:coding-plan:account:zai-individual-coding-plan:account:account-two:api-key": otherKey,
	}
	body, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	identity := "account-one"
	var calls []string
	prepareOS := func(ctx context.Context, gotPath string) (zcodeOSCredentialReader, func(), error) {
		if ctx.Err() != nil || gotPath != path {
			t.Fatal("unexpected Keychain reader context or file binding")
		}
		calls = append(calls, "prepare")
		read := func(value string) (string, error) {
			calls = append(calls, value)
			switch value {
			case profile:
				return `{"user_id":` + strconvQuote(identity) + `}`, nil
			case firstKey:
				return "fixture-coding-plan-key", nil
			default:
				t.Fatal("read of an unbound Keychain credential")
				return "", nil
			}
		}
		return read, func() { calls = append(calls, "close") }, nil
	}
	runtime, err := loadZCodeAccountRuntimeForSource(t.Context(), home, builtin, builtin, "", prepareOS)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := runtime.apiKey(t.Context(), zcodeIndividualPlanProviderID); err != nil || key != "fixture-coding-plan-key" {
		t.Fatal("expected the selected Coding Plan key")
	}
	want := []string{"prepare", profile, firstKey, "close", "prepare", profile, firstKey, "close"}
	if !slices.Equal(calls, want) {
		t.Fatalf("account reads should prepare once and release the reader each time: %v", calls)
	}
	if _, err := runtime.apiKey(t.Context(), "other-provider"); err == nil || !slices.Equal(calls, want) {
		t.Fatal("provider mismatch reached the Keychain reader")
	}
	identity = "account-two"
	if _, err := runtime.apiKey(t.Context(), zcodeIndividualPlanProviderID); err == nil {
		t.Fatal("changed account identity accepted")
	}
	if !slices.Equal(calls, append(want, "prepare", profile, "close")) {
		t.Fatal("account drift must stop before the API key read and close the reader")
	}
}

func TestZCodeAccountCredentialReadFailuresFailClosed(t *testing.T) {
	const encryptedProfile = zcodeOSCredentialPrefix + "profile-fixture"
	const encryptedKey = zcodeOSCredentialPrefix + "api-key-fixture"
	const keyName = "account-provider:coding-plan:account:zai-individual-coding-plan:account:account-one:api-key"
	profile := `{"user_id":"account-one"}`
	for _, test := range []struct {
		name, profileValue, keyValue, failOn, want string
		prepareFailed, prepareMissing, wantClose   bool
	}{
		{name: "missing source", profileValue: encryptedProfile, want: "Keychain reader is unavailable", prepareMissing: true},
		{name: "source error", profileValue: encryptedProfile, want: "fixture rejected", prepareFailed: true},
		{name: "profile error", profileValue: encryptedProfile, failOn: encryptedProfile, want: "account profile", wantClose: true},
		{name: "key error", profileValue: encryptedProfile, keyValue: encryptedKey, failOn: encryptedKey, want: "Coding Plan credential", wantClose: true},
		{name: "empty key after decryption", profileValue: profile, keyValue: encryptedKey, want: "credential is unavailable", wantClose: true},
		{name: "unsupported key format", profileValue: profile, keyValue: "enc:v2:env:fixture", want: "unsupported ZCode credential format"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home, _ := writeZCodeAccountFixture(t, "account-one", "unused")
			body, err := json.Marshal(map[string]string{"oauth:zai:user_info": test.profileValue, keyName: test.keyValue})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".zcode", "v2", "credentials.json"), body, 0600); err != nil {
				t.Fatal(err)
			}
			closed := false
			prepare := zcodeOSCredentialSource(func(context.Context, string) (zcodeOSCredentialReader, func(), error) {
				if test.prepareFailed {
					return nil, nil, errors.New("fixture rejected")
				}
				return func(value string) (string, error) {
					if value == test.failOn {
						return "", errors.New("fixture rejected")
					}
					if value == encryptedProfile {
						return profile, nil
					}
					return " ", nil
				}, func() { closed = true }, nil
			})
			if test.prepareMissing {
				prepare = nil
			}
			identity, key, err := readZCodeDesktopCredential(t.Context(), home, zcodeIndividualPlanProviderID, "account-one", prepare)
			if identity != "" || key != "" || err == nil || !strings.Contains(err.Error(), test.want) || closed != test.wantClose {
				t.Fatalf("unexpected failure or reader disposition: %v (closed=%t)", err, closed)
			}
		})
	}
}

func TestZCodeKeychainRejectsUnsafeBindingsAndOutputOverflow(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(root, "Contents/Info.plist")
	executable := filepath.Join(root, "Contents/MacOS/ZCode")
	definition := RuntimeDefinition{applicationMetadata: metadata, executable: executable + "-other"}
	if _, _, err := definition.zcodeKeychainBundle(); err == nil || !strings.Contains(err.Error(), "bundle binding") {
		t.Fatal("mismatched executable path was admitted")
	}
	definition.executable = executable
	addon := filepath.Join(root, zcodeKeychainAddon)
	if err := os.MkdirAll(filepath.Dir(addon), 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "fixture-module")
	body := []byte("fixture")
	if err := os.WriteFile(binary, body, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, addon); err != nil {
		t.Fatal(err)
	}
	if _, _, err := definition.zcodeKeychainBundle(); err == nil || !strings.Contains(err.Error(), "module is unavailable") {
		t.Fatal("symlinked credential module was admitted")
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	if !matchesZCodeKeychainFile(binary, digest) || matchesZCodeKeychainFile(binary, digest+"0") || matchesZCodeKeychainFile(addon, digest) {
		t.Fatal("credential helper file check accepted drift or a symlink")
	}
	var output zcodeCredentialOutput
	if n, err := output.Write(make([]byte, zcodeAccountFileLimit+1)); n != 0 || err == nil || output.buffer.Len() != 0 {
		t.Fatal("oversize credential reply was accepted or buffered")
	}
}

func TestZCodeKeychainModuleRejectsPathReplacement(t *testing.T) {
	addon := filepath.Join(t.TempDir(), "fixture.node")
	if err := os.WriteFile(addon, []byte("fixture"), 0400); err != nil {
		t.Fatal(err)
	}
	module, closeModule, err := prepareZCodeKeychainModule(addon)
	if err != nil {
		t.Fatal(err)
	}
	defer closeModule()
	info, err := module.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyZCodeKeychainModuleIdentity(module, info); err != nil {
		t.Fatal(err)
	}
	link := module.Name() + ".link"
	if err := os.Link(module.Name(), link); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(link) }()
	if err := verifyZCodeKeychainModuleIdentity(module, info); err == nil {
		t.Fatal("multiply linked credential module was admitted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(module.Name(), link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module.Name(), []byte("fixture"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := verifyZCodeKeychainModuleIdentity(module, info); err == nil {
		t.Fatal("replacement module was admitted")
	}
}

func TestZCodeKeychainCommandErrorPreservesOnlyParentDeadline(t *testing.T) {
	child, cancelChild := context.WithTimeout(t.Context(), 0)
	defer cancelChild()
	if err := zcodeKeychainCommandError(t.Context(), child, "fixture failure"); err.Error() != "ZCode Keychain operation timed out" ||
		errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("private helper deadline surfaced as a provider invocation timeout")
	}
	parent, cancelParent := context.WithTimeout(t.Context(), 0)
	defer cancelParent()
	if err := zcodeKeychainCommandError(parent, parent, "fixture failure"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("parent deadline was lost")
	}
}

func TestZCodeUnknownEncryptedFormatFailsClosed(t *testing.T) {
	for _, candidate := range []string{"enc:v2:env:fixture", "enc:v3:fixture"} {
		if plaintext, err := decryptZCodeCredential(candidate, "/Users/test"); err == nil || plaintext != "" {
			t.Fatal("unexpected plaintext for unsupported encrypted format")
		}
	}
}

func TestZCodeAccountFilesRejectFIFOsWithoutBlocking(t *testing.T) {
	home, _ := writeZCodeAccountFixture(t, "account-one", "key-one")
	path := filepath.Join(home, ".zcode", "v2", "credentials.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 2)
	go func() {
		_, err := readZCodeV2File(home, "credentials.json", true)
		result <- err
	}()
	go func() {
		_, err := readZCodeAccountFile(path, true, false)
		result <- err
	}()
	for range 2 {
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("account reader accepted FIFO")
			}
		case <-time.After(time.Second):
			t.Fatal("account reader blocked opening FIFO")
		}
	}
}

func TestZCodeAccountRuntimeFailsClosedOnSelectionAndIdentityDrift(t *testing.T) {
	home, builtin := writeZCodeAccountFixture(t, "account-one", "key-one")
	if _, err := loadZCodeAccountRuntime(home, builtin, zcodeIndividualPlanProviderID+"/missing"); err == nil {
		t.Fatal("missing bundled model accepted")
	}
	runtime, err := loadZCodeAccountRuntime(home, builtin, "")
	if err != nil {
		t.Fatal(err)
	}
	writeZCodeCredentialsFixture(t, home, "account-two", "key-two")
	if _, err := runtime.apiKey(t.Context(), zcodeIndividualPlanProviderID); err == nil {
		t.Fatal("changed account identity accepted")
	}
}

func TestZCodeActiveBuiltinPathMatchesEndpointScopedRegistrySource(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path, err := zcodeActiveBuiltinPath(home)
	if err != nil {
		t.Fatal(err)
	}
	wantSuffix := filepath.Join("darwin-aarch64", "0.0.0-dev", "endpoint-78d7c3bef4024722642626fe3669a799", "zcode-builtin.json")
	if filepath.Base(path) != "zcode-builtin.json" || !strings.HasSuffix(path, wantSuffix) {
		t.Fatalf("active built-in path = %q", path)
	}
}

func writeZCodeAccountFixture(t *testing.T, identity, apiKey string) (string, string) {
	t.Helper()
	home := t.TempDir()
	var err error
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	v2 := filepath.Join(home, ".zcode", "v2")
	if err := os.MkdirAll(v2, 0700); err != nil {
		t.Fatal(err)
	}
	settings := []byte(`{"providerFamilyDomain":"zai","providerFamilyConnectionSelections":{"zai":{"kind":"individual-coding-plan"}}}`)
	if err := os.WriteFile(filepath.Join(v2, "setting.json"), settings, 0644); err != nil {
		t.Fatal(err)
	}
	writeZCodeCredentialsFixture(t, home, identity, apiKey)
	builtin := filepath.Join(t.TempDir(), "zcode-builtin.json")
	release := []byte(`{"schemaVersion":1,"revision":30,"config":{"providerConfigRules":{"providerRules":[{"providerId":"account:zai-individual-coding-plan","config":{"builtinModelIds":["GLM-5.3","GLM-5.3-Flash"],"access":{"type":"zhipu-account","mode":"individual-coding-plan","accountType":"zai"}}}]}}}`)
	if err := os.WriteFile(builtin, release, 0644); err != nil {
		t.Fatal(err)
	}
	return home, builtin
}

func writeZCodeCredentialsFixture(t *testing.T, home, identity, apiKey string) {
	t.Helper()
	key := "account-provider:coding-plan:" + zcodeIndividualPlanProviderID + ":account:" + encodeURIComponent(identity) + ":api-key"
	values := map[string]string{
		"oauth:zai:user_info": `{"user_id":` + strconvQuote(identity) + `,"name":"fixture"}`,
		key:                   apiKey,
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".zcode", "v2", "credentials.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}
