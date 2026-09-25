package providercli

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if key, err := runtime.apiKey(zcodeIndividualPlanProviderID); err != nil || key != "key-one" {
		t.Fatalf("api key rotation read = %q, %v", key, err)
	}
	writeZCodeCredentialsFixture(t, home, "account-one", "key-two")
	if key, err := runtime.apiKey(zcodeIndividualPlanProviderID); err != nil || key != "key-two" {
		t.Fatalf("rotated api key = %q, %v", key, err)
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
	if _, err := runtime.apiKey(zcodeIndividualPlanProviderID); err == nil {
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
