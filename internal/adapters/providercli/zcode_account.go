package providercli

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	zcodeIndividualPlanProviderID = "account:zai-individual-coding-plan"
	zcodeDefaultEndpointOrigin    = "https://zcode.z.ai"
	zcodeRegistryAppVersion       = "0.0.0-dev"
	zcodeCredentialPrefix         = "enc:v1:"
	zcodeAccountFileLimit         = 4 << 20
)

type zcodeModelSelection struct {
	ProviderID string `json:"providerId"`
	ModelID    string `json:"modelId"`
}

func cloneZCodeModelSelection(selection *zcodeModelSelection) *zcodeModelSelection {
	if selection == nil {
		return nil
	}
	clone := *selection
	return &clone
}

func parseZCodeModelSelection(value string) (*zcodeModelSelection, error) {
	if value == "" {
		return nil, nil
	}
	providerID, modelID, found := strings.Cut(value, "/")
	selection := &zcodeModelSelection{ProviderID: providerID, ModelID: modelID}
	if !found || !validZCodeSettings(value, "") || providerID != zcodeIndividualPlanProviderID {
		return nil, fmt.Errorf("unsupported ZCode account model selection")
	}
	return selection, nil
}

func validZCodeSettings(model, effort string) bool {
	if model != "" {
		providerID, modelID, found := strings.Cut(model, "/")
		if !found || providerID != zcodeIndividualPlanProviderID || modelID == "" || strings.Contains(modelID, "//") || len(modelID) > 128 {
			return false
		}
		for _, character := range providerID {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-", character)) {
				return false
			}
		}
		for _, segment := range strings.Split(modelID, "/") {
			if segment == "" || segment == ".." {
				return false
			}
			for _, character := range segment {
				if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character)) {
					return false
				}
			}
		}
	}
	if effort != "" {
		if len(effort) > 128 {
			return false
		}
		for index, character := range effort {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._-", character)) {
				return false
			}
		}
	}
	return true
}

type zcodeAccountRuntime struct {
	nativeHome      string
	providerID      string
	accountIdentity string
	builtinRevision string
	revision        string
}

func loadZCodeAccountRuntime(nativeHome, builtinPath, configuredModel string) (*zcodeAccountRuntime, error) {
	return loadZCodeAccountRuntimeForSource(nativeHome, builtinPath, builtinPath, configuredModel)
}

func loadZCodeAccountRuntimeForSource(nativeHome, builtinPath, activeBuiltinPath, configuredModel string) (*zcodeAccountRuntime, error) {
	if !validCanonicalAbsolute(nativeHome) || !validCanonicalAbsolute(builtinPath) || !validCanonicalAbsolute(activeBuiltinPath) {
		return nil, errors.New("invalid ZCode account authority")
	}
	settingsBytes, err := readZCodeV2File(nativeHome, "setting.json", false)
	if err != nil {
		return nil, fmt.Errorf("read ZCode account settings: %w", err)
	}
	var settings struct {
		ProviderFamilyDomain               string `json:"providerFamilyDomain"`
		ProviderFamilyConnectionSelections map[string]struct {
			Kind string `json:"kind"`
		} `json:"providerFamilyConnectionSelections"`
	}
	if json.Unmarshal(settingsBytes, &settings) != nil || settings.ProviderFamilyDomain != "zai" || settings.ProviderFamilyConnectionSelections["zai"].Kind != "individual-coding-plan" {
		return nil, errors.New("Z.AI Individual Coding Plan is not current")
	}
	builtinBytes, err := readZCodeAccountFile(builtinPath, false, true)
	if err != nil {
		return nil, fmt.Errorf("read ZCode built-in provider config: %w", err)
	}
	providerID, models, releaseRevision, err := decodeZCodeIndividualPlanCatalog(builtinBytes)
	if err != nil {
		return nil, err
	}
	if configuredModel != "" {
		configuredSelection, parseErr := parseZCodeModelSelection(configuredModel)
		if parseErr != nil || configuredSelection.ProviderID != providerID || !containsExact(models, configuredSelection.ModelID) {
			return nil, errors.New("selected ZCode model is absent from the bundled account catalog")
		}
	}
	identity, _, err := readZCodeDesktopCredential(nativeHome, providerID, "")
	if err != nil {
		return nil, err
	}
	pathDigest := sha256.Sum256([]byte(filepath.Clean(activeBuiltinPath)))
	builtinRevision := fmt.Sprintf("zcode-builtin:%d:%x", releaseRevision, pathDigest)
	revisionDigest := sha256.Sum256([]byte(builtinRevision + "\x00" + providerID + "\x00" + identity))
	return &zcodeAccountRuntime{nativeHome: nativeHome, providerID: providerID, accountIdentity: identity, builtinRevision: builtinRevision, revision: "mulgae-account:" + hex.EncodeToString(revisionDigest[:])}, nil
}

func zcodeActiveBuiltinPath(runtimeHome string) (string, error) {
	if !validCanonicalAbsolute(runtimeHome) {
		return "", errors.New("invalid ZCode active catalog identity")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return "", errors.New("unsupported ZCode active catalog platform")
	}
	endpointDigest := sha256.Sum256([]byte(zcodeDefaultEndpointOrigin))
	endpointKey := "endpoint-" + hex.EncodeToString(endpointDigest[:])[:32]
	return filepath.Join(runtimeHome, ".zcode", "v2", "runtime", "provider", "darwin-aarch64", zcodeRegistryAppVersion, endpointKey, "zcode-builtin.json"), nil
}

func decodeZCodeIndividualPlanCatalog(data []byte) (string, []string, int, error) {
	var release struct {
		Revision int `json:"revision"`
		Config   struct {
			ProviderConfigRules struct {
				ProviderRules []struct {
					ProviderID string `json:"providerId"`
					Config     struct {
						BuiltinModelIDs []string `json:"builtinModelIds"`
						Access          struct {
							Type, Mode, AccountType string
						} `json:"access"`
					} `json:"config"`
				} `json:"providerRules"`
			} `json:"providerConfigRules"`
		} `json:"config"`
	}
	if json.Unmarshal(data, &release) != nil || release.Revision <= 0 {
		return "", nil, 0, errors.New("invalid ZCode built-in provider config")
	}
	var providerID string
	var models []string
	for _, rule := range release.Config.ProviderConfigRules.ProviderRules {
		if rule.Config.Access.Type == "zhipu-account" && rule.Config.Access.Mode == "individual-coding-plan" && rule.Config.Access.AccountType == "zai" {
			if providerID != "" || rule.ProviderID == "" || len(rule.Config.BuiltinModelIDs) == 0 {
				return "", nil, 0, errors.New("ambiguous Z.AI Individual Coding Plan provider")
			}
			providerID, models = rule.ProviderID, append([]string(nil), rule.Config.BuiltinModelIDs...)
		}
	}
	if providerID == "" {
		return "", nil, 0, errors.New("Z.AI Individual Coding Plan provider is unavailable")
	}
	return providerID, models, release.Revision, nil
}

func (runtime *zcodeAccountRuntime) accountConfigParams() map[string]any {
	return map[string]any{
		"revision":                    runtime.revision,
		"basedOnZCodeBuiltinRevision": runtime.builtinRevision,
		"providers":                   map[string]any{runtime.providerID: map[string]any{"access": map[string]any{"type": "zhipu-account", "entitled": true}}},
		"states":                      map[string]any{runtime.providerID: map[string]any{"availability": "available", "entitled": true, "current": true}},
	}
}

func (runtime *zcodeAccountRuntime) apiKey(providerID string) (string, error) {
	if runtime == nil || providerID != runtime.providerID {
		return "", errors.New("ZCode account provider identity mismatch")
	}
	identity, apiKey, err := readZCodeDesktopCredential(runtime.nativeHome, runtime.providerID, runtime.accountIdentity)
	if err != nil {
		return "", err
	}
	if identity != runtime.accountIdentity {
		return "", errors.New("ZCode account identity changed during invocation")
	}
	return apiKey, nil
}

func readZCodeDesktopCredential(nativeHome, providerID, expectedIdentity string) (string, string, error) {
	bytes, err := readZCodeV2File(nativeHome, "credentials.json", true)
	if err != nil {
		return "", "", fmt.Errorf("read ZCode credentials: %w", err)
	}
	var values map[string]string
	if json.Unmarshal(bytes, &values) != nil {
		return "", "", errors.New("invalid ZCode credentials")
	}
	profile, err := decryptZCodeCredential(values["oauth:zai:user_info"], nativeHome)
	if err != nil {
		return "", "", errors.New("invalid ZCode account profile")
	}
	var userInfo struct {
		ID     string `json:"id"`
		UserID string `json:"user_id"`
	}
	if json.Unmarshal([]byte(profile), &userInfo) != nil {
		return "", "", errors.New("invalid ZCode account profile")
	}
	identity := strings.TrimSpace(userInfo.ID)
	if identity == "" {
		identity = strings.TrimSpace(userInfo.UserID)
	}
	if identity == "" || expectedIdentity != "" && identity != expectedIdentity {
		return "", "", errors.New("ZCode account identity is unavailable")
	}
	key := "account-provider:coding-plan:" + providerID + ":account:" + encodeURIComponent(identity) + ":api-key"
	apiKey, err := decryptZCodeCredential(values[key], nativeHome)
	if err != nil || strings.TrimSpace(apiKey) == "" {
		return "", "", errors.New("ZCode Individual Coding Plan credential is unavailable")
	}
	return identity, strings.TrimSpace(apiKey), nil
}

func decryptZCodeCredential(value, nativeHome string) (string, error) {
	if !strings.HasPrefix(value, zcodeCredentialPrefix) {
		return value, nil
	}
	parts := strings.Split(strings.TrimPrefix(value, zcodeCredentialPrefix), ".")
	if len(parts) != 3 {
		return "", errors.New("invalid encrypted credential")
	}
	iv, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	tag, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	ciphertext, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != 12 || len(tag) != 16 {
		return "", errors.New("invalid encrypted credential")
	}
	secret := strings.TrimSpace(os.Getenv("ZCODE_CREDENTIAL_SECRET"))
	if secret == "" {
		username := "unknown"
		if current, err := user.Current(); err == nil && current.Username != "" {
			username = current.Username
		}
		secret = "zcode-credential-fallback:" + runtime.GOOS + ":" + nativeHome + ":" + username
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	sealed := append(append([]byte(nil), ciphertext...), tag...)
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return "", errors.New("credential decrypt failed")
	}
	return string(plain), nil
}

func readZCodeAccountFile(path string, private, allowRootOwner bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "zcode account state")
	defer file.Close()
	return readOpenedZCodeAccountFile(file, private, allowRootOwner)
}

func readZCodeV2File(nativeHome, name string, private bool) ([]byte, error) {
	if !validCanonicalAbsolute(nativeHome) || name == "" || filepath.Base(name) != name {
		return nil, errors.New("unsafe ZCode account state")
	}
	current, err := openAbsoluteDirectory(nativeHome)
	if err != nil {
		return nil, errors.New("unsafe ZCode account state")
	}
	defer func() { _ = current.Close() }()
	for _, component := range []string{".zcode", "v2"} {
		next, openErr := openDirectoryAt(current, component)
		if openErr != nil {
			return nil, errors.New("unsafe ZCode account state")
		}
		var stat unix.Stat_t
		if unix.Fstat(int(next.Fd()), &stat) != nil || stat.Uid != uint32(os.Getuid()) || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0022 != 0 {
			next.Close()
			return nil, errors.New("unsafe ZCode account state")
		}
		current.Close()
		current = next
	}
	fd, err := unix.Openat(int(current.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "zcode account state")
	defer file.Close()
	return readOpenedZCodeAccountFile(file, private, false)
}

func readOpenedZCodeAccountFile(file *os.File, private, allowRootOwner bool) ([]byte, error) {
	fd := int(file.Fd())
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		return nil, errors.New("unsafe ZCode account state")
	}
	ownerValid := stat.Uid == uint32(os.Getuid()) || allowRootOwner && stat.Uid == 0
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || !ownerValid || stat.Size < 0 || stat.Size > zcodeAccountFileLimit || private && stat.Mode&0777 != 0600 || !private && stat.Mode&0022 != 0 {
		return nil, errors.New("unsafe ZCode account state")
	}
	bytes := make([]byte, stat.Size)
	if _, err := io.ReadFull(file, bytes); err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || stat.Dev != after.Dev || stat.Ino != after.Ino || stat.Size != after.Size || stat.Mtim != after.Mtim {
		return nil, errors.New("ZCode account state changed while reading")
	}
	return bytes, nil
}

func encodeURIComponent(value string) string {
	var out strings.Builder
	for _, b := range []byte(value) {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-_.!~*'()", rune(b)) {
			out.WriteByte(b)
		} else {
			fmt.Fprintf(&out, "%%%02X", b)
		}
	}
	return out.String()
}

func containsExact(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
