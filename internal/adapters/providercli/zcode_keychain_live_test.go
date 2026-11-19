//go:build liveprovider && darwin && arm64

package providercli

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveZCodeCapabilityCipherFixtures(t *testing.T) {
	bundle := os.Getenv("MULGAE_LIVE_ZCODE_APP_BUNDLE")
	if bundle == "" {
		t.Fatal("MULGAE_LIVE_ZCODE_APP_BUNDLE is required")
	}
	electron := filepath.Join(bundle, "Contents/MacOS/ZCode")
	key := bytes.Repeat([]byte{0x42}, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	const plaintext = "synthetic-zcode-coding-plan-value"
	nonce := bytes.Repeat([]byte{0x23}, gcm.NonceSize())
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	split := len(sealed) - gcm.Overhead()
	ciphertext, tag := sealed[:split], sealed[split:]
	badTag := bytes.Clone(tag)
	badTag[0] ^= 1
	encode := base64.RawURLEncoding.EncodeToString
	fingerprint := sha256.Sum256(key)
	envelope := func(digest []byte, authTag []byte) string {
		return fmt.Sprintf("enc:v2:os:%x:%s.%s.%s", digest[:12], encode(nonce), encode(authTag), encode(ciphertext))
	}
	valid := envelope(fingerprint[:], tag)
	for _, fixture := range []struct {
		name, value, reader string
		pass                bool
	}{
		{"valid", valid, "() => process.argv[1]", true},
		{"malformed", "enc:v2:os:invalid", "() => process.argv[1]", false},
		{"wrong-key-fingerprint", envelope(make([]byte, 12), tag), "() => process.argv[1]", false},
		{"wrong-authentication-tag", envelope(fingerprint[:], badTag), "() => process.argv[1]", false},
		{"denied", valid, "() => { throw Error(process.argv[1]); }", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), zcodeCredentialReadTimeout)
			defer cancel()
			script := zcodeCredentialDecryptScript + "\nreadCredential(" + fixture.reader + ").catch(() => { process.exitCode = 1; });"
			command := exec.CommandContext(ctx, electron, "-e", script, encode(key))
			command.Dir = "/private/var/empty"
			command.Env = []string{"ELECTRON_RUN_AS_NODE=1"}
			command.Stdin = strings.NewReader(fixture.value)
			output, err := command.CombinedOutput()
			if fixture.pass {
				if err != nil || string(output) != plaintext {
					t.Fatal("signed runtime failed to decrypt the synthetic credential")
				}
				return
			}
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || len(output) != 0 {
				t.Fatal("cipher fixture failed to reject the input without disclosing data")
			}
		})
	}
}
