//go:build darwin && arm64

package filesystem

import (
	"strings"
	"testing"
)

func TestCredentialScannerDetectsHighRiskFormsAcrossChunks(t *testing.T) {
	tests := []struct {
		name     string
		chunks   []string
		detector string
	}{
		{
			name:     "authorization bearer",
			chunks:   []string{"Authoriz", "ation: Bea", "rer token"},
			detector: "authorization_bearer",
		},
		{
			name:     "password assignment",
			chunks:   []string{"PASS", "word = value"},
			detector: "credential_assignment",
		},
		{
			name:     "api key assignment",
			chunks:   []string{"api_", "KEY: value"},
			detector: "credential_assignment",
		},
		{
			name:     "access token assignment",
			chunks:   []string{"access ", "token=value"},
			detector: "credential_assignment",
		},
		{
			name:     "private key PEM",
			chunks:   []string{"-----BEGIN RSA PRI", "VATE KEY-----"},
			detector: "private_key_pem",
		},
		{
			name:     "AWS access key ID",
			chunks:   []string{"AKIAIOSFOD", "NN7EXAMPLE"},
			detector: "aws_access_key_id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var scanner credentialScanner
			for _, chunk := range test.chunks {
				match, found := scanner.Scan([]byte(chunk))
				if !found {
					continue
				}
				if match.detector != test.detector {
					t.Fatalf("detector = %q, want %q", match.detector, test.detector)
				}
				return
			}
			t.Fatalf("scanner did not detect %q", test.detector)
		})
	}
}

func TestCredentialScannerRetainsOnlyBoundedOverlap(t *testing.T) {
	var scanner credentialScanner
	chunk := make([]byte, scannerOverlap+1)
	for index := range chunk {
		chunk[index] = 'a'
	}
	if _, found := scanner.Scan(chunk); found {
		t.Fatal("scanner detected clean input")
	}
	if scanner.tailN != scannerOverlap {
		t.Fatalf("tail length = %d, want %d", scanner.tailN, scannerOverlap)
	}

	match, found := scanner.Scan([]byte("password=value"))
	if !found || match.detector != "credential_assignment" {
		t.Fatalf("scanner match = (%q, %t), want credential assignment", match.detector, found)
	}
	if scanner.tailN != 0 {
		t.Fatalf("tail length after match = %d, want 0", scanner.tailN)
	}
	for index, value := range scanner.tail {
		if value != 0 {
			t.Fatalf("tail[%d] = %d after match, want zero", index, value)
		}
	}
}
func TestCredentialScannerDetectsEveryChunkSplitAndErasesTail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		detector string
	}{
		{"authorization bearer", "Authorization: Bearer token", "authorization_bearer"},
		{"password assignment", "password=value", "credential_assignment"},
		{"API key assignment", "api_key:value", "credential_assignment"},
		{"access token assignment", "access token=value", "credential_assignment"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", "private_key_pem"},
		{"AWS key", "AKIAIOSFODNN7EXAMPLE", "aws_access_key_id"},
	}
	for _, test := range tests {
		for split := 0; split <= len(test.input); split++ {
			t.Run(test.name, func(t *testing.T) {
				var scanner credentialScanner
				found := false
				for _, chunk := range [][]byte{
					[]byte(test.input[:split]),
					[]byte(test.input[split:]),
				} {
					match, matched := scanner.Scan(chunk)
					if !matched {
						continue
					}
					if match.detector != test.detector {
						t.Fatalf("detector = %q, want %q at split %d", match.detector, test.detector, split)
					}
					found = true
					break
				}
				if !found {
					t.Fatalf("scanner missed %q at split %d", test.input, split)
				}
				if scanner.tailN != 0 {
					t.Fatalf("tail length after match = %d, want zero", scanner.tailN)
				}
				for index, value := range scanner.tail {
					if value != 0 {
						t.Fatalf("tail[%d] = %d after match, want zero", index, value)
					}
				}
			})
		}
	}
}

func TestCredentialScannerLargeChunksAndNearMisses(t *testing.T) {
	t.Run("credential inside large chunk", func(t *testing.T) {
		var scanner credentialScanner
		input := append([]byte(strings.Repeat("x", scannerOverlap+1)), []byte("password=value")...)
		input = append(input, []byte(strings.Repeat("y", streamBufferSize))...)
		match, found := scanner.Scan(input)
		if !found || match.detector != "credential_assignment" {
			t.Fatalf("large chunk match = (%q, %t), want credential assignment", match.detector, found)
		}
		if scanner.tailN != 0 {
			t.Fatalf("tail length after large-chunk match = %d, want zero", scanner.tailN)
		}
	})

	t.Run("tail to large prefix", func(t *testing.T) {
		var scanner credentialScanner
		if _, found := scanner.Scan([]byte("Authorization: Bea")); found {
			t.Fatal("scanner detected incomplete prefix")
		}
		large := append([]byte("rer token"), []byte(strings.Repeat("z", streamBufferSize))...)
		match, found := scanner.Scan(large)
		if !found || match.detector != "authorization_bearer" {
			t.Fatalf("cross-boundary large match = (%q, %t), want authorization bearer", match.detector, found)
		}
	})

	for _, clean := range []string{
		"Authorization: Beare",
		"password-value",
		"api_key value",
		"-----BEGIN RSA PRIVATE CERTIFICATE-----",
		"AKIAIOSFODNN7EXAMPL!",
		"Authorization:" + strings.Repeat(" ", 9) + "Bearer token",
	} {
		var scanner credentialScanner
		if match, found := scanner.Scan([]byte(clean)); found {
			t.Errorf("near miss %q matched detector %q", clean, match.detector)
		}
	}
}
