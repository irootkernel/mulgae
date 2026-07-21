package ports

import (
	"strings"
	"testing"
)

func TestVerifiedConfigInstallReceiptRequiresExactIdentityAndOwnership(t *testing.T) {
	directory, err := NewConfigDirectoryIdentity(1, 2, 501, 0o700, 1, 3, 501, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewConfigFileIdentity(1, 4, 501, 0o600, 1, 12, "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewVerifiedConfigInstallReceipt(directory, config)
	if err != nil || !receipt.Installed() {
		t.Fatalf("verified receipt = (%#v, %v)", receipt, err)
	}

	foreign, err := NewConfigFileIdentity(1, 5, 502, 0o600, 1, 12, "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifiedConfigInstallReceipt(directory, foreign); err == nil {
		t.Fatal("receipt accepted mismatched config ownership")
	}
	if _, err := NewConfigFileIdentity(1, 6, 501, 0o600, 1, 12, "not-a-digest"); err == nil {
		t.Fatal("config identity accepted an invalid digest")
	}
}
