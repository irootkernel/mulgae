package ports

import (
	"errors"
	"testing"
)

func TestConfigFileProofBindsPrivateDirectoryIdentity(t *testing.T) {
	proof, err := NewConfigFileProof(true, 1, 2, 501, 0o700, 1, 3, 501, 0o700, 1, 4, 501, 0o600, 1, 12, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	device, inode, uid, mode := proof.PrivateDirectoryIdentity()
	if device != 1 || inode != 3 || uid != 501 || mode != 0o700 {
		t.Fatalf("private identity = %d/%d/%d/%o", device, inode, uid, mode)
	}
	replacement, err := NewConfigFileProof(true, 1, 2, 501, 0o700, 1, 30, 501, 0o700, 1, 4, 501, 0o600, 1, 12, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if proof.Equal(replacement) {
		t.Fatal("private directory substitution preserved proof equality")
	}
}

func TestConfigFileProofRejectsPresentConfigWithoutPrivateDirectory(t *testing.T) {
	if _, err := NewConfigFileProof(true, 1, 2, 501, 0o700, 0, 0, 0, 0, 1, 4, 501, 0o600, 1, 12, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Fatal("present config without private directory was accepted")
	}
	if _, err := NewConfigFileProof(false, 1, 2, 501, 0o700, 1, 3, 501, 0o700, 0, 0, 0, 0, 0, 0, ""); err != nil {
		t.Fatalf("safe absent config in existing private directory rejected: %v", err)
	}
}

func TestConfigLocalityViolationRetainsOnlyClosedReason(t *testing.T) {
	cause := errors.New("sensitive adapter detail")
	err := NewConfigLocalityViolation(ConfigLocalityTargetPrivateConfigForbidden, cause)
	reason, ok := ConfigLocalityReasonFromError(err)
	if !ok || reason != ConfigLocalityTargetPrivateConfigForbidden || !errors.Is(err, cause) {
		t.Fatalf("violation = %q/%t/%v", reason, ok, err)
	}
	if invalid := NewConfigLocalityViolation("unknown", nil); invalid == nil {
		t.Fatal("invalid locality reason was accepted")
	}
}
