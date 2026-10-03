package domain

import (
	"strings"
	"testing"
)

func TestLiveTargetIdentityDoesNotClaimCapturedContent(t *testing.T) {
	identity, err := NewLiveTargetIdentity(strings.Repeat("a", 64), "", strings.Repeat("b", 40))
	if err != nil || identity.Kind() != TargetLiveSource || identity.SHA256() != "" || identity.SourceIdentitySHA256() != strings.Repeat("a", 64) || identity.HeadTreeObjectID() != "" || identity.IndexTreeObjectID() != "" {
		t.Fatalf("live target identity: %#v, %v", identity, err)
	}
	if _, err := NewTargetIdentity(TargetIdentityInput{Kind: TargetLiveSource, SHA256: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("captured target constructor accepted live source authority")
	}
	for _, value := range []string{"", strings.Repeat("0", 64), "sha256:" + strings.Repeat("a", 64), strings.Repeat("A", 64)} {
		if _, err := NewLiveTargetIdentity(value, "", ""); err == nil {
			t.Fatal("accepted invalid selection digest")
		}
	}
	if _, err := NewLiveTargetIdentity(strings.Repeat("a", 64), "HEAD", ""); err == nil {
		t.Fatal("accepted unresolved Git operand")
	}
}
