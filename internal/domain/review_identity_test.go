package domain

import (
	"strings"
	"testing"
)

func TestReviewIdentityValuesRejectNoncanonicalDigests(t *testing.T) {
	for _, value := range []string{"", "sha256:", "sha256:" + strings.Repeat("0", 64), "sha256:" + strings.Repeat("A", 64), strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 63)} {
		if _, err := ParseProjectBinding(value); err == nil {
			t.Fatal("invalid project binding accepted")
		}
		if _, err := ParseCaptureIdentity(value); err == nil {
			t.Fatal("invalid capture identity accepted")
		}
		if _, err := ParseRequestIdentity(value); err == nil {
			t.Fatal("invalid request identity accepted")
		}
		if _, err := ParsePublicationReceipt(value); err == nil {
			t.Fatal("invalid publication receipt accepted")
		}
	}
	value := "sha256:" + strings.Repeat("a", 64)
	project, _ := ParseProjectBinding(value)
	capture, _ := ParseCaptureIdentity(value)
	request, _ := ParseRequestIdentity(value)
	receipt, _ := ParsePublicationReceipt(value)
	if !project.Valid() || !capture.Valid() || !request.Valid() || !receipt.Valid() || project.String() != value || capture.String() != value || request.String() != value || receipt.String() != value {
		t.Fatal("canonical identities rejected")
	}
}
