package reviewrun

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestIdentityExamplesPinCanonicalEncodings(t *testing.T) {
	captureBytes, err := os.ReadFile("../../builtin/assets/examples/capture-manifest.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := DecodeCaptureManifest(captureBytes)
	if err != nil {
		t.Fatal(err)
	}
	id, err := capture.Identity()
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, err := os.ReadFile("../../builtin/assets/examples/request-receipt.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeRequestReceipt(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if request.CaptureIdentity != id.String() {
		t.Fatal("independent fixture capture digest diverged")
	}
	for name, data := range map[string][]byte{
		"missing digest":     bytes.Replace(requestBytes, []byte(request.RequestDigest), nil, 1),
		"unknown field":      append([]byte(`{"unknown":true,`), requestBytes[1:]...),
		"duplicate field":    append([]byte(`{"request_digest":"",`), requestBytes[1:]...),
		"tampered component": bytes.Replace(requestBytes, []byte(request.Components.Roles), []byte(request.Components.Objective), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequestReceipt(data); err == nil {
				t.Fatal("malformed receipt accepted")
			}
		})
	}
	// This old preflight fixture was frozen before application ownership moved.
	data, err := os.ReadFile("../../builtin/assets/examples/review-preflight.v5.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		FileSets []struct {
			ID     string          `json:"id"`
			Policy string          `json:"policy_identity"`
			Files  []PreflightFile `json:"files"`
		} `json:"file_sets"`
	}
	if err := json.Unmarshal(data, &old); err != nil {
		t.Fatal(err)
	}
	if len(old.FileSets) == 0 {
		t.Fatal("historical file set missing")
	}
	for _, set := range old.FileSets {
		got, err := PreflightFileSetID(set.Policy, set.Files)
		if err != nil || got != set.ID {
			t.Fatalf("historical file set changed: got %s, want %s, err %v", got, set.ID, err)
		}
	}
}
