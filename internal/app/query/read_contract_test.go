package query

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func receiptContractFixture() InspectionReceipt {
	digest := "sha256:" + strings.Repeat("1", 64)
	return InspectionReceipt{SchemaVersion: InspectionReceiptVersion, ProjectBinding: digest, SessionID: "s_01900000-0000-7000-8000-000000000001", RunID: "r_01900000-0000-7000-8000-000000000002", ReviewID: "01900000-0000-7000-8000-000000000003", RunType: "review", TargetSHA256: digest, FinalSHA256: digest, ManifestSHA256: digest, SupportSHA256: digest, Epoch: 1, CaptureIdentity: digest, CaptureAvailability: "verified"}
}

func TestPublicationReceiptBindsOneCompleteObservation(t *testing.T) {
	base := receiptContractFixture()
	identity, err := base.Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InspectionReceipt){
		"project": func(r *InspectionReceipt) { r.ProjectBinding = "sha256:" + strings.Repeat("2", 64) },
		"support": func(r *InspectionReceipt) { r.SupportSHA256 = "sha256:" + strings.Repeat("2", 64) },
		"epoch":   func(r *InspectionReceipt) { r.Epoch++ },
		"capture unavailable": func(r *InspectionReceipt) {
			r.CaptureIdentity = ""
			r.CaptureAvailability = "capture_identity_unavailable"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := changed.Identity()
			if err != nil || got == identity {
				t.Fatalf("receipt change not bound: %v", err)
			}
		})
	}
	base.CaptureAvailability = "capture_identity_unavailable"
	if _, err := base.Identity(); err == nil {
		t.Fatal("unavailable capture retained identity")
	}
	base = receiptContractFixture()
	base.SupportSHA256 = ""
	if _, err := base.Identity(); err == nil {
		t.Fatal("missing support binding accepted")
	}
}

func TestFindingCursorRejectsCrossSnapshotQueryAndNoncanonicalValues(t *testing.T) {
	receipt := receiptContractFixture()
	id, err := receipt.Identity()
	if err != nil {
		t.Fatal(err)
	}
	scope := FindingPageScope{receipt.ProjectBinding, id.String(), receipt.RunID, "findings", "low", 100}
	cursor, err := EncodeFindingCursor(scope, 100)
	if err != nil {
		t.Fatal(err)
	}
	if offset, err := DecodeFindingCursor(cursor, scope); err != nil || offset != 100 {
		t.Fatalf("round trip = %d/%v", offset, err)
	}
	for _, change := range []func(*FindingPageScope){func(s *FindingPageScope) { s.QueryKind = "inspect" }, func(s *FindingPageScope) { s.MinimumSeverity = "high" }, func(s *FindingPageScope) { s.Limit = 10 }, func(s *FindingPageScope) { s.PublicationReceipt = "sha256:" + strings.Repeat("2", 64) }, func(s *FindingPageScope) { s.ProjectBinding = "sha256:" + strings.Repeat("2", 64) }, func(s *FindingPageScope) { s.RunID = "r_01900000-0000-7000-8000-000000000099" }} {
		changed := scope
		change(&changed)
		if _, err := DecodeFindingCursor(cursor, changed); err != ErrCursorMismatch {
			t.Fatalf("foreign query accepted: %v", err)
		}
	}
	for _, invalid := range []string{cursor + "=", "bad", strings.Repeat("x", 4097), cursor[:len(cursor)-1] + "z"} {
		if _, err := DecodeFindingCursor(invalid, scope); err != ErrCursorInvalid {
			t.Fatalf("malformed cursor: %v", err)
		}
	}
	data, err := json.Marshal(findingCursor{FindingCursorVersion, scope, 100})
	if err != nil {
		t.Fatal(err)
	}
	data = append([]byte(`{"offset":100,`), data[1:]...)
	forged := base64.RawURLEncoding.EncodeToString(data) + "." + strings.TrimPrefix(readContractDigest(FindingCursorVersion, data), "sha256:")
	if _, err := DecodeFindingCursor(forged, scope); err != ErrCursorInvalid {
		t.Fatal("duplicate field cursor accepted")
	}
	if _, err := EncodeFindingCursor(scope, 101); err != ErrCursorInvalid {
		t.Fatal("non-issued page boundary accepted")
	}
	for _, test := range []struct{ input, want int }{{0, 100}, {1, 1}, {1000, 1000}} {
		got, err := FindingPageLimit(test.input)
		if err != nil || got != test.want {
			t.Fatalf("limit=%d/%v", got, err)
		}
	}
	for _, invalid := range []int{-1, 1001} {
		if _, err := FindingPageLimit(invalid); err == nil {
			t.Fatal("invalid limit accepted")
		}
	}
}

func TestContentContinuationHasResponseBoundButNoTotalSizeCeiling(t *testing.T) {
	receipt := receiptContractFixture()
	id, err := receipt.Identity()
	if err != nil {
		t.Fatal(err)
	}
	continuation := ContentContinuation{math.MaxInt64, id.String(), receipt.FinalSHA256}
	if err := continuation.Check(id, receipt.FinalSHA256); err != nil {
		t.Fatal(err)
	}
	continuation.ContentSHA256 = ""
	if err := continuation.Validate(); err != ErrReadContinuationIncomplete {
		t.Fatal("unbound continuation accepted")
	}
	continuation.Offset = 0
	if err := continuation.Check(id, receipt.FinalSHA256); err != nil {
		t.Fatal("first read rejected")
	}
	continuation.PublicationReceipt = "sha256:" + strings.Repeat("2", 64)
	if err := continuation.Check(id, receipt.FinalSHA256); err != ErrPublicationReceiptMismatch {
		t.Fatal("stale receipt accepted")
	}
	if err := (VerifiedReadCapabilities{Inspection: "v2"}).Validate(); err == nil {
		t.Fatal("unknown capability version accepted")
	}
	if err := (VerifiedReadCapabilities{}).Validate(); err != nil {
		t.Fatal("unavailable historical capabilities rejected")
	}
}
