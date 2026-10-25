//go:build darwin && arm64

package publication

import (
	"context"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
)

func retainedLiveNoChange(t *testing.T) PreparedLiveCandidate {
	t.Helper()
	session, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	target := livePublicationEmptyTarget(t)
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := PrepareLiveNoChangeCandidate(session, run, target, []domain.Role{domain.RoleLogic, domain.RoleSecurity}, domain.SeverityHigh, LiveProductionProvenance{BuildProduct: "mulgae", BuildVersion: "test", BuildCommit: "0123456789abcdef", SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestRetainedLiveGoldenBytes(t *testing.T) {
	// Every original inline member belongs to one classified family. Historical
	// construction is X and its readers are F; no expected member is removed.
	inventory := map[string]int{"live-changed-with-attempts": 20, "live-changed": 14, "live-no-change": 9, "captured": 12, "captured-no-change": 8, "runtime": 20, "followup": 18, "composite": 11}
	if len(publicationGoldenVectors) != len(inventory) {
		t.Fatal("unclassified inline golden family")
	}
	for family, count := range inventory {
		if len(publicationGoldenVectors[family]) != count {
			t.Fatalf("inline golden member inventory changed: %s", family)
		}
	}
	for _, family := range []struct {
		name      string
		candidate func(*testing.T) PreparedLiveCandidate
	}{
		{"live-changed", retainedLiveChangedFixture},
		{"live-changed-with-attempts", retainedLiveChangedWithAttemptsFixture},
		{"live-no-change", retainedLiveNoChange},
	} {
		t.Run(family.name, func(t *testing.T) {
			bundle, err := family.candidate(t).Build(context.Background(), retainedSchema(t), publicationIssuedReviewID(t), publicationTestTime(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(publicationGoldenVectorLines(t, bundle), publicationGoldenVectors[family.name]) {
				t.Fatal("actual retained Build differs from original ordered golden vectors")
			}
			assertNoRetiredSupport(t, bundle)
		})
	}
	expected := retainedGoldenMap(t, "m2-publication-wire.json", retainedPublicationGoldenOwners)
	actual := map[string]string{}
	for _, family := range []struct {
		name      string
		candidate PreparedLiveCandidate
	}{
		{"live-empty", retainedLiveNoChange(t)},
		{"live-findings", retainedLiveChangedFixture(t)},
	} {
		bundle, err := family.candidate.Build(context.Background(), retainedSchema(t), publicationIssuedReviewID(t), publicationTestTime(), 1)
		if err != nil {
			t.Fatal(err)
		}
		for member, raw := range map[string][]byte{"final": bundle.Final().Bytes(), "manifest": bundle.Manifest().Bytes(), "journal": bundle.Journal().Bytes(), "status": bundle.Status().Bytes(), "lineage": bundle.LineageEdge().Bytes(), "epoch": bundle.Epoch().Record().Bytes()} {
			actual[family.name+"/"+member] = string(raw)
		}
		for _, a := range bundle.SupportArtifacts() {
			value := string(a.Bytes())
			if !utf8.Valid(a.Bytes()) {
				value = "binary-hex:" + hex.EncodeToString(a.Bytes())
			}
			actual[family.name+"/support/"+a.Path().String()] = value
		}
	}
	count := 0
	for key, owner := range retainedPublicationGoldenOwners {
		if owner != "D:TestRetainedLiveGoldenBytes" {
			continue
		}
		count++
		if got, ok := actual[key]; !ok || got != expected[key] {
			t.Fatalf("actual live bytes changed: %s", key)
		}
	}
	if count != len(actual) {
		t.Fatal("unclassified actual live output")
	}
}
