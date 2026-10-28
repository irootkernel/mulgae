//go:build darwin && arm64

package publication

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/artifactwire"
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
			actual, want := publicationGoldenVectorLines(t, bundle), publicationGoldenVectors[family.name]
			if len(actual) != len(want) {
				t.Fatal("current version dropped a retained member")
			}
			for i, line := range actual {
				oldFields, newFields := strings.Fields(want[i]), strings.Fields(line)
				if len(oldFields) != 3 || len(newFields) != 3 || oldFields[0] != newFields[0] || oldFields[1] != newFields[1] {
					t.Fatal("current version changed retained member identity/order")
				}
				versionBound := i < 7 || strings.HasSuffix(newFields[1], "/support/index.json")
				if !versionBound && line != want[i] {
					t.Fatal("unchanged retained support bytes drifted")
				}
			}
			for name, raw := range map[string][]byte{"final": bundle.Final().Bytes(), "manifest": bundle.Manifest().Bytes()} {
				var value map[string]json.RawMessage
				if err := json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				expected := artifactwire.ReviewArtifactV4
				if name == "manifest" {
					expected = artifactwire.RunManifestV4
				}
				if string(value["schema_version"]) != `"`+expected+`"` || string(value["requirements_support"]) != "null" {
					t.Fatal("current producer lost v4/explicit-null expectation")
				}
			}
			for _, member := range bundle.SupportArtifacts() {
				if strings.HasSuffix(member.Path().String(), "/support/index.json") {
					var index runSupportIndexWire
					if err := json.Unmarshal(member.Bytes(), &index); err != nil || index.SchemaVersion != artifactwire.SupportIndexV4 {
						t.Fatal("current support index lost v4 expectation")
					}
				}
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
		got, ok := actual[key]
		if !ok {
			t.Fatalf("missing retained live member: %s", key)
		}
		// v3 is a historical wire contract after the v4 cutover. Verify its
		// exact DTO bytes without retaining a legacy production emitter.
		var destination any
		switch {
		case strings.HasSuffix(key, "/final"):
			destination = &finalReviewWire{}
		case strings.HasSuffix(key, "/manifest"):
			destination = &runManifestWire{}
		case strings.HasSuffix(key, "/journal"):
			destination = &publicationJournalWire{}
		case strings.HasSuffix(key, "/status"):
			destination = &publicationStatusWire{}
		case strings.HasSuffix(key, "/epoch"):
			destination = &publicationEpochWire{}
		case strings.HasSuffix(key, "/support/index.json"):
			destination = &runSupportIndexWire{}
		}
		if destination != nil {
			if err := unmarshalCanonicalPublicationRecord([]byte(expected[key]), destination, "retained historical live wire"); err != nil {
				t.Fatal(err)
			}
			raw, err := marshalCanonical(destination)
			if err != nil {
				t.Fatal(err)
			}
			got = string(raw)
		}
		if got != expected[key] {
			t.Fatalf("retained legacy DTO/support bytes changed: %s", key)
		}
	}
	if count != len(actual) {
		t.Fatal("unclassified actual live output")
	}
}
