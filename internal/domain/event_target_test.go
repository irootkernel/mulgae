package domain

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDomainEventDefensivePayload(t *testing.T) {
	t.Parallel()

	input := []byte("original")
	event, err := NewDomainEvent(1, time.Unix(1, 0).UTC(), "run.started", "r_test", input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	if !bytes.Equal(event.Payload(), []byte("original")) {
		t.Fatal("event retained caller payload")
	}
	copyOut := event.Payload()
	copyOut[0] = 'Y'
	if !bytes.Equal(event.Payload(), []byte("original")) {
		t.Fatal("event exposed mutable payload")
	}
}

func TestDomainEventRejectsInvalidOrderAndTime(t *testing.T) {
	t.Parallel()

	utc := time.Unix(1, 0).UTC()
	nonUTC := time.Unix(1, 0).In(time.FixedZone("offset", 3600))
	cases := []struct {
		name        string
		sequence    uint64
		occurredAt  time.Time
		kind        string
		aggregateID string
		want        string
	}{
		{"zero sequence", 0, utc, "kind", "id", "domain event: domain invariant violation: sequence must be positive"},
		{"zero timestamp", 1, time.Time{}, "kind", "id", "domain event: domain invariant violation: timestamp must be non-zero"},
		{"non-UTC timestamp", 1, nonUTC, "kind", "id", "domain event: domain invariant violation: timestamp must be UTC"},
		{"blank kind", 1, utc, " ", "id", "domain event: domain invariant violation: kind must be non-empty"},
		{"blank aggregate", 1, utc, "kind", "\t", "domain event: domain invariant violation: aggregate identity must be non-empty"},
		{"first error wins", 0, time.Time{}, "", "", "domain event: domain invariant violation: sequence must be positive"},
	}
	for _, test := range cases {
		_, err := NewDomainEvent(test.sequence, test.occurredAt, test.kind, test.aggregateID, nil)
		if !errors.Is(err, ErrInvariant) {
			t.Errorf("%s error = %v, want invariant", test.name, err)
			continue
		}
		if err.Error() != test.want {
			t.Errorf("%s error = %q, want %q", test.name, err, test.want)
		}
	}
}

func TestTargetIdentityKinds(t *testing.T) {
	t.Parallel()

	sha := "a962bf1a6f4e99c7fe9e0bcb553bbc748cbdfbddfb34f0b90610e33768ae6d17"
	oid := "de9330cd811eee2523745404fa672872113175f1"
	gitTarget, err := NewTargetIdentity(TargetIdentityInput{
		Kind: TargetGit, SHA256: sha, RepositoryID: "repo://example", BaseObjectID: oid,
		HeadObjectID: oid, HeadTreeObjectID: oid,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gitTarget.Kind() != TargetGit || gitTarget.HeadObjectID() != oid {
		t.Fatalf("unexpected Git target: %#v", gitTarget)
	}
	for _, kind := range []TargetKind{TargetPatch, TargetStdin} {
		target, err := NewTargetIdentity(TargetIdentityInput{Kind: kind, SHA256: sha})
		if err != nil {
			t.Errorf("valid %s target: %v", kind, err)
			continue
		}
		if target.Kind() != kind || target.SHA256() != sha {
			t.Errorf("unexpected %s target: %#v", kind, target)
		}
	}
	if _, err := NewTargetIdentity(TargetIdentityInput{Kind: "unknown", SHA256: sha}); err == nil {
		t.Error("unknown target kind accepted")
	}
}

func TestTargetIdentityHashAndObjectBoundaries(t *testing.T) {
	t.Parallel()

	sha := "a962bf1a6f4e99c7fe9e0bcb553bbc748cbdfbddfb34f0b90610e33768ae6d17"
	oid40 := "de9330cd811eee2523745404fa672872113175f1"
	oid64 := strings.Repeat("b", 64)
	validGit := func(oid string) TargetIdentityInput {
		return TargetIdentityInput{
			Kind: TargetGit, SHA256: sha, RepositoryID: "repo://example",
			BaseObjectID: oid, HeadObjectID: oid, HeadTreeObjectID: oid,
		}
	}
	for _, oid := range []string{oid40, oid64} {
		valid := validGit(oid)
		valid.IndexTreeObjectID = oid
		if _, err := NewTargetIdentity(valid); err != nil {
			t.Errorf("valid %d-character Git OID set rejected: %v", len(oid), err)
		}
	}
	input := validGit(oid40)
	input.IndexTreeObjectID = oid40
	captured, err := NewTargetIdentity(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Kind = TargetStdin
	input.SHA256 = strings.Repeat("c", 64)
	input.RepositoryID = "changed"
	input.BaseObjectID = oid64
	input.HeadObjectID = oid64
	input.HeadTreeObjectID = oid64
	input.IndexTreeObjectID = oid64
	if captured.Kind() != TargetGit ||
		captured.SHA256() != sha ||
		captured.RepositoryID() != "repo://example" ||
		captured.BaseObjectID() != oid40 ||
		captured.HeadObjectID() != oid40 ||
		captured.HeadTreeObjectID() != oid40 ||
		captured.IndexTreeObjectID() != oid40 {
		t.Fatalf("target did not preserve validated scalar identity: %#v", captured)
	}

	for _, badSHA := range []string{
		"",
		strings.ToUpper(sha),
		strings.Repeat("0", 64),
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("g", 64),
	} {
		if _, err := NewTargetIdentity(TargetIdentityInput{Kind: TargetStdin, SHA256: badSHA}); err == nil {
			t.Errorf("invalid SHA-256 accepted: %q", badSHA)
		}
	}
	invalidResult, err := NewTargetIdentity(TargetIdentityInput{Kind: TargetStdin, SHA256: strings.Repeat("0", 64)})
	if err == nil {
		t.Fatal("zero digest accepted")
	}
	if invalidResult != (TargetIdentity{}) {
		t.Fatalf("invalid target leaked partial identity: %#v", invalidResult)
	}

	requiredFields := []struct {
		name  string
		clear func(*TargetIdentityInput)
	}{
		{"base", func(input *TargetIdentityInput) { input.BaseObjectID = "" }},
		{"head", func(input *TargetIdentityInput) { input.HeadObjectID = "" }},
		{"head-tree", func(input *TargetIdentityInput) { input.HeadTreeObjectID = "" }},
	}
	for _, field := range requiredFields {
		input := validGit(oid40)
		field.clear(&input)
		if _, err := NewTargetIdentity(input); err == nil {
			t.Errorf("missing Git %s OID accepted", field.name)
		}
	}
	missingRepository := validGit(oid40)
	missingRepository.RepositoryID = ""
	if _, err := NewTargetIdentity(missingRepository); err == nil {
		t.Error("Git target without repository identity accepted")
	}

	invalidOIDs := []string{
		strings.Repeat("a", 39),
		strings.Repeat("a", 41),
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("g", 40),
		strings.ToUpper(oid40),
	}
	invalidOIDs = append(invalidOIDs, strings.Repeat("0", 40), strings.Repeat("0", 64))
	objectFields := []struct {
		name string
		set  func(*TargetIdentityInput, string)
	}{
		{"base", func(input *TargetIdentityInput, value string) { input.BaseObjectID = value }},
		{"head", func(input *TargetIdentityInput, value string) { input.HeadObjectID = value }},
		{"head-tree", func(input *TargetIdentityInput, value string) { input.HeadTreeObjectID = value }},
		{"index-tree", func(input *TargetIdentityInput, value string) { input.IndexTreeObjectID = value }},
	}
	for _, field := range objectFields {
		for _, oid := range invalidOIDs {
			input := validGit(oid40)
			field.set(&input, oid)
			if _, err := NewTargetIdentity(input); err == nil {
				t.Errorf("invalid Git %s OID accepted: %q", field.name, oid)
			}
		}
	}

	for _, kind := range []TargetKind{TargetPatch, TargetStdin} {
		gitFields := []struct {
			name string
			set  func(*TargetIdentityInput)
		}{
			{"repository", func(input *TargetIdentityInput) { input.RepositoryID = "repo://example" }},
			{"base", func(input *TargetIdentityInput) { input.BaseObjectID = oid40 }},
			{"head", func(input *TargetIdentityInput) { input.HeadObjectID = oid40 }},
			{"head-tree", func(input *TargetIdentityInput) { input.HeadTreeObjectID = oid40 }},
			{"index-tree", func(input *TargetIdentityInput) { input.IndexTreeObjectID = oid40 }},
		}
		for _, field := range gitFields {
			input := TargetIdentityInput{Kind: kind, SHA256: sha}
			field.set(&input)
			if _, err := NewTargetIdentity(input); err == nil {
				t.Errorf("%s accepted Git-only %s field", kind, field.name)
			}
		}
	}

	multipleInvalid := validGit(oid40)
	multipleInvalid.BaseObjectID = "bad-base"
	multipleInvalid.HeadObjectID = "bad-head"
	multipleInvalid.HeadTreeObjectID = "bad-tree"
	_, err = NewTargetIdentity(multipleInvalid)
	wantError := "target identity: domain invariant violation: base object is not a canonical nonzero Git object ID"
	if !errors.Is(err, ErrInvariant) || err == nil || err.Error() != wantError {
		t.Fatalf("multiple-invalid Git target error = %v, want exact %q", err, wantError)
	}
}
