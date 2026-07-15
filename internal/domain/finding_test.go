package domain

import (
	"reflect"
	"testing"
)

func mustFinding(t *testing.T, severity Severity, path string, line int, role Role, provider, title, rule, region string) Finding {
	t.Helper()
	finding, err := NewFinding(FindingInput{
		Severity: severity, Path: path, LineStart: line, Role: role, ProviderInstance: provider,
		Title: title, Description: "description", Recommendation: "recommendation",
		Confidence: ConfidenceHigh, Lifecycle: FindingOpen, EvidenceState: EvidenceVerified,
		NormalizedRuleCategory: rule, NormalizedEvidenceRegion: region,
	})
	if err != nil {
		t.Fatal(err)
	}
	return finding
}
func TestFindingWithEvidenceStatePreservesImmutableFields(t *testing.T) {
	t.Parallel()

	ordered, err := OrderAndAssignFindings([]Finding{
		mustFinding(t, SeverityHigh, "src/finding.go", 12, RoleSecurity, "provider-a", "title", "rule", "region"),
	})
	if err != nil {
		t.Fatal(err)
	}
	original := ordered[0]
	before := original
	for _, state := range []EvidenceState{
		EvidenceVerified,
		EvidencePartiallyVerified,
		EvidenceUnverified,
		EvidenceInvalidPath,
		EvidenceInvalidLine,
		EvidenceQuoteMismatch,
		EvidenceOutsideScope,
	} {
		t.Run(string(state), func(t *testing.T) {
			updated, err := original.WithEvidenceState(state)
			if err != nil {
				t.Fatal(err)
			}
			want := original
			want.evidenceState = state
			if updated != want {
				t.Fatalf("transition changed fields other than evidence state: got %#v, want %#v", updated, want)
			}
			if original != before {
				t.Fatal("transition mutated receiver")
			}
			if updated.ID() != original.ID() ||
				updated.Fingerprint() != original.Fingerprint() ||
				updated.Description() != original.Description() ||
				updated.Recommendation() != original.Recommendation() ||
				updated.Role() != original.Role() ||
				updated.ProviderInstance() != original.ProviderInstance() ||
				updated.NormalizedRuleCategory() != original.NormalizedRuleCategory() ||
				updated.NormalizedEvidenceRegion() != original.NormalizedEvidenceRegion() {
				t.Fatal("transition did not preserve assigned ID or immutable finding content")
			}
		})
	}
}

func TestFindingWithEvidenceStateRejectsInvalidReceiverOrState(t *testing.T) {
	t.Parallel()

	valid := mustFinding(t, SeverityHigh, "src/finding.go", 1, RoleLogic, "provider", "title", "rule", "region")
	tampered := valid
	tampered.fingerprint = "invalid"
	for _, test := range []struct {
		name    string
		finding Finding
		state   EvidenceState
	}{
		{name: "zero receiver", finding: Finding{}, state: EvidenceVerified},
		{name: "tampered receiver", finding: tampered, state: EvidenceVerified},
		{name: "zero state", finding: valid, state: ""},
		{name: "unknown state", finding: valid, state: EvidenceState("unknown")},
	} {
		t.Run(test.name, func(t *testing.T) {
			updated, err := test.finding.WithEvidenceState(test.state)
			if err == nil {
				t.Fatal("invalid transition succeeded")
			}
			if updated != (Finding{}) {
				t.Fatalf("invalid transition returned %#v, want zero finding", updated)
			}
		})
	}
}

func TestOrderAndAssignFindingsRemainsDeterministicAfterEvidenceTransition(t *testing.T) {
	t.Parallel()

	first := mustFinding(t, SeverityHigh, "src/finding.go", 1, RoleLogic, "provider", "title", "rule", "region")
	second := mustFinding(t, SeverityHigh, "src/finding.go", 1, RoleLogic, "provider", "title", "rule", "region")
	first, err := first.WithEvidenceState(EvidenceUnverified)
	if err != nil {
		t.Fatal(err)
	}
	second, err = second.WithEvidenceState(EvidencePartiallyVerified)
	if err != nil {
		t.Fatal(err)
	}

	ordered, err := OrderAndAssignFindings([]Finding{first, second})
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := OrderAndAssignFindings([]Finding{second, first})
	if err != nil {
		t.Fatal(err)
	}
	for index := range ordered {
		if ordered[index].ID() != reversed[index].ID() ||
			ordered[index].EvidenceState() != reversed[index].EvidenceState() ||
			ordered[index].Fingerprint() != reversed[index].Fingerprint() {
			t.Fatalf("transition ordering differs at %d: %#v != %#v", index, ordered[index], reversed[index])
		}
	}
}

func TestOrderAndAssignFindingsIgnoresCompletionOrder(t *testing.T) {
	t.Parallel()

	input := []Finding{
		mustFinding(t, SeverityLow, "b.go", 8, RoleTesting, "z", "last", "test", "b:8"),
		mustFinding(t, SeverityBlocker, "a.go", 20, RoleSecurity, "a", "blocker", "sec", "a:20"),
		mustFinding(t, SeverityHigh, "a.go", 3, RoleLogic, "b", "high", "logic", "a:3"),
		mustFinding(t, SeverityHigh, "a.go", 2, RoleLogic, "b", "earlier", "logic", "a:2"),
	}
	want := []string{"blocker", "earlier", "high", "last"}
	permutationCount := 0
	working := append([]Finding(nil), input...)
	var visit func(int)
	visit = func(index int) {
		if index == len(working) {
			permutationCount++
			ordered, err := OrderAndAssignFindings(working)
			if err != nil {
				t.Fatalf("permutation %d: %v", permutationCount, err)
			}
			titles := make([]string, len(ordered))
			for orderedIndex, finding := range ordered {
				titles[orderedIndex] = finding.Title()
				if finding.ID() != []string{"F001", "F002", "F003", "F004"}[orderedIndex] {
					t.Fatalf("permutation %d ID %d = %q", permutationCount, orderedIndex, finding.ID())
				}
			}
			if !reflect.DeepEqual(titles, want) {
				t.Fatalf("permutation %d order = %v, want %v", permutationCount, titles, want)
			}
			return
		}
		for candidate := index; candidate < len(working); candidate++ {
			working[index], working[candidate] = working[candidate], working[index]
			visit(index + 1)
			working[index], working[candidate] = working[candidate], working[index]
		}
	}
	visit(0)
	if permutationCount != 24 {
		t.Fatalf("visited %d permutations, want 24", permutationCount)
	}
	for _, finding := range input {
		if finding.ID() != "" {
			t.Error("ordering mutated caller finding")
		}
	}
}

func TestFindingTieBreakersProduceTotalOrder(t *testing.T) {
	t.Parallel()

	makeFinding := func(confidence Confidence, lifecycle FindingLifecycle, evidence EvidenceState) Finding {
		t.Helper()
		finding, err := NewFinding(FindingInput{
			Severity: SeverityHigh, Path: "same.go", LineStart: 1, Role: RoleLogic,
			ProviderInstance: "provider", Title: "same", Description: "same",
			Recommendation: "same", Confidence: confidence, Lifecycle: lifecycle,
			EvidenceState: evidence, NormalizedRuleCategory: "rule", NormalizedEvidenceRegion: "region",
		})
		if err != nil {
			t.Fatal(err)
		}
		return finding
	}
	values := []Finding{
		makeFinding(ConfidenceMedium, FindingOpen, EvidenceVerified),
		makeFinding(ConfidenceHigh, FindingOpen, EvidenceVerified),
		makeFinding(ConfidenceHigh, FindingResolved, EvidenceVerified),
		makeFinding(ConfidenceHigh, FindingResolved, EvidenceUnverified),
	}
	reversed := []Finding{values[3], values[2], values[1], values[0]}
	first, err := OrderAndAssignFindings(values)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OrderAndAssignFindings(reversed)
	if err != nil {
		t.Fatal(err)
	}
	for index := range first {
		if first[index].ID() != second[index].ID() ||
			first[index].Confidence() != second[index].Confidence() ||
			first[index].Lifecycle() != second[index].Lifecycle() ||
			first[index].EvidenceState() != second[index].EvidenceState() {
			t.Fatalf("tie order differs at %d: %#v != %#v", index, first[index], second[index])
		}
	}
}

func TestFindingComparatorCoversEveryImmutableField(t *testing.T) {
	t.Parallel()

	base := FindingInput{
		Severity: SeverityHigh, Path: "same.go", LineStart: 1, Role: RoleLogic,
		ProviderInstance: "provider", Title: "title", Description: "description",
		Recommendation: "recommendation", Confidence: ConfidenceHigh,
		Lifecycle: FindingOpen, EvidenceState: EvidenceVerified,
		NormalizedRuleCategory: "rule", NormalizedEvidenceRegion: "region",
	}
	makeFinding := func(mutate func(*FindingInput)) Finding {
		input := base
		mutate(&input)
		finding, err := NewFinding(input)
		if err != nil {
			t.Fatal(err)
		}
		return finding
	}
	assertFirst := func(name string, left, right, want Finding) {
		t.Helper()
		ordered, err := OrderAndAssignFindings([]Finding{left, right})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := ordered[0]
		got.id = ""
		if got != want {
			t.Errorf("%s selected the wrong first finding", name)
		}
	}

	info := makeFinding(func(input *FindingInput) { input.Severity = SeverityInfo })
	blocker := makeFinding(func(input *FindingInput) { input.Severity = SeverityBlocker })
	assertFirst("severity", info, blocker, blocker)

	pathB := makeFinding(func(input *FindingInput) { input.Path = "b.go" })
	pathA := makeFinding(func(input *FindingInput) { input.Path = "a.go" })
	assertFirst("path", pathB, pathA, pathA)

	lineTwo := makeFinding(func(input *FindingInput) { input.LineStart = 2 })
	lineOne := makeFinding(func(input *FindingInput) { input.LineStart = 1 })
	assertFirst("line", lineTwo, lineOne, lineOne)

	security := makeFinding(func(input *FindingInput) { input.Role = RoleSecurity })
	logic := makeFinding(func(input *FindingInput) { input.Role = RoleLogic })
	assertFirst("role", security, logic, logic)

	providerB := makeFinding(func(input *FindingInput) { input.ProviderInstance = "b" })
	providerA := makeFinding(func(input *FindingInput) { input.ProviderInstance = "a" })
	assertFirst("provider", providerB, providerA, providerA)

	titleB := makeFinding(func(input *FindingInput) { input.Title = "b" })
	titleA := makeFinding(func(input *FindingInput) { input.Title = "a" })
	assertFirst("title", titleB, titleA, titleA)

	ruleA := makeFinding(func(input *FindingInput) { input.NormalizedRuleCategory = "rule a" })
	ruleB := makeFinding(func(input *FindingInput) { input.NormalizedRuleCategory = "rule b" })
	if ruleA.Fingerprint() < ruleB.Fingerprint() {
		assertFirst("fingerprint-rule", ruleB, ruleA, ruleA)
	} else {
		assertFirst("fingerprint-rule", ruleA, ruleB, ruleB)
	}

	regionA := makeFinding(func(input *FindingInput) { input.NormalizedEvidenceRegion = "region a" })
	regionB := makeFinding(func(input *FindingInput) { input.NormalizedEvidenceRegion = "region b" })
	if regionA.Fingerprint() < regionB.Fingerprint() {
		assertFirst("fingerprint-region", regionB, regionA, regionA)
	} else {
		assertFirst("fingerprint-region", regionA, regionB, regionB)
	}

	medium := makeFinding(func(input *FindingInput) { input.Confidence = ConfidenceMedium })
	high := makeFinding(func(input *FindingInput) { input.Confidence = ConfidenceHigh })
	assertFirst("confidence", medium, high, high)

	resolved := makeFinding(func(input *FindingInput) { input.Lifecycle = FindingResolved })
	open := makeFinding(func(input *FindingInput) { input.Lifecycle = FindingOpen })
	assertFirst("lifecycle", resolved, open, open)

	verified := makeFinding(func(input *FindingInput) { input.EvidenceState = EvidenceVerified })
	unverified := makeFinding(func(input *FindingInput) { input.EvidenceState = EvidenceUnverified })
	assertFirst("evidence", verified, unverified, unverified)

	descriptionB := makeFinding(func(input *FindingInput) { input.Description = "b" })
	descriptionA := makeFinding(func(input *FindingInput) { input.Description = "a" })
	assertFirst("description", descriptionB, descriptionA, descriptionA)

	recommendationB := makeFinding(func(input *FindingInput) { input.Recommendation = "b" })
	recommendationA := makeFinding(func(input *FindingInput) { input.Recommendation = "a" })
	assertFirst("recommendation", recommendationB, recommendationA, recommendationA)
}
func TestOrderAndAssignRejectsUnvalidatedFinding(t *testing.T) {
	t.Parallel()

	if _, err := OrderAndAssignFindings([]Finding{{}}); err == nil {
		t.Fatal("zero finding received a system ID")
	}
	valid := mustFinding(t, SeverityHigh, "a.go", 1, RoleLogic, "p", "valid", "rule", "region")
	tampered := valid
	tampered.fingerprint = "0"
	if _, err := OrderAndAssignFindings([]Finding{valid, tampered}); err == nil {
		t.Fatal("tampered finding received a system ID")
	}
}
func TestFindingFingerprintUsesNormalizedContractFields(t *testing.T) {
	t.Parallel()

	first := mustFinding(t, SeverityHigh, "src/a.go", 1, RoleLogic, "p", "one", " RULE   A ", " Line  One ")
	second := mustFinding(t, SeverityLow, "src/a.go", 9, RoleSecurity, "q", "two", "rule a", "line one")
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("normalized fingerprints differ: %s != %s", first.Fingerprint(), second.Fingerprint())
	}
	third := mustFinding(t, SeverityHigh, "src/b.go", 1, RoleLogic, "p", "one", "rule a", "line one")
	if first.Fingerprint() == third.Fingerprint() {
		t.Fatal("path change did not affect fingerprint")
	}
	ruleChanged := mustFinding(t, SeverityHigh, "src/a.go", 1, RoleLogic, "p", "one", "other rule", "line one")
	regionChanged := mustFinding(t, SeverityHigh, "src/a.go", 1, RoleLogic, "p", "one", "rule a", "other region")
	if first.Fingerprint() == ruleChanged.Fingerprint() || first.Fingerprint() == regionChanged.Fingerprint() {
		t.Fatal("rule/category or evidence-region change did not affect fingerprint")
	}
}

func TestFindingRejectsUnsafeOrIncompleteInput(t *testing.T) {
	t.Parallel()

	base := FindingInput{
		Severity: SeverityHigh, Path: "src/a.go", LineStart: 1, Role: RoleLogic,
		ProviderInstance: "provider", Title: "title", Description: "description",
		Recommendation: "recommendation", Confidence: ConfidenceHigh,
		Lifecycle: FindingOpen, EvidenceState: EvidenceVerified,
		NormalizedRuleCategory: "rule", NormalizedEvidenceRegion: "region",
	}
	for _, badPath := range []string{"", "/absolute", "../escape", "a//b", "a/./b", "a\\b"} {
		candidate := base
		candidate.Path = badPath
		if _, err := NewFinding(candidate); err == nil {
			t.Errorf("unsafe path %q accepted", badPath)
		}
	}
	candidate := base
	candidate.LineStart = 0
	if _, err := NewFinding(candidate); err == nil {
		t.Error("zero line accepted")
	}
	mutations := []struct {
		name   string
		mutate func(*FindingInput)
	}{
		{"severity", func(input *FindingInput) { input.Severity = "unknown" }},
		{"role", func(input *FindingInput) { input.Role = "unknown" }},
		{"provider", func(input *FindingInput) { input.ProviderInstance = " " }},
		{"title", func(input *FindingInput) { input.Title = "" }},
		{"description", func(input *FindingInput) { input.Description = "" }},
		{"recommendation", func(input *FindingInput) { input.Recommendation = "" }},
		{"confidence", func(input *FindingInput) { input.Confidence = "unknown" }},
		{"lifecycle", func(input *FindingInput) { input.Lifecycle = "unknown" }},
		{"evidence", func(input *FindingInput) { input.EvidenceState = "unknown" }},
		{"rule", func(input *FindingInput) { input.NormalizedRuleCategory = " " }},
		{"region", func(input *FindingInput) { input.NormalizedEvidenceRegion = "" }},
	}
	for _, test := range mutations {
		candidate := base
		test.mutate(&candidate)
		if _, err := NewFinding(candidate); err == nil {
			t.Errorf("invalid %s accepted", test.name)
		}
	}
}
