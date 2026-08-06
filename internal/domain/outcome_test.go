package domain

import "testing"

func validRequiredResults() []RoleResultSummary {
	return []RoleResultSummary{
		{Role: RoleLogic, Selected: true, Required: true, Valid: true},
		{Role: RoleSecurity, Selected: true, Required: true, Valid: true},
	}
}

func TestComputeOutcomeAxesRemainIndependent(t *testing.T) {
	t.Parallel()

	finding := mustFinding(t, SeverityHigh, "a.go", 1, RoleLogic, "p", "change", "rule", "region")
	axes, err := ComputeOutcomeAxes([]Finding{finding}, validRequiredResults(), "", PublicationStaged, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.ContentVerdict() != ContentRequestChanges || axes.CoverageStatus() != CoverageComplete || axes.PublicationStatus() != PublicationStaged || axes.CIDecision() != CIFail {
		t.Fatalf("axes collapsed or incorrect: %#v", axes)
	}

	results := validRequiredResults()
	results[0].Valid = false
	axes, err = ComputeOutcomeAxes([]Finding{finding}, results, SeverityHigh, PublicationCommitted, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.ContentVerdict() != ContentRequestChanges || axes.CoverageStatus() != CoverageIncomplete || axes.PublicationStatus() != PublicationCommitted || axes.CIDecision() != CIFail {
		t.Fatalf("retained-finding incomplete axes incorrect: %#v", axes)
	}
}

func TestComputeCoverageRequiredAndOptional(t *testing.T) {
	t.Parallel()

	axes, err := ComputeOutcomeAxes(nil, nil, SeverityHigh, PublicationNotPublished, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.CoverageStatus() != CoverageComplete || axes.ContentVerdict() != ContentNoFindings {
		t.Fatalf("empty selected subset = %#v", axes)
	}

	optionalOnly := []RoleResultSummary{{Role: RoleDocumentation, Selected: true, Valid: true}}
	axes, err = ComputeOutcomeAxes(nil, optionalOnly, SeverityHigh, PublicationNotPublished, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.CoverageStatus() != CoverageComplete {
		t.Fatalf("valid optional-only result coverage = %q", axes.CoverageStatus())
	}

	results := append(validRequiredResults(), RoleResultSummary{Role: RoleDocumentation, Selected: true, Valid: false})
	axes, err = ComputeOutcomeAxes(nil, results, SeverityHigh, PublicationNotPublished, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.CoverageStatus() != CoverageIncomplete {
		t.Fatalf("invalid optional result coverage = %q", axes.CoverageStatus())
	}
	optionalDegraded := append(validRequiredResults(), RoleResultSummary{Role: RoleDocumentation, Selected: true, Valid: true, Degraded: true})
	axes, err = ComputeOutcomeAxes(nil, optionalDegraded, SeverityHigh, PublicationNotPublished, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.CoverageStatus() != CoverageDegraded {
		t.Fatalf("degraded optional result coverage = %q", axes.CoverageStatus())
	}

	results[2].Required = true
	axes, err = ComputeOutcomeAxes(nil, results, SeverityHigh, PublicationNotPublished, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.CoverageStatus() != CoverageIncomplete {
		t.Fatalf("invalid additional required result coverage = %q", axes.CoverageStatus())
	}
}

func TestEverySelectedRequiredRoleInvalidIsIncompleteAndDegradedIsDegraded(t *testing.T) {
	t.Parallel()

	for _, role := range FixedRoleOrder() {
		for _, state := range []struct {
			name     string
			valid    bool
			degraded bool
			want     CoverageStatus
		}{
			{name: "invalid", valid: false, want: CoverageIncomplete},
			{name: "degraded", valid: true, degraded: true, want: CoverageDegraded},
		} {
			results := validRequiredResults()
			found := false
			for index := range results {
				if results[index].Role == role {
					results[index].Valid = state.valid
					results[index].Degraded = state.degraded
					found = true
					break
				}
			}
			if !found {
				results = append(results, RoleResultSummary{
					Role:     role,
					Selected: true,
					Required: true,
					Valid:    state.valid,
					Degraded: state.degraded,
				})
			}
			axes, err := ComputeOutcomeAxes(nil, results, SeverityHigh, PublicationNotPublished, nil)
			if err != nil {
				t.Fatalf("%s %s: %v", role, state.name, err)
			}
			if axes.CoverageStatus() != state.want {
				t.Errorf("%s %s coverage = %q, want %q", role, state.name, axes.CoverageStatus(), state.want)
			}
		}
	}
}

func TestCoverageAdversarialMatrix(t *testing.T) {
	t.Parallel()

	base := validRequiredResults()
	cases := []struct {
		name    string
		results []RoleResultSummary
		want    CoverageStatus
		wantErr bool
	}{
		{"security-only subset", base[1:], CoverageComplete, false},
		{"logic-only subset", base[:1], CoverageComplete, false},
		{"required unselected", append(base, RoleResultSummary{Role: RoleTesting, Required: true, Selected: false, Valid: true}), CoverageIncomplete, false},
		{"optional unselected invalid", append(base, RoleResultSummary{Role: RoleTesting, Selected: false, Valid: false}), CoverageComplete, false},
		{"optional selected degraded", append(base, RoleResultSummary{Role: RoleTesting, Selected: true, Valid: true, Degraded: true}), CoverageDegraded, false},
		{"duplicate role", append(base, base[0]), "", true},
		{"invalid role", append(base, RoleResultSummary{Role: "unknown", Selected: true, Valid: true}), "", true},
	}
	for _, test := range cases {
		axes, err := ComputeOutcomeAxes(nil, test.results, SeverityHigh, PublicationNotPublished, nil)
		if test.wantErr {
			if err == nil {
				t.Errorf("%s: expected error", test.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", test.name, err)
			continue
		}
		if got := axes.CoverageStatus(); got != test.want {
			t.Errorf("%s: coverage = %q, want %q", test.name, got, test.want)
		}
	}
}

func TestSeverityThresholds(t *testing.T) {
	t.Parallel()

	results := validRequiredResults()
	for _, test := range []struct {
		severity  Severity
		threshold Severity
		want      ContentVerdict
	}{
		{SeverityInfo, SeverityHigh, ContentFindingsPresent},
		{SeverityHigh, SeverityHigh, ContentRequestChanges},
		{SeverityCritical, SeverityBlocker, ContentFindingsPresent},
		{SeverityBlocker, SeverityBlocker, ContentRequestChanges},
	} {
		finding := mustFinding(t, test.severity, "a.go", 1, RoleLogic, "p", string(test.severity), "rule", string(test.severity))
		axes, err := ComputeOutcomeAxes([]Finding{finding}, results, test.threshold, PublicationNotPublished, nil)
		if err != nil {
			t.Fatal(err)
		}
		if axes.ContentVerdict() != test.want {
			t.Errorf("severity %q threshold %q = %q, want %q", test.severity, test.threshold, axes.ContentVerdict(), test.want)
		}
	}
}

func TestEverySeverityThresholdPair(t *testing.T) {
	t.Parallel()

	severities := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical, SeverityBlocker}
	for findingIndex, findingSeverity := range severities {
		for thresholdIndex, threshold := range severities {
			finding := mustFinding(t, findingSeverity, "a.go", 1, RoleLogic, "p", string(findingSeverity), "rule", string(findingSeverity))
			axes, err := ComputeOutcomeAxes([]Finding{finding}, validRequiredResults(), threshold, PublicationNotPublished, nil)
			if err != nil {
				t.Fatalf("severity %q threshold %q: %v", findingSeverity, threshold, err)
			}
			want := ContentFindingsPresent
			if findingIndex >= thresholdIndex {
				want = ContentRequestChanges
			}
			if axes.ContentVerdict() != want {
				t.Errorf("severity %q threshold %q = %q, want %q", findingSeverity, threshold, axes.ContentVerdict(), want)
			}
		}
	}
	if _, err := ComputeOutcomeAxes(nil, validRequiredResults(), "unknown", PublicationNotPublished, nil); err == nil {
		t.Error("invalid threshold accepted")
	}
}

func TestDefaultThresholdAndMalformedFindingOrder(t *testing.T) {
	t.Parallel()

	medium := mustFinding(t, SeverityMedium, "a.go", 1, RoleLogic, "p", "medium", "rule", "medium")
	high := mustFinding(t, SeverityHigh, "b.go", 1, RoleLogic, "p", "high", "rule", "high")
	axes, err := ComputeOutcomeAxes([]Finding{medium}, validRequiredResults(), "", PublicationNotPublished, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.ContentVerdict() != ContentFindingsPresent {
		t.Fatalf("empty threshold treated medium as request changes: %q", axes.ContentVerdict())
	}
	axes, err = ComputeOutcomeAxes([]Finding{high}, validRequiredResults(), "", PublicationNotPublished, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.ContentVerdict() != ContentRequestChanges {
		t.Fatalf("empty threshold did not treat high as request changes: %q", axes.ContentVerdict())
	}
	for _, findings := range [][]Finding{{high, {}}, {{}, high}} {
		if _, err := ComputeOutcomeAxes(findings, validRequiredResults(), "", PublicationNotPublished, nil); err == nil {
			t.Error("malformed finding accepted based on input order")
		}
	}
}
func TestExplicitCIPolicyDoesNotEraseOtherAxes(t *testing.T) {
	t.Parallel()

	finding := mustFinding(t, SeverityBlocker, "a.go", 1, RoleLogic, "p", "block", "rule", "region")
	policy := &CIPolicy{}
	axes, err := ComputeOutcomeAxes([]Finding{finding}, validRequiredResults(), SeverityHigh, PublicationCommitted, policy)
	if err != nil {
		t.Fatal(err)
	}
	if axes.ContentVerdict() != ContentRequestChanges || axes.CIDecision() != CIPass || axes.PublicationStatus() != PublicationCommitted {
		t.Fatalf("explicit CI projection erased axes: %#v", axes)
	}
}
func TestFailingCoveragePolicyPreservesOtherAxes(t *testing.T) {
	t.Parallel()

	results := append(validRequiredResults(), RoleResultSummary{Role: RoleTesting, Selected: true, Valid: true, Degraded: true})
	policy := &CIPolicy{DegradedReviewFails: true}
	axes, err := ComputeOutcomeAxes(nil, results, SeverityHigh, PublicationInstalled, policy)
	if err != nil {
		t.Fatal(err)
	}
	if axes.ContentVerdict() != ContentNoFindings ||
		axes.CoverageStatus() != CoverageDegraded ||
		axes.PublicationStatus() != PublicationInstalled ||
		axes.CIDecision() != CIFail {
		t.Fatalf("failing CI projection erased independent axes: %#v", axes)
	}
}

func TestReportsOnlyContentVerdictDoesNotInventFindingsOrFailCI(t *testing.T) {
	t.Parallel()

	results := []RoleResultSummary{
		{Role: RoleLogic, Selected: true, Required: true, Valid: true, ReportsOnly: true},
		{Role: RoleSecurity, Selected: true, Required: true, Valid: true, ReportsOnly: true},
	}
	axes, err := ComputeOutcomeAxes(nil, results, SeverityHigh, PublicationNotPublished, nil)
	if err != nil {
		t.Fatal(err)
	}
	if axes.ContentVerdict() != ContentReportsOnly || axes.CoverageStatus() != CoverageComplete || axes.CIDecision() != CIPass {
		t.Fatalf("reports-only axes = %#v", axes)
	}
}

func TestCIPolicyMatrix(t *testing.T) {
	t.Parallel()

	requestFinding := mustFinding(t, SeverityHigh, "a.go", 1, RoleLogic, "p", "change", "rule", "region")
	degradedResults := append(validRequiredResults(), RoleResultSummary{Role: RoleTesting, Selected: true, Valid: true, Degraded: true})
	incompleteResults := validRequiredResults()
	incompleteResults[0].Valid = false

	cases := []struct {
		name     string
		findings []Finding
		results  []RoleResultSummary
		policy   *CIPolicy
		want     CIDecision
	}{
		{"default pass", nil, validRequiredResults(), nil, CIPass},
		{"default request changes fails", []Finding{requestFinding}, validRequiredResults(), nil, CIFail},
		{"default degraded fails", nil, degradedResults, nil, CIFail},
		{"default incomplete fails", nil, incompleteResults, nil, CIFail},
		{"request changes disabled", []Finding{requestFinding}, validRequiredResults(), &CIPolicy{DegradedReviewFails: true, IncompleteReviewFails: true}, CIPass},
		{"degraded disabled", nil, degradedResults, &CIPolicy{RequestChangesFails: true, IncompleteReviewFails: true}, CIPass},
		{"incomplete disabled", nil, incompleteResults, &CIPolicy{RequestChangesFails: true, DegradedReviewFails: true}, CIPass},
	}
	for _, test := range cases {
		axes, err := ComputeOutcomeAxes(test.findings, test.results, SeverityHigh, PublicationNotPublished, test.policy)
		if err != nil {
			t.Errorf("%s: %v", test.name, err)
			continue
		}
		if axes.CIDecision() != test.want {
			t.Errorf("%s: CI decision = %q, want %q", test.name, axes.CIDecision(), test.want)
		}
	}
}
