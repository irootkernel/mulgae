package domain

import (
	"reflect"
	"testing"
)

func TestPublicationClassifierEveryHintObservationPair(t *testing.T) {
	t.Parallel()

	hints := []PersistedJournalState{
		JournalCollecting,
		JournalContentValidated,
		JournalFinalStaged,
		JournalFinalFileInstalled,
		JournalManifestCommitted,
		JournalCompleted,
	}
	observations := []DurableObservationClass{
		DurableObservationP2Committed,
		DurableObservationP1Installed,
		DurableObservationP0Staged,
		DurableObservationP0None,
		DurableObservationAmbiguousOrMismatch,
	}
	for _, hint := range hints {
		for _, observation := range observations {
			input := publicationClassifierInput(t, hint, observation, ExitCommittedPass)
			decision, err := ClassifyPublication(input)
			if err != nil {
				t.Fatalf("%q %q: %v", hint, observation, err)
			}
			wantStatus, wantAuthority, wantAction, wantExit := expectedPublicationDecision(hint, observation, ExitCommittedPass)
			if decision.Status() != wantStatus || decision.Authority() != wantAuthority || decision.Action() != wantAction {
				t.Errorf("%q %q = (%q, %q, %q), want (%q, %q, %q)", hint, observation, decision.Status(), decision.Authority(), decision.Action(), wantStatus, wantAuthority, wantAction)
			}
			gotExit, hasExit := decision.ExitCode()
			if hasExit != (wantExit != nil) || hasExit && gotExit != *wantExit {
				t.Errorf("%q %q exit = (%d, %t), want (%v, %t)", hint, observation, gotExit, hasExit, wantExit, wantExit != nil)
			}
		}
	}
}

func TestPublicationClassifierCrossBoundaryFixtures(t *testing.T) {
	t.Parallel()

	fixtures := []struct {
		id          string
		hint        PersistedJournalState
		observation DurableObservationClass
		exit        OperationalExitCode
		status      PublicationStatus
		authority   PublicationAuthority
		action      RecoveryAction
		wantExit    *OperationalExitCode
	}{
		{
			id:          "pub-cross-content-validated-staged-temp",
			hint:        JournalContentValidated,
			observation: DurableObservationP0Staged,
			status:      PublicationStaged,
			authority:   PublicationAuthorityP0,
			action:      RecoveryActionInstallStagedFinal,
		},
		{
			id:          "pub-cross-final-staged-installed-final",
			hint:        JournalFinalStaged,
			observation: DurableObservationP1Installed,
			status:      PublicationInstalled,
			authority:   PublicationAuthorityP1,
			action:      RecoveryActionCommitCompositeEpoch,
		},
		{
			id:          "pub-cross-final-installed-composite-commit",
			hint:        JournalFinalFileInstalled,
			observation: DurableObservationP2Committed,
			exit:        ExitCommittedPass,
			status:      PublicationCommitted,
			authority:   PublicationAuthorityP2,
			action:      RecoveryActionReconstructCompletedStatus,
			wantExit:    publicationExitPointer(ExitCommittedPass),
		},
		{
			id:          "pub-cross-manifest-committed-completed-side-effect",
			hint:        JournalManifestCommitted,
			observation: DurableObservationP2Committed,
			exit:        ExitCommittedCIRejected,
			status:      PublicationCommitted,
			authority:   PublicationAuthorityP2,
			action:      RecoveryActionReconstructCompletedStatus,
			wantExit:    publicationExitPointer(ExitCommittedCIRejected),
		},
		{
			id:          "pub-cross-hint-low-valid-p2",
			hint:        JournalCollecting,
			observation: DurableObservationP2Committed,
			exit:        ExitIncompleteCoverage,
			status:      PublicationCommitted,
			authority:   PublicationAuthorityP2,
			action:      RecoveryActionReconstructCompletedStatus,
			wantExit:    publicationExitPointer(ExitIncompleteCoverage),
		},
		{
			id:          "pub-cross-staged-and-installed-conflict",
			hint:        JournalFinalStaged,
			observation: DurableObservationAmbiguousOrMismatch,
			status:      PublicationCorrupt,
			authority:   PublicationAuthorityNone,
			action:      RecoveryActionEmitImmutableCorruptionDiagnostic,
			wantExit:    publicationExitPointer(ExitArtifactFailure),
		},
		{
			id:          "pub-cross-p2-manifest-edge-mismatch",
			hint:        JournalCompleted,
			observation: DurableObservationAmbiguousOrMismatch,
			status:      PublicationCorrupt,
			authority:   PublicationAuthorityNone,
			action:      RecoveryActionEmitImmutableCorruptionDiagnostic,
			wantExit:    publicationExitPointer(ExitArtifactFailure),
		},
		{
			id:          "pub-cross-completed-missing-final",
			hint:        JournalCompleted,
			observation: DurableObservationAmbiguousOrMismatch,
			status:      PublicationCorrupt,
			authority:   PublicationAuthorityNone,
			action:      RecoveryActionEmitImmutableCorruptionDiagnostic,
			wantExit:    publicationExitPointer(ExitArtifactFailure),
		},
		{
			id:          "pub-cross-final-installed-no-journal",
			hint:        JournalFinalFileInstalled,
			observation: DurableObservationAmbiguousOrMismatch,
			status:      PublicationCorrupt,
			authority:   PublicationAuthorityNone,
			action:      RecoveryActionEmitImmutableCorruptionDiagnostic,
			wantExit:    publicationExitPointer(ExitArtifactFailure),
		},
		{
			id:          "pub-cross-p0-none-impossible-high-hint",
			hint:        JournalManifestCommitted,
			observation: DurableObservationP0None,
			status:      PublicationCorrupt,
			authority:   PublicationAuthorityNone,
			action:      RecoveryActionEmitImmutableCorruptionDiagnostic,
			wantExit:    publicationExitPointer(ExitArtifactFailure),
		},
	}

	wantIDs := map[string]struct{}{
		"pub-cross-content-validated-staged-temp":            {},
		"pub-cross-final-staged-installed-final":             {},
		"pub-cross-final-installed-composite-commit":         {},
		"pub-cross-manifest-committed-completed-side-effect": {},
		"pub-cross-hint-low-valid-p2":                        {},
		"pub-cross-staged-and-installed-conflict":            {},
		"pub-cross-p2-manifest-edge-mismatch":                {},
		"pub-cross-completed-missing-final":                  {},
		"pub-cross-final-installed-no-journal":               {},
		"pub-cross-p0-none-impossible-high-hint":             {},
	}
	seen := make(map[string]int, len(fixtures))
	for _, fixture := range fixtures {
		seen[fixture.id]++
		input := publicationClassifierInput(t, fixture.hint, fixture.observation, fixture.exit)
		decision, err := ClassifyPublication(input)
		if err != nil {
			t.Fatalf("%s: %v", fixture.id, err)
		}
		if decision.Status() != fixture.status || decision.Authority() != fixture.authority || decision.Action() != fixture.action {
			t.Errorf("%s = (%q, %q, %q), want (%q, %q, %q)", fixture.id, decision.Status(), decision.Authority(), decision.Action(), fixture.status, fixture.authority, fixture.action)
		}
		gotExit, hasExit := decision.ExitCode()
		if hasExit != (fixture.wantExit != nil) || hasExit && gotExit != *fixture.wantExit {
			t.Errorf("%s exit = (%d, %t), want (%v, %t)", fixture.id, gotExit, hasExit, fixture.wantExit, fixture.wantExit != nil)
		}
	}
	if len(seen) != len(wantIDs) {
		t.Fatalf("fixture count = %d, want %d", len(seen), len(wantIDs))
	}
	for id := range wantIDs {
		if seen[id] != 1 {
			t.Errorf("fixture %q occurred %d times, want once", id, seen[id])
		}
	}
}

func TestPublicationClassifierDerivesHighHintP0NoneCorruptionReason(t *testing.T) {
	t.Parallel()

	input, err := NewPublicationClassifierInput(
		JournalCompleted,
		DurableObservationP0None,
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := ClassifyPublication(input)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Status() != PublicationCorrupt ||
		decision.Action() != RecoveryActionEmitImmutableCorruptionDiagnostic ||
		!reflect.DeepEqual(decision.Reasons(), []string{"missing_required_durable_effect"}) {
		t.Fatalf("high-hint P0_NONE decision = (%q, %q, %#v)", decision.Status(), decision.Action(), decision.Reasons())
	}
}

func TestPublicationClassifierStoredNormalExits(t *testing.T) {
	t.Parallel()

	for _, exit := range []OperationalExitCode{ExitCommittedPass, ExitCommittedCIRejected, ExitIncompleteCoverage} {
		input := publicationClassifierInput(t, JournalCollecting, DurableObservationP2Committed, exit)
		decision, err := ClassifyPublication(input)
		if err != nil {
			t.Fatalf("exit %d: %v", exit, err)
		}
		got, ok := decision.ExitCode()
		if !ok || got != exit {
			t.Errorf("stored exit %d produced (%d, %t)", exit, got, ok)
		}
	}
}

func TestPublicationConstructorsRejectInvalidValuesAndDefensivelyCopy(t *testing.T) {
	t.Parallel()

	storedInvalid := ExitConfiguration
	if _, err := NewPublicationClassifierInput("unknown", DurableObservationP0None, nil, nil); err == nil {
		t.Error("unknown journal state accepted")
	}
	if _, err := NewPublicationClassifierInput(JournalCollecting, "unknown", nil, nil); err == nil {
		t.Error("unknown observation class accepted")
	}
	if _, err := NewPublicationClassifierInput(JournalCollecting, DurableObservationP2Committed, nil, nil); err == nil {
		t.Error("P2 without stored normal exit accepted")
	}
	if _, err := NewPublicationClassifierInput(JournalCollecting, DurableObservationP2Committed, &storedInvalid, nil); err == nil {
		t.Error("P2 with non-normal exit accepted")
	}
	if _, err := NewPublicationClassifierInput(JournalCollecting, DurableObservationP0None, publicationExitPointer(ExitCommittedPass), nil); err == nil {
		t.Error("non-P2 stored exit accepted")
	}
	if _, err := NewPublicationClassifierInput(JournalCollecting, DurableObservationAmbiguousOrMismatch, nil, nil); err == nil {
		t.Error("ambiguity without a reason accepted")
	}
	if _, err := NewPublicationClassifierInput(JournalCollecting, DurableObservationP0None, nil, []string{"artifact_mismatch"}); err == nil {
		t.Error("non-ambiguity reasons accepted")
	}

	reasons := []string{"artifact_mismatch"}
	input, err := NewPublicationClassifierInput(JournalCollecting, DurableObservationAmbiguousOrMismatch, nil, reasons)
	if err != nil {
		t.Fatal(err)
	}
	reasons[0] = "mutated"
	if got := input.AmbiguityReasons(); !reflect.DeepEqual(got, []string{"artifact_mismatch"}) {
		t.Fatalf("input retained caller slice: %#v", got)
	}
	copied := input.AmbiguityReasons()
	copied[0] = "mutated"
	if got := input.AmbiguityReasons(); !reflect.DeepEqual(got, []string{"artifact_mismatch"}) {
		t.Fatalf("input accessor leaked slice: %#v", got)
	}
	decisionReasons := []string{"artifact_mismatch"}
	decision, err := NewPublicationDecision(
		PublicationCorrupt,
		PublicationAuthorityNone,
		RecoveryActionEmitImmutableCorruptionDiagnostic,
		publicationExitPointer(ExitArtifactFailure),
		decisionReasons,
	)
	if err != nil {
		t.Fatal(err)
	}
	decisionReasons[0] = "mutated"
	if got := decision.Reasons(); !reflect.DeepEqual(got, []string{"artifact_mismatch"}) {
		t.Fatalf("decision retained caller slice: %#v", got)
	}
	decisionCopied := decision.Reasons()
	decisionCopied[0] = "mutated"
	if got := decision.Reasons(); !reflect.DeepEqual(got, []string{"artifact_mismatch"}) {
		t.Fatalf("decision accessor leaked slice: %#v", got)
	}

	if _, err := NewPublicationDecision(PublicationCorrupt, PublicationAuthorityNone, RecoveryActionEmitImmutableCorruptionDiagnostic, publicationExitPointer(ExitCommittedPass), []string{"artifact_mismatch"}); err == nil {
		t.Error("corrupt decision with non-artifact exit accepted")
	}
	if _, err := NewPublicationDecision(PublicationCommitted, PublicationAuthorityP1, RecoveryActionReconstructCompletedStatus, publicationExitPointer(ExitCommittedPass), nil); err == nil {
		t.Error("committed decision with P1 authority accepted")
	}
	if _, err := NewExitReason(3, "invalid_exit"); err == nil {
		t.Error("unknown exit code accepted")
	}
	if _, err := NewExitReason(ExitArtifactFailure, "Invalid"); err == nil {
		t.Error("invalid reason code accepted")
	}
	if _, err := NewOperationalExitInput(nil); err == nil {
		t.Error("empty exit input accepted")
	}
}

func TestReduceOperationalExitPairwisePrecedenceAndReasonRetention(t *testing.T) {
	t.Parallel()

	precedence := []OperationalExitCode{
		ExitInternalError,
		ExitArtifactFailure,
		ExitSecurityViolation,
		ExitCancelled,
		ExitConfiguration,
		ExitIncompleteCoverage,
		ExitCommittedCIRejected,
		ExitCommittedPass,
	}
	for higherIndex, higher := range precedence {
		for _, lower := range precedence[higherIndex+1:] {
			input := operationalExitInput(t, []ExitReason{
				mustExitReason(t, lower, "lower_reason"),
				mustExitReason(t, higher, "higher_reason"),
			})
			decision, err := ReduceOperationalExit(input)
			if err != nil {
				t.Fatalf("%d over %d: %v", higher, lower, err)
			}
			if decision.Code() != higher {
				t.Errorf("%d over %d selected %d", higher, lower, decision.Code())
			}
			wantReasons := []ExitReason{
				mustExitReason(t, lower, "lower_reason"),
				mustExitReason(t, higher, "higher_reason"),
			}
			if got := decision.Reasons(); !reflect.DeepEqual(got, wantReasons) {
				t.Errorf("%d over %d retained %#v, want %#v", higher, lower, got, wantReasons)
			}
		}
	}
}

func TestOutcomeAxesWithPublicationStatusPreservesIndependentAxes(t *testing.T) {
	t.Parallel()

	axes, err := ComputeOutcomeAxes(nil, validRequiredResults(), SeverityHigh, PublicationNotPublished, nil)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := axes.WithPublicationStatus(PublicationCommitted)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ContentVerdict() != axes.ContentVerdict() || updated.CoverageStatus() != axes.CoverageStatus() || updated.CIDecision() != axes.CIDecision() || updated.PublicationStatus() != PublicationCommitted {
		t.Fatalf("publication replacement changed independent axes: before %#v after %#v", axes, updated)
	}
	if _, err := axes.WithPublicationStatus("unknown"); err == nil {
		t.Error("unknown publication status accepted")
	}
}

func publicationClassifierInput(t *testing.T, hint PersistedJournalState, observation DurableObservationClass, exit OperationalExitCode) PublicationClassifierInput {
	t.Helper()
	var stored *OperationalExitCode
	var reasons []string
	if observation == DurableObservationP2Committed {
		stored = publicationExitPointer(exit)
	}
	if observation == DurableObservationAmbiguousOrMismatch {
		reasons = []string{"artifact_mismatch"}
	}
	input, err := NewPublicationClassifierInput(hint, observation, stored, reasons)
	if err != nil {
		t.Fatalf("NewPublicationClassifierInput(%q, %q): %v", hint, observation, err)
	}
	return input
}

func expectedPublicationDecision(hint PersistedJournalState, observation DurableObservationClass, stored OperationalExitCode) (PublicationStatus, PublicationAuthority, RecoveryAction, *OperationalExitCode) {
	switch observation {
	case DurableObservationAmbiguousOrMismatch:
		return PublicationCorrupt, PublicationAuthorityNone, RecoveryActionEmitImmutableCorruptionDiagnostic, publicationExitPointer(ExitArtifactFailure)
	case DurableObservationP2Committed:
		return PublicationCommitted, PublicationAuthorityP2, RecoveryActionReconstructCompletedStatus, publicationExitPointer(stored)
	case DurableObservationP1Installed:
		return PublicationInstalled, PublicationAuthorityP1, RecoveryActionCommitCompositeEpoch, nil
	case DurableObservationP0Staged:
		return PublicationStaged, PublicationAuthorityP0, RecoveryActionInstallStagedFinal, nil
	case DurableObservationP0None:
		switch hint {
		case JournalCollecting:
			return PublicationNotPublished, PublicationAuthorityNone, RecoveryActionResumeCollection, nil
		case JournalContentValidated, JournalFinalStaged:
			return PublicationNotPublished, PublicationAuthorityNone, RecoveryActionRestageValidatedCandidate, nil
		default:
			return PublicationCorrupt, PublicationAuthorityNone, RecoveryActionEmitImmutableCorruptionDiagnostic, publicationExitPointer(ExitArtifactFailure)
		}
	}
	return "", "", "", nil
}

func publicationExitPointer(exit OperationalExitCode) *OperationalExitCode {
	copyExit := exit
	return &copyExit
}

func mustExitReason(t *testing.T, code OperationalExitCode, reason string) ExitReason {
	t.Helper()
	value, err := NewExitReason(code, reason)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func operationalExitInput(t *testing.T, reasons []ExitReason) OperationalExitInput {
	t.Helper()
	input, err := NewOperationalExitInput(reasons)
	if err != nil {
		t.Fatal(err)
	}
	return input
}
