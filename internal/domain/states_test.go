package domain

import (
	"errors"
	"testing"
)

func TestRoleTaskTransitionsMatchContract(t *testing.T) {
	t.Parallel()

	allowed := map[[2]RoleTaskState]bool{
		{RoleTaskPending, RoleTaskPrimaryQueued}:          true,
		{RoleTaskPending, RoleTaskCancelled}:              true,
		{RoleTaskPending, RoleTaskBlocked}:                true,
		{RoleTaskPrimaryQueued, RoleTaskPrimaryRunning}:   true,
		{RoleTaskPrimaryQueued, RoleTaskCancelled}:        true,
		{RoleTaskPrimaryQueued, RoleTaskBlocked}:          true,
		{RoleTaskPrimaryRunning, RoleTaskSucceeded}:       true,
		{RoleTaskPrimaryRunning, RoleTaskFallbackQueued}:  true,
		{RoleTaskPrimaryRunning, RoleTaskFailed}:          true,
		{RoleTaskPrimaryRunning, RoleTaskCancelled}:       true,
		{RoleTaskFallbackQueued, RoleTaskFallbackRunning}: true,
		{RoleTaskFallbackQueued, RoleTaskCancelled}:       true,
		{RoleTaskFallbackRunning, RoleTaskSucceeded}:      true,
		{RoleTaskFallbackRunning, RoleTaskFailed}:         true,
		{RoleTaskFallbackRunning, RoleTaskCancelled}:      true,
	}
	states := []RoleTaskState{RoleTaskPending, RoleTaskPrimaryQueued, RoleTaskPrimaryRunning, RoleTaskFallbackQueued, RoleTaskFallbackRunning, RoleTaskSucceeded, RoleTaskFailed, RoleTaskCancelled, RoleTaskBlocked}
	for _, from := range states {
		for _, to := range states {
			want := allowed[[2]RoleTaskState{from, to}]
			if got := from.CanTransition(to); got != want {
				t.Errorf("CanTransition(%q, %q) = %v, want %v", from, to, got, want)
			}
			err := from.RequireTransition(to)
			if want && err != nil {
				t.Errorf("RequireTransition(%q, %q): %v", from, to, err)
			}
			if !want && !errors.Is(err, ErrInvariant) {
				t.Errorf("RequireTransition(%q, %q) error = %v, want invariant", from, to, err)
			}
		}
	}
}

func TestRunTransitionsExhaustive(t *testing.T) {
	t.Parallel()

	states := []RunState{RunPending, RunRunning, RunCompleted, RunDegraded, RunFailed, RunCancelled}
	allowed := map[[2]RunState]bool{
		{RunPending, RunRunning}: true, {RunPending, RunCancelled}: true,
		{RunRunning, RunCompleted}: true, {RunRunning, RunDegraded}: true,
		{RunRunning, RunFailed}: true, {RunRunning, RunCancelled}: true,
	}
	for _, from := range states {
		for _, to := range states {
			want := allowed[[2]RunState{from, to}]
			if got := from.CanTransition(to); got != want {
				t.Errorf("run %q -> %q = %v, want %v", from, to, got, want)
			}
			err := from.RequireTransition(to)
			if want && err != nil {
				t.Errorf("run %q -> %q: %v", from, to, err)
			}
			if !want && !errors.Is(err, ErrInvariant) {
				t.Errorf("run %q -> %q error = %v, want invariant", from, to, err)
			}
		}
	}
	if err := RunState("unknown").RequireTransition(RunRunning); !errors.Is(err, ErrInvariant) {
		t.Errorf("unknown run state error = %v", err)
	}
}

func TestAttemptTransitionsExhaustive(t *testing.T) {
	t.Parallel()

	states := []AttemptState{AttemptQueued, AttemptRunning, AttemptValidating, AttemptRepairing, AttemptSucceeded, AttemptFailed, AttemptTimedOut, AttemptCancelled, AttemptBlocked}
	allowed := map[[2]AttemptState]bool{
		{AttemptQueued, AttemptRunning}: true, {AttemptQueued, AttemptCancelled}: true, {AttemptQueued, AttemptBlocked}: true,
		{AttemptRunning, AttemptValidating}: true, {AttemptRunning, AttemptFailed}: true, {AttemptRunning, AttemptTimedOut}: true, {AttemptRunning, AttemptCancelled}: true, {AttemptRunning, AttemptBlocked}: true,
		{AttemptValidating, AttemptRepairing}: true, {AttemptValidating, AttemptSucceeded}: true, {AttemptValidating, AttemptFailed}: true, {AttemptValidating, AttemptCancelled}: true, {AttemptValidating, AttemptBlocked}: true,
		{AttemptRepairing, AttemptValidating}: true, {AttemptRepairing, AttemptFailed}: true, {AttemptRepairing, AttemptTimedOut}: true, {AttemptRepairing, AttemptCancelled}: true, {AttemptRepairing, AttemptBlocked}: true,
	}
	for _, from := range states {
		for _, to := range states {
			want := allowed[[2]AttemptState{from, to}]
			if got := from.CanTransition(to); got != want {
				t.Errorf("attempt %q -> %q = %v, want %v", from, to, got, want)
			}
			err := from.RequireTransition(to)
			if want && err != nil {
				t.Errorf("attempt %q -> %q: %v", from, to, err)
			}
			if !want && !errors.Is(err, ErrInvariant) {
				t.Errorf("attempt %q -> %q error = %v, want invariant", from, to, err)
			}
		}
	}
	if err := AttemptState("unknown").RequireTransition(AttemptRunning); !errors.Is(err, ErrInvariant) {
		t.Errorf("unknown attempt state error = %v", err)
	}
}

func TestInvocationTransitionsExhaustive(t *testing.T) {
	t.Parallel()

	states := []InvocationState{InvocationQueued, InvocationRunning, InvocationSucceeded, InvocationFailed, InvocationTimedOut, InvocationCancelled, InvocationBlocked}
	allowed := map[[2]InvocationState]bool{
		{InvocationQueued, InvocationRunning}: true, {InvocationQueued, InvocationCancelled}: true, {InvocationQueued, InvocationBlocked}: true,
		{InvocationRunning, InvocationSucceeded}: true, {InvocationRunning, InvocationFailed}: true,
		{InvocationRunning, InvocationTimedOut}: true, {InvocationRunning, InvocationCancelled}: true, {InvocationRunning, InvocationBlocked}: true,
	}
	for _, from := range states {
		for _, to := range states {
			want := allowed[[2]InvocationState{from, to}]
			if got := from.CanTransition(to); got != want {
				t.Errorf("invocation %q -> %q = %v, want %v", from, to, got, want)
			}
			err := from.RequireTransition(to)
			if want && err != nil {
				t.Errorf("invocation %q -> %q: %v", from, to, err)
			}
			if !want && !errors.Is(err, ErrInvariant) {
				t.Errorf("invocation %q -> %q error = %v, want invariant", from, to, err)
			}
		}
	}
	if err := InvocationState("unknown").RequireTransition(InvocationRunning); !errors.Is(err, ErrInvariant) {
		t.Errorf("unknown invocation state error = %v", err)
	}
}

func TestUnknownStatesCannotTransition(t *testing.T) {
	t.Parallel()

	for _, state := range []RunState{RunPending, RunRunning, RunCompleted, RunDegraded, RunFailed, RunCancelled} {
		if state.CanTransition(RunState("unknown")) {
			t.Errorf("run state %q accepted unknown destination", state)
		}
		if err := state.RequireTransition(RunState("unknown")); !errors.Is(err, ErrInvariant) {
			t.Errorf("run state %q unknown destination error = %v, want invariant", state, err)
		}
	}
	if RunState("unknown").CanTransition(RunRunning) {
		t.Error("unknown run source transitioned")
	}

	for _, state := range []RoleTaskState{RoleTaskPending, RoleTaskPrimaryQueued, RoleTaskPrimaryRunning, RoleTaskFallbackQueued, RoleTaskFallbackRunning, RoleTaskSucceeded, RoleTaskFailed, RoleTaskCancelled, RoleTaskBlocked} {
		if state.CanTransition(RoleTaskState("unknown")) {
			t.Errorf("role-task state %q accepted unknown destination", state)
		}
		if err := state.RequireTransition(RoleTaskState("unknown")); !errors.Is(err, ErrInvariant) {
			t.Errorf("role-task state %q unknown destination error = %v, want invariant", state, err)
		}
	}
	if RoleTaskState("unknown").CanTransition(RoleTaskPrimaryQueued) {
		t.Error("unknown role-task source transitioned")
	}
	if err := RoleTaskState("unknown").RequireTransition(RoleTaskPrimaryQueued); !errors.Is(err, ErrInvariant) {
		t.Errorf("unknown role-task source error = %v, want invariant", err)
	}

	for _, state := range []AttemptState{AttemptQueued, AttemptRunning, AttemptValidating, AttemptRepairing, AttemptSucceeded, AttemptFailed, AttemptTimedOut, AttemptCancelled, AttemptBlocked} {
		if state.CanTransition(AttemptState("unknown")) {
			t.Errorf("attempt state %q accepted unknown destination", state)
		}
		if err := state.RequireTransition(AttemptState("unknown")); !errors.Is(err, ErrInvariant) {
			t.Errorf("attempt state %q unknown destination error = %v, want invariant", state, err)
		}
	}
	if AttemptState("unknown").CanTransition(AttemptRunning) {
		t.Error("unknown attempt source transitioned")
	}

	for _, state := range []InvocationState{InvocationQueued, InvocationRunning, InvocationSucceeded, InvocationFailed, InvocationTimedOut, InvocationCancelled, InvocationBlocked} {
		if state.CanTransition(InvocationState("unknown")) {
			t.Errorf("invocation state %q accepted unknown destination", state)
		}
		if err := state.RequireTransition(InvocationState("unknown")); !errors.Is(err, ErrInvariant) {
			t.Errorf("invocation state %q unknown destination error = %v, want invariant", state, err)
		}
	}
	if InvocationState("unknown").CanTransition(InvocationRunning) {
		t.Error("unknown invocation source transitioned")
	}
}
func TestTerminalStatesCannotTransition(t *testing.T) {
	t.Parallel()

	if RunCompleted.CanTransition(RunRunning) || RunFailed.CanTransition(RunRunning) || RunCancelled.CanTransition(RunRunning) {
		t.Error("terminal run state transitioned")
	}
	if AttemptSucceeded.CanTransition(AttemptRunning) || AttemptFailed.CanTransition(AttemptRunning) {
		t.Error("terminal attempt state transitioned")
	}
	if InvocationSucceeded.CanTransition(InvocationRunning) || InvocationFailed.CanTransition(InvocationRunning) {
		t.Error("terminal invocation state transitioned")
	}
}

func TestStateDomainsRemainDistinctAndValidate(t *testing.T) {
	t.Parallel()

	if !RunPending.Valid() || !RoleTaskPending.Valid() || !AttemptQueued.Valid() || !InvocationQueued.Valid() {
		t.Fatal("known state rejected")
	}
	if RunState(RoleTaskPrimaryQueued).Valid() {
		t.Error("role-task state accepted as run state")
	}
	if ParseState(ValidationRepairedValid).Valid() {
		t.Error("validation state accepted as parse state")
	}
}

func TestClassifySuccessfulAttemptExtractionClosedPairs(t *testing.T) {
	t.Parallel()

	parses := []ParseState{
		ParseNotStarted, ParseValid, ParseInvalidJSON, ParseEmptyOutput, ParseOutputTooLarge,
	}
	validations := []ValidationState{
		ValidationNotStarted, ValidationValid, ValidationRepairedValid,
		ValidationInvalid, ValidationRepairExhausted, ValidationInternalError,
	}
	want := map[string]struct {
		reportsOnly bool
		ok          bool
	}{
		"not_started/not_started":           {reportsOnly: true, ok: true},
		"valid/valid":                       {reportsOnly: false, ok: true},
		"valid/repaired_valid":              {reportsOnly: false, ok: true},
		"valid/invalid":                     {reportsOnly: true, ok: true},
		"valid/repair_exhausted":            {reportsOnly: true, ok: true},
		"invalid_json/invalid":              {reportsOnly: true, ok: true},
		"invalid_json/repair_exhausted":     {reportsOnly: true, ok: true},
		"output_too_large/invalid":          {reportsOnly: true, ok: true},
		"output_too_large/repair_exhausted": {reportsOnly: true, ok: true},
	}
	for _, parse := range parses {
		for _, validation := range validations {
			key := string(parse) + "/" + string(validation)
			reportsOnly, ok := ClassifySuccessfulAttemptExtraction(parse, validation)
			expected, allowed := want[key]
			if !allowed {
				expected = struct {
					reportsOnly bool
					ok          bool
				}{}
			}
			if reportsOnly != expected.reportsOnly || ok != expected.ok {
				t.Fatalf(
					"ClassifySuccessfulAttemptExtraction(%q, %q) = (%t, %t), want (%t, %t)",
					parse, validation, reportsOnly, ok, expected.reportsOnly, expected.ok,
				)
			}
		}
	}
}

func TestEveryStateVocabularyValidatesExactly(t *testing.T) {
	t.Parallel()

	domains := []struct {
		name    string
		valid   func(string) bool
		allowed []string
	}{
		{"run type", func(value string) bool { return RunType(value).Valid() }, []string{string(RunTypeReview), string(RunTypeFollowup), string(RunTypeDelta), string(RunTypeRerun)}},
		{"run state", func(value string) bool { return RunState(value).Valid() }, []string{string(RunPending), string(RunRunning), string(RunCompleted), string(RunDegraded), string(RunFailed), string(RunCancelled)}},
		{"role-task state", func(value string) bool { return RoleTaskState(value).Valid() }, []string{string(RoleTaskPending), string(RoleTaskPrimaryQueued), string(RoleTaskPrimaryRunning), string(RoleTaskFallbackQueued), string(RoleTaskFallbackRunning), string(RoleTaskSucceeded), string(RoleTaskFailed), string(RoleTaskCancelled), string(RoleTaskBlocked)}},
		{"attempt state", func(value string) bool { return AttemptState(value).Valid() }, []string{string(AttemptQueued), string(AttemptRunning), string(AttemptValidating), string(AttemptRepairing), string(AttemptSucceeded), string(AttemptFailed), string(AttemptTimedOut), string(AttemptCancelled), string(AttemptBlocked)}},
		{"invocation state", func(value string) bool { return InvocationState(value).Valid() }, []string{string(InvocationQueued), string(InvocationRunning), string(InvocationSucceeded), string(InvocationFailed), string(InvocationTimedOut), string(InvocationCancelled), string(InvocationBlocked)}},
		{"parse state", func(value string) bool { return ParseState(value).Valid() }, []string{string(ParseNotStarted), string(ParseValid), string(ParseInvalidJSON), string(ParseEmptyOutput), string(ParseOutputTooLarge)}},
		{"validation state", func(value string) bool { return ValidationState(value).Valid() }, []string{string(ValidationNotStarted), string(ValidationValid), string(ValidationRepairedValid), string(ValidationInvalid), string(ValidationRepairExhausted), string(ValidationInternalError)}},
		{"evidence state", func(value string) bool { return EvidenceState(value).Valid() }, []string{string(EvidenceVerified), string(EvidencePartiallyVerified), string(EvidenceUnverified), string(EvidenceInvalidPath), string(EvidenceInvalidLine), string(EvidenceQuoteMismatch), string(EvidenceOutsideScope)}},
		{"publication status", func(value string) bool { return PublicationStatus(value).Valid() }, []string{string(PublicationNotPublished), string(PublicationStaged), string(PublicationInstalled), string(PublicationCommitted), string(PublicationCorrupt)}},
		{"finding lifecycle", func(value string) bool { return FindingLifecycle(value).Valid() }, []string{string(FindingOpen), string(FindingAcknowledged), string(FindingResolved), string(FindingDismissed)}},
		{"followup resolution", func(value string) bool { return FollowupResolution(value).Valid() }, []string{string(FollowupResolved), string(FollowupPartiallyResolved), string(FollowupStillOpen), string(FollowupUnclear)}},
		{"invocation purpose", func(value string) bool { return InvocationPurpose(value).Valid() }, []string{string(InvocationInitial), string(InvocationRepair)}},
	}
	for _, domain := range domains {
		for _, value := range domain.allowed {
			if !domain.valid(value) {
				t.Errorf("%s rejected declared value %q", domain.name, value)
			}
		}
		for _, value := range []string{"", "unknown", " " + domain.allowed[0], domain.allowed[0] + " "} {
			if domain.valid(value) {
				t.Errorf("%s accepted undeclared value %q", domain.name, value)
			}
		}
	}
}
