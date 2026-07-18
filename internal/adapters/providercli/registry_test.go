package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestBuildArgvUsesExactFamilyProfiles(t *testing.T) {
	tests := []struct {
		family string
		want   []string
	}{
		{FamilyKimi, []string{"/private/bin/kimi", "--prompt", "review bytes", "--output-format", "stream-json"}},
		{FamilyZcode, []string{"/private/bin/zcode", "--mode", "plan", "--no-color", "--prompt", "review bytes"}},
		{FamilyAgy, []string{"/private/bin/agy", "--print", "review bytes", "--sandbox", "--mode", "plan", "--print-timeout", "2m"}},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			got := buildArgv(definition{
				family:   test.family,
				baseArgv: []string{"/private/bin/" + test.family},
			}, []byte("review bytes"))
			if len(got) != len(test.want) {
				t.Fatalf("argv = %q, want %q", got, test.want)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Fatalf("argv = %q, want %q", got, test.want)
				}
			}
		})
	}
}

func TestProviderResultStrictness(t *testing.T) {
	content, isolated, err := providerResult(FamilyKimi, []byte("{\"role\":\"system\"}\n{\"role\":\"assistant\",\"content\":\"answer\"}\n"))
	if err != nil || !isolated || !bytes.Equal(content, []byte("answer")) {
		t.Fatalf("Kimi result = %q, isolated=%t, err=%v", content, isolated, err)
	}
	invalidKimi := [][]byte{
		[]byte("{\"role\":\"assistant\",\"content\":\"one\"}\n{\"role\":\"assistant\",\"content\":\"two\"}"),
		[]byte("{\"role\":\"assistant\",\"content\":[]}"),
		[]byte("{\"role\":\"assistant\"}"),
		[]byte("{bad}"),
		[]byte("{\"type\":\"assistant\",\"content\":\"wrong field\"}"),
		[]byte("[]"),
	}
	for _, stdout := range invalidKimi {
		if _, _, err := providerResult(FamilyKimi, stdout); err == nil {
			t.Fatalf("Kimi accepted malformed output %q", stdout)
		}
	}
	for _, family := range []string{FamilyZcode, FamilyAgy} {
		if _, _, err := providerResult(family, []byte("{\"findings\":[]} trailing")); err == nil {
			t.Fatalf("%s accepted trailing bytes", family)
		}
		want := []byte(" {\"findings\":[]}\n")
		got, isolated, err := providerResult(family, want)
		if err != nil || isolated || !bytes.Equal(got, want) {
			t.Fatalf("%s result = %q, isolated=%t, err=%v", family, got, isolated, err)
		}
	}
}

func TestDefinitionRejectsNonPassOrMismatchedEvidence(t *testing.T) {
	key, err := ports.ParseConcurrencyKey("kimi_default")
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"/private/bin/kimi"}
	evidence, err := newTupleEvidence(FamilyKimi, "kimi_default", "0.23.6", testSHA256, key, "kimi_default", EvidencePass, argv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newDefinition(FamilyKimi, "kimi_default", "0.23.6", "/private/bin/kimi", testSHA256, key, "kimi_default", evidence, argv, nil, "/private/work", time.Second, 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := newTupleEvidence(FamilyKimi, "kimi_default", "0.23.6", testSHA256, key, "kimi_default", "FAIL", argv); err == nil {
		t.Fatal("non-PASS evidence accepted")
	}

	otherKey, err := ports.ParseConcurrencyKey("kimi_other")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		evidence tupleEvidence
	}{
		{"family", mustTupleEvidence(t, FamilyZcode, "kimi_default", "0.23.6", testSHA256, key, "kimi_default", argv)},
		{"instance", mustTupleEvidence(t, FamilyKimi, "kimi_other", "0.23.6", testSHA256, key, "kimi_default", argv)},
		{"version", mustTupleEvidence(t, FamilyKimi, "kimi_default", "0.23.7", testSHA256, key, "kimi_default", argv)},
		{"executable SHA", mustTupleEvidence(t, FamilyKimi, "kimi_default", "0.23.6", "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", key, "kimi_default", argv)},
		{"concurrency key", mustTupleEvidence(t, FamilyKimi, "kimi_default", "0.23.6", testSHA256, otherKey, "kimi_default", argv)},
		{"profile ID", mustTupleEvidence(t, FamilyKimi, "kimi_default", "0.23.6", testSHA256, key, "kimi_other", argv)},
		{"base argv", mustTupleEvidence(t, FamilyKimi, "kimi_default", "0.23.6", testSHA256, key, "kimi_default", []string{"/private/bin/kimi", "--other"})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newDefinition(FamilyKimi, "kimi_default", "0.23.6", "/private/bin/kimi", testSHA256, key, "kimi_default", test.evidence, argv, nil, "/private/work", time.Second, 1, 1); err == nil {
				t.Fatal("mismatched evidence accepted")
			}
		})
	}
	if _, err := newTupleEvidence("unsupported", "kimi_default", "0.23.6", testSHA256, key, "kimi_default", EvidencePass, argv); err == nil {
		t.Fatal("unsupported family accepted")
	}
	if _, err := newTupleEvidence(FamilyKimi, "kimi_default", "0.23.6", testSHA256, key, "kimi.default", EvidencePass, argv); err == nil {
		t.Fatal("dotted profile ID accepted")
	}
	if _, err := newDefinition(FamilyKimi, "kimi.default", "0.23.6", "/private/bin/kimi", testSHA256, key, "kimi_default", mustTupleEvidence(t, FamilyKimi, "kimi.default", "0.23.6", testSHA256, key, "kimi_default", argv), argv, nil, "/private/work", time.Second, 1, 1); err != nil {
		t.Fatalf("dotted provider instance rejected: %v", err)
	}
}

func TestRegistryOptInDefinitions(t *testing.T) {
	runner := &barrierRunner{}
	kimi := testDefinition(t, FamilyKimi, "kimi_default", "kimi_default")
	registry, err := newRegistry(runner, kimi)
	if err != nil {
		t.Fatal(err)
	}
	if registry == nil {
		t.Fatal("single opt-in definition returned nil registry")
	}
	if _, err := newRegistry(runner); err == nil {
		t.Fatal("empty registry accepted")
	}
}
func TestNewAuthorizedRegistryAuthorizesExactCandidatesBeforeConstruction(t *testing.T) {
	kimi := testCandidate(t, FamilyKimi, "kimi_default", "kimi_lane")
	zcode := testCandidate(t, FamilyZcode, "zcode_default", "zcode_lane")
	runner := &countingRunner{}
	authorizer := &recordingAuthorizer{expected: []RuntimeDefinitionCandidate{kimi, zcode}}

	registry, err := NewAuthorizedRegistry(context.Background(), runner, authorizer, kimi, zcode)
	if err != nil {
		t.Fatal(err)
	}
	if registry == nil || authorizer.calls != 2 || runner.calls != 0 {
		t.Fatalf("registry=%v authorizer calls=%d runner calls=%d", registry, authorizer.calls, runner.calls)
	}
	if !reflect.DeepEqual(authorizer.seen, []RuntimeDefinitionCandidate{kimi, zcode}) {
		t.Fatalf("authorized candidates = %#v", authorizer.seen)
	}
}

func TestNewAuthorizedRegistryFailsClosed(t *testing.T) {
	candidate := testCandidate(t, FamilyKimi, "kimi_default", "kimi_lane")
	runner := &countingRunner{}

	if _, err := NewAuthorizedRegistry(context.Background(), runner, nil, candidate); err == nil {
		t.Fatal("nil authorizer accepted")
	}
	var typedNil *recordingAuthorizer
	if _, err := NewAuthorizedRegistry(context.Background(), runner, typedNil, candidate); err == nil {
		t.Fatal("typed-nil authorizer accepted")
	}
	authorizer := &recordingAuthorizer{expected: []RuntimeDefinitionCandidate{candidate}, err: errors.New("denied"), failAt: 0}
	if _, err := NewAuthorizedRegistry(context.Background(), runner, authorizer, candidate); err == nil {
		t.Fatal("authorizer error accepted")
	}
	if authorizer.calls != 1 || runner.calls != 0 {
		t.Fatalf("authorizer calls=%d runner calls=%d", authorizer.calls, runner.calls)
	}
	if _, err := NewAuthorizedRegistry(nil, runner, &recordingAuthorizer{}, candidate); err == nil {
		t.Fatal("nil context accepted")
	}
	var typedNilRunner *countingRunner
	if _, err := NewAuthorizedRegistry(context.Background(), typedNilRunner, &recordingAuthorizer{}, candidate); err == nil {
		t.Fatal("typed-nil runner accepted")
	}
}

func TestNewAuthorizedRegistryAcceptsDistinctInstancesOfSameFamily(t *testing.T) {
	primary := testCandidate(t, FamilyKimi, "kimi_primary", "kimi_primary_lane")
	secondary := testCandidate(t, FamilyKimi, "kimi_secondary", "kimi_secondary_lane")
	authorizer := &recordingAuthorizer{expected: []RuntimeDefinitionCandidate{primary, secondary}}

	registry, err := NewAuthorizedRegistry(context.Background(), &countingRunner{}, authorizer, primary, secondary)
	if err != nil {
		t.Fatal(err)
	}
	if registry == nil || authorizer.calls != 2 {
		t.Fatalf("registry=%v authorizer calls=%d", registry, authorizer.calls)
	}
	primaryDefinition := registry.definitions[primary.Instance()]
	secondaryDefinition := registry.definitions[secondary.Instance()]
	if primaryDefinition.family != FamilyKimi || primaryDefinition.instance != primary.Instance() ||
		primaryDefinition.concurrencyKey != primary.ConcurrencyKey() ||
		secondaryDefinition.family != FamilyKimi || secondaryDefinition.instance != secondary.Instance() ||
		secondaryDefinition.concurrencyKey != secondary.ConcurrencyKey() {
		t.Fatalf("registered definitions = %#v, %#v", primaryDefinition, secondaryDefinition)
	}
	if primaryDefinition.concurrencyKey == secondaryDefinition.concurrencyKey ||
		registry.lanes[primaryDefinition.concurrencyKey] == registry.lanes[secondaryDefinition.concurrencyKey] {
		t.Fatal("distinct Kimi instances do not have independent tuple and lane identities")
	}
}

func TestNewAuthorizedRegistryRejectsDuplicateInstancesAndNoncanonicalOrder(t *testing.T) {
	kimiPrimary := testCandidate(t, FamilyKimi, "kimi_primary", "kimi_primary_lane")
	kimiSecondary := testCandidate(t, FamilyKimi, "kimi_secondary", "kimi_secondary_lane")
	kimiDuplicate := testCandidate(t, FamilyKimi, "kimi_primary", "kimi_duplicate_lane")
	zcode := testCandidate(t, FamilyZcode, "zcode_default", "zcode_lane")
	unlisted := kimiPrimary
	unlisted.family = "other"

	for name, candidates := range map[string][]RuntimeDefinitionCandidate{
		"duplicate instance":        {kimiPrimary, kimiDuplicate},
		"out of order same family":  {kimiSecondary, kimiPrimary},
		"out of order cross family": {zcode, kimiPrimary},
		"unlisted family":           {unlisted},
	} {
		t.Run(name, func(t *testing.T) {
			authorizer := &recordingAuthorizer{}
			registry, err := NewAuthorizedRegistry(context.Background(), &countingRunner{}, authorizer, candidates...)
			if err == nil || registry != nil {
				t.Fatalf("registry=%v err=%v", registry, err)
			}
			if authorizer.calls != 0 {
				t.Fatalf("authorizer called %d times", authorizer.calls)
			}
		})
	}
}

func TestNewAuthorizedRegistryAcceptsUpToThirtyTwoCandidatesAndRejectsMore(t *testing.T) {
	candidates := make([]RuntimeDefinitionCandidate, 0, 33)
	for index := 0; index < 32; index++ {
		instance := fmt.Sprintf("kimi_%02d", index)
		candidates = append(candidates, testCandidate(t, FamilyKimi, instance, instance+"_lane"))
	}

	authorizer := &recordingAuthorizer{expected: candidates}
	registry, err := NewAuthorizedRegistry(context.Background(), &countingRunner{}, authorizer, candidates...)
	if err != nil || registry == nil {
		t.Fatalf("registry=%v err=%v", registry, err)
	}
	if authorizer.calls != len(candidates) {
		t.Fatalf("authorizer called %d times", authorizer.calls)
	}

	overMax := append(candidates, testCandidate(t, FamilyKimi, "kimi_32", "kimi_32_lane"))
	authorizer = &recordingAuthorizer{}
	registry, err = NewAuthorizedRegistry(context.Background(), &countingRunner{}, authorizer, overMax...)
	if err == nil || registry != nil {
		t.Fatalf("registry=%v err=%v", registry, err)
	}
	if authorizer.calls != 0 {
		t.Fatalf("authorizer called %d times", authorizer.calls)
	}
}

func TestNewAuthorizedRegistryPreservesExactCandidateAndDefensiveCopies(t *testing.T) {
	argv := []string{"/private/bin/kimi", "--safe"}
	environment := []ports.EnvironmentVariable{mustEnvironment(t, "HOME", "/private/home")}
	key, err := ports.ParseConcurrencyKey("kimi_lane")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewRuntimeDefinitionCandidate(FamilyKimi, "kimi_default", "1.0.0", argv[0], testSHA256, key, "kimi_default", argv, environment, "/private/work", time.Second, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	argv[1] = "--mutated"
	environment[0] = mustEnvironment(t, "HOME", "/mutated")
	authorizer := &recordingAuthorizer{expected: []RuntimeDefinitionCandidate{candidate}}
	registry, err := NewAuthorizedRegistry(context.Background(), &countingRunner{}, authorizer, candidate)
	if err != nil {
		t.Fatal(err)
	}
	gotArgv := authorizer.seen[0].BaseArgv()
	gotArgv[1] = "--authority-mutation"
	if got := registry.definitions["kimi_default"].baseArgv; !equalStrings(got, []string{"/private/bin/kimi", "--safe"}) {
		t.Fatalf("runnable argv = %q", got)
	}
	if got := registry.definitions["kimi_default"].environment[0].Value(); got != "/private/home" {
		t.Fatalf("runnable environment value = %q", got)
	}
}
func TestNewAuthorizedRegistryRejectsEveryChangedCandidateField(t *testing.T) {
	baseline := testCandidate(t, FamilyKimi, "kimi_default", "kimi_lane")
	otherKey, err := ports.ParseConcurrencyKey("other_lane")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*RuntimeDefinitionCandidate){
		"family":   func(c *RuntimeDefinitionCandidate) { c.family = FamilyZcode },
		"instance": func(c *RuntimeDefinitionCandidate) { c.instance = "kimi_other" },
		"version":  func(c *RuntimeDefinitionCandidate) { c.version = "2.0.0" },
		"executable": func(c *RuntimeDefinitionCandidate) {
			c.executable, c.baseArgv[0] = "/private/bin/kimi-other", "/private/bin/kimi-other"
		},
		"executable SHA": func(c *RuntimeDefinitionCandidate) {
			c.executableSHA256 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		},
		"concurrency key": func(c *RuntimeDefinitionCandidate) { c.concurrencyKey = otherKey },
		"profile ID":      func(c *RuntimeDefinitionCandidate) { c.profileID = "kimi_other" },
		"base argv":       func(c *RuntimeDefinitionCandidate) { c.baseArgv = append(c.baseArgv, "--changed") },
		"environment": func(c *RuntimeDefinitionCandidate) {
			c.environment = []ports.EnvironmentVariable{mustEnvironment(t, "HOME", "/other")}
		},
		"working directory": func(c *RuntimeDefinitionCandidate) {
			c.workingDirectory = "/private/other"
		},
		"timeout":      func(c *RuntimeDefinitionCandidate) { c.timeout = 2 * time.Second },
		"stdout limit": func(c *RuntimeDefinitionCandidate) { c.maxStdoutBytes = 8192 },
		"stderr limit": func(c *RuntimeDefinitionCandidate) { c.maxStderrBytes = 8192 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneCandidate(baseline)
			change(&candidate)
			authorizer := &recordingAuthorizer{expected: []RuntimeDefinitionCandidate{baseline}}
			registry, err := NewAuthorizedRegistry(context.Background(), &countingRunner{}, authorizer, candidate)
			if err == nil || registry != nil || authorizer.calls != 1 {
				t.Fatalf("registry=%v err=%v authorizer calls=%d", registry, err, authorizer.calls)
			}
		})
	}
}

func TestNewAuthorizedRegistryReturnsNoPartialRegistry(t *testing.T) {
	kimi := testCandidate(t, FamilyKimi, "kimi_default", "kimi_lane")
	zcode := testCandidate(t, FamilyZcode, "zcode_default", "zcode_lane")
	runner := &countingRunner{}
	authorizer := &recordingAuthorizer{
		expected: []RuntimeDefinitionCandidate{kimi, zcode},
		err:      errors.New("second candidate denied"),
		failAt:   1,
	}
	registry, err := NewAuthorizedRegistry(context.Background(), runner, authorizer, kimi, zcode)
	if err == nil || registry != nil || authorizer.calls != 2 || runner.calls != 0 {
		t.Fatalf("registry=%v err=%v authorizer calls=%d runner calls=%d", registry, err, authorizer.calls, runner.calls)
	}
}
func TestRegistryAcceptsDistinctInstancesOfSameFamilyAndRejectsDuplicateInstance(t *testing.T) {
	runner := newBarrierRunner()
	first := testDefinition(t, FamilyKimi, "kimi_primary", "kimi_primary_lane")
	second := testDefinition(t, FamilyKimi, "kimi_secondary", "kimi_secondary_lane")
	registry, err := newRegistry(runner, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.definitions["kimi_primary"]; !ok {
		t.Fatal("primary Kimi instance was not registered")
	}
	if _, ok := registry.definitions["kimi_secondary"]; !ok {
		t.Fatal("secondary Kimi instance was not registered")
	}
	observed := make(chan error, 1)
	secondaryInvocation := testInvocation(t, "kimi_secondary")
	go func() {
		_, observeErr := registry.Observe(context.Background(), secondaryInvocation)
		observed <- observeErr
	}()
	<-runner.started
	close(runner.release)
	if observeErr := <-observed; observeErr != nil {
		t.Fatalf("secondary Kimi dispatch failed: %v", observeErr)
	}
	if _, err := newRegistry(runner, first, first); err == nil {
		t.Fatal("duplicate provider instance accepted")
	}
}
func TestRegistryRejectsUnregisteredProviderBeforeRunnerCall(t *testing.T) {
	runner := newBarrierRunner()
	kimi := testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane")
	registry, err := newRegistry(runner, kimi)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Observe(context.Background(), testInvocation(t, "codex_default")); err == nil {
		t.Fatal("unregistered provider was accepted")
	}
	select {
	case <-runner.started:
		t.Fatal("runner called for unregistered provider")
	default:
	}
}

func TestRegistrySerializesEqualKeysAndAllowsDistinctKeys(t *testing.T) {
	runner := newBarrierRunner()
	kimi := testDefinition(t, FamilyKimi, "kimi_default", "shared_lane")
	zcode := testDefinition(t, FamilyZcode, "zcode_default", "shared_lane")
	agy := testDefinition(t, FamilyAgy, "agy_default", "other_lane")
	registry, err := newRegistry(runner, kimi, zcode, agy)
	if err != nil {
		t.Fatal(err)
	}

	var calls sync.WaitGroup
	calls.Add(2)
	go func() {
		defer calls.Done()
		_, _ = registry.Observe(context.Background(), testInvocation(t, "kimi_default"))
	}()
	<-runner.started
	go func() {
		defer calls.Done()
		_, _ = registry.Observe(context.Background(), testInvocation(t, "zcode_default"))
	}()
	select {
	case <-runner.started:
		t.Fatal("equal concurrency keys overlapped")
	default:
		if active := runner.activeCount(); active != 1 {
			t.Fatalf("equal concurrency key active count = %d, want 1", active)
		}
	}
	close(runner.release)
	calls.Wait()

	runner = newBarrierRunner()
	registry.runner = runner
	calls.Add(2)
	go func() {
		defer calls.Done()
		_, _ = registry.Observe(context.Background(), testInvocation(t, "kimi_default"))
	}()
	go func() {
		defer calls.Done()
		_, _ = registry.Observe(context.Background(), testInvocation(t, "agy_default"))
	}()
	<-runner.started
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("distinct concurrency keys did not overlap")
	}
	close(runner.release)
	calls.Wait()
}
func TestRegistryObserveQueuedCancellationDoesNotRunOrLeakLane(t *testing.T) {
	runner := newBarrierRunner()
	registry, err := newRegistry(runner, testDefinition(t, FamilyKimi, "kimi_default", "shared_lane"))
	if err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, observeErr := registry.Observe(context.Background(), testInvocation(t, "kimi_default"))
		firstDone <- observeErr
	}()
	<-runner.started

	ctx, cancel := context.WithCancel(context.Background())
	queuedDone := make(chan error, 1)
	go func() {
		_, observeErr := registry.Observe(ctx, testInvocation(t, "kimi_default"))
		queuedDone <- observeErr
	}()
	cancel()
	if observeErr := <-queuedDone; observeErr == nil {
		t.Fatal("queued cancellation succeeded")
	}
	select {
	case <-runner.started:
		t.Fatal("cancelled queued call reached runner")
	default:
	}
	if active := runner.activeCount(); active != 1 {
		t.Fatalf("active count after queued cancellation = %d, want 1", active)
	}

	close(runner.release)
	if observeErr := <-firstDone; observeErr != nil {
		t.Fatalf("first observe failed: %v", observeErr)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default"))
	if err != nil {
		t.Fatalf("lane was not released after cancellation: %v", err)
	}
	if err := observed.Validate(); err != nil {
		t.Fatalf("observation after cancellation is invalid: %v", err)
	}
}

func TestRegistryObserveFailsClosedOnRunnerErrorWithObservation(t *testing.T) {
	process := testProcessObservation(t, []byte("{\"role\":\"assistant\",\"content\":\"answer\"}\n"), nil, ports.ProcessTerminationExited, 0)
	runner := &observationRunner{observation: process, err: errors.New("runner failed")}
	registry, err := newRegistry(runner, testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default"))
	if err == nil {
		t.Fatal("runner error with a valid observation succeeded")
	}
	if err := observed.Validate(); err == nil {
		t.Fatal("runner error returned an observation")
	}
}
func TestRegistryObservePreservesSuccessfulProcessEvidenceAndRequest(t *testing.T) {
	tests := []struct {
		family       string
		stdout       []byte
		wantResult   []byte
		wantIsolated bool
		wantArgv     []string
	}{
		{
			family:       FamilyKimi,
			stdout:       []byte("{\"role\":\"system\",\"content\":\"ignored\"}\n{\"role\":\"assistant\",\"content\":\"answer\"}\n"),
			wantResult:   []byte("answer"),
			wantIsolated: true,
			wantArgv:     []string{"/private/bin/kimi", "--prompt", "review bytes", "--output-format", "stream-json"},
		},
		{
			family:     FamilyZcode,
			stdout:     []byte("{\"findings\":[]}"),
			wantResult: []byte("{\"findings\":[]}"),
			wantArgv:   []string{"/private/bin/zcode", "--mode", "plan", "--no-color", "--prompt", "review bytes"},
		},
		{
			family:     FamilyAgy,
			stdout:     []byte("{\"findings\":[]}"),
			wantResult: []byte("{\"findings\":[]}"),
			wantArgv:   []string{"/private/bin/agy", "--print", "review bytes", "--sandbox", "--mode", "plan", "--print-timeout", "2m"},
		},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			invocation := testInvocation(t, test.family+"_default")
			process := testProcessObservation(t, test.stdout, []byte("provider diagnostics"), ports.ProcessTerminationExited, 0)
			runner := &observationRunner{observation: process}
			definition := testDefinition(t, test.family, test.family+"_default", test.family+"_lane")
			registry, err := newRegistry(runner, definition)
			if err != nil {
				t.Fatal(err)
			}

			observed, err := registry.Observe(context.Background(), invocation)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Status() != ports.ProviderExecutionStatusSucceeded {
				t.Fatalf("status = %q", observed.Status())
			}
			result, ok := observed.Result()
			if !ok || !bytes.Equal(result.Stdout(), test.wantResult) {
				t.Fatalf("result = %q, present=%t", result.Stdout(), ok)
			}
			if !bytes.Equal(observed.Stdout(), test.stdout) || !bytes.Equal(observed.Stderr(), []byte("provider diagnostics")) {
				t.Fatalf("raw process evidence = stdout %q stderr %q", observed.Stdout(), observed.Stderr())
			}
			if test.wantIsolated == bytes.Equal(result.Stdout(), observed.Stdout()) {
				t.Fatalf("result isolation = %t", test.wantIsolated)
			}
			request := runner.request
			if !equalStrings(request.Argv(), test.wantArgv) ||
				!bytes.Equal(request.Stdin(), invocation.Stdin()) ||
				request.Timeout() != definition.timeout ||
				request.MaxStdoutBytes() != definition.maxStdoutBytes ||
				request.MaxStderrBytes() != definition.maxStderrBytes ||
				request.ConcurrencyKey() != definition.concurrencyKey {
				t.Fatalf("request = argv %q stdin %q timeout %s stdout cap %d stderr cap %d lane %q",
					request.Argv(), request.Stdin(), request.Timeout(), request.MaxStdoutBytes(), request.MaxStderrBytes(), request.ConcurrencyKey())
			}
		})
	}
}

func TestRegistryObserveMalformedSuccessfulOutputIsArtifactFailure(t *testing.T) {
	tests := []struct {
		family string
		stdout []byte
	}{
		{FamilyKimi, []byte("{\"role\":\"assistant\",\"content\":\"one\"}\n{\"role\":\"assistant\",\"content\":\"two\"}")},
		{FamilyZcode, []byte("{\"findings\":[]} trailing")},
		{FamilyAgy, []byte("{\"findings\":[]} trailing")},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			instance := test.family + "_default"
			invocation := testInvocation(t, instance)
			process := testProcessObservation(t, test.stdout, []byte("provider diagnostics"), ports.ProcessTerminationExited, 0)
			runner := &observationRunner{observation: process}
			registry, err := newRegistry(runner, testDefinition(t, test.family, instance, test.family+"_lane"))
			if err != nil {
				t.Fatal(err)
			}

			observed, err := registry.Observe(context.Background(), invocation)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Status() != ports.ProviderExecutionStatusArtifactFailure || observed.DiagnosticCode() != "invalid_provider_output" {
				t.Fatalf("status = %q, diagnostic = %q", observed.Status(), observed.DiagnosticCode())
			}
			if _, ok := observed.Result(); ok {
				t.Fatal("malformed output produced a result")
			}
			if !bytes.Equal(observed.Stdout(), process.Stdout()) || !bytes.Equal(observed.Stderr(), process.Stderr()) {
				t.Fatal("malformed output did not preserve raw process evidence")
			}
		})
	}
}

func TestRegistryObserveClassifiesProcessTerminations(t *testing.T) {
	tests := []struct {
		name        string
		termination ports.ProcessTermination
		exitCode    int
		wantStatus  ports.ProviderExecutionStatus
		wantCode    string
	}{
		{"timeout", ports.ProcessTerminationTimedOut, 0, ports.ProviderExecutionStatusTimedOut, "process_timeout"},
		{"cancelled", ports.ProcessTerminationCancelled, 0, ports.ProviderExecutionStatusCancelled, "process_cancelled"},
		{"stdout cap", ports.ProcessTerminationStdoutLimit, 0, ports.ProviderExecutionStatusArtifactFailure, "stdout_limit"},
		{"stderr cap", ports.ProcessTerminationStderrLimit, 0, ports.ProviderExecutionStatusArtifactFailure, "stderr_limit"},
		{"start unavailable", ports.ProcessTerminationStartUnavailable, 0, ports.ProviderExecutionStatusUnavailable, "process_unavailable"},
		{"lock unavailable", ports.ProcessTerminationLockUnavailable, 0, ports.ProviderExecutionStatusUnavailable, "process_unavailable"},
		{"start configuration", ports.ProcessTerminationStartConfiguration, 0, ports.ProviderExecutionStatusConfigurationViolation, "process_configuration"},
		{"lock configuration", ports.ProcessTerminationLockConfiguration, 0, ports.ProviderExecutionStatusConfigurationViolation, "process_configuration"},
		{"start security", ports.ProcessTerminationStartSecurity, 0, ports.ProviderExecutionStatusSecurityViolation, "process_security"},
		{"lock security", ports.ProcessTerminationLockSecurity, 0, ports.ProviderExecutionStatusSecurityViolation, "process_security"},
		{"residual process group", ports.ProcessTerminationResidualProcessGroup, 0, ports.ProviderExecutionStatusSecurityViolation, "process_security"},
		{"nonzero exit", ports.ProcessTerminationExited, 1, ports.ProviderExecutionStatusInternalFailure, "process_internal"},
		{"signaled", ports.ProcessTerminationSignaled, 0, ports.ProviderExecutionStatusInternalFailure, "process_internal"},
		{"start failed", ports.ProcessTerminationStartFailed, 0, ports.ProviderExecutionStatusInternalFailure, "process_internal"},
		{"lock failed", ports.ProcessTerminationLockFailed, 0, ports.ProviderExecutionStatusInternalFailure, "process_internal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invocation := testInvocation(t, "kimi_default")
			runner := &observationRunner{
				observation: testProcessObservation(t, []byte("raw stdout"), []byte("raw stderr"), test.termination, test.exitCode),
			}
			registry, err := newRegistry(runner, testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane"))
			if err != nil {
				t.Fatal(err)
			}

			observed, err := registry.Observe(context.Background(), invocation)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Status() != test.wantStatus || observed.DiagnosticCode() != test.wantCode {
				t.Fatalf("status = %q, diagnostic = %q; want %q, %q",
					observed.Status(), observed.DiagnosticCode(), test.wantStatus, test.wantCode)
			}
		})
	}
}

type observationRunner struct {
	observation ports.ProcessObservation
	request     ports.ProcessRequest
	err         error
}

func (runner *observationRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.request = request
	return runner.observation, runner.err
}

func testProcessObservation(t *testing.T, stdout, stderr []byte, termination ports.ProcessTermination, exitCode int) ports.ProcessObservation {
	t.Helper()
	stdin := []byte("review bytes")
	written := stdin
	complete := true
	switch termination {
	case ports.ProcessTerminationStartFailed,
		ports.ProcessTerminationStartUnavailable,
		ports.ProcessTerminationStartConfiguration,
		ports.ProcessTerminationStartSecurity,
		ports.ProcessTerminationLockFailed,
		ports.ProcessTerminationLockUnavailable,
		ports.ProcessTerminationLockConfiguration,
		ports.ProcessTerminationLockSecurity:
		written = nil
		complete = false
	}
	receipt, err := ports.NewStdinWriteReceipt(int64(len(stdin)), int64(len(written)), testStdinDigest(written), complete)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Unix(0, 0).UTC()
	endedAt := time.Unix(1, 0).UTC()
	if termination == ports.ProcessTerminationExited {
		observation, err := ports.NewProcessObservation(stdout, stderr, &exitCode, termination, receipt, startedAt, endedAt)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	if termination == ports.ProcessTerminationSignaled {
		signal, err := ports.NewProcessSignal(15, "SIGTERM")
		if err != nil {
			t.Fatal(err)
		}
		observation, err := ports.NewProcessObservation(stdout, stderr, nil, termination, receipt, startedAt, endedAt, signal)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	observation, err := ports.NewProcessObservation(stdout, stderr, nil, termination, receipt, startedAt, endedAt)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

const testSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type barrierRunner struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	active  int
}

func newBarrierRunner() *barrierRunner {
	return &barrierRunner{
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
}

func (runner *barrierRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.mu.Lock()
	runner.active++
	runner.mu.Unlock()
	defer func() {
		runner.mu.Lock()
		runner.active--
		runner.mu.Unlock()
	}()
	runner.started <- struct{}{}
	<-runner.release
	stdin := request.Stdin()
	receipt, err := ports.NewStdinWriteReceipt(int64(len(stdin)), int64(len(stdin)), testStdinDigest(stdin), true)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	exitCode := 0
	return ports.NewProcessObservation([]byte("{}"), nil, &exitCode, ports.ProcessTerminationExited, receipt, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
}

func (runner *barrierRunner) activeCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.active
}

type countingRunner struct {
	calls int
}

func (runner *countingRunner) Run(_ context.Context, _ ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.calls++
	return ports.ProcessObservation{}, errors.New("unexpected process run")
}

type recordingAuthorizer struct {
	expected []RuntimeDefinitionCandidate
	seen     []RuntimeDefinitionCandidate
	calls    int
	err      error
	failAt   int
}

func (authorizer *recordingAuthorizer) Authorize(_ context.Context, candidate RuntimeDefinitionCandidate) error {
	authorizer.calls++
	authorizer.seen = append(authorizer.seen, candidate)
	index := authorizer.calls - 1
	if len(authorizer.expected) > index && !reflect.DeepEqual(candidate, authorizer.expected[index]) {
		return errors.New("candidate does not match authorization subject")
	}
	if authorizer.err != nil && index == authorizer.failAt {
		return authorizer.err
	}
	return nil
}

func testCandidate(t *testing.T, family, instance, lane string) RuntimeDefinitionCandidate {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(lane)
	if err != nil {
		t.Fatal(err)
	}
	executable := "/private/bin/" + family
	candidate, err := NewRuntimeDefinitionCandidate(
		family, instance, "1.0.0", executable, testSHA256, key, instance,
		[]string{executable}, nil, "/private/work", time.Second, 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func mustEnvironment(t *testing.T, name, value string) ports.EnvironmentVariable {
	t.Helper()
	variable, err := ports.NewEnvironmentVariable(name, value)
	if err != nil {
		t.Fatal(err)
	}
	return variable
}

func testDefinition(t *testing.T, family, instance, lane string) definition {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(lane)
	if err != nil {
		t.Fatal(err)
	}
	executable := "/private/bin/" + family
	argv := []string{executable}
	evidence, err := newTupleEvidence(family, instance, "1.0.0", testSHA256, key, instance, EvidencePass, argv)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := newDefinition(family, instance, "1.0.0", executable, testSHA256, key, instance, evidence, argv, nil, "/private/work", time.Second, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	return definition
}
func mustTupleEvidence(t *testing.T, family, instance, version, executableSHA256 string, concurrencyKey ports.ConcurrencyKey, profileID string, argv []string) tupleEvidence {
	t.Helper()
	evidence, err := newTupleEvidence(family, instance, version, executableSHA256, concurrencyKey, profileID, EvidencePass, argv)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func testInvocation(t *testing.T, instance string) ports.ProviderInvocation {
	t.Helper()
	attempt, err := domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	stdin := []byte("review bytes")
	invocation, err := ports.NewProviderInvocation(
		domain.RoleSecurity,
		instance,
		attempt,
		ports.ProviderInvocationInitial,
		stdin,
		"i_019f596a-cf80-7c67-b265-f37053d51ccd",
		"019f596a-cf80-7c67-b265-f37053d51cce",
		testStdinDigest(stdin),
	)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func testStdinDigest(stdin []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(stdin)
	return hex.EncodeToString(hash.Sum(nil))
}
