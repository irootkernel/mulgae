package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestBuildArgvUsesFamilyCapabilityProfiles(t *testing.T) {
	tests := []struct {
		family string
		want   []string
	}{
		{FamilyKimi, []string{"/private/bin/kimi", "--model", "kimi-code/kimi-for-coding", "--prompt", "review bytes", "--output-format", "stream-json"}},
		{FamilyZcode, []string{"/private/bin/zcode", "--mode", "build", "--no-color", "--prompt", "review bytes", "--json", "--disallowed-tools", "*"}},
		{FamilyAgy, []string{"/private/bin/agy", "--new-project", "--sandbox", "--dangerously-skip-permissions", "--add-dir", "/private/work", "--mode", "plan", "--effort", "low", "--print-timeout", "29m55s", "--print", "review bytes"}},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			transport, err := defaultRuntimeTransport(test.family, 1)
			if err != nil {
				t.Fatal(err)
			}
			got, err := buildArgv(definition{
				family:    test.family,
				baseArgv:  []string{"/private/bin/" + test.family},
				transport: transport,
				timeout:   30 * time.Minute,
			}, "/private/work", []byte("review bytes"))
			if err != nil {
				t.Fatal(err)
			}
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
		[]byte("{\"role\":\"assistant\",\"content\":[]}"),
		[]byte("{\"role\":\"assistant\"}"),
		[]byte("{bad}"),
		[]byte("{\"type\":\"assistant\",\"content\":\"wrong field\"}"),
		[]byte("[]"),
	}
	for index, stdout := range invalidKimi {
		if _, _, err := providerResult(FamilyKimi, stdout); err == nil {
			t.Fatalf("Kimi accepted malformed fixture %d", index)
		} else {
			var failure *providerOutputFailure
			if !errors.As(err, &failure) || !failure.Cause().Valid() || strings.Contains(err.Error(), string(stdout)) {
				t.Fatalf("Kimi fixture %d did not return a safe typed cause", index)
			}
		}
	}
	content, isolated, err = providerResult(FamilyKimi, []byte("{\"role\":\"assistant\",\"content\":\"draft\"}\n{\"role\":\"assistant\",\"content\":\"final answer\"}"))
	if err != nil || !isolated || !bytes.Equal(content, []byte("final answer")) {
		t.Fatalf("Kimi terminal assistant result = %q, isolated=%t, err=%v", content, isolated, err)
	}
	kimiToolStream := []byte("{\"role\":\"assistant\",\"tool_calls\":[{\"type\":\"function\"}]}\n" +
		"{\"role\":\"tool\",\"content\":\"tool output\"}\n" +
		"{\"role\":\"assistant\",\"content\":\"final answer\"}\n" +
		"{\"role\":\"meta\",\"content\":\"resume hint\"}\n")
	content, isolated, err = providerResult(FamilyKimi, kimiToolStream)
	if err != nil || !isolated || !bytes.Equal(content, []byte("final answer")) {
		t.Fatalf("Kimi tool stream result = %q, isolated=%t, err=%v", content, isolated, err)
	}
	want := []byte("{\"findings\":[]}")
	zcodeRaw := []byte("```json\n{\"findings\":[]}\n```")
	got, isolated, err := providerResult(FamilyZcode, zcodeRaw)
	if err != nil || !isolated || !bytes.Equal(got, want) {
		t.Fatalf("ZCode result = %q, isolated=%t, err=%v", got, isolated, err)
	}
	got, isolated, err = providerResult(FamilyZcode, want)
	if err != nil || !isolated || !bytes.Equal(got, want) {
		t.Fatalf("ZCode result = %q, isolated=%t, err=%v", got, isolated, err)
	}
	zcodeEnvelope := []byte(`{"sessionId":"session","response":"{\"findings\":[]}","usage":{"inputTokens":1}}`)
	got, isolated, err = providerResult(FamilyZcode, zcodeEnvelope)
	if err != nil || !isolated || !bytes.Equal(got, want) {
		t.Fatalf("ZCode envelope result = %q, isolated=%t, err=%v", got, isolated, err)
	}
	zcodeNarratedEnvelope := []byte(`{"sessionId":"session","response":"The review is complete.\n\n` + "```json\\n{\\\"findings\\\":[]}\\n```" + `","usage":{"inputTokens":1}}`)
	got, isolated, err = providerResult(FamilyZcode, zcodeNarratedEnvelope)
	if err != nil || !isolated || !bytes.Equal(got, want) {
		t.Fatalf("ZCode narrated envelope result = %q, isolated=%t, err=%v", got, isolated, err)
	}
	zcodeTrailingNarrationEnvelope := []byte(`{"sessionId":"session","response":"Analysis before the result.\n\n` + "```json\\n{\\\"findings\\\":[]}\\n```\\n\\nThe requested review is complete." + `","usage":{"inputTokens":1}}`)
	got, isolated, err = providerResult(FamilyZcode, zcodeTrailingNarrationEnvelope)
	if err != nil || !isolated || !bytes.Equal(got, want) {
		t.Fatalf("ZCode trailing narration envelope result = %q, isolated=%t, err=%v", got, isolated, err)
	}
	zcodeAmbiguousEnvelope := []byte(`{"sessionId":"session","response":"` + "```json\\n{\\\"findings\\\":[]}\\n```\\n```json\\n{\\\"findings\\\":[]}\\n```\\ntrailing" + `","usage":{"inputTokens":1}}`)
	if _, _, err := providerResult(FamilyZcode, zcodeAmbiguousEnvelope); err == nil {
		t.Fatal("ZCode accepted multiple nonterminal JSON fences")
	}
	if _, _, err := providerResult(FamilyZcode, []byte(`{"response":""}`)); err == nil {
		t.Fatal("ZCode accepted an empty headless response")
	}
	if _, _, err := providerResult(FamilyZcode, []byte(`{"response":"narration without terminal JSON"}`)); err == nil {
		t.Fatal("ZCode accepted a headless response without terminal JSON")
	}
	zcodeNarrated := []byte("I inspected the snapshot.\n{\"findings\":[]}\n")
	got, isolated, err = providerResult(FamilyZcode, zcodeNarrated)
	if err != nil || !isolated || !bytes.Equal(got, want) {
		t.Fatalf("ZCode narrated result = %q, isolated=%t, err=%v", got, isolated, err)
	}
	agyStdout := []byte("I inspected the immutable snapshot.\n{\"findings\":[]}\n")
	got, isolated, err = providerResult(FamilyAgy, agyStdout)
	if err != nil || !isolated || !bytes.Equal(got, want) {
		t.Fatalf("AGY result = %q, isolated=%t, err=%v", got, isolated, err)
	}
	for index, invalid := range [][]byte{[]byte("same-line {\"findings\":[]}"), []byte("{\"findings\":[]}\ntrailing")} {
		if _, _, err := providerResult(FamilyAgy, invalid); err == nil {
			t.Fatalf("AGY accepted nonterminal fixture %d", index)
		}
	}
}

func TestProviderResultFailuresExposeExactTypedCausesWithoutRawText(t *testing.T) {
	tests := []struct {
		name      string
		family    string
		fixture   []byte
		wantCause domain.RuntimeDiagnosticCause
	}{
		{"Kimi missing output", FamilyKimi, nil, domain.DiagnosticCauseOutputMissing},
		{"Kimi missing frame", FamilyKimi, []byte(`{"role":"system"}`), domain.DiagnosticCauseOutputFrameMissing},
		{"Kimi decode failure", FamilyKimi, []byte(`{"role":"assistant","content":[]}`), domain.DiagnosticCauseOutputDecodeFailed},
		{"ZCode missing output", FamilyZcode, nil, domain.DiagnosticCauseOutputMissing},
		{"ZCode invalid envelope", FamilyZcode, []byte(`{"response":""}`), domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"AGY missing output", FamilyAgy, nil, domain.DiagnosticCauseOutputMissing},
		{"AGY malformed stream", FamilyAgy, []byte(`{"findings":[]} trailing`), domain.DiagnosticCauseOutputDecodeFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := providerResult(test.family, test.fixture)
			var failure *providerOutputFailure
			if !errors.As(err, &failure) {
				t.Fatal("provider result did not return a typed output failure")
			}
			if failure.Cause() != test.wantCause {
				t.Fatalf("typed cause = %q, want %q", failure.Cause(), test.wantCause)
			}
			if len(test.fixture) != 0 && strings.Contains(err.Error(), string(test.fixture)) {
				t.Fatal("safe provider output error exposed fixture bytes")
			}
		})
	}
}

func TestRegistryObserveClassifiesSuccessfulAgyPermissionDenialBeforeMissingOutput(t *testing.T) {
	invocation := testInvocation(t, "agy_default")
	runner := &observationRunner{observation: testProcessObservation(
		t, nil, []byte("tool permission was denied"), ports.ProcessTerminationExited, 0,
	)}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyAgy, "agy_default", "agy_lane"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusAuthentication ||
		observed.PrimaryCause() != domain.DiagnosticCausePermissionDenied ||
		observed.DiagnosticCode() != "provider_permission_denied" {
		t.Fatalf("permission observation = status %q cause %q diagnostic %q", observed.Status(), observed.PrimaryCause(), observed.DiagnosticCode())
	}
}

func TestAgyPermissionDeniedUsesOnlyBoundedStderrSignals(t *testing.T) {
	if !agyPermissionDenied([]byte("request denied by permission policy")) {
		t.Fatal("known AGY permission denial was not recognized")
	}
	if agyPermissionDenied([]byte("review finding: application returned permission denied")) {
		t.Fatal("generic review prose was classified as an AGY permission denial")
	}
}

func TestNewRuntimeDefinitionAllowsOptionalProvenance(t *testing.T) {
	for _, provenance := range []struct {
		name      string
		version   string
		hash      string
		profileID string
	}{
		{"empty", "", "", ""},
		{"arbitrary", "future-build+unknown", "not-a-sha", "vendor profile 2030.4"},
		{"different hash", "0.23.6", "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "kimi.default"},
	} {
		for _, family := range []string{FamilyKimi, FamilyZcode, FamilyAgy} {
			t.Run(family+"/"+provenance.name, func(t *testing.T) {
				profile := testProfile(t, family, family+"_default", family+"_lane", provenance.version, provenance.hash)
				profile.profileID = provenance.profileID
				registry, err := NewRegistry(&countingRunner{}, profile)
				if err != nil || registry == nil {
					t.Fatalf("registry=%v err=%v", registry, err)
				}
			})
		}
	}
}
func TestNewRuntimeDefinitionWithTransportValidatesRuntimeShape(t *testing.T) {
	baseArgv := []string{"/private/bin/kimi"}
	argvTransport, err := NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 4, "")
	if err != nil {
		t.Fatal(err)
	}
	stdinTransport, err := NewRuntimeTransport(ports.ProviderPacketChannelStdin, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	promptFileTransport, err := NewRuntimeTransport(ports.ProviderPacketChannelPromptFile, 4, "@prompt/request.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []RuntimeTransport{argvTransport, stdinTransport, promptFileTransport} {
		profile, err := newTestProfileWithTransport(t, FamilyKimi, "kimi_default", "kimi_lane", baseArgv, transport)
		if err != nil {
			t.Fatalf("transport %q: %v", transport.Channel(), err)
		}
		if profile.Transport() != transport {
			t.Fatalf("transport = %#v, want %#v", profile.Transport(), transport)
		}
	}
	for _, transport := range []RuntimeTransport{
		{channel: ports.ProviderPacketChannelArgvLiteral, argvIndex: -1},
		{channel: ports.ProviderPacketChannelStdin, argvIndex: 0},
		{channel: ports.ProviderPacketChannelPromptFile, argvIndex: 2, reference: "@/absolute"},
		{channel: ports.ProviderPacketChannelArgvLiteral, argvIndex: 1},
	} {
		if _, err := newTestProfileWithTransport(t, FamilyKimi, "kimi_default", "kimi_lane", baseArgv, transport); err == nil {
			t.Fatalf("transport %#v was accepted", transport)
		}
	}
}

func TestNewRegistryRejectsMalformedProfilesAndUnlistedFamilies(t *testing.T) {
	profile := testProfile(t, FamilyKimi, "kimi_default", "kimi_lane", "", "")
	tests := map[string]func(*RuntimeDefinition){
		"unlisted family": func(p *RuntimeDefinition) { p.family = "other" },
		"relative executable": func(p *RuntimeDefinition) {
			p.executable, p.baseArgv[0] = "kimi", "kimi"
		},
		"unclean executable": func(p *RuntimeDefinition) {
			p.executable, p.baseArgv[0] = "/private/bin/../kimi", "/private/bin/../kimi"
		},
		"invalid argv": func(p *RuntimeDefinition) { p.baseArgv = []string{p.executable, ""} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			invalid := cloneRuntimeDefinition(profile)
			mutate(&invalid)
			if registry, err := NewRegistry(&countingRunner{}, invalid); err == nil || registry != nil {
				t.Fatalf("registry=%v err=%v", registry, err)
			}
		})
	}
}

func TestNewRegistryPreservesProfileAndDefensiveCopies(t *testing.T) {
	argv := []string{"/private/bin/kimi", "--safe"}
	environment := []ports.EnvironmentVariable{mustEnvironment(t, "HOME", "/private/home")}
	key, err := ports.ParseConcurrencyKey("kimi_lane")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewRuntimeDefinition(FamilyKimi, "kimi_default", "", argv[0], "", key, "kimi_default", argv, environment, "/private/work", time.Second, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	argv[1] = "--mutated"
	environment[0] = mustEnvironment(t, "HOME", "/mutated")
	registry, err := NewRegistry(&countingRunner{}, profile)
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.definitions["kimi_default"].baseArgv; !equalStrings(got, []string{"/private/bin/kimi", "--safe"}) {
		t.Fatalf("runnable argv = %q", got)
	}
	if got := registry.definitions["kimi_default"].environment[0].Value(); got != "/private/home" {
		t.Fatalf("runnable environment value = %q", got)
	}
}

func TestNewRegistryRejectsDuplicateInstancesAndNoncanonicalOrder(t *testing.T) {
	kimiPrimary := testProfile(t, FamilyKimi, "kimi_primary", "kimi_primary_lane", "", "")
	kimiSecondary := testProfile(t, FamilyKimi, "kimi_secondary", "kimi_secondary_lane", "", "")
	kimiDuplicate := testProfile(t, FamilyKimi, "kimi_primary", "kimi_duplicate_lane", "", "")
	zcode := testProfile(t, FamilyZcode, "zcode_default", "zcode_lane", "", "")
	for name, profiles := range map[string][]RuntimeDefinition{
		"duplicate instance":        {kimiPrimary, kimiDuplicate},
		"out of order same family":  {kimiSecondary, kimiPrimary},
		"out of order cross family": {zcode, kimiPrimary},
	} {
		t.Run(name, func(t *testing.T) {
			registry, err := NewRegistry(&countingRunner{}, profiles...)
			if err == nil || registry != nil {
				t.Fatalf("registry=%v err=%v", registry, err)
			}
		})
	}
}
func TestRegistryAcceptsDistinctInstancesOfSameFamilyAndRejectsDuplicateInstance(t *testing.T) {
	runner := newBarrierRunner()
	first := testDefinition(t, FamilyKimi, "kimi_primary", "kimi_primary_lane")
	second := testDefinition(t, FamilyKimi, "kimi_secondary", "kimi_secondary_lane")
	registry, err := newRegistry(context.Background(), runner, first, second)
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
	if _, err := newRegistry(context.Background(), runner, first, first); err == nil {
		t.Fatal("duplicate provider instance accepted")
	}
}
func TestRegistryRejectsUnregisteredProviderBeforeRunnerCall(t *testing.T) {
	runner := newBarrierRunner()
	kimi := testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane")
	registry, err := newRegistry(context.Background(), runner, kimi)
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
	registry, err := newRegistry(context.Background(), runner, kimi, zcode, agy)
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

func TestRegistryRunsSixZCodeRoleInstancesConcurrentlyInSameGuardedCWD(t *testing.T) {
	runner := newBarrierRunner()
	instances := []string{"zcode-logic", "zcode-security", "zcode-maintainability", "zcode-product", "zcode-documentation", "zcode-testing"}
	definitions := make([]definition, 0, len(instances))
	for _, instance := range instances {
		definitions = append(definitions, testDefinition(t, FamilyZcode, instance, instance))
	}
	registry, err := newRegistry(context.Background(), runner, definitions...)
	if err != nil {
		t.Fatal(err)
	}
	root, identity := testWorkspaceRoot(t)
	var calls sync.WaitGroup
	calls.Add(len(instances))
	for _, instance := range instances {
		instance := instance
		events := []string{}
		authority := &workspaceAuthorityFake{identity: identity, guard: &workspaceGuardFake{root: root, identity: identity, events: &events}, events: &events}
		go func() {
			defer calls.Done()
			_, _ = registry.Observe(context.Background(), testWorkspaceInvocation(t, instance, authority))
		}()
	}
	for index := 0; index < len(instances); index++ {
		select {
		case <-runner.started:
		case <-time.After(time.Second):
			t.Fatal("six ZCode role instances did not enter the runner concurrently")
		}
	}
	if active := runner.activeCount(); active != len(instances) {
		t.Fatalf("active ZCode requests = %d, want %d", active, len(instances))
	}
	directories := runner.workingDirectories()
	wantDirectories := make([]string, len(instances))
	for index := range wantDirectories {
		wantDirectories[index] = root.Path()
	}
	if !reflect.DeepEqual(directories, wantDirectories) {
		t.Fatalf("ZCode working directories = %v, want shared guarded root %q", directories, root.Path())
	}
	close(runner.release)
	calls.Wait()
}
func TestRegistryObserveQueuedCancellationDoesNotRunOrLeakLane(t *testing.T) {
	runner := newBarrierRunner()
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyKimi, "kimi_default", "shared_lane"))
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

func TestRegistryObservePreservesRunnerErrorWithObservation(t *testing.T) {
	process := testProcessObservation(t, []byte("{\"role\":\"assistant\",\"content\":\"answer\"}\n"), nil, ports.ProcessTerminationExited, 0)
	runnerFailure, err := ports.NewProcessExecutionError(
		domain.DiagnosticCauseProviderProcessWaitFailed, "", process.Stdout(), process.Stderr(), errors.New("runner failed"),
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &observationRunner{observation: process, err: runnerFailure}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default"))
	if err != nil {
		t.Fatal(err)
	}
	if err := observed.Validate(); err != nil {
		t.Fatal(err)
	}
	if observed.PrimaryCause() != domain.DiagnosticCauseProviderProcessWaitFailed ||
		string(observed.Stdout()) != string(process.Stdout()) {
		t.Fatalf("cause = %q, stdout was preserved = %t", observed.PrimaryCause(), bytes.Equal(observed.Stdout(), process.Stdout()))
	}
}

func TestRegistryObservePreservesPartialStreamsAndCleanupCause(t *testing.T) {
	runnerFailure, err := ports.NewProcessExecutionError(
		domain.DiagnosticCauseProviderProcessWaitFailed,
		domain.DiagnosticCauseProcessGroupCleanupFailed,
		[]byte("partial stdout"),
		[]byte("partial stderr"),
		errors.New("private runner detail"),
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &observationRunner{err: runnerFailure}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := observed.AvailableProcessObservation(); ok {
		t.Fatal("partial execution claimed a coherent process observation")
	}
	cleanup, ok := observed.CleanupCause()
	if observed.PrimaryCause() != domain.DiagnosticCauseProviderProcessWaitFailed ||
		!ok || cleanup != domain.DiagnosticCauseProcessGroupCleanupFailed {
		t.Fatalf("primary = %q, cleanup = %q, present = %t", observed.PrimaryCause(), cleanup, ok)
	}
	if string(observed.Stdout()) != "partial stdout" || string(observed.Stderr()) != "partial stderr" {
		t.Fatal("partial runner streams were lost")
	}
}

func TestRegistryObservePreservesTransportVerificationCause(t *testing.T) {
	runnerFailure, err := ports.NewProcessExecutionError(
		domain.DiagnosticCauseTransportVerificationFailed, "", []byte("partial stdout"), nil,
		errors.New("private prompt-file identity detail"),
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &observationRunner{err: runnerFailure}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default"))
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusSecurityViolation ||
		observed.PrimaryCause() != domain.DiagnosticCauseTransportVerificationFailed ||
		string(observed.Stdout()) != "partial stdout" {
		t.Fatalf("status = %q, cause = %q, stdout preserved = %t", observed.Status(), observed.PrimaryCause(), string(observed.Stdout()) == "partial stdout")
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
			wantArgv:     []string{"/private/bin/kimi", "--model", "kimi-code/kimi-for-coding", "--prompt", "review bytes", "--output-format", "stream-json"},
		},
		{
			family:       FamilyZcode,
			stdout:       []byte(`{"sessionId":"session","response":"I inspected the snapshot.\n\n` + "```json\\n{\\\"findings\\\":[]}\\n```\\n\\nThe review is complete.\\n\\n```go\\nfunc checked() {}\\n```" + `","usage":{"inputTokens":1}}`),
			wantResult:   []byte("{\"findings\":[]}"),
			wantIsolated: true,
			wantArgv:     []string{"/private/bin/zcode", "--mode", "build", "--no-color", "--prompt", "review bytes", "--json", "--disallowed-tools", "*"},
		},
		{
			family:     FamilyAgy,
			stdout:     []byte("{\"findings\":[]}"),
			wantResult: []byte("{\"findings\":[]}"),
			wantArgv:   []string{"/private/bin/agy", "--new-project", "--sandbox", "--dangerously-skip-permissions", "--add-dir", "/private/work", "--mode", "plan", "--effort", "low", "--print-timeout", "500ms", "--print", "review bytes"},
		},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			invocation := testInvocation(t, test.family+"_default")
			process := testProcessObservation(t, test.stdout, []byte("provider diagnostics"), ports.ProcessTerminationExited, 0)
			runner := &observationRunner{observation: process}
			definition := testDefinition(t, test.family, test.family+"_default", test.family+"_lane")
			registry, err := newRegistry(context.Background(), runner, definition)
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
			binding, ok := request.ProviderPacketBinding()
			if !ok ||
				binding.Channel() != ports.ProviderPacketChannelArgvLiteral ||
				binding.PacketIdentity() != invocation.InputIdentity() ||
				binding.ArgvIndex() < 0 ||
				!equalStrings(request.Argv(), test.wantArgv) ||
				len(request.Stdin()) != 0 ||
				packetOccurrences(request.Argv(), string(invocation.PacketBytes())) != 1 ||
				request.Timeout() != definition.timeout ||
				request.MaxStdoutBytes() != definition.maxStdoutBytes ||
				request.MaxStderrBytes() != definition.maxStderrBytes ||
				request.ConcurrencyKey() != definition.concurrencyKey {
				t.Fatalf("request = argv %q stdin %q binding %#v timeout %s stdout cap %d stderr cap %d lane %q",
					request.Argv(), request.Stdin(), binding, request.Timeout(), request.MaxStdoutBytes(), request.MaxStderrBytes(), request.ConcurrencyKey())
			}
			transport, ok := process.ProviderPacketTransportReceipt()
			if !ok || transport.Channel() != ports.ProviderPacketChannelArgvLiteral ||
				transport.PacketIdentity() != invocation.InputIdentity() {
				t.Fatalf("transport receipt = %#v, present=%t", transport, ok)
			}
			if result.InputIdentity() != invocation.InputIdentity() {
				t.Fatalf("result input identity = %#v, want %#v", result.InputIdentity(), invocation.InputIdentity())
			}
		})
	}
}

func TestRegistryObserveMalformedSuccessfulOutputIsArtifactFailure(t *testing.T) {
	tests := []struct {
		family         string
		stdout         []byte
		wantCause      domain.RuntimeDiagnosticCause
		wantDiagnostic string
	}{
		{FamilyKimi, []byte("{\"role\":\"assistant\",\"content\":[]}"), domain.DiagnosticCauseOutputDecodeFailed, "invalid_provider_output"},
		{FamilyAgy, nil, domain.DiagnosticCauseOutputMissing, "provider_output_missing"},
		{FamilyAgy, []byte("{\"findings\":[]} trailing"), domain.DiagnosticCauseOutputDecodeFailed, "invalid_provider_output"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			instance := test.family + "_default"
			invocation := testInvocation(t, instance)
			process := testProcessObservation(t, test.stdout, []byte("provider diagnostics"), ports.ProcessTerminationExited, 0)
			runner := &observationRunner{observation: process}
			registry, err := newRegistry(context.Background(), runner, testDefinition(t, test.family, instance, test.family+"_lane"))
			if err != nil {
				t.Fatal(err)
			}

			observed, err := registry.Observe(context.Background(), invocation)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Status() != ports.ProviderExecutionStatusArtifactFailure || observed.DiagnosticCode() != test.wantDiagnostic {
				t.Fatalf("status = %q, diagnostic = %q", observed.Status(), observed.DiagnosticCode())
			}
			if observed.PrimaryCause() != test.wantCause {
				t.Fatalf("cause = %q, want %q", observed.PrimaryCause(), test.wantCause)
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
		wantCause   domain.RuntimeDiagnosticCause
	}{
		{"timeout", ports.ProcessTerminationTimedOut, 0, ports.ProviderExecutionStatusTimedOut, "process_timeout", domain.DiagnosticCauseTimedOut},
		{"cancelled", ports.ProcessTerminationCancelled, 0, ports.ProviderExecutionStatusCancelled, "process_cancelled", domain.DiagnosticCauseProviderExecutionFailed},
		{"stdout cap", ports.ProcessTerminationStdoutLimit, 0, ports.ProviderExecutionStatusArtifactFailure, "stdout_limit", domain.DiagnosticCauseObservationInvalid},
		{"stderr cap", ports.ProcessTerminationStderrLimit, 0, ports.ProviderExecutionStatusArtifactFailure, "stderr_limit", domain.DiagnosticCauseObservationInvalid},
		{"start unavailable", ports.ProcessTerminationStartUnavailable, 0, ports.ProviderExecutionStatusUnavailable, "process_unavailable", domain.DiagnosticCauseProviderSpawnFailed},
		{"lock unavailable", ports.ProcessTerminationLockUnavailable, 0, ports.ProviderExecutionStatusUnavailable, "process_unavailable", domain.DiagnosticCauseProviderSpawnFailed},
		{"start configuration", ports.ProcessTerminationStartConfiguration, 0, ports.ProviderExecutionStatusConfigurationViolation, "process_configuration", domain.DiagnosticCauseProviderSpawnFailed},
		{"lock configuration", ports.ProcessTerminationLockConfiguration, 0, ports.ProviderExecutionStatusConfigurationViolation, "process_configuration", domain.DiagnosticCauseProviderSpawnFailed},
		{"start security", ports.ProcessTerminationStartSecurity, 0, ports.ProviderExecutionStatusSecurityViolation, "process_security", domain.DiagnosticCauseProviderSpawnFailed},
		{"lock security", ports.ProcessTerminationLockSecurity, 0, ports.ProviderExecutionStatusSecurityViolation, "process_security", domain.DiagnosticCauseProviderSpawnFailed},
		{"residual process group", ports.ProcessTerminationResidualProcessGroup, 0, ports.ProviderExecutionStatusSecurityViolation, "process_security", domain.DiagnosticCauseProcessGroupCleanupFailed},
		{"nonzero exit", ports.ProcessTerminationExited, 1, ports.ProviderExecutionStatusInternalFailure, "process_internal", domain.DiagnosticCauseProviderExecutionFailed},
		{"signaled", ports.ProcessTerminationSignaled, 0, ports.ProviderExecutionStatusInternalFailure, "process_internal", domain.DiagnosticCauseProviderExecutionFailed},
		{"start failed", ports.ProcessTerminationStartFailed, 0, ports.ProviderExecutionStatusInternalFailure, "process_internal", domain.DiagnosticCauseProviderSpawnFailed},
		{"lock failed", ports.ProcessTerminationLockFailed, 0, ports.ProviderExecutionStatusInternalFailure, "process_internal", domain.DiagnosticCauseProviderSpawnFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invocation := testInvocation(t, "kimi_default")
			runner := &observationRunner{
				observation: testProcessObservation(t, []byte("raw stdout"), []byte("raw stderr"), test.termination, test.exitCode),
			}
			registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane"))
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
			if observed.PrimaryCause() != test.wantCause {
				t.Fatalf("cause = %q, want %q", observed.PrimaryCause(), test.wantCause)
			}
		})
	}
}

func TestRegistryObserveClassifiesExplicitLoginRequired(t *testing.T) {
	invocation := testInvocation(t, "kimi_default")
	runner := &observationRunner{
		observation: testProcessObservation(
			t,
			nil,
			[]byte(`{"code":"auth.login_required","message":"login first"}`),
			ports.ProcessTerminationExited,
			1,
		),
	}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane"))
	if err != nil {
		t.Fatal(err)
	}

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusAuthentication || observed.DiagnosticCode() != "login_required" {
		t.Fatalf("status = %q, diagnostic = %q", observed.Status(), observed.DiagnosticCode())
	}
	if observed.PrimaryCause() != domain.DiagnosticCauseLoginRequired {
		t.Fatalf("cause = %q", observed.PrimaryCause())
	}
}

func TestRegistryObserveClassifiesNativeProviderTimeout(t *testing.T) {
	invocation := testInvocation(t, "agy_default")
	runner := &observationRunner{
		observation: testProcessObservation(
			t,
			nil,
			[]byte("Error: timeout waiting for response\n"),
			ports.ProcessTerminationExited,
			1,
		),
	}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyAgy, "agy_default", "agy_lane"))
	if err != nil {
		t.Fatal(err)
	}

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusTimedOut || observed.DiagnosticCode() != "provider_timeout" {
		t.Fatalf("status = %q, diagnostic = %q", observed.Status(), observed.DiagnosticCode())
	}
	if observed.PrimaryCause() != domain.DiagnosticCauseTimedOut {
		t.Fatalf("cause = %q", observed.PrimaryCause())
	}
}

func TestRegistryObserveNormalizesFamilyNativeFailureSignals(t *testing.T) {
	tests := []struct {
		name, family, instance string
		stderr                 []byte
		wantStatus             ports.ProviderExecutionStatus
		wantCause              domain.RuntimeDiagnosticCause
		wantDiagnostic         string
	}{
		{"kimi login", FamilyKimi, "kimi_default", []byte("kimi.login_required"), ports.ProviderExecutionStatusAuthentication, domain.DiagnosticCauseLoginRequired, "login_required"},
		{"zcode login", FamilyZcode, "zcode_default", []byte("zcode login required"), ports.ProviderExecutionStatusAuthentication, domain.DiagnosticCauseLoginRequired, "login_required"},
		{"agy login", FamilyAgy, "agy_default", []byte("agy.login_required"), ports.ProviderExecutionStatusAuthentication, domain.DiagnosticCauseLoginRequired, "login_required"},
		{"agy permission", FamilyAgy, "agy_default", []byte("tool permission was denied"), ports.ProviderExecutionStatusAuthentication, domain.DiagnosticCausePermissionDenied, "provider_permission_denied"},
		{"authentication", FamilyKimi, "kimi_default", []byte("authentication_failed"), ports.ProviderExecutionStatusAuthentication, domain.DiagnosticCauseAuthenticationFailed, "provider_auth"},
		{"quota", FamilyZcode, "zcode_default", []byte("quota_exceeded"), ports.ProviderExecutionStatusQuota, domain.DiagnosticCauseQuotaExceeded, "provider_quota"},
		{"rate limit", FamilyAgy, "agy_default", []byte("too many requests"), ports.ProviderExecutionStatusRateLimit, domain.DiagnosticCauseRateLimited, "provider_rate_limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invocation := testInvocation(t, test.instance)
			runner := &observationRunner{observation: testProcessObservation(t, nil, test.stderr, ports.ProcessTerminationExited, 1)}
			registry, err := newRegistry(context.Background(), runner, testDefinition(t, test.family, test.instance, test.family+"_lane"))
			if err != nil {
				t.Fatal(err)
			}
			observed, err := registry.Observe(context.Background(), invocation)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Status() != test.wantStatus || observed.PrimaryCause() != test.wantCause || observed.DiagnosticCode() != test.wantDiagnostic {
				t.Fatalf("status = %q, cause = %q, diagnostic = %q; want %q, %q, %q", observed.Status(), observed.PrimaryCause(), observed.DiagnosticCode(), test.wantStatus, test.wantCause, test.wantDiagnostic)
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
	packet := []byte("review bytes")
	receipt, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	packetIdentity, err := ports.NewProviderPacketIdentity(len(packet), testStdinDigest(packet))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelArgvLiteral, packetIdentity, "", "",
		ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{},
	)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Unix(0, 0).UTC()
	endedAt := time.Unix(1, 0).UTC()
	switch termination {
	case ports.ProcessTerminationStartFailed, ports.ProcessTerminationStartUnavailable,
		ports.ProcessTerminationStartConfiguration, ports.ProcessTerminationStartSecurity,
		ports.ProcessTerminationLockFailed, ports.ProcessTerminationLockUnavailable,
		ports.ProcessTerminationLockConfiguration, ports.ProcessTerminationLockSecurity:
		observation, err := ports.NewProcessObservation(stdout, stderr, nil, termination, receipt, startedAt, endedAt)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	if termination == ports.ProcessTerminationExited {
		observation, err := ports.NewProviderProcessObservation(stdout, stderr, &exitCode, termination, receipt, transport, startedAt, endedAt)
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
		observation, err := ports.NewProviderProcessObservation(stdout, stderr, nil, termination, receipt, transport, startedAt, endedAt, signal)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	observation, err := ports.NewProviderProcessObservation(stdout, stderr, nil, termination, receipt, transport, startedAt, endedAt)
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
func packetOccurrences(argv []string, packet string) int {
	occurrences := 0
	for _, argument := range argv {
		if argument == packet {
			occurrences++
		}
	}
	return occurrences
}

func TestRegistryObserveWorkspaceUsesGuardedCWDLifecycleAndBoundRequest(t *testing.T) {
	root, identity := testWorkspaceRoot(t)
	events := make([]string, 0, 5)
	guard := &workspaceGuardFake{root: root, identity: identity, events: &events}
	authority := &workspaceAuthorityFake{identity: identity, guard: guard, events: &events}
	runner := &workspaceRunnerFake{
		events:      &events,
		observation: testProcessObservation(t, []byte("{\"role\":\"assistant\",\"content\":\"answer\"}\n"), nil, ports.ProcessTerminationExited, 0),
	}
	profile := testProfile(t, FamilyKimi, "kimi_default", "kimi_lane", "", "")
	registry, err := NewRegistry(runner, profile)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := registry.Observe(context.Background(), testWorkspaceInvocation(t, "kimi_default", authority)); err != nil {
		t.Fatal(err)
	}
	if runner.request.WorkingDirectory() != root.Path() {
		t.Fatalf("working directory = %q, want guard root %q", runner.request.WorkingDirectory(), root.Path())
	}
	if _, boundRoot, ok := runner.request.BoundLaunchDirectory(); !ok || boundRoot != root {
		t.Fatalf("bound request = (%v, %v)", ok, boundRoot)
	}
	if got, want := events, []string{"pre", "duplicate", "run", "post", "close"}; !equalStrings(got, want) {
		t.Fatalf("lifecycle = %q, want %q", got, want)
	}
}

func TestRegistryObserveWorkspaceBindsProductionAgyAddDirAndPacketReceipt(t *testing.T) {
	root, identity := testWorkspaceRoot(t)
	events := make([]string, 0, 5)
	guard := &workspaceGuardFake{root: root, identity: identity, events: &events}
	authority := &workspaceAuthorityFake{identity: identity, guard: guard, events: &events}
	runner := &workspaceRunnerFake{
		events:      &events,
		observation: testProcessObservation(t, []byte("{\"findings\":[]}"), nil, ports.ProcessTerminationExited, 0),
	}
	profile := testProfile(t, FamilyAgy, "agy_production", "agy_lane", "", "")
	registry, err := NewRegistry(runner, profile)
	if err != nil {
		t.Fatal(err)
	}

	invocation := testWorkspaceInvocation(t, "agy_production", authority)
	if _, err := registry.Observe(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}

	wantArgv := []string{"/private/bin/agy", "--new-project", "--sandbox", "--dangerously-skip-permissions", "--add-dir", root.Path(), "--mode", "plan", "--effort", "low", "--print-timeout", "500ms", "--print", string(invocation.PacketBytes())}
	if !equalStrings(runner.request.Argv(), wantArgv) || runner.request.WorkingDirectory() != root.Path() {
		t.Fatalf("request argv=%q working directory=%q, want argv=%q working directory=%q", runner.request.Argv(), runner.request.WorkingDirectory(), wantArgv, root.Path())
	}
	binding, ok := runner.request.ProviderPacketBinding()
	if !ok || binding.Channel() != ports.ProviderPacketChannelArgvLiteral ||
		binding.ArgvIndex() != len(profile.baseArgv)+12 ||
		runner.request.Argv()[binding.ArgvIndex()] != string(invocation.PacketBytes()) {
		t.Fatalf("packet binding = %#v, argv=%q", binding, runner.request.Argv())
	}
	if got, want := events, []string{"pre", "duplicate", "run", "post", "close"}; !equalStrings(got, want) {
		t.Fatalf("lifecycle = %q, want %q", got, want)
	}
}

func TestProviderProcessRequestRejectsMalformedWorkingDirectory(t *testing.T) {
	definition := testDefinition(t, FamilyAgy, "agy_default", "agy_lane")
	packet := testInvocation(t, "agy_default").Packet()
	for _, workingDirectory := range []string{"relative", "/private/work/../escape", "/private/work\x00"} {
		t.Run(workingDirectory, func(t *testing.T) {
			if _, _, err := providerProcessRequest(definition, packet, workingDirectory); err == nil {
				t.Fatal("malformed working directory accepted")
			}
		})
	}
}

func TestRegistryObserveWorkspaceDriftOverridesProviderSuccess(t *testing.T) {
	root, identity := testWorkspaceRoot(t)
	events := make([]string, 0, 5)
	guard := &workspaceGuardFake{root: root, identity: identity, events: &events, postErr: errors.New("changed")}
	authority := &workspaceAuthorityFake{identity: identity, guard: guard, events: &events}
	runner := &workspaceRunnerFake{
		events:      &events,
		observation: testProcessObservation(t, []byte("{\"role\":\"assistant\",\"content\":\"answer\"}\n"), nil, ports.ProcessTerminationExited, 0),
	}
	registry, err := NewRegistry(runner, testProfile(t, FamilyKimi, "kimi_default", "kimi_lane", "", ""))
	if err != nil {
		t.Fatal(err)
	}

	_, err = registry.Observe(context.Background(), testWorkspaceInvocation(t, "kimi_default", authority))
	if !errors.Is(err, ports.ErrWorkspaceSnapshotDrift) {
		t.Fatalf("error = %v, want workspace drift", err)
	}
	if got, want := events, []string{"pre", "duplicate", "run", "post", "close"}; !equalStrings(got, want) {
		t.Fatalf("lifecycle = %q, want %q", got, want)
	}
}

func TestRegistryObserveStrictDefinitionRejectsMissingWorkspaceAuthority(t *testing.T) {
	key, err := ports.ParseConcurrencyKey("kimi_lane")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewProductionRuntimeDefinition(
		FamilyKimi, "kimi_default", "", "/private/bin/kimi", "", key, "kimi_default",
		[]string{"/private/bin/kimi"}, nil, "/private/work", time.Second, 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &workspaceRunnerFake{}
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistryWithNamespaceFactory(runner, factory, profile)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default")); err == nil {
		t.Fatal("strict definition accepted authority-free invocation")
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestRegistryObserveLegacyDefinitionSupportsAuthorityFreeInvocation(t *testing.T) {
	runner := &workspaceRunnerFake{
		observation: testProcessObservation(t, []byte("{\"role\":\"assistant\",\"content\":\"answer\"}\n"), nil, ports.ProcessTerminationExited, 0),
	}
	registry, err := NewRegistry(runner, testProfile(t, FamilyKimi, "kimi_default", "kimi_lane", "", ""))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default")); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
}
func TestRegistryNamespaceBlocksHostHomeDriftAndTerminalReuse(t *testing.T) {
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	profile := testProfile(t, FamilyKimi, "kimi_default", "kimi_lane", "", "")
	profile.environment = []ports.EnvironmentVariable{mustEnvironment(t, "HOME", "/host/home/must-not-leak")}
	runner := &workspaceRunnerFake{
		observation: testProcessObservation(t, []byte("{\"role\":\"assistant\",\"content\":\"answer\"}\n"), nil, ports.ProcessTerminationExited, 0),
	}
	registry, err := NewRegistryWithNamespaceFactory(runner, factory, profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default")); err != nil {
		t.Fatal(err)
	}
	for _, variable := range runner.request.Environment() {
		if variable.Name() == "HOME" && variable.Value() == "/host/home/must-not-leak" {
			t.Fatal("runner inherited host HOME")
		}
	}
	lease := registry.namespaces["kimi_default"]
	cache := namespaceEnvironmentMap(t, lease.Environment())["XDG_CACHE_HOME"]
	if err := os.Remove(cache); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default")); err == nil {
		t.Fatal("namespace drift reached runner")
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
	if _, err := registry.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Observe(context.Background(), testInvocation(t, "kimi_default")); err == nil {
		t.Fatal("terminally drained registry reached runner")
	}
}

type workspaceAuthorityFake struct {
	identity ports.WorkspaceSnapshotIdentity
	guard    ports.WorkspaceExecutionGuard
	err      error
	events   *[]string
}

func (authority *workspaceAuthorityFake) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return authority.identity
}

func (authority *workspaceAuthorityFake) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	*authority.events = append(*authority.events, "pre")
	return authority.guard, authority.err
}

type workspaceGuardFake struct {
	root     ports.ValidatedWorkspaceRoot
	identity ports.WorkspaceSnapshotIdentity
	events   *[]string
	postErr  error
	closeErr error
}

func (guard *workspaceGuardFake) WorkspaceRoot() ports.ValidatedWorkspaceRoot { return guard.root }
func (guard *workspaceGuardFake) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return guard.identity
}
func (guard *workspaceGuardFake) DuplicateLaunchDirectory() (*os.File, error) {
	*guard.events = append(*guard.events, "duplicate")
	return os.Open(guard.root.Path())
}
func (guard *workspaceGuardFake) RevalidateAfterExecution() error {
	*guard.events = append(*guard.events, "post")
	return guard.postErr
}
func (guard *workspaceGuardFake) Close() error {
	*guard.events = append(*guard.events, "close")
	return guard.closeErr
}

type workspaceRunnerFake struct {
	request     ports.ProcessRequest
	observation ports.ProcessObservation
	err         error
	events      *[]string
	calls       int
}

func (runner *workspaceRunnerFake) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.calls++
	runner.request = request
	if runner.events != nil {
		*runner.events = append(*runner.events, "run")
	}
	if directory, _, ok := request.BoundLaunchDirectory(); ok {
		_ = directory.Close()
	}
	return runner.observation, runner.err
}

func testWorkspaceRoot(t *testing.T) (ports.ValidatedWorkspaceRoot, ports.WorkspaceSnapshotIdentity) {
	t.Helper()
	path := t.TempDir()
	identity, err := ports.NewWorkspaceSnapshotIdentity(
		path, "snapshot-0123456789abcdef0123456789abcdef", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy",
		1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	return root, identity
}

func testWorkspaceInvocation(t *testing.T, instance string, workspace ports.WorkspaceExecutionAuthority) ports.ProviderInvocation {
	t.Helper()
	legacy := testInvocation(t, instance)
	invocation, err := ports.NewProviderInvocationWithPacketInWorkspace(
		legacy.Role(), instance, legacy.AttemptID(), legacy.Purpose(), legacy.Packet(),
		legacy.SourceInvocationID(), legacy.ExecutionInvocationID(), workspace,
	)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}
func cloneRuntimeDefinition(profile RuntimeDefinition) RuntimeDefinition {
	profile.baseArgv = append([]string(nil), profile.baseArgv...)
	profile.environment = append([]ports.EnvironmentVariable(nil), profile.environment...)
	return profile
}

func TestProviderFailureProjectionKeepsTransportLifecycleSubtypesSecurityClosed(t *testing.T) {
	for _, cause := range []domain.RuntimeDiagnosticCause{
		domain.DiagnosticCausePromptFilePreStartFailed,
		domain.DiagnosticCausePromptFilePostEndFailed,
		domain.DiagnosticCauseTransportReceiptMismatch,
		domain.DiagnosticCauseLifecycleReceiptInvalid,
		domain.DiagnosticCauseOutputFrameMismatch,
		domain.DiagnosticCauseSignalReceiptMismatch,
	} {
		status, diagnostic := providerFailureProjection(cause)
		if status != ports.ProviderExecutionStatusSecurityViolation || diagnostic != "process_security" {
			t.Fatalf("cause %q projection = (%q, %q)", cause, status, diagnostic)
		}
	}
}

type barrierRunner struct {
	started     chan struct{}
	release     chan struct{}
	mu          sync.Mutex
	active      int
	directories []string
}

func newBarrierRunner() *barrierRunner {
	return &barrierRunner{
		started: make(chan struct{}, 4),
		release: make(chan struct{}),
	}
}

func (runner *barrierRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.mu.Lock()
	runner.active++
	runner.directories = append(runner.directories, request.WorkingDirectory())
	runner.mu.Unlock()
	defer func() {
		runner.mu.Lock()
		runner.active--
		runner.mu.Unlock()
	}()
	runner.started <- struct{}{}
	<-runner.release
	if directory, _, ok := request.BoundLaunchDirectory(); ok {
		_ = directory.Close()
	}
	receipt, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	packetIdentity, err := ports.NewProviderPacketIdentity(len([]byte("review bytes")), testStdinDigest([]byte("review bytes")))
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelArgvLiteral, packetIdentity, "", "",
		ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{},
	)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	exitCode := 0
	return ports.NewProviderProcessObservation([]byte("{}"), nil, &exitCode, ports.ProcessTerminationExited, receipt, transport, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
}

func (runner *barrierRunner) workingDirectories() []string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	result := append([]string(nil), runner.directories...)
	sort.Strings(result)
	return result
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

func mustEnvironment(t *testing.T, name, value string) ports.EnvironmentVariable {
	t.Helper()
	variable, err := ports.NewEnvironmentVariable(name, value)
	if err != nil {
		t.Fatal(err)
	}
	return variable
}

func testProfile(t *testing.T, family, instance, lane, version, executableSHA256 string) RuntimeDefinition {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(lane)
	if err != nil {
		t.Fatal(err)
	}
	executable := "/private/bin/" + family
	profile, err := NewRuntimeDefinition(
		family, instance, version, executable, executableSHA256, key, instance,
		[]string{executable}, nil, "/private/work", time.Second, 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}
func newTestProfileWithTransport(
	t *testing.T, family, instance, lane string, baseArgv []string, transport RuntimeTransport,
) (RuntimeDefinition, error) {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(lane)
	if err != nil {
		t.Fatal(err)
	}
	return NewRuntimeDefinitionWithTransport(
		family, instance, "", "/private/bin/"+family, "", key, instance,
		baseArgv, transport, nil, "/private/work", time.Second, 4096, 4096,
	)
}

func testDefinition(t *testing.T, family, instance, lane string) definition {
	t.Helper()
	return definition(testProfile(t, family, instance, lane, "", ""))
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
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(stdin)
	return hex.EncodeToString(hash.Sum(nil))
}

type scriptedNamespaceFactory struct {
	leases  map[string]*scriptedNamespace
	capture func(context.Context, string)
}

func (factory scriptedNamespaceFactory) AcquireProviderNamespace(ctx context.Context, instance string) (ports.ProviderNamespaceLease, error) {
	if factory.capture != nil {
		factory.capture(ctx, instance)
	}
	return ports.AcquireProviderNamespaceLease(ctx, instance, func(_ context.Context, _ string, binding ports.ProviderNamespaceTerminalBinding) (ports.ProviderNamespaceLease, error) {
		lease := factory.leases[instance]
		if lease == nil {
			return nil, errors.New("missing scripted namespace")
		}
		drain, err := binding.Bind(lease.generation, lease.drainTerminalEffects)
		if err != nil {
			return nil, err
		}
		lease.terminalDrain = drain
		return lease, nil
	})
}

type scriptedNamespace struct {
	instance, generation        string
	runtimeSafetyPolicyIdentity string
	mu                          sync.Mutex
	terminalDrain               ports.ProviderNamespaceTerminalDrain
	validateErr                 error
	drainCalls                  int
	failCalls                   int
	drainContext                func(context.Context)
}

func (lease *scriptedNamespace) ProviderInstance() string { return lease.instance }
func (lease *scriptedNamespace) Generation() string       { return lease.generation }
func (lease *scriptedNamespace) Environment() []ports.EnvironmentVariable {
	return nil
}
func (lease *scriptedNamespace) RuntimeSafetyPolicyIdentity() string {
	return lease.runtimeSafetyPolicyIdentity
}
func (*scriptedNamespace) ProjectCredential(context.Context, ports.CredentialProjectionRequest) (ports.CredentialProjectionReceipt, error) {
	return ports.CredentialProjectionReceipt{}, errors.New("unexpected credential projection")
}
func (lease *scriptedNamespace) ValidateForSpawn() error { return lease.validateErr }
func (lease *scriptedNamespace) DrainTerminal(ctx context.Context) (ports.ProviderNamespaceTerminalReceipt, error) {
	if lease == nil || lease.terminalDrain == nil {
		return ports.ProviderNamespaceTerminalReceipt{}, errors.New("missing scripted terminal drain")
	}
	return lease.terminalDrain(ctx)
}

func (lease *scriptedNamespace) drainTerminalEffects(ctx context.Context) error {
	if lease.drainContext != nil {
		lease.drainContext(ctx)
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.drainCalls++
	if ctx.Err() != nil || lease.failCalls > 0 {
		if lease.failCalls > 0 {
			lease.failCalls--
		}
		return context.Canceled
	}
	return nil
}

type testSpawnVerifier struct{}

func (testSpawnVerifier) VerifyProviderSpawn(context.Context, RuntimeDefinition) error { return nil }

func testProductionSafetyProfile(t *testing.T, family, policyIdentity string) RuntimeDefinition {
	t.Helper()
	key, err := ports.ParseConcurrencyKey("production_lane")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := defaultRuntimeTransport(family, 1)
	if err != nil {
		t.Fatal(err)
	}
	executable := "/private/bin/" + family
	profile, err := NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		family, family+"_production", "", executable, "executable-sha256", executable, "executable-sha256",
		key, family+"_production", "generation-1", policyIdentity, []string{executable}, transport, nil,
		"/private/work", time.Second, 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestNewProductionRegistryBindsAcquiredRuntimeSafetyPolicyIdentity(t *testing.T) {
	profile := testProductionSafetyProfile(t, FamilyKimi, "policy-expected")

	for _, test := range []struct {
		name   string
		policy string
		wantOK bool
	}{
		{name: "missing actual identity"},
		{name: "mismatched actual identity", policy: "policy-other"},
		{name: "matching actual identity", policy: "policy-expected", wantOK: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := &scriptedNamespace{
				instance: profile.Instance(), generation: "generation-1", runtimeSafetyPolicyIdentity: test.policy,
			}
			registry, err := NewProductionRegistry(&countingRunner{}, scriptedNamespaceFactory{
				leases: map[string]*scriptedNamespace{profile.Instance(): lease},
			}, testSpawnVerifier{}, profile)
			if test.wantOK {
				if err != nil || registry == nil {
					t.Fatalf("registry=%v err=%v", registry, err)
				}
				namespace, ok := registry.QualificationNamespace(profile.Instance())
				if !ok || namespace.RuntimeSafetyPolicyIdentity() != test.policy {
					t.Fatalf("qualification namespace policy = %q, ok=%t", namespace.RuntimeSafetyPolicyIdentity(), ok)
				}
				if _, exposesWorkingDirectory := namespace.(interface{ WorkingDirectory() string }); exposesWorkingDirectory {
					t.Fatal("qualification namespace exposed working-directory authority")
				}
				return
			}
			if err == nil || registry != nil {
				t.Fatalf("registry=%v err=%v", registry, err)
			}
			if lease.drainCalls != 1 {
				t.Fatalf("drain calls = %d, want 1", lease.drainCalls)
			}
		})
	}
}
func TestNewProductionRegistryConstructionUsesCallerContextForAcquireAndCleanup(t *testing.T) {
	profile := testProductionSafetyProfile(t, FamilyKimi, "policy-expected")
	type contextKey struct{}
	key := contextKey{}
	deadline := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.WithValue(context.Background(), key, "caller-value"), deadline)
	defer cancel()

	var acquisitionContext, cleanupContext context.Context
	lease := &scriptedNamespace{
		instance: profile.Instance(), generation: "generation-1", validateErr: errors.New("invalid namespace"),
		drainContext: func(ctx context.Context) { cleanupContext = ctx },
	}
	_, err := NewProductionRegistryWithContext(ctx, &countingRunner{}, scriptedNamespaceFactory{
		leases:  map[string]*scriptedNamespace{profile.Instance(): lease},
		capture: func(ctx context.Context, _ string) { acquisitionContext = ctx },
	}, testSpawnVerifier{}, profile)
	if err == nil {
		t.Fatal("malformed namespace construction succeeded")
	}
	for name, captured := range map[string]context.Context{"acquisition": acquisitionContext, "cleanup": cleanupContext} {
		if captured == nil || captured.Value(key) != "caller-value" {
			t.Fatalf("%s context value = %#v", name, captured)
		}
		gotDeadline, ok := captured.Deadline()
		if !ok || !gotDeadline.Equal(deadline) {
			t.Fatalf("%s deadline = %v, present=%t; want %v", name, gotDeadline, ok, deadline)
		}
	}
}

func TestNewProductionRegistryPolicyCleanupFailureRetainsPartialRegistry(t *testing.T) {
	first := testProductionSafetyProfile(t, FamilyKimi, "policy-kimi")
	second := testProductionSafetyProfile(t, FamilyKimi, "policy-zcode")
	second.instance = "kimi_secondary"
	firstLease := &scriptedNamespace{
		instance: first.Instance(), generation: "generation-1", runtimeSafetyPolicyIdentity: "policy-kimi",
	}
	secondLease := &scriptedNamespace{
		instance: second.Instance(), generation: "generation-1", runtimeSafetyPolicyIdentity: "wrong-policy", failCalls: 2,
	}
	registry, err := NewProductionRegistryWithContext(context.Background(), &countingRunner{}, scriptedNamespaceFactory{
		leases: map[string]*scriptedNamespace{first.Instance(): firstLease, second.Instance(): secondLease},
	}, testSpawnVerifier{}, first, second)
	if registry != nil || err == nil {
		t.Fatalf("registry=%v err=%v", registry, err)
	}
	owner, ok := RegistryFromConstructionError(err)
	if !ok || owner == nil {
		t.Fatalf("construction cleanup owner = %#v, present=%t", owner, ok)
	}
	if firstLease.drainCalls != 1 || secondLease.drainCalls != 1 {
		t.Fatalf("initial drains = first:%d second:%d", firstLease.drainCalls, secondLease.drainCalls)
	}
	secondLease.failCalls = 0
	receipt, closeErr := owner.Close(context.Background())
	if closeErr != nil || !receipt.Valid() {
		t.Fatalf("retry receipt=%#v err=%v", receipt, closeErr)
	}
	if firstLease.drainCalls != 1 || secondLease.drainCalls != 2 {
		t.Fatalf("retry drains = first:%d second:%d", firstLease.drainCalls, secondLease.drainCalls)
	}
}
func TestNewProductionRuntimeDefinitionWithSafetyPolicyAndPostOutputLifecycle(t *testing.T) {
	key, err := ports.ParseConcurrencyKey("agy_production_lane")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := defaultRuntimeTransport(FamilyAgy, 1)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle(
		FamilyAgy, "agy_production", "", "/private/bin/agy", "executable-sha256",
		"/private/bin/agy", "executable-sha256", key, "agy_production", "generation-1", "policy-identity",
		[]string{"/private/bin/agy"}, transport, lifecycle, nil, "/private/work", time.Second, 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	if profile.RuntimeSafetyPolicyIdentity() != "policy-identity" {
		t.Fatalf("runtime safety policy identity = %q", profile.RuntimeSafetyPolicyIdentity())
	}
	if got, ok := profile.PostOutputLifecycle(); !ok || got != lifecycle {
		t.Fatalf("post-output lifecycle = %#v, enabled=%t", got, ok)
	}
	if _, err := NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle(
		FamilyKimi, "kimi_production", "", "/private/bin/kimi", "executable-sha256",
		"/private/bin/kimi", "executable-sha256", key, "kimi_production", "generation-1", "policy-identity",
		[]string{"/private/bin/kimi"}, transport, lifecycle, nil, "/private/work", time.Second, 4096, 4096,
	); err == nil {
		t.Fatal("non-AGY profile accepted post-output lifecycle")
	}
}

func TestRegistryQualificationNamespaceIsNarrowRetainedLease(t *testing.T) {
	profile := testProfile(t, FamilyKimi, "kimi_default", "kimi_lane", "", "")
	lease := &scriptedNamespace{instance: "kimi_default", generation: "generation-1"}
	registry, err := NewRegistryWithNamespaceFactory(&countingRunner{}, scriptedNamespaceFactory{
		leases: map[string]*scriptedNamespace{"kimi_default": lease},
	}, profile)
	if err != nil {
		t.Fatal(err)
	}
	namespace, ok := registry.QualificationNamespace("kimi_default")
	if !ok || namespace == nil || namespace.ProviderInstance() != lease.instance ||
		namespace.Generation() != lease.generation || namespace.ValidateForSpawn() != nil {
		t.Fatalf("qualification namespace = %#v, ok=%t", namespace, ok)
	}
	if _, isLease := namespace.(ports.ProviderNamespaceLease); isLease {
		t.Fatal("qualification namespace exposed drain or credential authority")
	}
	if _, exposesWorkingDirectory := namespace.(interface{ WorkingDirectory() string }); exposesWorkingDirectory {
		t.Fatal("qualification namespace exposed working-directory authority")
	}
}

func TestRegistryCloseRetriesOnlyUndrainedNamespaces(t *testing.T) {
	first := testDefinition(t, FamilyKimi, "kimi_primary", "kimi_primary_lane")
	second := testDefinition(t, FamilyKimi, "kimi_secondary", "kimi_secondary_lane")
	primary := &scriptedNamespace{instance: "kimi_primary", generation: "generation-primary"}
	secondary := &scriptedNamespace{instance: "kimi_secondary", generation: "generation-secondary", failCalls: 1}
	registry, err := newRegistryWithNamespaces(context.Background(), &countingRunner{}, scriptedNamespaceFactory{leases: map[string]*scriptedNamespace{
		"kimi_primary": primary, "kimi_secondary": secondary,
	}}, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := registry.Close(context.Background()); err == nil || receipt.Valid() {
		t.Fatalf("partial close = %#v, %v", receipt, err)
	}
	if primary.drainCalls != 1 || secondary.drainCalls != 1 {
		t.Fatalf("first drain calls = primary %d secondary %d", primary.drainCalls, secondary.drainCalls)
	}
	receipt, err := registry.Close(context.Background())
	if err != nil || !receipt.Valid() || len(receipt.NamespaceReceipts()) != 2 {
		t.Fatalf("retry receipt = %#v, %v", receipt, err)
	}
	if primary.drainCalls != 1 || secondary.drainCalls != 2 {
		t.Fatalf("retry drain calls = primary %d secondary %d", primary.drainCalls, secondary.drainCalls)
	}
}
func TestRegistryCloseRetriesAfterCancellation(t *testing.T) {
	definition := testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane")
	lease := &scriptedNamespace{instance: "kimi_default", generation: "generation-1"}
	registry, err := newRegistryWithNamespaces(context.Background(), &countingRunner{}, scriptedNamespaceFactory{
		leases: map[string]*scriptedNamespace{"kimi_default": lease},
	}, definition)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if receipt, err := registry.Close(cancelled); err == nil || receipt.Valid() {
		t.Fatalf("cancelled close = %#v, %v", receipt, err)
	}
	if _, err := registry.Close(context.Background()); err != nil {
		t.Fatalf("retry close: %v", err)
	}
	if lease.drainCalls != 1 {
		t.Fatalf("drain calls = %d, want 1 after pre-drain cancellation", lease.drainCalls)
	}
}
func TestRegistryCloseCancellationWhileObservationIsActiveIsRetryable(t *testing.T) {
	runner := newBarrierRunner()
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyKimi, "kimi_default", "kimi_lane"))
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan error, 1)
	go func() {
		_, observeErr := registry.Observe(context.Background(), testInvocation(t, "kimi_default"))
		observed <- observeErr
	}()
	<-runner.started

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	closed := make(chan error, 1)
	go func() {
		_, closeErr := registry.Close(cancelled)
		closed <- closeErr
	}()
	select {
	case closeErr := <-closed:
		if !errors.Is(closeErr, context.Canceled) {
			t.Fatalf("cancelled close error = %v", closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled close waited for active observation")
	}
	close(runner.release)
	<-observed
	if _, err := registry.Close(context.Background()); err != nil {
		t.Fatalf("retry close: %v", err)
	}
}
