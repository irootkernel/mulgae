package mulgae

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/doctor"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestParseAgySettingsAndSingleAccountBoundary(t *testing.T) {
	for _, selection := range []string{"agy", "auto", "agy,zcode"} {
		invocation := mustParse(t, []string{"init", "--providers", selection, "--agy-executable", "/opt/bin/agy", "--agy-model", "gemini-3", "--agy-reasoning-effort", "max"})
		request, ok := invocation.Init()
		if !ok {
			t.Fatal("no init request")
		}
		executable, model, effort, hasModel, hasEffort := request.AgyOverrides()
		if executable != "/opt/bin/agy" || model != "gemini-3" || effort != "max" || !hasModel || !hasEffort {
			t.Fatalf("AGY overrides: %#v", request)
		}
	}
	for _, arguments := range [][]string{
		{"init", "--providers", "grok", "--agy-model", "gemini-3"},
		{"init", "--providers", "agy", "--agy-model", "../model"},
		{"init", "--providers", "agy", "--agy-model", ""},
		{"init", "--providers", "agy", "--agy-reasoning-effort", "ultra"},
		{"init", "--providers", "agy", "--agy-executable", "relative/agy"},
		{"init", "--refresh-local", "--agy-model", "gemini-3"},
		{"init", "--providers", "agy", "--agy-home", "/account"},
		{"heartbeat", "--provider", "agy", "--credential-profile", "secondary"},
	} {
		if _, err := Parse(arguments, testProjectRoot, testRequestID); !errors.Is(err, ErrUsage) {
			t.Errorf("accepted invalid arguments %v: %v", arguments, err)
		}
	}
	invocation := mustParse(t, []string{"heartbeat", "--provider", "agy", "--authorize-live-request"})
	request, ok := invocation.Heartbeat()
	if !ok || request.ProviderID() != "agy" || !request.Authorized() || request.CredentialProfile() != "" {
		t.Fatalf("heartbeat: %#v", request)
	}
}

func TestApplicationInitAgyPublishesCurrentContractAndSplitPolicy(t *testing.T) {
	fixture := newFoundationFixture(t)
	fixture.application.versionObserver = doctorVersionObserverFunc(func(_ context.Context, family string, _ []string, _ ports.ProviderVersionIdentity) (ports.ProviderVersionObservation, error) {
		if family != "agy" {
			return ports.ProviderVersionObservation{}, errors.New("unexpected provider")
		}
		return ports.NewProviderVersionObservation(ports.ProviderVersionObserved, "1.4.2")
	})
	root := testAnchoredRoot(t)
	result := fixture.application.Run(context.Background(), []string{"init", "--providers", "agy", "--roles", "documentation", "--agy-executable", "/bin/sh", "--agy-model", "gemini-3", "--agy-reasoning-effort", "max", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, result, app.ExitCodeSuccess)
	project, err := os.ReadFile(filepath.Join(root, ".mulgae", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	local, err := os.ReadFile(filepath.Join(root, ".mulgae", "local.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := adapterconfig.DecodeSplit(project, local)
	if err != nil || config.Providers.Agy == nil || config.Providers.Agy.Model != "gemini-3" || config.Providers.Agy.ReasoningEffort != "max" || config.Roles.Documentation.PrimaryProvider != "agy" {
		t.Fatalf("AGY config: %#v %v", config, err)
	}
	var envelope struct {
		SchemaVersion string `json:"schema_version"`
		Result        struct {
			Discovery []struct {
				Family string `json:"family"`
			} `json:"discovery"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Stdout(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != "mulgae-command-result.v21" || len(envelope.Result.Discovery) != 5 || envelope.Result.Discovery[4].Family != "agy" {
		t.Fatalf("AGY envelope: %#v", envelope)
	}
	diagnosed := fixture.application.Run(context.Background(), []string{"doctor", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, diagnosed, app.ExitCodeSuccess)
	var diagnosis struct {
		Result struct {
			Doctor doctor.LocalDoctorResult `json:"doctor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(diagnosed.Stdout(), &diagnosis); err != nil {
		t.Fatal(err)
	}
	d := diagnosis.Result.Doctor
	if d.SchemaVersion != "mulgae-doctor-result.v7" || len(d.ProviderInventory) != 5 || !d.ProviderInventory[4].Configured || d.ProviderInventory[4].State != "eligible" || d.ProviderInventory[4].CLICompatible.ObservedVersion != "1.4.2" {
		t.Fatalf("AGY doctor: %#v", d)
	}
	providers := fixture.application.Run(context.Background(), []string{"providers", "--include-unverified", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, providers, app.ExitCodeSuccess)
	unauthorized := fixture.application.Run(context.Background(), []string{"heartbeat", "--provider", "agy", "--output", "json"}, root)
	assertFoundationEnvelope(t, fixture, unauthorized, app.ExitCodeUsage)
}
