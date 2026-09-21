package providercli

import (
	"testing"
)

func TestGrokSettingsIdentityDistinguishesEveryConfiguredDimension(t *testing.T) {
	identities := map[string]bool{}
	for _, settings := range []grokInvocationSettings{
		{},
		{model: "grok-4.5"},
		{reasoningEffort: "low"},
		{model: "grok-4.5", reasoningEffort: "low"},
	} {
		identity := grokSettingsIdentity(settings.model, settings.reasoningEffort)
		if identities[identity] {
			t.Fatalf("duplicate identity for %#v", settings)
		}
		identities[identity] = true
	}
}

func TestGrokSettingsAreBoundToRuntimeAndProbeIdentity(t *testing.T) {
	base := testProfile(t, FamilyGrok, "grok-logic", "1.0.34", "")
	configured := base
	configured.grokModel = "grok-4.5"
	configured.grokReasoningEffort = "low"
	configured.grokSettingsIdentity = grokSettingsIdentity(configured.grokModel, configured.grokReasoningEffort)
	if err := configured.validate(); err != nil {
		t.Fatal(err)
	}
	if equivalentFamilyRuntimeProfiles(base, configured) {
		t.Fatal("configured and provider-default Grok profiles were equivalent")
	}
	baseIdentity, err := currentProbeRuntimeDefinitionIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	configuredIdentity, err := currentProbeRuntimeDefinitionIdentity(configured)
	if err != nil {
		t.Fatal(err)
	}
	if baseIdentity == configuredIdentity {
		t.Fatal("Grok settings did not change the current-probe runtime identity")
	}
}

func TestGrokSettingsValidationMatchesPublicGrammar(t *testing.T) {
	for _, valid := range []grokInvocationSettings{
		{},
		{model: "grok-4.5"},
		{model: "vendor/grok_4.5-preview", reasoningEffort: "extra-high"},
	} {
		if _, err := newGrokInvocationSettings(valid.model, valid.reasoningEffort); err != nil {
			t.Fatalf("valid settings %#v: %v", valid, err)
		}
	}
	for _, invalid := range []grokInvocationSettings{
		{model: "/absolute"},
		{model: "vendor//model"},
		{model: "vendor/../model"},
		{reasoningEffort: "contains space"},
	} {
		if _, err := newGrokInvocationSettings(invalid.model, invalid.reasoningEffort); err == nil {
			t.Fatalf("invalid settings accepted: %#v", invalid)
		}
	}
}
