package providercli

import (
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestDeriveEquivalentRouteRequiresSourceMatches(t *testing.T) {
	definition, authority := currentProbeAuthorityForDefinition(t)
	foreign := definition
	foreign.instance = "other"
	foreign.profileID = "other-profile"
	if _, err := DeriveEquivalentRouteDirectExecutionAuthority(
		authority, foreign, definition, "1.2.3", "generation", "generation",
		[]domain.Role{domain.RoleLogic}, []domain.Role{domain.RoleLogic},
	); err == nil {
		t.Fatal("derivation accepted source authority that does not match source runtime")
	}
}

func TestDeriveEquivalentRouteZCodePositiveAndAuthorityIsolation(t *testing.T) {
	source, authority := currentProbeAuthorityForDefinition(t)
	destination := source
	destination.instance = "zcode-security"
	destination.profileID = "zcode-security"

	derived, err := DeriveEquivalentRouteDirectExecutionAuthority(
		authority,
		source,
		destination,
		"1.2.3",
		"namespace",
		"namespace-security",
		[]domain.Role{domain.RoleLogic},
		[]domain.Role{domain.RoleSecurity},
	)
	if err != nil {
		t.Fatalf("ZCode -> ZCode derivation failed: %v", err)
	}
	if !derived.Valid() {
		t.Fatal("derived authority is invalid")
	}
	if derived.AuthorityID() == authority.AuthorityID() {
		t.Fatal("derived authority reused source authority ID")
	}
	if !derived.Matches(destination, "1.2.3", "namespace-security", []domain.Role{domain.RoleSecurity}) {
		t.Fatal("derived authority does not match destination runtime")
	}
	if derived.Matches(destination, "1.2.3", "namespace-security", []domain.Role{domain.RoleLogic}) {
		t.Fatal("derived authority matched source-only role")
	}
	if derived.Matches(source, "1.2.3", "namespace", []domain.Role{domain.RoleLogic}) {
		t.Fatal("derived authority matched source runtime")
	}
	if derived.Matches(source, "1.2.3", "namespace-security", []domain.Role{domain.RoleSecurity}) {
		t.Fatal("derived authority matched source runtime with destination role")
	}
	if derived.Matches(destination, "1.2.3", "namespace", []domain.Role{domain.RoleSecurity}) {
		t.Fatal("derived authority matched source namespace generation")
	}
}

func TestDeriveEquivalentRouteZCodeRejectsProfileMismatches(t *testing.T) {
	source, authority := currentProbeAuthorityForDefinition(t)
	for _, tc := range []struct {
		name   string
		mutate func(*RuntimeDefinition)
	}{
		{name: "zcode_model", mutate: func(d *RuntimeDefinition) { d.zcodeModel = "account:zai-individual-coding-plan/GLM-5.3-Flash" }},
		{name: "zcode_reasoning_effort", mutate: func(d *RuntimeDefinition) { d.zcodeReasoningEffort = "high" }},
		{name: "zcode_provider_config", mutate: func(d *RuntimeDefinition) { d.zcodeProviderConfig = "/private/config/other.json" }},
		{name: "zcode_provider_config_sha256", mutate: func(d *RuntimeDefinition) { d.zcodeProviderConfigSHA256 = "sha256:" + repeatHex('f') }},
		{name: "application_version", mutate: func(d *RuntimeDefinition) { d.applicationVersion = "3.19.0" }},
		{name: "companion_package", mutate: func(d *RuntimeDefinition) { d.zcodeCompanion.PackageSHA256 = repeatHex('e') }},
		{name: "companion_bundle_omission", mutate: func(d *RuntimeDefinition) { d.zcodeCompanion.BundleOverride = d.zcodeCompanion.AppBundle }},
		{name: "application_metadata", mutate: func(d *RuntimeDefinition) { d.applicationMetadata = "/Applications/OtherZCode.app/Contents/Info.plist" }},
		{name: "application_metadata_sha256", mutate: func(d *RuntimeDefinition) { d.applicationMetadataSHA256 = "sha256:" + repeatHex('e') }},
		{name: "executable", mutate: func(d *RuntimeDefinition) { d.executable = "/private/bin/other-node" }},
		{name: "launcher", mutate: func(d *RuntimeDefinition) { d.launcher = "/private/bin/other-zcode.cjs" }},
		{name: "runtime_safety_policy_identity", mutate: func(d *RuntimeDefinition) { d.runtimeSafetyPolicyIdentity = "other-safety-policy" }},
		{name: "cross_family_grok", mutate: func(d *RuntimeDefinition) { d.family = FamilyGrok }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			destination := source
			destination.instance = "zcode-security"
			destination.profileID = "zcode-security"
			tc.mutate(&destination)
			if _, err := DeriveEquivalentRouteDirectExecutionAuthority(
				authority,
				source,
				destination,
				"1.2.3",
				"namespace",
				"namespace-security",
				[]domain.Role{domain.RoleLogic},
				[]domain.Role{domain.RoleSecurity},
			); err == nil {
				t.Fatalf("derivation accepted mismatched %s", tc.name)
			}
		})
	}
}

func repeatHex(digit byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = digit
	}
	return string(out)
}
