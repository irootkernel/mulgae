package reviewrun

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestFamiliesAndGuidanceUseCanonicalOrder(t *testing.T) {
	want := []Family{FamilyZCode, FamilyGrok}
	if got := Families(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Families() = %v, want %v", got, want)
	}
	guidance := []VersionGuidance{
		{Family: FamilyZCode, Minimum: "0.2.0", VerifiedLatest: "0.2.0"},
		{Family: FamilyGrok, Minimum: "1.0.89", VerifiedLatest: "1.0.89"},
	}
	for _, want := range guidance {
		got, ok := Guidance(want.Family)
		if !ok || got != want {
			t.Fatalf("Guidance(%q) = (%+v, %t), want (%+v, true)", want.Family, got, ok, want)
		}
	}
}
func TestReceiptKindsUseCanonicalOrder(t *testing.T) {
	want := []ReceiptKind{
		ReceiptWorkspace,
		ReceiptEnvironment,
		ReceiptTransport,
		ReceiptNativeReference,
		ReceiptCapability,
		ReceiptBaseRole,
		ReceiptAssignment,
		ReceiptSecurityPolicy,
	}
	if got := ReceiptKinds(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ReceiptKinds() = %v, want %v", got, want)
	}
}

func TestClassifyVersion(t *testing.T) {
	tests := []struct {
		name    string
		family  Family
		version string
		want    VersionClassification
	}{
		{name: "below minimum", family: FamilyZCode, version: "0.1.9", want: VersionRed},
		{name: "minimum", family: FamilyZCode, version: "0.2.0", want: VersionGreen},
		{name: "verified latest", family: FamilyZCode, version: "0.2.0", want: VersionGreen},
		{name: "above verified latest", family: FamilyZCode, version: "0.2.1", want: VersionYellow},
		{name: "minimum", family: FamilyZCode, version: "0.2.0", want: VersionGreen},
		{name: "verified latest", family: FamilyZCode, version: "0.2.0", want: VersionGreen},
		{name: "above verified latest", family: FamilyZCode, version: "0.2.1", want: VersionYellow},
		{name: "below minimum", family: FamilyGrok, version: "1.0.40", want: VersionRed},
		{name: "below minimum 1.0.88", family: FamilyGrok, version: "1.0.88", want: VersionRed},
		{name: "minimum", family: FamilyGrok, version: "1.0.89", want: VersionGreen},
		{name: "verified latest", family: FamilyGrok, version: "1.0.89", want: VersionGreen},
		{name: "above verified latest", family: FamilyGrok, version: "1.0.90", want: VersionYellow},
		{name: "unparseable", family: FamilyZCode, version: "latest", want: VersionUnknown},
		{name: "unknown family", family: "other", version: "1.0.0", want: VersionUnknown},
		{name: "october semver remains semver", family: FamilyZCode, version: "2026.10.14", want: VersionYellow},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyVersion(test.family, test.version); got != test.want {
				t.Fatalf("ClassifyVersion(%q, %q) = %q, want %q", test.family, test.version, got, test.want)
			}
		})
	}
}

func TestValidateQualificationBlocksKnownIncompatibleProvider(t *testing.T) {
	input := completeInput(t, FamilyZCode, "0.2.0")
	input.KnownIncompatible = true
	qualification := ValidateQualification(input)
	if qualification.Available() || qualification.Reason() != "known_incompatible" {
		t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
	}
}

func TestValidateQualificationRejectsMissingAndExpiredReceipts(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		input := completeInput(t, FamilyGrok, "1.0.89")
		input.Receipts = input.Receipts[:len(input.Receipts)-1]
		qualification := ValidateQualification(input)
		if qualification.Available() || qualification.Reason() != "missing_receipt" {
			t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
		}
	})
	t.Run("expired", func(t *testing.T) {
		input := completeInput(t, FamilyGrok, "1.0.89")
		input.Receipts[0].ExpiresAt = input.Now
		qualification := ValidateQualification(input)
		if qualification.Available() || qualification.Reason() != "expired_receipt" {
			t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
		}
	})
}

func TestValidateQualificationRejectsEveryNonPassReceiptState(t *testing.T) {
	states := []ReceiptState{ReceiptMissing, ReceiptStale, ReceiptSkipped, ReceiptInconclusive, ReceiptFailed}
	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			input := completeInput(t, FamilyGrok, "1.0.89")
			input.Receipts[0].State = state
			qualification := ValidateQualification(input)
			if qualification.Available() || qualification.Reason() != "non_passing_receipt" {
				t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
			}
		})
	}
}

func TestValidateQualificationRejectsIdentityMismatches(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Identity)
	}{
		{name: "profile", change: func(identity *Identity) { identity.ProfileGeneration = "profile-2" }},
		{name: "snapshot", change: func(identity *Identity) { identity.ExecutionTargetIdentity = "manifest-2" }},
		{name: "lease", change: func(identity *Identity) { identity.NamespaceLease = "lease-2" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := completeInput(t, FamilyGrok, "1.0.89")
			test.change(&input.Receipts[0].Identity)
			qualification := ValidateQualification(input)
			if qualification.Available() || qualification.Reason() != "identity_mismatch" {
				t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
			}
		})
	}
}

func TestValidateQualificationAdmitsCompleteNewerPassSet(t *testing.T) {
	input := completeInput(t, FamilyGrok, "1.0.90")
	qualification := ValidateQualification(input)
	if !qualification.Available() {
		t.Fatalf("qualification unavailable: %s", qualification.Reason())
	}
	if qualification.Classification() != VersionYellow {
		t.Fatalf("classification = %q, want %q", qualification.Classification(), VersionYellow)
	}
}
func TestValidateQualificationTreatsProvenanceAsDiagnostic(t *testing.T) {
	input := completeInput(t, FamilyGrok, "1.0.89")
	input.Receipts[0].Provenance = Provenance{
		Version: "older-version",
		Path:    "/former/path",
		SHA256:  "former-sha",
		Profile: "former-profile",
	}
	if qualification := ValidateQualification(input); !qualification.Available() {
		t.Fatalf("qualification unavailable: %s", qualification.Reason())
	}
}

func TestValidateQualificationRequiresScopedAuthorities(t *testing.T) {
	t.Run("missing capability authority", func(t *testing.T) {
		input := completeInput(t, FamilyGrok, "1.0.89")
		for index := range input.Receipts {
			if input.Receipts[index].Kind == ReceiptCapability {
				input.Receipts[index].AuthorityID = ""
			}
		}
		if qualification := ValidateQualification(input); qualification.Available() || qualification.Reason() != "invalid_receipts" {
			t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
		}
	})
	t.Run("wrong authority scope", func(t *testing.T) {
		input := completeInput(t, FamilyGrok, "1.0.89")
		for index := range input.Receipts {
			if input.Receipts[index].Kind == ReceiptSecurityPolicy {
				input.Receipts[index].AuthorityScope = AuthorityScope("retired-provider-controls")
			}
		}
		if qualification := ValidateQualification(input); qualification.Available() || qualification.Reason() != "invalid_receipts" {
			t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
		}
	})
	t.Run("generic runtime safety authority", func(t *testing.T) {
		for _, test := range []struct {
			family  Family
			version string
		}{
			{family: FamilyZCode, version: "0.2.0"},
			{family: FamilyZCode, version: "0.2.0"},
		} {
			family := test.family
			t.Run(string(family), func(t *testing.T) {
				input := completeInput(t, family, test.version)
				if qualification := ValidateQualification(input); !qualification.Available() {
					t.Fatalf("qualification unavailable: %s", qualification.Reason())
				}
				for _, mutate := range []struct {
					name  string
					apply func(*Receipt)
				}{
					{name: "missing authority", apply: func(receipt *Receipt) { receipt.AuthorityID = "" }},
					{name: "mismatched authority scope", apply: func(receipt *Receipt) { receipt.AuthorityScope = AuthorityScope("retired-provider-controls") }},
				} {
					t.Run(mutate.name, func(t *testing.T) {
						rejected := completeInput(t, family, test.version)
						for index := range rejected.Receipts {
							if rejected.Receipts[index].Kind == ReceiptSecurityPolicy {
								mutate.apply(&rejected.Receipts[index])
							}
						}
						if qualification := ValidateQualification(rejected); qualification.Available() || qualification.Reason() != "invalid_receipts" {
							t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
						}
					})
				}
			})
		}
	})
}
func TestValidateQualificationRejectsCallerManufacturedAuthorities(t *testing.T) {
	for _, test := range []struct {
		family  Family
		version string
	}{
		{family: FamilyZCode, version: "0.2.0"},
		{family: FamilyZCode, version: "0.2.0"},
		{family: FamilyGrok, version: "1.0.89"},
	} {
		t.Run(string(test.family), func(t *testing.T) {
			input := completeInput(t, test.family, test.version)
			for index := range input.Receipts {
				if input.Receipts[index].Kind == ReceiptCapability || input.Receipts[index].Kind == ReceiptSecurityPolicy {
					input.Receipts[index].AuthorityID = "sha256:caller-manufactured"
				}
			}
			if qualification := ValidateQualification(input); qualification.Available() || qualification.Reason() != "invalid_receipts" {
				t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
			}
		})
	}
}
func TestAdapterIssuedAuthorityBaselinesRejectBindingMutations(t *testing.T) {
	for _, test := range []struct {
		name    string
		family  Family
		version string
		mutate  func(*QualificationInput)
	}{
		{name: "identity", family: FamilyZCode, version: "0.2.0", mutate: func(input *QualificationInput) {
			input.Identity.Instance = "other-instance"
			for index := range input.Receipts {
				input.Receipts[index].Identity.Instance = "other-instance"
			}
		}},
		{name: "namespace generation", family: FamilyZCode, version: "0.2.0", mutate: func(input *QualificationInput) {
			input.Identity.NamespaceGeneration = "stale-generation"
			for index := range input.Receipts {
				input.Receipts[index].Identity.NamespaceGeneration = "stale-generation"
			}
		}},
		{name: "expiry", family: FamilyGrok, version: "1.0.89", mutate: func(input *QualificationInput) {
			for index := range input.Receipts {
				input.Receipts[index].ExpiresAt = input.Receipts[index].ExpiresAt.Add(time.Second)
			}
		}},
		{name: "family", family: FamilyZCode, version: "9.0.0", mutate: func(input *QualificationInput) {
			for index := range input.Receipts {
				input.Receipts[index].Identity.Family = FamilyGrok
			}
		}},
		{name: "canonical control scope", family: FamilyGrok, version: "1.0.89", mutate: func(input *QualificationInput) {
			for index := range input.Receipts {
				if input.Receipts[index].Kind == ReceiptSecurityPolicy {
					input.Receipts[index].AuthorityScope = AuthorityScope("retired-provider-controls")
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := completeInput(t, test.family, test.version)
			if baseline := ValidateQualification(input); !baseline.Available() {
				t.Fatalf("adapter-issued authority baseline = available %t, reason %q", baseline.Available(), baseline.Reason())
			}
			test.mutate(&input)
			if qualification := ValidateQualification(input); qualification.Available() {
				t.Fatalf("mutated adapter-issued authority baseline = available %t, reason %q", qualification.Available(), qualification.Reason())
			}
		})
	}
}
func TestQualificationReceiptIDIncludesAuthorityScope(t *testing.T) {
	input := completeInput(t, FamilyGrok, "1.0.89")
	var receipt Receipt
	for _, candidate := range input.Receipts {
		if candidate.Kind == ReceiptSecurityPolicy {
			receipt = candidate
			break
		}
	}
	first := qualificationReceiptID(receipt)
	receipt.AuthorityScope = AuthorityScope("retired-provider-controls")
	if second := qualificationReceiptID(receipt); second == first {
		t.Fatal("qualification receipt ID did not bind authority scope")
	}
}

func TestQualificationDefensivelyCopiesMutableInput(t *testing.T) {
	input := completeInput(t, FamilyGrok, "1.0.89")
	qualification := ValidateQualification(input)
	input.Receipts[0].State = ReceiptFailed
	got := qualification.Receipts()
	if got[0].State != ReceiptPass {
		t.Fatalf("stored receipt state = %q, want %q", got[0].State, ReceiptPass)
	}
	got[0].State = ReceiptFailed
	if qualification.Receipts()[0].State != ReceiptPass {
		t.Fatal("Receipts exposed mutable stored state")
	}
	families := Families()
	families[0] = "mutated"
	if Families()[0] != FamilyZCode {
		t.Fatal("Families exposed mutable stored state")
	}
}
func TestValidateQualificationVersionPolicy(t *testing.T) {
	tests := []struct {
		name      string
		family    Family
		version   string
		mutate    func(*QualificationInput)
		available bool
		reason    string
		class     VersionClassification
	}{
		{name: "below minimum", family: FamilyZCode, version: "0.1.9", available: false, reason: "ineligible_version", class: VersionRed},
		{name: "below Grok minimum", family: FamilyGrok, version: "1.0.40", available: false, reason: "ineligible_version", class: VersionRed},
		{name: "minimum", family: FamilyGrok, version: "1.0.89", available: true, reason: "eligible", class: VersionGreen},
		{name: "verified latest", family: FamilyGrok, version: "1.0.89", available: true, reason: "eligible", class: VersionGreen},
		{name: "grok 1.0.90 yellow eligible", family: FamilyGrok, version: "1.0.90", available: true, reason: "eligible", class: VersionYellow},
		{name: "newer with current pass", family: FamilyGrok, version: "1.0.90", available: true, reason: "eligible", class: VersionYellow},
		{name: "newer with failed current pass", family: FamilyGrok, version: "1.0.90", mutate: func(input *QualificationInput) { input.Receipts[0].State = ReceiptFailed }, available: false, reason: "non_passing_receipt", class: VersionYellow},
		{name: "unparseable", family: FamilyZCode, version: "current", available: false, reason: "unparseable_version", class: VersionUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := completeInput(t, test.family, test.version)
			if test.mutate != nil {
				test.mutate(&input)
			}
			qualification := ValidateQualification(input)
			if qualification.Available() != test.available || qualification.Reason() != test.reason || qualification.Classification() != test.class {
				t.Fatalf("qualification = available %t, reason %q, classification %q", qualification.Available(), qualification.Reason(), qualification.Classification())
			}
		})
	}
}

func TestValidateQualificationRequiresCanonicalExecutableProvenance(t *testing.T) {
	input := completeInput(t, FamilyZCode, "0.2.0")
	input.Identity.Executable = "provider"
	for index := range input.Receipts {
		input.Receipts[index].Identity.Executable = input.Identity.Executable
	}
	if qualification := ValidateQualification(input); qualification.Available() || qualification.Reason() != "invalid_identity" {
		t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
	}
}

func TestDiscoverProviderProfilesUsesDirectZCodeCompanion(t *testing.T) {
	inspector := discoveryInspector{}
	profile, err := DiscoverProviderProfile(context.Background(), inspector, FamilyZCode)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/opt/providers/bin/herdr-zcode"}
	if profile.Available() || profile.Reason() != "unqualified_discovery" || profile.Executable() != profile.Launcher() || !reflect.DeepEqual(profile.Argv(), want) {
		t.Fatalf("unqualified companion profile = %#v", profile)
	}
	qualified := profile.WithQualifiedVersion(append(want, "--version", "--json"), "0.2.0")
	if !qualified.Available() || qualified.Version() != "0.2.0" {
		t.Fatalf("qualified companion profile = %#v", qualified)
	}
}
func TestDiscoverProviderProfileObservesOnlyRequestedFamily(t *testing.T) {
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{
			"grok": discoveredExecutable(t, "grok", "/opt/providers/grok", "1.0.89"),
		},
		errors: map[string]error{"node": errors.New("poisoned ZCode")},
	}
	profile, err := DiscoverProviderProfile(context.Background(), inspector, FamilyGrok)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Family() != FamilyGrok || profile.Executable() != "/opt/providers/grok" || !reflect.DeepEqual(inspector.calls, []string{"grok"}) {
		t.Fatalf("profile=%#v calls=%v", profile, inspector.calls)
	}
}

func TestDiscoverConfiguredProviderProfilesKeepsEligibleFamilyWhenAnotherIsUnavailable(t *testing.T) {
	const bundle = "/opt/providers/ZCode.app"
	const grok = "/opt/providers/grok"
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{
			grok: discoveredExecutable(t, grok, grok, ""),
		},
		errors: map[string]error{
			bundle: ports.NewIdentityObservationError(ports.IdentityObservationUnavailable, "executable is unavailable"),
		},
		fileMissing: map[string]bool{filepath.Join(bundle, filepath.FromSlash("Contents/Resources/glm/zcode.cjs")): true},
	}
	profiles, err := DiscoverConfiguredProviderProfiles(context.Background(), inspector, map[Family][]string{
		FamilyZCode: {bundle},
		FamilyGrok:  {grok},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[0].Family() != FamilyZCode || profiles[0].Executable() != "" || profiles[1].Family() != FamilyGrok || profiles[1].Executable() != grok {
		t.Fatalf("profiles = %#v", profiles)
	}
}

func TestDiscoverConfiguredProviderProfilesReportsScopedSecurityFailureAfterOtherFamilies(t *testing.T) {
	const bundle = "/opt/providers/ZCode.app"
	const grok = "/opt/providers/grok"
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{
			grok: discoveredExecutable(t, grok, grok, ""),
		},
		errors: map[string]error{
			bundle: ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "executable identity changed"),
		},
	}
	profiles, err := DiscoverConfiguredProviderProfiles(context.Background(), inspector, map[Family][]string{
		FamilyZCode: {bundle},
		FamilyGrok:  {grok},
	})
	if !reflect.DeepEqual(ConfiguredProviderSecurityFamilies(err), []Family{FamilyZCode}) {
		t.Fatalf("security families = %v, error = %v", ConfiguredProviderSecurityFamilies(err), err)
	}
	if len(profiles) != 2 || profiles[0].Family() != FamilyZCode || profiles[1].Family() != FamilyGrok || profiles[1].Executable() != grok {
		t.Fatalf("profiles = %#v", profiles)
	}
}

func TestDiscoverConfiguredProviderProfilesPropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	const bundle = "/opt/providers/ZCode.app"
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{},
		errors: map[string]error{
			bundle: ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "executable identity changed"),
		},
	}
	profiles, err := DiscoverConfiguredProviderProfiles(ctx, inspector, map[Family][]string{FamilyZCode: {bundle}})
	if !errors.Is(err, context.Canceled) || profiles != nil {
		t.Fatalf("profiles = %#v, error = %v", profiles, err)
	}
}

func TestDiscoverConfiguredProviderProfilesRejectsInvalidConfiguredTuplesBeforeObservation(t *testing.T) {
	inspector := &recordingDiscoveryInspector{executables: map[string]ports.ExecutableObservation{}, errors: map[string]error{}}
	for name, configured := range map[string]map[Family][]string{
		"unknown family":   {Family("other"): {"/opt/providers/other"}},
		"empty tuple":      {FamilyZCode: {}},
		"extra path":       {FamilyGrok: {"/opt/providers/grok", "/opt/providers/other"}},
		"extra app bundle": {FamilyZCode: {"/opt/providers/ZCode.app", "/opt/providers/other.app"}},
	} {
		t.Run(name, func(t *testing.T) {
			if profiles, err := DiscoverConfiguredProviderProfiles(context.Background(), inspector, configured); err == nil || profiles != nil {
				t.Fatalf("profiles = %#v, error = %v", profiles, err)
			}
		})
	}
	if len(inspector.calls) != 0 {
		t.Fatalf("identity observations = %v", inspector.calls)
	}
}

func TestDiscoverZCodeProfileObservesOnlyEffectiveAppBundle(t *testing.T) {
	for _, override := range []string{"", "/opt/custom/ZCode.app"} {
		t.Run(override, func(t *testing.T) {
			inspector := &recordingDiscoveryInspector{}
			profile, err := DiscoverProviderProfileWithOverride(context.Background(), inspector, FamilyZCode, override)
			if err != nil {
				t.Fatal(err)
			}
			if profile.ZCodeCompanion().BundleOverride != override || !reflect.DeepEqual(inspector.calls, []string{"herdr-zcode:" + override}) {
				t.Fatalf("companion=%+v calls=%v", profile.ZCodeCompanion(), inspector.calls)
			}
			argv := append(profile.Argv(), "--version", "--json")
			if override != "" {
				argv = append(argv, "--app-bundle", override)
			}
			if !profile.WithQualifiedVersion(argv, "0.2.0").Available() {
				t.Fatalf("bound bundle argv rejected: %v", argv)
			}
		})
	}
}

func TestDiscoverProviderProfilesDoesNotPinHistoricalProvenance(t *testing.T) {
	zcodeExecutable := filepath.Join(ZCodeAppBundle, filepath.FromSlash("Contents/MacOS/ZCode"))
	zcodeLauncher := filepath.Join(ZCodeAppBundle, filepath.FromSlash("Contents/Resources/glm/zcode.cjs"))
	inspector := discoveryInspector{executables: map[string]ports.ExecutableObservation{
		zcodeExecutable: discoveredExecutable(t, zcodeExecutable, zcodeExecutable, "0.2.0"),
		zcodeLauncher:   discoveredExecutable(t, zcodeLauncher, zcodeLauncher, "0.2.0"),
		"grok":          discoveredExecutable(t, "grok", "/new/location/grok", "1.0.89"),
	}}
	profiles, err := DiscoverProviderProfiles(context.Background(), inspector)
	if err != nil {
		t.Fatalf("DiscoverProviderProfiles() error = %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("profiles = %d, want 2", len(profiles))
	}
	for _, profile := range profiles {
		if profile.Available() || profile.Reason() != "unqualified_discovery" {
			t.Fatalf("%s unexpectedly routable: %s", profile.Family(), profile.Reason())
		}
	}
}

func TestDiscoverProviderProfilesRejectsZCodeVersionDrift(t *testing.T) {
	profile, err := DiscoverProviderProfile(context.Background(), discoveryInspector{}, FamilyZCode)
	if err != nil {
		t.Fatal(err)
	}
	qualified := profile.WithQualifiedVersion(append(profile.Argv(), "--version", "--json"), "current")
	if qualified.Available() || qualified.Reason() != "version_identity_drift" {
		t.Fatalf("version drift was not rejected: %#v", qualified)
	}
}
func completeInput(t *testing.T, family Family, version string) QualificationInput {
	return currentProbeAuthorityInput(t, family, version)
}

func TestZCodeApplicationVersionGuidanceAllowsFutureVersionsAboveMinimum(t *testing.T) {
	for version, want := range map[string]VersionClassification{
		"3.18.1":  VersionRed,
		"3.18.2":  VersionGreen,
		"4.1.0":   VersionYellow,
		"garbage": VersionUnknown,
	} {
		if got := ClassifyZCodeApplicationVersion(version); got != want {
			t.Fatalf("application version %s classified as %q, want %q", version, got, want)
		}
	}
}

type discoveryInspector struct {
	executables map[string]ports.ExecutableObservation
}

type recordingDiscoveryInspector struct {
	executables map[string]ports.ExecutableObservation
	errors      map[string]error
	fileMissing map[string]bool
	calls       []string
}

func (*recordingDiscoveryInspector) ObservePlatform(context.Context) (ports.PlatformObservation, error) {
	return ports.PlatformObservation{}, nil
}
func (inspector *recordingDiscoveryInspector) ObserveExecutable(_ context.Context, name string) (ports.ExecutableObservation, error) {
	return ports.ExecutableObservation{}, errors.New("version-observing executable path must not run")
}
func (inspector *recordingDiscoveryInspector) ObserveExecutableIdentity(_ context.Context, name string) (ports.ExecutableObservation, error) {
	inspector.calls = append(inspector.calls, name)
	if err := inspector.errors[name]; err != nil {
		return ports.ExecutableObservation{}, err
	}
	return inspector.executables[name], nil
}
func (inspector *recordingDiscoveryInspector) ObserveReadableFileIdentity(_ context.Context, name string) (ports.FileIdentityObservation, error) {
	inspector.calls = append(inspector.calls, name)
	if err := inspector.errors[name]; err != nil {
		return ports.FileIdentityObservation{}, err
	}
	if inspector.fileMissing[name] {
		return ports.NewFileIdentityObservation(name, false, "", "")
	}
	if strings.HasSuffix(name, "/zcode-builtin.json") {
		return ports.NewFileIdentityObservation(name, true, name, "sha256:"+strings.Repeat("a", 64))
	}
	return fileIdentityFromExecutable(inspector.executables[name])
}
func (inspector *recordingDiscoveryInspector) ObserveZCodeCompanion(ctx context.Context, bundle string, excluded ...string) (ports.ZCodeCompanionObservation, error) {
	inspector.calls = append(inspector.calls, "herdr-zcode:"+bundle)
	if err := ctx.Err(); err != nil {
		return ports.ZCodeCompanionObservation{}, err
	}
	if err := inspector.errors[bundle]; err != nil {
		return ports.ZCodeCompanionObservation{}, err
	}
	return discoveryInspector{}.ObserveZCodeCompanion(ctx, bundle, excluded...)
}

func (discoveryInspector) ObserveZCodeCompanion(_ context.Context, bundle string, _ ...string) (ports.ZCodeCompanionObservation, error) {
	override := bundle
	if bundle == "" {
		bundle = ZCodeAppBundle
	}
	return ports.ZCodeCompanionObservation{
		Executable: "/opt/providers/bin/herdr-zcode", ExecutableSHA256: "sha256:" + strings.Repeat("a", 64), PackageSHA256: strings.Repeat("b", 64),
		Version: "0.2.0", AppVersion: "4.0.0", AppBundle: bundle, BundleOverride: override, MinimumAppVersion: "3.18.2",
	}, nil
}

func (*recordingDiscoveryInspector) ObserveNativeHomeIdentity(context.Context, string) (ports.NativeHomeLaunchAuthority, error) {
	return ports.NativeHomeLaunchAuthority{}, nil
}
func (*recordingDiscoveryInspector) ObservePermission(context.Context, ports.AnchoredRoot, ports.SafeRelativePath) (ports.PermissionObservation, error) {
	return ports.PermissionObservation{}, nil
}

func (inspector discoveryInspector) ObservePlatform(context.Context) (ports.PlatformObservation, error) {
	return ports.PlatformObservation{}, nil
}

func (inspector discoveryInspector) ObserveExecutable(_ context.Context, name string) (ports.ExecutableObservation, error) {
	return inspector.executables[name], nil
}
func (inspector discoveryInspector) ObserveExecutableIdentity(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	return inspector.ObserveExecutable(ctx, name)
}
func (inspector discoveryInspector) ObserveReadableFileIdentity(_ context.Context, name string) (ports.FileIdentityObservation, error) {
	if strings.HasSuffix(name, "/zcode-builtin.json") {
		return ports.NewFileIdentityObservation(name, true, name, "sha256:"+strings.Repeat("a", 64))
	}
	return fileIdentityFromExecutable(inspector.executables[name])
}
func (discoveryInspector) ObserveNativeHomeIdentity(context.Context, string) (ports.NativeHomeLaunchAuthority, error) {
	return ports.NativeHomeLaunchAuthority{}, nil
}

func (inspector discoveryInspector) ObservePermission(context.Context, ports.AnchoredRoot, ports.SafeRelativePath) (ports.PermissionObservation, error) {
	return ports.PermissionObservation{}, nil
}

func discoveredExecutable(t *testing.T, name, path, version string) ports.ExecutableObservation {
	t.Helper()
	observation, err := ports.NewExecutableObservation(name, true, path, version, "")
	if err != nil {
		t.Fatalf("NewExecutableObservation() error = %v", err)
	}
	return observation
}

func fileIdentityFromExecutable(observation ports.ExecutableObservation) (ports.FileIdentityObservation, error) {
	return ports.NewFileIdentityObservation(observation.Name(), observation.Found(), observation.ResolvedPath(), observation.SHA256())
}
