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
	want := []Family{FamilyZCode, FamilyGrok, FamilyCodex}
	if got := Families(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Families() = %v, want %v", got, want)
	}
	guidance := []VersionGuidance{
		{Family: FamilyZCode, Minimum: "0.16.5", VerifiedLatest: "0.16.5"},
		{Family: FamilyGrok, Minimum: "1.0.34", VerifiedLatest: "1.0.40"},
		{Family: FamilyCodex, Minimum: "0.154.0", VerifiedLatest: "0.154.0"},
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
		{name: "below minimum", family: FamilyZCode, version: "0.16.4", want: VersionRed},
		{name: "minimum", family: FamilyZCode, version: "0.16.5", want: VersionGreen},
		{name: "verified latest", family: FamilyZCode, version: "0.16.5", want: VersionGreen},
		{name: "above verified latest", family: FamilyZCode, version: "0.16.6", want: VersionYellow},
		{name: "minimum", family: FamilyZCode, version: "0.16.5", want: VersionGreen},
		{name: "verified latest", family: FamilyZCode, version: "0.16.5", want: VersionGreen},
		{name: "above verified latest", family: FamilyZCode, version: "0.16.6", want: VersionYellow},
		{name: "below minimum", family: FamilyGrok, version: "1.0.33", want: VersionRed},
		{name: "minimum", family: FamilyGrok, version: "1.0.34", want: VersionGreen},
		{name: "verified latest", family: FamilyGrok, version: "1.0.40", want: VersionGreen},
		{name: "above verified latest", family: FamilyGrok, version: "1.0.41", want: VersionYellow},
		{name: "unparseable", family: FamilyZCode, version: "latest", want: VersionUnknown},
		{name: "unknown family", family: "other", version: "1.0.0", want: VersionUnknown},
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
	input := completeInput(t, FamilyZCode, "0.16.5")
	input.KnownIncompatible = true
	qualification := ValidateQualification(input)
	if qualification.Available() || qualification.Reason() != "known_incompatible" {
		t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
	}
}

func TestValidateQualificationRejectsMissingAndExpiredReceipts(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		input := completeInput(t, FamilyGrok, "1.0.34")
		input.Receipts = input.Receipts[:len(input.Receipts)-1]
		qualification := ValidateQualification(input)
		if qualification.Available() || qualification.Reason() != "missing_receipt" {
			t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
		}
	})
	t.Run("expired", func(t *testing.T) {
		input := completeInput(t, FamilyGrok, "1.0.34")
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
			input := completeInput(t, FamilyGrok, "1.0.34")
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
		{name: "snapshot", change: func(identity *Identity) { identity.SnapshotManifest = "manifest-2" }},
		{name: "lease", change: func(identity *Identity) { identity.NamespaceLease = "lease-2" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := completeInput(t, FamilyGrok, "1.0.34")
			test.change(&input.Receipts[0].Identity)
			qualification := ValidateQualification(input)
			if qualification.Available() || qualification.Reason() != "identity_mismatch" {
				t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
			}
		})
	}
}

func TestValidateQualificationAdmitsCompleteNewerPassSet(t *testing.T) {
	input := completeInput(t, FamilyGrok, "1.0.41")
	qualification := ValidateQualification(input)
	if !qualification.Available() {
		t.Fatalf("qualification unavailable: %s", qualification.Reason())
	}
	if qualification.Classification() != VersionYellow {
		t.Fatalf("classification = %q, want %q", qualification.Classification(), VersionYellow)
	}
}
func TestValidateQualificationTreatsProvenanceAsDiagnostic(t *testing.T) {
	input := completeInput(t, FamilyGrok, "1.0.34")
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
		input := completeInput(t, FamilyGrok, "1.0.34")
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
		input := completeInput(t, FamilyGrok, "1.0.34")
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
			{family: FamilyZCode, version: "0.16.5"},
			{family: FamilyZCode, version: "0.16.5"},
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
		{family: FamilyZCode, version: "0.16.5"},
		{family: FamilyZCode, version: "0.16.5"},
		{family: FamilyGrok, version: "1.0.34"},
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
		{name: "identity", family: FamilyZCode, version: "0.16.5", mutate: func(input *QualificationInput) {
			input.Identity.Instance = "other-instance"
			for index := range input.Receipts {
				input.Receipts[index].Identity.Instance = "other-instance"
			}
		}},
		{name: "namespace generation", family: FamilyZCode, version: "0.16.5", mutate: func(input *QualificationInput) {
			input.Identity.NamespaceGeneration = "stale-generation"
			for index := range input.Receipts {
				input.Receipts[index].Identity.NamespaceGeneration = "stale-generation"
			}
		}},
		{name: "expiry", family: FamilyGrok, version: "1.0.34", mutate: func(input *QualificationInput) {
			for index := range input.Receipts {
				input.Receipts[index].ExpiresAt = input.Receipts[index].ExpiresAt.Add(time.Second)
			}
		}},
		{name: "family", family: FamilyZCode, version: "9.0.0", mutate: func(input *QualificationInput) {
			for index := range input.Receipts {
				input.Receipts[index].Identity.Family = FamilyGrok
			}
		}},
		{name: "canonical control scope", family: FamilyGrok, version: "1.0.34", mutate: func(input *QualificationInput) {
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
	input := completeInput(t, FamilyGrok, "1.0.34")
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
	input := completeInput(t, FamilyGrok, "1.0.34")
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
		{name: "below minimum", family: FamilyZCode, version: "0.16.4", available: false, reason: "ineligible_version", class: VersionRed},
		{name: "below AGY baseline", family: FamilyGrok, version: "1.0.33", available: false, reason: "ineligible_version", class: VersionRed},
		{name: "minimum", family: FamilyGrok, version: "1.0.34", available: true, reason: "eligible", class: VersionGreen},
		{name: "verified latest", family: FamilyGrok, version: "1.0.40", available: true, reason: "eligible", class: VersionGreen},
		{name: "newer AGY", family: FamilyGrok, version: "1.0.41", available: true, reason: "eligible", class: VersionYellow},
		{name: "newer with current pass", family: FamilyGrok, version: "1.0.41", available: true, reason: "eligible", class: VersionYellow},
		{name: "newer with failed current pass", family: FamilyGrok, version: "1.0.41", mutate: func(input *QualificationInput) { input.Receipts[0].State = ReceiptFailed }, available: false, reason: "non_passing_receipt", class: VersionYellow},
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
	input := completeInput(t, FamilyZCode, "0.16.5")
	input.Identity.Executable = "provider"
	for index := range input.Receipts {
		input.Receipts[index].Identity.Executable = input.Identity.Executable
	}
	if qualification := ValidateQualification(input); qualification.Available() || qualification.Reason() != "invalid_identity" {
		t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
	}
}

func TestDiscoverProviderProfilesUsesIdentityOnlyZCodeNodeLauncher(t *testing.T) {
	zcodeExecutable := filepath.Join(ZCodeAppBundle, filepath.FromSlash(ZCodeExecutableRelativePath))
	zcodeLauncher := filepath.Join(ZCodeAppBundle, filepath.FromSlash(ZCodeLauncherRelativePath))
	inspector := discoveryInspector{executables: map[string]ports.ExecutableObservation{
		zcodeExecutable: discoveredExecutable(t, zcodeExecutable, zcodeExecutable, "0.16.5"),
		zcodeLauncher:   discoveredExecutable(t, zcodeLauncher, zcodeLauncher, "0.16.5"),
		"grok":          discoveredExecutable(t, "grok", "/opt/providers/grok", "1.0.34"),
		"codex":         discoveredExecutable(t, "codex", "/opt/providers/codex", "0.149.0"),
	}}
	profiles, err := DiscoverProviderProfiles(context.Background(), inspector)
	if err != nil {
		t.Fatalf("DiscoverProviderProfiles() error = %v", err)
	}
	zcode := profiles[0]
	wantArgv := []string{zcodeExecutable, zcodeLauncher}
	if zcode.Version() != "" || zcode.Available() || zcode.Reason() != "unqualified_discovery" ||
		zcode.Family() != FamilyZCode || zcode.Executable() != wantArgv[0] ||
		zcode.Launcher() != zcodeLauncher || !reflect.DeepEqual(zcode.Argv(), wantArgv) {
		t.Fatalf("unqualified zcode profile = %#v", zcode)
	}
	zcode = zcode.WithQualifiedVersion(append(wantArgv, "--version"), "0.16.5")
	if !zcode.Available() || zcode.Version() != "0.16.5" {
		t.Fatalf("qualified zcode profile = available %t version %q", zcode.Available(), zcode.Version())
	}
}

func TestDiscoverProviderProfileObservesOnlyRequestedFamily(t *testing.T) {
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{
			"grok": discoveredExecutable(t, "grok", "/opt/providers/grok", "1.0.34"),
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
	zcodeExecutable := filepath.Join(bundle, filepath.FromSlash(ZCodeExecutableRelativePath))
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{
			grok: discoveredExecutable(t, grok, grok, ""),
		},
		errors: map[string]error{
			zcodeExecutable: ports.NewIdentityObservationError(ports.IdentityObservationUnavailable, "executable is unavailable"),
		},
		fileMissing: map[string]bool{filepath.Join(bundle, filepath.FromSlash(ZCodeLauncherRelativePath)): true},
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
	zcodeExecutable := filepath.Join(bundle, filepath.FromSlash(ZCodeExecutableRelativePath))
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{
			grok: discoveredExecutable(t, grok, grok, ""),
		},
		errors: map[string]error{
			zcodeExecutable: ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "executable identity changed"),
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
	zcodeExecutable := filepath.Join(bundle, filepath.FromSlash(ZCodeExecutableRelativePath))
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{},
		errors: map[string]error{
			zcodeExecutable: ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "executable identity changed"),
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
		"extra path":       {FamilyGrok: {"/opt/providers/agy", "/opt/providers/other"}},
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
	const overrideBundle = "/opt/custom/ZCode.app"
	for _, test := range []struct {
		name     string
		bundle   string
		override string
	}{
		{name: "standard app bundle", bundle: ZCodeAppBundle},
		{name: "override app bundle", bundle: overrideBundle, override: overrideBundle},
	} {
		t.Run(test.name, func(t *testing.T) {
			executable := filepath.Join(test.bundle, filepath.FromSlash(ZCodeExecutableRelativePath))
			launcher := filepath.Join(test.bundle, filepath.FromSlash(ZCodeLauncherRelativePath))
			providerConfig := filepath.Join(test.bundle, filepath.FromSlash(ZCodeProviderConfigRelativePath))
			applicationMetadata := filepath.Join(test.bundle, filepath.FromSlash(ZCodeApplicationMetadataRelativePath))
			inspector := &recordingDiscoveryInspector{
				executables: map[string]ports.ExecutableObservation{
					executable: discoveredExecutable(t, executable, executable, ""),
					launcher:   discoveredExecutable(t, launcher, launcher, ""),
				},
				errors: map[string]error{},
			}
			profile, err := DiscoverProviderProfileWithOverride(context.Background(), inspector, FamilyZCode, test.override)
			if err != nil {
				t.Fatal(err)
			}
			wantCalls := []string{executable, executable, launcher, providerConfig, applicationMetadata}
			if profile.Executable() == "" || profile.Launcher() == "" || !reflect.DeepEqual(inspector.calls, wantCalls) {
				t.Fatalf("profile=%#v calls=%v", profile, inspector.calls)
			}
		})
	}
}

func TestDiscoverProviderProfilesDoesNotPinHistoricalProvenance(t *testing.T) {
	zcodeExecutable := filepath.Join(ZCodeAppBundle, filepath.FromSlash(ZCodeExecutableRelativePath))
	zcodeLauncher := filepath.Join(ZCodeAppBundle, filepath.FromSlash(ZCodeLauncherRelativePath))
	inspector := discoveryInspector{executables: map[string]ports.ExecutableObservation{
		zcodeExecutable: discoveredExecutable(t, zcodeExecutable, zcodeExecutable, "0.16.5"),
		zcodeLauncher:   discoveredExecutable(t, zcodeLauncher, zcodeLauncher, "0.16.5"),
		"grok":          discoveredExecutable(t, "grok", "/new/location/grok", "1.0.34"),
		"codex":         discoveredExecutable(t, "codex", "/new/location/codex", "0.149.0"),
	}}
	profiles, err := DiscoverProviderProfiles(context.Background(), inspector)
	if err != nil {
		t.Fatalf("DiscoverProviderProfiles() error = %v", err)
	}
	for _, profile := range profiles {
		if profile.Available() || profile.Reason() != "unqualified_discovery" {
			t.Fatalf("%s unexpectedly routable: %s", profile.Family(), profile.Reason())
		}
	}
}

func TestDiscoverProviderProfilesTreatsUnparseableAsYellowUnavailable(t *testing.T) {
	zcodeExecutable := filepath.Join(ZCodeAppBundle, filepath.FromSlash(ZCodeExecutableRelativePath))
	zcodeLauncher := filepath.Join(ZCodeAppBundle, filepath.FromSlash(ZCodeLauncherRelativePath))
	inspector := discoveryInspector{executables: map[string]ports.ExecutableObservation{
		zcodeExecutable: discoveredExecutable(t, zcodeExecutable, zcodeExecutable, "0.16.5"),
		zcodeLauncher:   discoveredExecutable(t, zcodeLauncher, zcodeLauncher, "0.16.5"),
		"grok":          discoveredExecutable(t, "grok", "/opt/providers/grok", "1.0.34"),
		"codex":         discoveredExecutable(t, "codex", "/opt/providers/codex", "0.149.0"),
	}}
	profiles, err := DiscoverProviderProfiles(context.Background(), inspector)
	if err != nil {
		t.Fatalf("DiscoverProviderProfiles() error = %v", err)
	}
	zcode := profiles[0].WithQualifiedVersion(append(profiles[0].Argv(), "--version"), "current")
	if zcode.Available() || zcode.Classification() != VersionUnknown || zcode.Reason() != "unparseable_version" {
		t.Fatalf("zcode = available %t class %q reason %q", zcode.Available(), zcode.Classification(), zcode.Reason())
	}
}

func completeInput(t *testing.T, family Family, version string) QualificationInput {
	return currentProbeAuthorityInput(t, family, version)
}

func TestZCodeApplicationVersionGuidanceAllowsFutureVersionsAboveMinimum(t *testing.T) {
	for version, want := range map[string]VersionClassification{
		"3.12.2":  VersionRed,
		"3.12.3":  VersionGreen,
		"3.99.0":  VersionYellow,
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
func (inspector *recordingDiscoveryInspector) ObserveApplicationMetadata(_ context.Context, name string) (ports.ApplicationMetadataObservation, error) {
	inspector.calls = append(inspector.calls, name)
	if err := inspector.errors[name]; err != nil {
		return ports.ApplicationMetadataObservation{}, err
	}
	if inspector.fileMissing[name] {
		return ports.ApplicationMetadataObservation{}, ports.NewIdentityObservationErrorWithReason(ports.IdentityObservationUnavailable, ports.IdentityObservationReasonUnreadable, "application metadata missing")
	}
	return ports.NewApplicationMetadataObservation(name, "sha256:"+strings.Repeat("b", 64), "3.12.3")
}

func TestDiscoverZCodeProviderConfigUsesCertifiedBundleLayout(t *testing.T) {
	const bundle = ZCodeAppBundle
	launcher := filepath.Join(bundle, filepath.FromSlash(ZCodeLauncherRelativePath))
	executable := filepath.Join(bundle, filepath.FromSlash(ZCodeExecutableRelativePath))
	providerConfig := filepath.Join(bundle, filepath.FromSlash(ZCodeProviderConfigRelativePath))
	applicationMetadata := filepath.Join(bundle, filepath.FromSlash(ZCodeApplicationMetadataRelativePath))
	for _, test := range []struct {
		name       string
		missing    map[string]bool
		wantPath   string
		wantReason string
		wantCalls  []string
	}{
		{name: "certified layout", wantPath: providerConfig, wantReason: "unqualified_discovery", wantCalls: []string{executable, executable, launcher, providerConfig, applicationMetadata}},
		{name: "certified layout missing", missing: map[string]bool{providerConfig: true}, wantReason: "provider_config_not_found", wantCalls: []string{executable, executable, launcher, providerConfig, applicationMetadata}},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspector := &recordingDiscoveryInspector{
				executables: map[string]ports.ExecutableObservation{
					executable: discoveredExecutable(t, executable, executable, ""),
					launcher:   discoveredExecutable(t, launcher, launcher, ""),
				},
				errors: map[string]error{}, fileMissing: test.missing,
			}
			profile, err := DiscoverProviderProfile(context.Background(), inspector, FamilyZCode)
			if err != nil {
				t.Fatal(err)
			}
			if profile.ZCodeProviderConfig() != test.wantPath || profile.Reason() != test.wantReason || !reflect.DeepEqual(inspector.calls, test.wantCalls) {
				t.Fatalf("profile config/reason/calls = %q/%q/%v", profile.ZCodeProviderConfig(), profile.Reason(), inspector.calls)
			}
		})
	}
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
func (discoveryInspector) ObserveApplicationMetadata(_ context.Context, name string) (ports.ApplicationMetadataObservation, error) {
	return ports.NewApplicationMetadataObservation(name, "sha256:"+strings.Repeat("b", 64), "3.12.3")
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
