package reviewrun

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestFamiliesAndGuidanceUseCanonicalOrder(t *testing.T) {
	want := []Family{FamilyKimi, FamilyZCode, FamilyAGY}
	if got := Families(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Families() = %v, want %v", got, want)
	}
	guidance := []VersionGuidance{
		{Family: FamilyKimi, Minimum: "0.23.6", VerifiedLatest: "0.28.0"},
		{Family: FamilyZCode, Minimum: "0.15.2", VerifiedLatest: "0.15.2"},
		{Family: FamilyAGY, Minimum: "1.1.4", VerifiedLatest: "1.1.4"},
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
		{name: "below minimum", family: FamilyKimi, version: "0.23.5", want: VersionRed},
		{name: "minimum", family: FamilyKimi, version: "0.23.6", want: VersionGreen},
		{name: "between minimum and verified latest", family: FamilyKimi, version: "0.23.7", want: VersionGreen},
		{name: "verified latest", family: FamilyKimi, version: "0.28.0", want: VersionGreen},
		{name: "above verified latest", family: FamilyKimi, version: "0.28.1", want: VersionYellow},
		{name: "minimum", family: FamilyZCode, version: "0.15.2", want: VersionGreen},
		{name: "below minimum", family: FamilyAGY, version: "1.1.3", want: VersionRed},
		{name: "verified latest", family: FamilyAGY, version: "1.1.4", want: VersionGreen},
		{name: "newer", family: FamilyAGY, version: "1.1.5", want: VersionYellow},
		{name: "unparseable", family: FamilyKimi, version: "latest", want: VersionYellow},
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
	input := completeInput(t, FamilyKimi, "0.23.6")
	input.KnownIncompatible = true
	qualification := ValidateQualification(input)
	if qualification.Available() || qualification.Reason() != "known_incompatible" {
		t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
	}
}

func TestValidateQualificationRejectsMissingAndExpiredReceipts(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		input := completeInput(t, FamilyAGY, "1.1.4")
		input.Receipts = input.Receipts[:len(input.Receipts)-1]
		qualification := ValidateQualification(input)
		if qualification.Available() || qualification.Reason() != "missing_receipt" {
			t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
		}
	})
	t.Run("expired", func(t *testing.T) {
		input := completeInput(t, FamilyAGY, "1.1.4")
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
			input := completeInput(t, FamilyAGY, "1.1.4")
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
			input := completeInput(t, FamilyAGY, "1.1.4")
			test.change(&input.Receipts[0].Identity)
			qualification := ValidateQualification(input)
			if qualification.Available() || qualification.Reason() != "identity_mismatch" {
				t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
			}
		})
	}
}

func TestValidateQualificationAdmitsCompleteNewerPassSet(t *testing.T) {
	input := completeInput(t, FamilyAGY, "1.1.5")
	qualification := ValidateQualification(input)
	if !qualification.Available() {
		t.Fatalf("qualification unavailable: %s", qualification.Reason())
	}
	if qualification.Classification() != VersionYellow {
		t.Fatalf("classification = %q, want %q", qualification.Classification(), VersionYellow)
	}
}
func TestValidateQualificationTreatsProvenanceAsDiagnostic(t *testing.T) {
	input := completeInput(t, FamilyAGY, "1.1.4")
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
		input := completeInput(t, FamilyAGY, "1.1.4")
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
		input := completeInput(t, FamilyAGY, "1.1.4")
		for index := range input.Receipts {
			if input.Receipts[index].Kind == ReceiptSecurityPolicy {
				input.Receipts[index].AuthorityScope = AuthorityScopeDirectExecution
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
			{family: FamilyKimi, version: "0.23.6"},
			{family: FamilyZCode, version: "0.15.2"},
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
					{name: "mismatched authority scope", apply: func(receipt *Receipt) { receipt.AuthorityScope = AuthorityScopeAGYCanonicalPlanControls }},
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
		{family: FamilyKimi, version: "0.23.6"},
		{family: FamilyZCode, version: "0.15.2"},
		{family: FamilyAGY, version: "1.1.4"},
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
		{name: "identity", family: FamilyKimi, version: "0.23.6", mutate: func(input *QualificationInput) {
			input.Identity.Instance = "other-instance"
			for index := range input.Receipts {
				input.Receipts[index].Identity.Instance = "other-instance"
			}
		}},
		{name: "namespace generation", family: FamilyZCode, version: "0.15.2", mutate: func(input *QualificationInput) {
			input.Identity.NamespaceGeneration = "stale-generation"
			for index := range input.Receipts {
				input.Receipts[index].Identity.NamespaceGeneration = "stale-generation"
			}
		}},
		{name: "expiry", family: FamilyAGY, version: "1.1.4", mutate: func(input *QualificationInput) {
			for index := range input.Receipts {
				input.Receipts[index].ExpiresAt = input.Receipts[index].ExpiresAt.Add(time.Second)
			}
		}},
		{name: "family", family: FamilyKimi, version: "9.0.0", mutate: func(input *QualificationInput) {
			input.Identity.Family = FamilyZCode
			for index := range input.Receipts {
				input.Receipts[index].Identity.Family = FamilyZCode
			}
		}},
		{name: "canonical control scope", family: FamilyAGY, version: "1.1.4", mutate: func(input *QualificationInput) {
			for index := range input.Receipts {
				if input.Receipts[index].Kind == ReceiptSecurityPolicy {
					input.Receipts[index].AuthorityScope = AuthorityScopeDirectExecution
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
			if qualification := ValidateQualification(input); qualification.Available() || qualification.Reason() != "invalid_receipts" {
				t.Fatalf("mutated adapter-issued authority baseline = available %t, reason %q", qualification.Available(), qualification.Reason())
			}
		})
	}
}
func TestQualificationReceiptIDIncludesAuthorityScope(t *testing.T) {
	input := completeInput(t, FamilyAGY, "1.1.4")
	var receipt Receipt
	for _, candidate := range input.Receipts {
		if candidate.Kind == ReceiptSecurityPolicy {
			receipt = candidate
			break
		}
	}
	first := qualificationReceiptID(receipt)
	receipt.AuthorityScope = AuthorityScopeDirectExecution
	if second := qualificationReceiptID(receipt); second == first {
		t.Fatal("qualification receipt ID did not bind authority scope")
	}
}

func TestQualificationDefensivelyCopiesMutableInput(t *testing.T) {
	input := completeInput(t, FamilyAGY, "1.1.4")
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
	if Families()[0] != FamilyKimi {
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
		{name: "below minimum", family: FamilyKimi, version: "0.23.5", available: false, reason: "ineligible_version", class: VersionRed},
		{name: "below AGY baseline", family: FamilyAGY, version: "1.1.3", available: false, reason: "ineligible_version", class: VersionRed},
		{name: "latest", family: FamilyAGY, version: "1.1.4", available: true, reason: "eligible", class: VersionGreen},
		{name: "newer AGY", family: FamilyAGY, version: "1.1.5", available: true, reason: "eligible", class: VersionYellow},
		{name: "newer with current pass", family: FamilyAGY, version: "1.1.5", available: true, reason: "eligible", class: VersionYellow},
		{name: "newer with failed current pass", family: FamilyAGY, version: "1.1.5", mutate: func(input *QualificationInput) { input.Receipts[0].State = ReceiptFailed }, available: false, reason: "non_passing_receipt", class: VersionYellow},
		{name: "unparseable", family: FamilyKimi, version: "current", available: false, reason: "unparseable_version", class: VersionYellow},
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
	input := completeInput(t, FamilyKimi, "0.23.6")
	input.Identity.Executable = "provider"
	for index := range input.Receipts {
		input.Receipts[index].Identity.Executable = input.Identity.Executable
	}
	if qualification := ValidateQualification(input); qualification.Available() || qualification.Reason() != "invalid_identity" {
		t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
	}
}

func TestDiscoverProviderProfilesUsesIdentityOnlyZCodeNodeLauncher(t *testing.T) {
	inspector := discoveryInspector{executables: map[string]ports.ExecutableObservation{
		"kimi":        discoveredExecutable(t, "kimi", "/opt/providers/kimi", "0.23.6"),
		"node":        discoveredExecutable(t, "node", "/opt/node/bin/node", "0.15.2"),
		ZCodeLauncher: discoveredExecutable(t, ZCodeLauncher, ZCodeLauncher, "0.15.2"),
		"agy":         discoveredExecutable(t, "agy", "/opt/providers/agy", "1.1.5"),
	}}
	profiles, err := DiscoverProviderProfiles(context.Background(), inspector)
	if err != nil {
		t.Fatalf("DiscoverProviderProfiles() error = %v", err)
	}
	zcode := profiles[1]
	wantArgv := []string{"/opt/node/bin/node", ZCodeLauncher}
	if zcode.Version() != "" || zcode.Available() || zcode.Reason() != "unqualified_discovery" ||
		zcode.Family() != FamilyZCode || zcode.Executable() != wantArgv[0] ||
		zcode.Launcher() != ZCodeLauncher || !reflect.DeepEqual(zcode.Argv(), wantArgv) {
		t.Fatalf("unqualified zcode profile = %#v", zcode)
	}
	zcode = zcode.WithQualifiedVersion(append(wantArgv, "--version"), "0.15.2")
	if !zcode.Available() || zcode.Version() != "0.15.2" {
		t.Fatalf("qualified zcode profile = available %t version %q", zcode.Available(), zcode.Version())
	}
}

func TestDiscoverProviderProfileObservesOnlyRequestedFamily(t *testing.T) {
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{
			"agy": discoveredExecutable(t, "agy", "/opt/providers/agy", "1.1.5"),
		},
		errors: map[string]error{"kimi": errors.New("poisoned Kimi"), "node": errors.New("poisoned ZCode")},
	}
	profile, err := DiscoverProviderProfile(context.Background(), inspector, FamilyAGY)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Family() != FamilyAGY || profile.Executable() != "/opt/providers/agy" || !reflect.DeepEqual(inspector.calls, []string{"agy"}) {
		t.Fatalf("profile=%#v calls=%v", profile, inspector.calls)
	}
}

func TestDiscoverConfiguredProviderProfilesKeepsEligibleFamilyWhenAnotherIsUnavailable(t *testing.T) {
	const kimi = "/opt/providers/kimi"
	const agy = "/opt/providers/agy"
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{
			agy: discoveredExecutable(t, agy, agy, ""),
		},
		errors: map[string]error{
			kimi: ports.NewIdentityObservationError(ports.IdentityObservationUnavailable, "executable is unavailable"),
		},
	}
	profiles, err := DiscoverConfiguredProviderProfiles(context.Background(), inspector, map[Family][]string{
		FamilyKimi: {kimi},
		FamilyAGY:  {agy},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[0].Family() != FamilyKimi || profiles[0].Executable() != "" || profiles[1].Family() != FamilyAGY || profiles[1].Executable() != agy {
		t.Fatalf("profiles = %#v", profiles)
	}
}

func TestDiscoverConfiguredProviderProfilesReportsScopedSecurityFailureAfterOtherFamilies(t *testing.T) {
	const kimi = "/opt/providers/kimi"
	const agy = "/opt/providers/agy"
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{
			agy: discoveredExecutable(t, agy, agy, ""),
		},
		errors: map[string]error{
			kimi: ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "executable identity changed"),
		},
	}
	profiles, err := DiscoverConfiguredProviderProfiles(context.Background(), inspector, map[Family][]string{
		FamilyKimi: {kimi},
		FamilyAGY:  {agy},
	})
	if !reflect.DeepEqual(ConfiguredProviderSecurityFamilies(err), []Family{FamilyKimi}) {
		t.Fatalf("security families = %v, error = %v", ConfiguredProviderSecurityFamilies(err), err)
	}
	if len(profiles) != 2 || profiles[0].Family() != FamilyKimi || profiles[1].Family() != FamilyAGY || profiles[1].Executable() != agy {
		t.Fatalf("profiles = %#v", profiles)
	}
}

func TestDiscoverConfiguredProviderProfilesPropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	const kimi = "/opt/providers/kimi"
	inspector := &recordingDiscoveryInspector{
		executables: map[string]ports.ExecutableObservation{},
		errors: map[string]error{
			kimi: ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "executable identity changed"),
		},
	}
	profiles, err := DiscoverConfiguredProviderProfiles(ctx, inspector, map[Family][]string{FamilyKimi: {kimi}})
	if !errors.Is(err, context.Canceled) || profiles != nil {
		t.Fatalf("profiles = %#v, error = %v", profiles, err)
	}
}

func TestDiscoverConfiguredProviderProfilesRejectsInvalidConfiguredTuplesBeforeObservation(t *testing.T) {
	inspector := &recordingDiscoveryInspector{executables: map[string]ports.ExecutableObservation{}, errors: map[string]error{}}
	for name, configured := range map[string]map[Family][]string{
		"unknown family":   {Family("other"): {"/opt/providers/other"}},
		"empty tuple":      {FamilyKimi: {}},
		"extra path":       {FamilyAGY: {"/opt/providers/agy", "/opt/providers/other"}},
		"missing launcher": {FamilyZCode: {"/opt/providers/node"}},
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

func TestDiscoverZCodeProfileObservesOnlyEffectiveOverrideComponents(t *testing.T) {
	const nodeOverride = "/opt/custom/node"
	const launcherOverride = "/opt/custom/zcode.cjs"
	for _, test := range []struct {
		name               string
		executableOverride string
		launcherOverride   string
		poisoned           string
		wantCalls          []string
	}{
		{name: "node override with bundled launcher", executableOverride: nodeOverride, poisoned: "node", wantCalls: []string{nodeOverride, ZCodeLauncher}},
		{name: "PATH node with launcher override", launcherOverride: launcherOverride, poisoned: ZCodeLauncher, wantCalls: []string{"node", launcherOverride}},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspector := &recordingDiscoveryInspector{
				executables: map[string]ports.ExecutableObservation{
					"node":           discoveredExecutable(t, "node", "/opt/path/node", ""),
					nodeOverride:     discoveredExecutable(t, nodeOverride, nodeOverride, ""),
					ZCodeLauncher:    discoveredExecutable(t, ZCodeLauncher, ZCodeLauncher, ""),
					launcherOverride: discoveredExecutable(t, launcherOverride, launcherOverride, ""),
				},
				errors: map[string]error{test.poisoned: errors.New("unused source observed")},
			}
			profile, err := DiscoverProviderProfileWithOverrides(context.Background(), inspector, FamilyZCode, test.executableOverride, test.launcherOverride)
			if err != nil {
				t.Fatal(err)
			}
			if profile.Executable() == "" || profile.Launcher() == "" || !reflect.DeepEqual(inspector.calls, test.wantCalls) {
				t.Fatalf("profile=%#v calls=%v", profile, inspector.calls)
			}
		})
	}
}

func TestDiscoverProviderProfilesDoesNotPinHistoricalProvenance(t *testing.T) {
	inspector := discoveryInspector{executables: map[string]ports.ExecutableObservation{
		"kimi":        discoveredExecutable(t, "kimi", "/new/location/kimi", "0.23.6"),
		"node":        discoveredExecutable(t, "node", "/new/location/node", "0.15.2"),
		ZCodeLauncher: discoveredExecutable(t, ZCodeLauncher, ZCodeLauncher, "0.15.2"),
		"agy":         discoveredExecutable(t, "agy", "/new/location/agy", "1.1.4"),
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
	inspector := discoveryInspector{executables: map[string]ports.ExecutableObservation{
		"kimi":        discoveredExecutable(t, "kimi", "/opt/providers/kimi", "current"),
		"node":        discoveredExecutable(t, "node", "/opt/node/bin/node", "0.15.2"),
		ZCodeLauncher: discoveredExecutable(t, ZCodeLauncher, ZCodeLauncher, "0.15.2"),
		"agy":         discoveredExecutable(t, "agy", "/opt/providers/agy", "1.1.4"),
	}}
	profiles, err := DiscoverProviderProfiles(context.Background(), inspector)
	if err != nil {
		t.Fatalf("DiscoverProviderProfiles() error = %v", err)
	}
	kimi := profiles[0].WithQualifiedVersion([]string{"/opt/providers/kimi", "--version"}, "current")
	if kimi.Available() || kimi.Classification() != VersionYellow || kimi.Reason() != "unparseable_version" {
		t.Fatalf("kimi = available %t class %q reason %q", kimi.Available(), kimi.Classification(), kimi.Reason())
	}
}

func completeInput(t *testing.T, family Family, version string) QualificationInput {
	return currentProbeAuthorityInput(t, family, version)
}

type discoveryInspector struct {
	executables map[string]ports.ExecutableObservation
}

type recordingDiscoveryInspector struct {
	executables map[string]ports.ExecutableObservation
	errors      map[string]error
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
	return fileIdentityFromExecutable(inspector.executables[name])
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
