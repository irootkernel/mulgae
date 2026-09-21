// Package reviewrun contains provider-independent review-run admission policy.
package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

// Family identifies a current allowlisted provider family.
type Family string

const (
	// Retired family tokens remain available for historical-artifact
	// classification. Valid deliberately rejects them.
	FamilyZCode Family = "zcode"
	FamilyGrok  Family = "grok"
	FamilyCodex Family = "codex"
)

var families = [...]Family{FamilyZCode, FamilyGrok, FamilyCodex}

// Families returns the allowlisted families in canonical order. The returned
// slice is caller-owned.
func Families() []Family { return append([]Family(nil), families[:]...) }

// Valid reports whether family is allowlisted.
func (family Family) Valid() bool {
	return family == FamilyZCode || family == FamilyGrok || family == FamilyCodex
}

// VersionClassification describes a version's qualification guidance.
type VersionClassification string

const (
	VersionRed     VersionClassification = "red"
	VersionGreen   VersionClassification = "green"
	VersionYellow  VersionClassification = "yellow"
	VersionUnknown VersionClassification = "unknown"
)

// VersionGuidance is the immutable qualification guidance for one family.
type VersionGuidance struct {
	Family         Family
	Minimum        string
	VerifiedLatest string
}

var guidance = [...]VersionGuidance{
	// ZCode launcher protocol guidance is independent from the app version.
	{Family: FamilyZCode, Minimum: "0.16.5", VerifiedLatest: "0.16.5"},
	{Family: FamilyGrok, Minimum: "1.0.34", VerifiedLatest: "1.0.40"},
	{Family: FamilyCodex, Minimum: "0.154.0", VerifiedLatest: "0.154.0"},
}

var zcodeApplicationGuidance = VersionGuidance{Family: FamilyZCode, Minimum: "3.12.3", VerifiedLatest: "3.12.3"}

// ZCodeApplicationGuidance returns the independently enforced app-release
// compatibility floor and latest verified release.
func ZCodeApplicationGuidance() VersionGuidance { return zcodeApplicationGuidance }

// Guidance returns the qualification guidance for family.
func Guidance(family Family) (VersionGuidance, bool) {
	for _, candidate := range guidance {
		if candidate.Family == family {
			return candidate, true
		}
	}
	return VersionGuidance{}, false
}

// ClassifyVersion returns red below the minimum, green through the verified
// latest version, yellow above it, and unknown when the observation cannot be
// parsed. Unparseable versions remain unavailable to admission and doctor.
func ClassifyVersion(family Family, text string) VersionClassification {
	familyGuidance, ok := Guidance(family)
	if !ok {
		return VersionUnknown
	}
	if _, ok := parseVersion(text); !ok {
		return VersionUnknown
	}
	return classifyVersionAgainstGuidance(familyGuidance, text)
}

// ClassifyZCodeApplicationVersion classifies the app bundle independently from
// the bundled launcher protocol.
func ClassifyZCodeApplicationVersion(text string) VersionClassification {
	if _, ok := parseVersion(text); !ok {
		return VersionUnknown
	}
	return classifyVersionAgainstGuidance(zcodeApplicationGuidance, text)
}

func classifyVersionAgainstGuidance(familyGuidance VersionGuidance, text string) VersionClassification {
	actual, ok := parseVersion(text)
	if !ok {
		return VersionYellow
	}
	minimum, _ := parseVersion(familyGuidance.Minimum)
	latest, _ := parseVersion(familyGuidance.VerifiedLatest)
	if actual.compare(minimum) < 0 {
		return VersionRed
	}
	if actual.compare(latest) <= 0 {
		return VersionGreen
	}
	return VersionYellow
}

const (
	// ZCodeAppBundle is the standard ZCode application bundle on Darwin.
	ZCodeAppBundle = "/Applications/ZCode.app"
	// ZCodeExecutableRelativePath is the app-owned Electron runtime used as Node.
	ZCodeExecutableRelativePath = "Contents/MacOS/ZCode"
	// ZCodeLauncherRelativePath is the app-server launcher bundled by ZCode.
	ZCodeLauncherRelativePath = "Contents/Resources/glm/zcode.cjs"
	// ZCodeProviderConfigRelativePath is the provider catalog certified with the app bundle.
	ZCodeProviderConfigRelativePath = "Contents/Resources/config/provider/zcode-builtin.json"
	// ZCodeApplicationMetadataRelativePath contains the independently observed app version.
	ZCodeApplicationMetadataRelativePath = "Contents/Info.plist"
)

// DiscoveredProviderProfile is an immutable identity-only executable discovery result.
// Discovery never launches a provider and is therefore not routable until a qualified
// version result is bound to this exact invocation shape.
type DiscoveredProviderProfile struct {
	family                           Family
	version                          string
	classification                   VersionClassification
	executable                       string
	launcher                         string
	argv                             []string
	sha256                           string
	launcherSHA256                   string
	providerConfig                   string
	providerConfigSHA256             string
	applicationVersion               string
	applicationVersionClassification VersionClassification
	applicationMetadata              string
	applicationMetadataSHA256        string
	available                        bool
	reason                           string
}

func observeExecutableIdentity(
	ctx context.Context, inspector ports.EnvironmentInspector, name string,
) (ports.ExecutableObservation, error) {
	return inspector.ObserveExecutableIdentity(ctx, name)
}

func observeReadableFileIdentity(
	ctx context.Context, inspector ports.EnvironmentInspector, name string,
) (ports.FileIdentityObservation, error) {
	return inspector.ObserveReadableFileIdentity(ctx, name)
}

// DiscoverProviderProfile discovers one allowlisted family without observing
// any other provider. Discovery never executes the provider. ZCode has distinct
// app-owned Electron runtime and CJS launcher identities.
func DiscoverProviderProfile(ctx context.Context, inspector ports.EnvironmentInspector, family Family) (DiscoveredProviderProfile, error) {
	return DiscoverProviderProfileWithOverride(ctx, inspector, family, "")
}

// DiscoverProviderProfileWithOverride observes one effective provider tuple.
// For ZCode the override is an application bundle; for direct providers it is
// an executable. An empty override selects the family-owned default.
func DiscoverProviderProfileWithOverride(ctx context.Context, inspector ports.EnvironmentInspector, family Family, pathOverride string) (DiscoveredProviderProfile, error) {
	if inspector == nil {
		return DiscoveredProviderProfile{}, fmt.Errorf("review run: environment inspector unavailable")
	}
	if !family.Valid() {
		return DiscoveredProviderProfile{}, fmt.Errorf("review run: unsupported provider family %q", family)
	}
	name := string(family)
	if family == FamilyZCode {
		bundle := ZCodeAppBundle
		if pathOverride != "" {
			bundle = pathOverride
		}
		if !canonicalAbsolute(bundle) {
			return DiscoveredProviderProfile{}, fmt.Errorf("review run: configured zcode app bundle is not canonical absolute")
		}
		name = filepath.Join(bundle, filepath.FromSlash(ZCodeExecutableRelativePath))
	} else if pathOverride != "" {
		if !canonicalAbsolute(pathOverride) {
			return DiscoveredProviderProfile{}, fmt.Errorf("review run: configured %s executable is not canonical absolute", family)
		}
		name = pathOverride
	}
	executableUnavailable := false
	executableUnavailableReason := ports.IdentityObservationReasonObservationFailed
	var executable ports.ExecutableObservation
	var err error
	if family == FamilyZCode {
		executable, err = observeZCodeAppExecutableIdentity(ctx, inspector, name)
	} else {
		executable, err = observeExecutableIdentity(ctx, inspector, name)
	}
	if err != nil {
		if kind, classified := ports.IdentityObservationFailure(err); classified && kind == ports.IdentityObservationUnavailable {
			executableUnavailable = true
			if reason, ok := ports.IdentityObservationReason(err); ok {
				executableUnavailableReason = reason
			}
			executable, err = ports.NewExecutableObservation(name, false, "", "", "")
		}
	}
	if err != nil {
		return DiscoveredProviderProfile{}, &providerIdentityComponentError{component: "executable", err: fmt.Errorf("review run: discover %s executable: %w", family, err)}
	}
	if family != FamilyZCode {
		profile := discoveredProviderProfile(family, executable, ports.FileIdentityObservation{}, ports.FileIdentityObservation{})
		if executableUnavailable {
			profile.reason = "executable_observation_failed"
			if executableUnavailableReason == ports.IdentityObservationReasonNonExecutable {
				profile.reason = "executable_not_executable"
			}
		}
		return profile, nil
	}
	bundle := ZCodeAppBundle
	if pathOverride != "" {
		bundle = pathOverride
	}
	launcherName := filepath.Join(bundle, filepath.FromSlash(ZCodeLauncherRelativePath))
	launcherUnavailable := false
	launcherUnavailableReason := ports.IdentityObservationReasonObservationFailed
	launcher, err := observeReadableFileIdentity(ctx, inspector, launcherName)
	if err != nil {
		if kind, classified := ports.IdentityObservationFailure(err); classified && kind == ports.IdentityObservationUnavailable {
			launcherUnavailable = true
			if reason, ok := ports.IdentityObservationReason(err); ok {
				launcherUnavailableReason = reason
			}
			launcher, err = ports.NewFileIdentityObservation(launcherName, false, "", "")
		}
	}
	if err != nil {
		return DiscoveredProviderProfile{}, &providerIdentityComponentError{component: "launcher", err: fmt.Errorf("review run: discover %s launcher: %w", family, err)}
	}
	providerConfig := ports.FileIdentityObservation{}
	providerConfigUnavailable := false
	providerConfigUnavailableReason := ports.IdentityObservationReasonObservationFailed
	if launcher.Found() && !launcherUnavailable {
		providerConfig, providerConfigUnavailable, providerConfigUnavailableReason, err = observeZCodeProviderConfigIdentity(ctx, inspector, bundle)
		if err != nil {
			return DiscoveredProviderProfile{}, &providerIdentityComponentError{component: "provider_config", err: fmt.Errorf("review run: discover %s provider config: %w", family, err)}
		}
	}
	applicationMetadataName := filepath.Join(bundle, filepath.FromSlash(ZCodeApplicationMetadataRelativePath))
	applicationMetadata, applicationMetadataUnavailable, applicationMetadataReason, err := observeZCodeApplicationMetadata(ctx, inspector, applicationMetadataName)
	if err != nil {
		return DiscoveredProviderProfile{}, &providerIdentityComponentError{component: "application_metadata", err: fmt.Errorf("review run: discover %s application metadata: %w", family, err)}
	}
	profile := discoveredProviderProfile(family, executable, launcher, providerConfig)
	if applicationMetadata.Valid() {
		profile.applicationVersion = applicationMetadata.Version()
		profile.applicationVersionClassification = ClassifyZCodeApplicationVersion(applicationMetadata.Version())
		profile.applicationMetadata = applicationMetadata.Path()
		profile.applicationMetadataSHA256 = applicationMetadata.SHA256()
	}
	switch {
	case executableUnavailable:
		profile.reason = "executable_observation_failed"
		if executableUnavailableReason == ports.IdentityObservationReasonNonExecutable {
			profile.reason = "executable_not_executable"
		}
	case launcherUnavailable && executable.Found():
		profile.reason = "launcher_observation_failed"
		if launcherUnavailableReason == ports.IdentityObservationReasonUnreadable {
			profile.reason = "launcher_unreadable"
		}
	case providerConfigUnavailable && executable.Found() && launcher.Found():
		profile.reason = "provider_config_observation_failed"
		if providerConfigUnavailableReason == ports.IdentityObservationReasonUnreadable {
			profile.reason = "provider_config_unreadable"
		}
	case applicationMetadataUnavailable && executable.Found() && launcher.Found() && providerConfig.Found():
		profile.reason = "application_metadata_observation_failed"
		if applicationMetadataReason == ports.IdentityObservationReasonUnreadable {
			profile.reason = "application_metadata_unreadable"
		} else if applicationMetadataReason == ports.IdentityObservationReasonMalformed {
			profile.reason = "application_version_malformed"
		}
	case profile.applicationVersion != "" && !validVersionText(profile.applicationVersion):
		profile.reason = "application_version_malformed"
	case profile.applicationVersionClassification == VersionRed:
		profile.reason = "application_version_ineligible"
	}
	return profile, nil
}

func validVersionText(value string) bool {
	_, ok := parseVersion(value)
	return ok
}

func observeZCodeApplicationMetadata(ctx context.Context, inspector ports.EnvironmentInspector, name string) (ports.ApplicationMetadataObservation, bool, ports.IdentityObservationFailureReason, error) {
	observation, err := inspector.ObserveApplicationMetadata(ctx, name)
	if err == nil {
		return observation, false, "", nil
	}
	if kind, classified := ports.IdentityObservationFailure(err); classified && kind == ports.IdentityObservationUnavailable {
		reason := ports.IdentityObservationReasonObservationFailed
		if observed, ok := ports.IdentityObservationReason(err); ok {
			reason = observed
		}
		return ports.ApplicationMetadataObservation{}, true, reason, nil
	}
	return ports.ApplicationMetadataObservation{}, false, "", err
}

func observeZCodeProviderConfigIdentity(ctx context.Context, inspector ports.EnvironmentInspector, appBundle string) (ports.FileIdentityObservation, bool, ports.IdentityObservationFailureReason, error) {
	candidate := filepath.Join(appBundle, filepath.FromSlash(ZCodeProviderConfigRelativePath))
	observation, err := observeReadableFileIdentity(ctx, inspector, candidate)
	if err != nil {
		if kind, classified := ports.IdentityObservationFailure(err); classified && kind == ports.IdentityObservationUnavailable {
			reason := ports.IdentityObservationReasonObservationFailed
			if observed, ok := ports.IdentityObservationReason(err); ok {
				reason = observed
			}
			return ports.FileIdentityObservation{}, true, reason, nil
		}
		return ports.FileIdentityObservation{}, false, "", err
	}
	return observation, false, "", nil
}

func observeZCodeAppExecutableIdentity(ctx context.Context, inspector ports.EnvironmentInspector, name string) (ports.ExecutableObservation, error) {
	file, err := observeReadableFileIdentity(ctx, inspector, name)
	if err != nil {
		return ports.ExecutableObservation{}, err
	}
	if !file.Found() {
		return ports.NewExecutableObservation(name, false, "", "", "")
	}
	return observeExecutableIdentity(ctx, inspector, name)
}

// DiscoverProviderProfiles discovers every allowlisted family in canonical
// order. Callers that select a subset must use DiscoverProviderProfile so an
// unselected provider cannot influence discovery.
func DiscoverProviderProfiles(ctx context.Context, inspector ports.EnvironmentInspector) ([]DiscoveredProviderProfile, error) {
	profiles := make([]DiscoveredProviderProfile, 0, len(families))
	for _, family := range families {
		profile, err := DiscoverProviderProfile(ctx, inspector, family)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

// DiscoverConfiguredProviderProfiles observes only the exact app-bundle or
// executable paths admitted from the project-local configuration.
func DiscoverConfiguredProviderProfiles(ctx context.Context, inspector ports.EnvironmentInspector, configured map[Family][]string) ([]DiscoveredProviderProfile, error) {
	if inspector == nil || len(configured) == 0 {
		return nil, fmt.Errorf("review run: configured provider discovery unavailable")
	}
	for family, paths := range configured {
		if !family.Valid() {
			return nil, fmt.Errorf("review run: configured provider family is invalid")
		}
		if len(paths) != 1 {
			return nil, fmt.Errorf("review run: configured %s path tuple is invalid", family)
		}
	}
	profiles := make([]DiscoveredProviderProfile, 0, len(configured))
	securityFamilies := make([]Family, 0, len(configured))
	for _, family := range families {
		paths, ok := configured[family]
		if !ok {
			continue
		}
		for _, configuredPath := range paths {
			if !canonicalAbsolute(configuredPath) {
				return nil, fmt.Errorf("review run: configured %s path is not canonical absolute", family)
			}
		}
		profile, err := DiscoverProviderProfileWithOverride(ctx, inspector, family, paths[0])
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			if kind, classified := ports.IdentityObservationFailure(err); classified && kind == ports.IdentityObservationSecurity {
				reason := "executable_security_failure"
				var component *providerIdentityComponentError
				if errors.As(err, &component) {
					switch component.component {
					case "launcher":
						reason = "launcher_security_failure"
					case "provider_config":
						reason = "provider_config_security_failure"
					case "application_metadata":
						reason = "application_metadata_security_failure"
					}
				}
				profiles = append(profiles, DiscoveredProviderProfile{family: family, reason: reason})
				securityFamilies = append(securityFamilies, family)
				continue
			}
			return nil, fmt.Errorf("review run: discover configured %s: %w", family, err)
		}
		profiles = append(profiles, profile)
	}
	if len(securityFamilies) > 0 {
		return profiles, &configuredProviderSecurityError{families: securityFamilies}
	}
	return profiles, nil
}

type providerIdentityComponentError struct {
	component string
	err       error
}

func (failure *providerIdentityComponentError) Error() string { return failure.err.Error() }
func (failure *providerIdentityComponentError) Unwrap() error { return failure.err }

type configuredProviderSecurityError struct{ families []Family }

func (failure *configuredProviderSecurityError) Error() string {
	return "review run: configured provider identity security admission failed"
}

// ConfiguredProviderSecurityFamilies returns the configured families whose
// identity observation failed security admission. The returned slice is
// caller-owned and contains no local path material.
func ConfiguredProviderSecurityFamilies(err error) []Family {
	var failure *configuredProviderSecurityError
	if !errors.As(err, &failure) || failure == nil {
		return nil
	}
	return append([]Family(nil), failure.families...)
}

func discoveredProviderProfile(
	family Family, executableObservation ports.ExecutableObservation, launcherObservation, providerConfigObservation ports.FileIdentityObservation,
) DiscoveredProviderProfile {
	profile := DiscoveredProviderProfile{
		family: family,
		reason: "executable_not_found",
	}
	if executableObservation.Found() {
		executable := executableObservation.ResolvedPath()
		if !canonicalAbsolute(executable) {
			profile.reason = "invalid_executable_provenance"
			return profile
		}
		profile.executable = executable
		profile.sha256 = executableObservation.SHA256()
		profile.argv = []string{executable}
	}
	if family != FamilyZCode {
		if profile.executable == "" {
			return profile
		}
		profile.launcher = profile.executable
		profile.launcherSHA256 = profile.sha256
		profile.reason = "unqualified_discovery"
		return profile
	}
	if launcherObservation.Found() {
		launcher := launcherObservation.ResolvedPath()
		if !canonicalAbsolute(launcher) {
			profile.reason = "invalid_launcher_provenance"
			return profile
		}
		profile.launcher = launcher
		profile.launcherSHA256 = launcherObservation.SHA256()
	}
	if profile.executable == "" {
		return profile
	}
	if profile.launcher == "" {
		profile.reason = "launcher_not_found"
		return profile
	}
	if providerConfigObservation.Found() {
		providerConfig := providerConfigObservation.ResolvedPath()
		if !canonicalAbsolute(providerConfig) {
			profile.reason = "invalid_provider_config_provenance"
			return profile
		}
		profile.providerConfig = providerConfig
		profile.providerConfigSHA256 = providerConfigObservation.SHA256()
	}
	if profile.providerConfig == "" {
		profile.reason = "provider_config_not_found"
		return profile
	}
	profile.argv = append(profile.argv, profile.launcher)
	profile.reason = "unqualified_discovery"
	return profile
}

// WithQualifiedVersion binds a version returned by the isolated exact
// [executable, launcher, "--version"] invocation. Direct families use the
// executable as their launcher.
func (profile DiscoveredProviderProfile) WithQualifiedVersion(argv []string, version string) DiscoveredProviderProfile {
	expected := append(profile.Argv(), "--version")
	if !reflect.DeepEqual(argv, expected) {
		profile.available = false
		profile.reason = "invalid_qualified_version_invocation"
		return profile
	}
	profile.version = version
	profile.classification = ClassifyVersion(profile.family, version)
	if profile.executable == "" || profile.launcher == "" || profile.family == FamilyZCode && profile.providerConfig == "" {
		profile.reason = "unqualified_discovery"
		return profile
	}
	if _, ok := parseVersion(version); !ok {
		profile.reason = "unparseable_version"
		return profile
	}
	if profile.classification == VersionRed || profile.classification == VersionUnknown {
		profile.reason = "ineligible_version"
		return profile
	}
	if profile.family == FamilyZCode {
		if profile.applicationVersion == "" || profile.applicationMetadata == "" || profile.applicationMetadataSHA256 == "" || !validVersionText(profile.applicationVersion) {
			profile.reason = "application_version_unavailable"
			return profile
		}
		if profile.applicationVersionClassification == VersionRed || profile.applicationVersionClassification == VersionUnknown {
			profile.reason = "application_version_ineligible"
			return profile
		}
	}
	profile.available = true
	profile.reason = "version_eligible"
	return profile
}

// Family returns the allowlisted family discovered by this profile.
func (profile DiscoveredProviderProfile) Family() Family { return profile.family }

// Version returns the observed version text.
func (profile DiscoveredProviderProfile) Version() string { return profile.version }

// Classification returns the version guidance classification.
func (profile DiscoveredProviderProfile) Classification() VersionClassification {
	return profile.classification
}

// Executable returns the canonical executable provenance, when discovered.
func (profile DiscoveredProviderProfile) Executable() string { return profile.executable }

// Launcher returns ZCode's fixed canonical launcher, or empty for direct binaries.
func (profile DiscoveredProviderProfile) Launcher() string { return profile.launcher }

// Argv returns a caller-owned direct invocation shape.
func (profile DiscoveredProviderProfile) Argv() []string {
	return append([]string(nil), profile.argv...)
}

// SHA256 returns diagnostic executable provenance.
func (profile DiscoveredProviderProfile) SHA256() string { return profile.sha256 }

// LauncherSHA256 returns the current launcher identity hash.
func (profile DiscoveredProviderProfile) LauncherSHA256() string { return profile.launcherSHA256 }

// ZCodeProviderConfig returns the exact bundled provider configuration bound to
// this ZCode runtime. Other provider families return an empty string.
func (profile DiscoveredProviderProfile) ZCodeProviderConfig() string { return profile.providerConfig }

// ZCodeProviderConfigSHA256 returns the identity of the bundled ZCode provider
// configuration. Other provider families return an empty string.
func (profile DiscoveredProviderProfile) ZCodeProviderConfigSHA256() string {
	return profile.providerConfigSHA256
}

func (profile DiscoveredProviderProfile) ApplicationVersion() string {
	return profile.applicationVersion
}
func (profile DiscoveredProviderProfile) ApplicationVersionClassification() VersionClassification {
	return profile.applicationVersionClassification
}
func (profile DiscoveredProviderProfile) ApplicationMetadata() string {
	return profile.applicationMetadata
}
func (profile DiscoveredProviderProfile) ApplicationMetadataSHA256() string {
	return profile.applicationMetadataSHA256
}

// Available reports whether executable discovery and version-floor eligibility passed.
func (profile DiscoveredProviderProfile) Available() bool { return profile.available }

// Reason returns the stable discovery reason.
func (profile DiscoveredProviderProfile) Reason() string { return profile.reason }

func canonicalAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

// ReceiptKind identifies a required current qualification receipt.
type ReceiptKind string

const (
	ReceiptWorkspace       ReceiptKind = "workspace"
	ReceiptEnvironment     ReceiptKind = "environment"
	ReceiptTransport       ReceiptKind = "transport"
	ReceiptNativeReference ReceiptKind = "native-reference"
	ReceiptCapability      ReceiptKind = "capability"
	ReceiptBaseRole        ReceiptKind = "base-role"
	ReceiptAssignment      ReceiptKind = "assignment"
	ReceiptSecurityPolicy  ReceiptKind = "security-policy"
)

var receiptKinds = [...]ReceiptKind{
	ReceiptWorkspace,
	ReceiptEnvironment,
	ReceiptTransport,
	ReceiptNativeReference,
	ReceiptCapability,
	ReceiptBaseRole,
	ReceiptAssignment,
	ReceiptSecurityPolicy,
}

// ReceiptKinds returns the required receipt kinds in canonical order. The
// returned slice is caller-owned.
func ReceiptKinds() []ReceiptKind { return append([]ReceiptKind(nil), receiptKinds[:]...) }

// ReceiptState is the closed state of a qualification receipt.
type ReceiptState string

const (
	ReceiptPass         ReceiptState = "pass"
	ReceiptMissing      ReceiptState = "missing"
	ReceiptStale        ReceiptState = "stale"
	ReceiptSkipped      ReceiptState = "skipped"
	ReceiptInconclusive ReceiptState = "inconclusive"
	ReceiptFailed       ReceiptState = "failed"
)

// Identity is the full current binding that every qualification receipt must share.
type Identity struct {
	Family                    Family
	Instance                  string
	ProfileGeneration         string
	AdapterProfile            string
	Version                   string
	Executable                string
	ExecutableSHA256          string
	Launcher                  string
	LauncherSHA256            string
	ApplicationVersion        string
	ApplicationMetadata       string
	ApplicationMetadataSHA256 string
	SnapshotManifest          string
	NamespaceLease            string
	NamespaceGeneration       string
}

// complete reports whether identity can bind a current receipt.
func (identity Identity) complete() bool {
	if !identity.Family.Valid() || identity.Instance == "" ||
		identity.ProfileGeneration == "" || identity.AdapterProfile == "" ||
		identity.Version == "" || !canonicalAbsolute(identity.Executable) ||
		identity.ExecutableSHA256 == "" || !canonicalAbsolute(identity.Launcher) ||
		identity.LauncherSHA256 == "" || identity.SnapshotManifest == "" ||
		identity.NamespaceLease == "" || identity.NamespaceGeneration == "" {
		return false
	}
	if identity.Family == FamilyZCode {
		return identity.ApplicationVersion != "" && canonicalAbsolute(identity.ApplicationMetadata) && identity.ApplicationMetadataSHA256 != ""
	}
	return identity.Launcher == identity.Executable && identity.LauncherSHA256 == identity.ExecutableSHA256 &&
		identity.ApplicationVersion == "" && identity.ApplicationMetadata == "" && identity.ApplicationMetadataSHA256 == ""
}

// Provenance is diagnostic-only receipt metadata. Its values deliberately do
// not participate in admission identity comparisons.
type Provenance struct {
	Version string
	Path    string
	SHA256  string
	Profile string
}

// AuthorityScope is the closed execution authority scope carried by a receipt.
type AuthorityScope string

const (
	AuthorityScopeDirectExecution AuthorityScope = "direct-execution"
)

// validatedAuthorityProof is package-private evidence emitted only after the
// provider adapter validates a typed execution authority against the complete
// current qualification binding.
type validatedAuthorityProof struct {
	directAuthorityID string
	identity          Identity
	expiresAt         time.Time
}

// Receipt is a provider-independent qualification fact. AuthorityID and
// AuthorityScope are diagnostic projections of package-private validated proof;
// callers cannot use raw values to establish an authoritative PASS.
type Receipt struct {
	Kind           ReceiptKind
	State          ReceiptState
	ExpiresAt      time.Time
	Identity       Identity
	AuthorityID    string
	AuthorityScope AuthorityScope
	Provenance     Provenance
	authority      *validatedAuthorityProof
}

// QualificationInput supplies the current facts for one admission decision.
// Receipts are copied before evaluation and are never retained by the result.
type QualificationInput struct {
	Identity          Identity
	Version           string
	KnownIncompatible bool
	Receipts          []Receipt
	Now               time.Time
}

// Qualification is an immutable provider-independent admission decision.
type Qualification struct {
	identity       Identity
	version        string
	classification VersionClassification
	available      bool
	reason         string
	receipts       []Receipt
}

// ValidateQualification applies the complete, side-effect-free admission
// conjunction. It always returns a decision; malformed or incomplete facts are
// ineligible rather than errors.
func ValidateQualification(input QualificationInput) Qualification {
	decision := Qualification{
		identity:       input.Identity,
		version:        input.Version,
		classification: ClassifyVersion(input.Identity.Family, input.Version),
		receipts:       append([]Receipt(nil), input.Receipts...),
	}
	if !input.Identity.complete() {
		decision.reason = "invalid_identity"
		return decision
	}
	if input.Identity.Version != input.Version {
		decision.reason = "identity_version_mismatch"
		return decision
	}
	if input.KnownIncompatible {
		decision.reason = "known_incompatible"
		return decision
	}
	if _, parsed := parseVersion(input.Version); !parsed {
		decision.reason = "unparseable_version"
		return decision
	}
	if decision.classification == VersionRed || decision.classification == VersionUnknown {
		decision.reason = "ineligible_version"
		return decision
	}
	if input.Now.IsZero() {
		decision.reason = "missing_evaluation_time"
		return decision
	}
	seen := make(map[ReceiptKind]bool, len(receiptKinds))
	var expiry time.Time
	var directAuthorityID string
	for _, receipt := range input.Receipts {
		if receipt.Kind == ReceiptCapability && receipt.hasDirectExecutionAuthority() {
			directAuthorityID = receipt.authority.directAuthorityID
			break
		}
	}
	for _, receipt := range input.Receipts {
		if !requiredReceiptKind(receipt.Kind) || seen[receipt.Kind] {
			decision.reason = "invalid_receipts"
			return decision
		}
		seen[receipt.Kind] = true
		if receipt.State != ReceiptPass {
			decision.reason = "non_passing_receipt"
			return decision
		}
		if !receipt.ExpiresAt.After(input.Now) {
			decision.reason = "expired_receipt"
			return decision
		}
		if expiry.IsZero() {
			expiry = receipt.ExpiresAt
		} else if !receipt.ExpiresAt.Equal(expiry) {
			decision.reason = "expiry_mismatch"
			return decision
		}
		if receipt.Identity != input.Identity {
			decision.reason = "identity_mismatch"
			return decision
		}
		switch receipt.Kind {
		case ReceiptCapability:
			if !receipt.hasDirectExecutionAuthority() {
				decision.reason = "invalid_receipts"
				return decision
			}
		case ReceiptSecurityPolicy:
			if !receipt.hasDirectExecutionAuthority() ||
				receipt.authority.directAuthorityID != directAuthorityID {
				decision.reason = "invalid_receipts"
				return decision
			}
		default:
			if receipt.AuthorityID != "" || receipt.AuthorityScope != "" || receipt.authority != nil {
				decision.reason = "invalid_receipts"
				return decision
			}
		}
	}
	for _, kind := range receiptKinds {
		if !seen[kind] {
			decision.reason = "missing_receipt"
			return decision
		}
	}
	decision.available = true
	decision.reason = "eligible"
	return decision
}
func (receipt Receipt) hasDirectExecutionAuthority() bool {
	proof := receipt.authority
	return proof != nil &&
		receipt.AuthorityID == proof.directAuthorityID &&
		receipt.AuthorityScope == AuthorityScopeDirectExecution &&
		proof.identity == receipt.Identity &&
		proof.expiresAt.Equal(receipt.ExpiresAt)
}

// Available reports whether the admission conjunction is satisfied.
func (qualification Qualification) Available() bool { return qualification.available }

// Identity returns the evaluated identity.
func (qualification Qualification) Identity() Identity { return qualification.identity }

// Version returns the evaluated version text.
func (qualification Qualification) Version() string { return qualification.version }

// Classification returns the evaluated version classification.
func (qualification Qualification) Classification() VersionClassification {
	return qualification.classification
}

// Reason returns the stable reason for the admission decision.
func (qualification Qualification) Reason() string { return qualification.reason }

// Receipts returns a caller-owned copy of the evaluated receipt facts.
func (qualification Qualification) Receipts() []Receipt {
	return append([]Receipt(nil), qualification.receipts...)
}

func requiredReceiptKind(kind ReceiptKind) bool {
	for _, candidate := range receiptKinds {
		if kind == candidate {
			return true
		}
	}
	return false
}

type version struct{ major, minor, patch int }

func (left version) compare(right version) int {
	if left.major != right.major {
		return compareInt(left.major, right.major)
	}
	if left.minor != right.minor {
		return compareInt(left.minor, right.minor)
	}
	return compareInt(left.patch, right.patch)
}

func compareInt(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func parseVersion(text string) (version, bool) {
	text = strings.TrimPrefix(text, "v")
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return version{}, false
	}
	var values [3]int
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return version{}, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return version{}, false
		}
		values[index] = value
	}
	return version{major: values[0], minor: values[1], patch: values[2]}, true
}
