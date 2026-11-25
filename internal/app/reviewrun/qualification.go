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
	FamilyZCode Family = "zcode"
	FamilyGrok  Family = "grok"
)

var families = [...]Family{FamilyZCode, FamilyGrok}

// Families returns the allowlisted families in canonical order. The returned
// slice is caller-owned.
func Families() []Family { return append([]Family(nil), families[:]...) }

// Valid reports whether family is allowlisted.
func (family Family) Valid() bool {
	return family == FamilyZCode || family == FamilyGrok
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
	{Family: FamilyZCode, Minimum: "0.2.0", VerifiedLatest: "0.2.0"},
	{Family: FamilyGrok, Minimum: "1.0.89", VerifiedLatest: "1.0.89"},
}

var zcodeApplicationGuidance = VersionGuidance{Family: FamilyZCode, Minimum: "3.18.2", VerifiedLatest: "4.0.0"}

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

// ZCodeAppBundle is the standard ZCode Desktop location.
const ZCodeAppBundle = "/Applications/ZCode.app"

// DiscoveredProviderProfile is an immutable identity-only executable discovery result.
// Discovery never launches a provider and is therefore not routable until a qualified
// version result is bound to this exact invocation shape.
type DiscoveredProviderProfile struct {
	family                           Family
	zcodeCompanion                   ports.ZCodeCompanionObservation
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

// DiscoverProviderProfile discovers one allowlisted family without observing
// any other provider. ZCode uses isolated companion diagnostics.
func DiscoverProviderProfile(ctx context.Context, inspector ports.EnvironmentInspector, family Family) (DiscoveredProviderProfile, error) {
	return DiscoverProviderProfileWithOverride(ctx, inspector, family, "")
}

// DiscoverProviderProfileWithOverride observes one effective provider tuple.
// For ZCode the override is an application bundle; for direct providers it is
// an executable. An empty override selects the family-owned default.
func DiscoverProviderProfileWithOverride(ctx context.Context, inspector ports.EnvironmentInspector, family Family, pathOverride string, excluded ...string) (DiscoveredProviderProfile, error) {
	if inspector == nil || !family.Valid() {
		return DiscoveredProviderProfile{}, fmt.Errorf("review run: invalid provider discovery authority")
	}
	if pathOverride != "" && !canonicalAbsolute(pathOverride) {
		return DiscoveredProviderProfile{}, fmt.Errorf("review run: configured provider path is not canonical absolute")
	}
	if family == FamilyZCode {
		observer, ok := inspector.(ports.ZCodeCompanionObserver)
		if !ok {
			return DiscoveredProviderProfile{family: family, reason: "herdr_zcode_observation_failed"}, nil
		}
		observation, err := observer.ObserveZCodeCompanion(ctx, pathOverride, excluded...)
		if err != nil {
			if kind, classified := ports.IdentityObservationFailure(err); classified && kind == ports.IdentityObservationUnavailable {
				return unavailableZCodeCompanionProfile(observation), nil
			}
			return DiscoveredProviderProfile{}, &providerIdentityComponentError{component: "herdr_zcode", err: err}
		}
		if observation == (ports.ZCodeCompanionObservation{}) {
			return DiscoveredProviderProfile{family: family, reason: "herdr_zcode_missing"}, nil
		}
		desktopClass := classifyZCodeCompanionDesktop(observation)
		if !observation.Valid() || !validVersionText(observation.Version) || desktopClass == VersionUnknown ||
			observation.DesktopBelowMinimum != (desktopClass == VersionRed) {
			return unavailableZCodeCompanionProfile(observation), nil
		}
		return DiscoveredProviderProfile{
			family: family, zcodeCompanion: observation, executable: observation.Executable, launcher: observation.Executable,
			sha256: observation.ExecutableSHA256, launcherSHA256: observation.ExecutableSHA256, argv: []string{observation.Executable},
			applicationVersion: observation.AppVersion, applicationVersionClassification: desktopClass,
			reason: "unqualified_discovery",
		}, nil
	}
	name := string(family)
	if pathOverride != "" {
		name = pathOverride
	}
	executable, err := observeExecutableIdentity(ctx, inspector, name)
	if err != nil {
		if kind, classified := ports.IdentityObservationFailure(err); classified && kind == ports.IdentityObservationUnavailable {
			reason := "executable_observation_failed"
			if reasonCode, _ := ports.IdentityObservationReason(err); reasonCode == ports.IdentityObservationReasonNonExecutable {
				reason = "executable_not_executable"
			}
			return DiscoveredProviderProfile{family: family, reason: reason}, nil
		}
		return DiscoveredProviderProfile{}, &providerIdentityComponentError{component: "executable", err: fmt.Errorf("review run: discover %s executable: %w", family, err)}
	}
	return discoveredProviderProfile(family, executable), nil
}

func unavailableZCodeCompanionProfile(observation ports.ZCodeCompanionObservation) DiscoveredProviderProfile {
	if !observation.PackageVerified() {
		observation = ports.ZCodeCompanionObservation{}
	} else {
		observation.AppVersion, observation.AppBundle, observation.MinimumAppVersion = "", "", ""
		observation.DesktopBelowMinimum = false
		if !validVersionText(observation.Version) {
			observation.Version = ""
		}
	}
	return DiscoveredProviderProfile{
		family: FamilyZCode, zcodeCompanion: observation, reason: "herdr_zcode_observation_failed",
	}
}

func classifyZCodeCompanionDesktop(observation ports.ZCodeCompanionObservation) VersionClassification {
	if !validVersionText(observation.AppVersion) || !validVersionText(observation.MinimumAppVersion) {
		return VersionUnknown
	}
	guidance := zcodeApplicationGuidance
	guidance.Minimum = observation.MinimumAppVersion
	return classifyVersionAgainstGuidance(guidance, observation.AppVersion)
}

func validVersionText(value string) bool {
	_, ok := parseVersion(value)
	return ok
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
func DiscoverConfiguredProviderProfiles(ctx context.Context, inspector ports.EnvironmentInspector, configured map[Family][]string, excluded ...string) ([]DiscoveredProviderProfile, error) {
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
		profile, err := DiscoverProviderProfileWithOverride(ctx, inspector, family, paths[0], excluded...)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			if kind, classified := ports.IdentityObservationFailure(err); classified && kind == ports.IdentityObservationSecurity {
				reason := "executable_security_failure"
				var component *providerIdentityComponentError
				if errors.As(err, &component) {
					if component.component == "herdr_zcode" {
						reason = "herdr_zcode_unsafe_identity"
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

func discoveredProviderProfile(family Family, observation ports.ExecutableObservation) DiscoveredProviderProfile {
	profile := DiscoveredProviderProfile{family: family, reason: "executable_not_found"}
	if !observation.Found() {
		return profile
	}
	executable := observation.ResolvedPath()
	if !canonicalAbsolute(executable) {
		profile.reason = "invalid_executable_provenance"
		return profile
	}
	profile.executable, profile.launcher = executable, executable
	profile.sha256, profile.launcherSHA256 = observation.SHA256(), observation.SHA256()
	profile.argv = []string{executable}
	profile.reason = "unqualified_discovery"
	return profile
}

// WithQualifiedVersion binds a version returned by the isolated exact
// version invocation for the admitted executable.
func (profile DiscoveredProviderProfile) WithQualifiedVersion(argv []string, version string) DiscoveredProviderProfile {
	expected := append(profile.Argv(), "--version")
	if profile.zcodeCompanion.Valid() {
		expected = append(expected, "--json")
		if profile.zcodeCompanion.BundleOverride != "" {
			expected = append(expected, "--app-bundle", profile.zcodeCompanion.BundleOverride)
		}
		if version != profile.zcodeCompanion.Version {
			profile.reason = "version_identity_drift"
			return profile
		}
	}
	if !reflect.DeepEqual(argv, expected) {
		profile.available = false
		profile.reason = "invalid_qualified_version_invocation"
		return profile
	}
	profile.version = version
	profile.classification = ClassifyVersion(profile.family, version)
	if profile.executable == "" || profile.launcher == "" || profile.family == FamilyZCode && !profile.zcodeCompanion.Valid() {
		profile.reason = "unqualified_discovery"
		return profile
	}
	if !observedVersionParsed(version) {
		profile.reason = "unparseable_version"
		return profile
	}
	if profile.classification == VersionRed || profile.classification == VersionUnknown {
		profile.reason = "ineligible_version"
		return profile
	}
	if profile.family == FamilyZCode {
		if profile.applicationVersion == "" || !validVersionText(profile.applicationVersion) {
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

func (profile DiscoveredProviderProfile) ZCodeCompanion() ports.ZCodeCompanionObservation {
	return profile.zcodeCompanion
}

func (profile DiscoveredProviderProfile) matchesCompanion(definition ports.ProviderRuntimeDefinition) bool {
	if profile.family != FamilyZCode {
		return true
	}
	native, ok := definition.(ports.ProviderZCodeCompanionDefinition)
	return ok && profile.zcodeCompanion.Valid() && profile.zcodeCompanion == native.ZCodeCompanion()
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
	ExecutionTargetIdentity   string
	NamespaceLease            string
	NamespaceGeneration       string
}

// complete reports whether identity can bind a current receipt.
func (identity Identity) complete() bool {
	if !identity.Family.Valid() || identity.Instance == "" ||
		identity.ProfileGeneration == "" || identity.AdapterProfile == "" ||
		identity.Version == "" || !canonicalAbsolute(identity.Executable) ||
		identity.ExecutableSHA256 == "" || !canonicalAbsolute(identity.Launcher) ||
		identity.LauncherSHA256 == "" || identity.ExecutionTargetIdentity == "" ||
		identity.NamespaceLease == "" || identity.NamespaceGeneration == "" {
		return false
	}
	if identity.Family == FamilyZCode {
		return identity.ApplicationVersion != "" && identity.Launcher == identity.Executable && identity.LauncherSHA256 == identity.ExecutableSHA256
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
	if !observedVersionParsed(input.Version) {
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

func observedVersionParsed(text string) bool {
	_, ok := parseVersion(text)
	return ok
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
