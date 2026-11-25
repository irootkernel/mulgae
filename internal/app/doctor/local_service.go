package doctor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/ports"
)

// LocalDependencies are the existing observation capabilities for offline diagnosis.
// Platform is build metadata supplied by composition, not another observation.
type LocalDependencies struct {
	Clock           ports.Clock
	Sources         ports.ConfigSourceFactory
	Codec           appconfig.Codec
	Accounts        appconfig.AccountObserver
	Locality        ports.ConfigLocalityAttestor
	Inspector       ports.EnvironmentInspector
	Versions        ports.ProviderVersionObserver
	TerminalRuntime ports.TerminalRuntimeObserver
	Platform        LocalPlatformEvidence
}

// LocalService owns local v7 admission and reduction. Recorded evidence remains
// with Service, and CLI envelopes and human formatting remain with the transport.
type LocalService struct{ dependencies LocalDependencies }

// NewLocalService binds capabilities without performing or advancing observations.
// The locality and optional version dependencies are consulted at their existing
// diagnosis positions, including the missing-project early return.
func NewLocalService(dependencies LocalDependencies) *LocalService {
	return &LocalService{dependencies: dependencies}
}

func (service *LocalService) DiagnoseLocal(ctx context.Context, root ports.AnchoredRoot) (LocalDoctorResult, error) {
	now := service.dependencies.Clock.Now().UTC()
	base := LocalDoctorResult{
		SchemaVersion: LocalSchemaVersion, CheckedAt: now, ProjectRootURI: ".",
		Config:                LocalConfigProjection{Status: "missing", URI: appconfig.ConfigRelativePath, Authority: "project_local", Locality: "not_observed", TargetCommitOIDs: []string{}, ReasonCodes: []string{"config_missing"}},
		ConfigV3:              LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{"config_missing"}},
		LocalConfiguration:    LocalDiagnosticCheck{Status: "not_applicable", ReasonCodes: []string{}},
		ProviderIdentity:      LocalDiagnosticCheck{Status: "not_applicable", ReasonCodes: []string{}},
		ConfiguredProviderIDs: []string{},
		ProviderInventory:     localUnobservedProviderInventory(),
		Assignment:            LocalAssignmentProjection{State: "not_observed", Resilience: "not_observed"},
		PlatformEvidence:      []LocalPlatformEvidence{service.dependencies.Platform},
		ToolsLock:             LocalToolsLock{State: "not_observed"},
		Readiness:             LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"config_missing"}},
		ConfiguredReadiness:   LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"config_missing"}},
		RoleRouteReadiness:    LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"config_missing"}},
		Diagnostics:           []LocalDiagnostic{{Code: "config_missing", Category: "readiness", Message: "Project-local Mulgae configuration is missing.", Redacted: true}},
	}
	source, err := service.dependencies.Sources.OpenConfigSource(root, true)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return finalizeLocalDoctor(base)
		}
		reason := configLocalityFailureCode(err, "config_locality_unsafe")
		base.Config.Status, base.Config.Locality = "unsafe", "rejected"
		base.Config.ReasonCodes = []string{reason}
		base.ConfigV3 = LocalDiagnosticCheck{Status: "unverifiable", ReasonCodes: []string{"config_not_observed_due_to_locality"}}
		base.LocalConfiguration = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{reason}}
		base.Readiness = LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
		base.Diagnostics = []LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local Mulgae configuration failed security admission.", Redacted: true}}
		return finalizeLocalDoctor(base)
	}
	splitSource, ok := source.(ports.SplitConfigSource)
	if !ok {
		return LocalDoctorResult{}, fmt.Errorf("doctor split config source unavailable")
	}
	if !splitSource.ProjectPresent() {
		return finalizeLocalDoctor(base)
	}
	attestor := service.dependencies.Locality
	if attestor == nil {
		return LocalDoctorResult{}, fmt.Errorf("doctor locality attestor unavailable")
	}
	proof, err := source.Proof()
	if err != nil {
		return LocalDoctorResult{}, err
	}
	request, err := ports.NewConfigLocalityRequest(root, proof, nil, nil)
	if err != nil {
		return LocalDoctorResult{}, err
	}
	locality, err := attestor.Attest(ctx, request)
	if err != nil {
		reason := configLocalityFailureCode(err, "config_locality_unsafe")
		base.Config.Status, base.Config.Locality = "unsafe", "rejected"
		base.Config.ReasonCodes = []string{reason}
		base.ConfigV3 = LocalDiagnosticCheck{Status: "unverifiable", ReasonCodes: []string{"config_not_observed_due_to_locality"}}
		base.LocalConfiguration = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{reason}}
		base.Readiness = LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
		base.Diagnostics = []LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local Mulgae configuration failed locality admission.", Redacted: true}}
		return finalizeLocalDoctor(base)
	}
	if err := appconfig.ConfirmLocality(ctx, source, attestor, request, locality); err != nil {
		reason := configLocalityFailureCode(err, "config_locality_drifted")
		base.Config.Status, base.Config.Locality = "drifted", "drifted"
		base.Config.ReasonCodes = []string{reason}
		base.ConfigV3 = LocalDiagnosticCheck{Status: "unverifiable", ReasonCodes: []string{"config_not_observed_due_to_locality"}}
		base.LocalConfiguration = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{reason}}
		base.Readiness = LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
		base.Diagnostics = []LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local Mulgae configuration changed during admission.", Redacted: true}}
		return finalizeLocalDoctor(base)
	}
	if !source.Present() {
		splitCodec, ok := service.dependencies.Codec.(appconfig.SplitCodec)
		if !ok {
			return LocalDoctorResult{}, fmt.Errorf("doctor split config codec unavailable")
		}
		if _, err := splitCodec.ProjectProviderIDs(splitSource.ProjectBytes()); err != nil {
			base = rejectDoctorConfig(base, err)
			return finalizeLocalDoctor(base)
		}
		base.Config.Status, base.Config.Locality = "missing", "verified"
		base.Config.ReasonCodes = []string{"local_config_missing"}
		base.ConfigV3 = LocalDiagnosticCheck{Status: "unverifiable", ReasonCodes: []string{"local_config_missing"}}
		base.LocalConfiguration = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{"local_config_missing"}}
		base.ProviderIdentity = LocalDiagnosticCheck{Status: "unverifiable", ReasonCodes: []string{"local_config_missing"}}
		base.Readiness = LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"local_config_missing"}}
		base.Diagnostics = []LocalDiagnostic{{Code: "local_config_missing", Category: "configuration", Message: "Machine-local Mulgae configuration is missing; run mulgae init.", Redacted: true}}
		return finalizeLocalDoctor(base)
	}
	data, identity, err := source.Read()
	if err != nil {
		base = rejectDoctorConfig(base, err)
		return finalizeLocalDoctor(base)
	}
	config, err := service.dependencies.Codec.Decode(data)
	if err != nil {
		base = rejectDoctorConfig(base, err)
		return finalizeLocalDoctor(base)
	}
	base.ConfigV3 = LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}}
	base.LocalConfiguration = LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}}
	base.ProviderIdentity = LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}}
	if err := appconfig.ConfirmLocality(ctx, source, attestor, request, locality); err != nil {
		reason := configLocalityFailureCode(err, "config_locality_drifted")
		base.Config.Status, base.Config.Locality = "drifted", "drifted"
		base.Config.ReasonCodes = []string{reason}
		base.Readiness = LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
		base.Diagnostics = []LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local Mulgae configuration changed during admission.", Redacted: true}}
		return finalizeLocalDoctor(base)
	}
	head, _ := locality.Checkout()
	indexDigest, _, _ := locality.Index()
	base.Config = LocalConfigProjection{Status: "ready", URI: appconfig.ConfigRelativePath, SHA256: identity.SHA256(), Authority: "project_local", Locality: "verified", CheckoutHeadOID: head, IndexEntriesSHA256: indexDigest, TargetCommitOIDs: append([]string{}, locality.ApplicableCommitOIDs()...), ProvenanceState: "accepted", ReasonCodes: []string{}}
	account := service.dependencies.Accounts.ObserveAccount()
	_, accountErr := appconfig.EffectiveAccountUID(account)
	if account.Err != nil || !account.Available || accountErr != nil || account.Home != config.NativeUser.Home {
		base.Config.Status = "unsafe"
		base.Config.NativeHomeIdentity = "mismatch"
		base.Config.ReasonCodes = []string{"native_home_mismatch"}
		base.LocalConfiguration = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{"native_home_mismatch"}}
		base.Readiness = LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{"native_home_mismatch"}}
		base.Diagnostics = []LocalDiagnostic{{Code: "native_home_mismatch", Category: "security", Message: "Configured native home does not match the installed user.", Redacted: true}}
		return finalizeLocalDoctor(base)
	}
	nativeHomeAuthority, nativeHomeErr := service.dependencies.Inspector.ObserveNativeHomeIdentity(ctx, account.Home)
	if localDoctorCancellation(nativeHomeErr) {
		return LocalDoctorResult{}, nativeHomeErr
	}
	if nativeHomeErr != nil || !nativeHomeAuthority.Valid() || nativeHomeAuthority.Path() != account.Home || nativeHomeAuthority.EffectiveUID() != uint32(account.EffectiveUID) {
		base.Config.Status = "unsafe"
		base.Config.NativeHomeIdentity = "mismatch"
		base.Config.ReasonCodes = []string{"native_home_mismatch"}
		base.LocalConfiguration = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{"native_home_mismatch"}}
		base.Readiness = LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{"native_home_mismatch"}}
		base.Diagnostics = []LocalDiagnostic{{Code: "native_home_mismatch", Category: "security", Message: "Configured native home failed descriptor identity admission.", Redacted: true}}
		return finalizeLocalDoctor(base)
	}
	base.Config.NativeHomeIdentity = "verified"
	base.ConfiguredProviderIDs = config.Providers.Families()
	roleReferences := localConfiguredRoleReferences(config)
	configured := make(map[reviewrun.Family][]string, len(base.ConfiguredProviderIDs))
	if provider := config.Providers.ZCode; provider != nil {
		configured[reviewrun.FamilyZCode] = []string{provider.AppBundle}
	}
	if provider := config.Providers.Grok; provider != nil {
		configured[reviewrun.FamilyGrok] = []string{provider.Executable}
	}
	profiles, discoveryErr := reviewrun.DiscoverConfiguredProviderProfiles(ctx, service.dependencies.Inspector, configured, root.String())
	securityDiscoveryFamilies := make(map[reviewrun.Family]struct{})
	for _, family := range reviewrun.ConfiguredProviderSecurityFamilies(discoveryErr) {
		securityDiscoveryFamilies[family] = struct{}{}
	}
	if discoveryErr != nil && len(securityDiscoveryFamilies) == 0 {
		return LocalDoctorResult{}, discoveryErr
	}
	profileByFamily := make(map[string]reviewrun.DiscoveredProviderProfile, len(profiles))
	for _, profile := range profiles {
		profileByFamily[string(profile.Family())] = profile
	}
	base.ProviderInventory = make([]LocalProviderInventoryRow, 0, 2)
	eligible := 0
	unsafeAdmission := len(securityDiscoveryFamilies) > 0
	for _, family := range []string{"zcode", "grok"} {
		if _, configuredFamily := configured[reviewrun.Family(family)]; !configuredFamily {
			base.ProviderInventory = append(base.ProviderInventory, LocalProviderInventoryRow{
				Family: family, ReferencedByRoles: []string{}, State: "not_configured", Reason: "not_configured",
				BinaryAvailable:       LocalDiagnosticCheck{Status: "not_applicable", ReasonCodes: []string{}},
				CLICompatible:         LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"},
				ApplicationCompatible: LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"},
			})
			continue
		}
		row := LocalProviderInventoryRow{Family: family, Configured: true, ReferencedByRoles: roleReferences[family]}
		profile := profileByFamily[family]
		row.ApplicationCompatible = LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"}
		if family == "zcode" {
			row.ApplicationCompatible = localZCodeApplicationCompatibility(profile)
		}
		if _, unsafeIdentity := securityDiscoveryFamilies[reviewrun.Family(family)]; unsafeIdentity {
			row.State, row.Reason = "unavailable", "provider_executable_unsafe_identity"
			if family == "zcode" {
				row.Reason = "herdr_zcode_unsafe_identity"
			}
			row.BinaryAvailable = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{row.Reason}}
			row.CLICompatible = LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"}
			base.ProviderInventory = append(base.ProviderInventory, row)
			continue
		}
		companion := profile.ZCodeCompanion()
		if !companion.PackageVerified() && (profile.Executable() == "" || profile.Launcher() == "") {
			reason := "provider_executable_missing"
			switch profile.Reason() {
			case "executable_not_executable":
				reason = "provider_executable_not_executable"
			case "executable_observation_failed":
				reason = "provider_binary_observation_failed"
			case "herdr_zcode_missing", "herdr_zcode_observation_failed":
				reason = profile.Reason()
			}
			row.State, row.Reason = "unavailable", reason
			row.BinaryAvailable = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{reason}}
			row.CLICompatible = LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"}
			base.ProviderInventory = append(base.ProviderInventory, row)
			continue
		}
		row.BinaryAvailable = LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}}
		guidance, _ := reviewrun.Guidance(reviewrun.Family(family))
		row.CLICompatible = LocalCLICompatibility{
			Status: "unverifiable", Eligibility: "not_evaluated", Compatibility: "not_observed",
			MinimumVersion: guidance.Minimum, VerifiedLatest: guidance.VerifiedLatest, ReasonCode: "provider_cli_version_observation_failed",
		}
		if family == "zcode" {
			row.CLICompatible.ReasonCode = "herdr_zcode_cli_observation_failed"
			observation, err := ports.NewProviderVersionObservation(ports.ProviderVersionObserved, companion.Version)
			if err == nil {
				row.CLICompatible = localCLICompatibility(reviewrun.FamilyZCode, guidance, observation)
			}
		} else if !nilInterface(service.dependencies.Versions) {
			argv := append(profile.Argv(), "--version")
			observation, observeErr := service.dependencies.Versions.ObserveProviderVersion(ctx, family, argv, ports.ProviderVersionIdentity{
				ExecutableSHA256: profile.SHA256(), LauncherSHA256: profile.LauncherSHA256(),
			})
			if observeErr == nil {
				row.CLICompatible = localCLICompatibility(reviewrun.Family(family), guidance, observation)
			}
		}
		cliIdentityUnsafe := row.CLICompatible.ReasonCode == "provider_cli_version_unsafe_identity"
		unsafeAdmission = unsafeAdmission || cliIdentityUnsafe
		herdrReason := ""
		if family == "grok" || family == "zcode" {
			if nilInterface(service.dependencies.TerminalRuntime) {
				herdrReason = "herdr_core_observation_failed"
			} else {
				rtObs, rtErr := service.dependencies.TerminalRuntime.ObserveTerminalRuntime(ctx, account.Home, root.String())
				if localDoctorCancellation(rtErr) {
					return LocalDoctorResult{}, rtErr
				}
				switch {
				case rtErr != nil || !rtObs.Valid():
					herdrReason = "herdr_core_observation_failed"
				case rtObs.State() == ports.TerminalRuntimeAvailable:
				case rtObs.State() == ports.TerminalRuntimeMissing:
					herdrReason = "herdr_core_missing"
				case rtObs.State() == ports.TerminalRuntimeUnsafeIdentity:
					herdrReason = "herdr_core_unsafe_identity"
					unsafeAdmission = true
				default:
					herdrReason = "herdr_core_observation_failed"
				}
			}
			if herdrReason != "" {
				row.BinaryAvailable = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{herdrReason}}
			}
		}
		applicationEligible := family != "zcode" || row.ApplicationCompatible.Eligibility == "eligible"
		if row.CLICompatible.Eligibility == "eligible" && applicationEligible && herdrReason == "" {
			eligible++
			row.State, row.Reason = "eligible", row.CLICompatible.ReasonCode
			if family == "zcode" {
				row.Reason = row.ApplicationCompatible.ReasonCode
			}
		} else {
			row.State, row.Reason = "unavailable", row.CLICompatible.ReasonCode
			if !applicationEligible && row.CLICompatible.Eligibility == "eligible" {
				row.Reason = row.ApplicationCompatible.ReasonCode
			}
			if herdrReason == "herdr_core_unsafe_identity" && !cliIdentityUnsafe {
				row.Reason = herdrReason
			} else if herdrReason != "" && row.CLICompatible.Eligibility == "eligible" {
				row.Reason = herdrReason
			}
		}
		base.ProviderInventory = append(base.ProviderInventory, row)
	}
	nativeHomeCurrent, nativeHomeErr := service.dependencies.Inspector.ObserveNativeHomeIdentity(ctx, account.Home)
	if localDoctorCancellation(nativeHomeErr) {
		return LocalDoctorResult{}, nativeHomeErr
	}
	if nativeHomeErr != nil || !appconfig.SameNativeHomeAuthority(nativeHomeAuthority, nativeHomeCurrent) {
		base.Config.Status = "unsafe"
		base.Config.NativeHomeIdentity = "mismatch"
		base.Config.ReasonCodes = []string{"native_home_mismatch"}
		base.LocalConfiguration = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{"native_home_mismatch"}}
		base.ConfiguredProviderIDs = []string{}
		base.ProviderInventory = localUnobservedProviderInventory()
		base.Assignment = LocalAssignmentProjection{State: "not_observed", Resilience: "not_observed"}
		base.Readiness = LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{"native_home_mismatch"}}
		base.Diagnostics = []LocalDiagnostic{{Code: "native_home_mismatch", Category: "security", Message: "Configured native home changed during admission.", Redacted: true}}
		return finalizeLocalDoctor(base)
	}
	switch {
	case unsafeAdmission:
		base.Assignment = LocalAssignmentProjection{State: "unavailable", Resilience: "unavailable"}
		base.Readiness = LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{"provider_security_admission_failed"}}
		base.Diagnostics = []LocalDiagnostic{{Code: "provider_security_admission_failed", Category: "security", Message: "A configured provider failed security admission.", Redacted: true}}
	case eligible != len(configured):
		base.Assignment = LocalAssignmentProjection{State: "unavailable", Resilience: "unavailable"}
		base.Readiness = LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"provider_offline_readiness_failed"}}
		base.Diagnostics = []LocalDiagnostic{{Code: "provider_offline_readiness_failed", Category: "readiness", Message: "At least one configured provider failed offline binary or CLI compatibility checks.", Redacted: true}}
	default:
		// Every role runs on exactly one provider, so one eligible family is a
		// complete configuration, not a degraded one.
		base.Assignment = LocalAssignmentProjection{State: "ready", Resilience: "ready"}
		base.Readiness = LocalReadiness{State: "ready", ExitCode: 0, ReasonCodes: []string{}}
		base.Diagnostics = []LocalDiagnostic{}
	}
	base.ConfiguredReadiness = base.Readiness
	base.RoleRouteReadiness = localRoleRouteReadiness(base.ProviderInventory)
	return finalizeLocalDoctor(base)
}

func finalizeLocalDoctor(result LocalDoctorResult) (LocalDoctorResult, error) {
	if result.ConfiguredReadiness.State == "unverified" && len(result.ConfiguredReadiness.ReasonCodes) == 1 && result.ConfiguredReadiness.ReasonCodes[0] == "config_missing" {
		result.ConfiguredReadiness = result.Readiness
	}
	if result.RoleRouteReadiness.State == "unverified" && len(result.RoleRouteReadiness.ReasonCodes) == 1 && result.RoleRouteReadiness.ReasonCodes[0] == "config_missing" {
		result.RoleRouteReadiness = result.Readiness
	}
	return result, result.Validate()
}

func localCLICompatibility(family reviewrun.Family, guidance reviewrun.VersionGuidance, observation ports.ProviderVersionObservation) LocalCLICompatibility {
	result := LocalCLICompatibility{MinimumVersion: guidance.Minimum, VerifiedLatest: guidance.VerifiedLatest, Eligibility: "not_evaluated", Compatibility: "not_observed"}
	switch observation.State() {
	case ports.ProviderVersionObserved:
		result.ObservedVersion = observation.Version()
		switch reviewrun.ClassifyVersion(family, observation.Version()) {
		case reviewrun.VersionGreen:
			result.Status, result.Eligibility, result.Compatibility, result.ReasonCode = "verified", "eligible", "verified", "provider_cli_version_supported"
		case reviewrun.VersionYellow:
			result.Status, result.Eligibility, result.Compatibility, result.ReasonCode = "verified", "eligible", "newer_than_verified", "provider_cli_version_newer_than_verified"
		case reviewrun.VersionRed:
			result.Status, result.Eligibility, result.Compatibility, result.ReasonCode = "failed", "ineligible", "below_minimum", "provider_cli_version_below_minimum"
		default:
			result.Status, result.Eligibility, result.Compatibility, result.ReasonCode = "failed", "ineligible", "malformed", "provider_cli_version_malformed"
		}
	case ports.ProviderVersionTimedOut:
		result.Status, result.ReasonCode = "unverifiable", "provider_cli_version_timeout"
	case ports.ProviderVersionExecutionFailed:
		result.Status, result.ReasonCode = "unverifiable", "provider_cli_version_command_failed"
	case ports.ProviderVersionMalformed:
		result.Status, result.Eligibility, result.Compatibility, result.ReasonCode = "failed", "ineligible", "malformed", "provider_cli_version_malformed"
	case ports.ProviderVersionUnsafeIdentity:
		result.Status, result.ReasonCode = "failed", "provider_cli_version_unsafe_identity"
	default:
		result.Status, result.ReasonCode = "unverifiable", "provider_cli_version_observation_failed"
	}
	return result
}

func localZCodeApplicationCompatibility(profile reviewrun.DiscoveredProviderProfile) LocalCLICompatibility {
	guidance := reviewrun.ZCodeApplicationGuidance()
	companion := profile.ZCodeCompanion()
	if !companion.Valid() {
		result := LocalCLICompatibility{Status: "unverifiable", Eligibility: "not_evaluated", Compatibility: "not_observed"}
		if companion.PackageVerified() {
			result.ReasonCode = "herdr_zcode_desktop_observation_failed"
		}
		return result
	}
	guidance.Minimum = companion.MinimumAppVersion
	result := LocalCLICompatibility{
		Status: "failed", ObservedVersion: profile.ApplicationVersion(), Eligibility: "ineligible", Compatibility: "malformed",
		MinimumVersion: guidance.Minimum, VerifiedLatest: guidance.VerifiedLatest, ReasonCode: "zcode_application_version_malformed",
	}
	switch profile.ApplicationVersionClassification() {
	case reviewrun.VersionGreen:
		result.Status, result.Eligibility, result.Compatibility, result.ReasonCode = "verified", "eligible", "verified", "zcode_application_version_supported"
	case reviewrun.VersionYellow:
		result.Status, result.Eligibility, result.Compatibility, result.ReasonCode = "verified", "eligible", "newer_than_verified", "zcode_application_version_newer_than_verified"
	case reviewrun.VersionRed:
		result.Compatibility, result.ReasonCode = "below_minimum", "zcode_application_version_below_minimum"
	}
	return result
}

func localUnobservedProviderInventory() []LocalProviderInventoryRow {
	rows := make([]LocalProviderInventoryRow, 0, 2)
	for _, family := range []string{"zcode", "grok"} {
		rows = append(rows, LocalProviderInventoryRow{
			Family: family, ReferencedByRoles: []string{}, State: "not_observed", Reason: "config_not_ready",
			BinaryAvailable:       LocalDiagnosticCheck{Status: "not_applicable", ReasonCodes: []string{}},
			CLICompatible:         LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"},
			ApplicationCompatible: LocalCLICompatibility{Status: "not_applicable", Eligibility: "not_evaluated", Compatibility: "not_observed"},
		})
	}
	return rows
}

func localConfiguredRoleReferences(config appconfig.Config) map[string][]string {
	references := map[string][]string{"zcode": {}, "grok": {}}
	roles := []struct {
		name string
		role appconfig.RoleConfig
	}{
		{"logic", config.Roles.Logic}, {"security", config.Roles.Security},
		{"maintainability", config.Roles.Maintainability}, {"product", config.Roles.Product},
		{"documentation", config.Roles.Documentation}, {"testing", config.Roles.Testing},
		{"artist", config.Roles.Artist},
	}
	for _, candidate := range roles {
		if candidate.role.Enabled {
			references[candidate.role.PrimaryProvider] = append(references[candidate.role.PrimaryProvider], candidate.name)
		}
	}
	return references
}

func localRoleRouteReadiness(rows []LocalProviderInventoryRow) LocalReadiness {
	for _, row := range rows {
		if len(row.ReferencedByRoles) > 0 && row.State != "eligible" {
			return LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{"provider_role_route_unavailable"}}
		}
	}
	return LocalReadiness{State: "ready", ExitCode: 0, ReasonCodes: []string{}}
}

func rejectDoctorConfig(base LocalDoctorResult, err error) LocalDoctorResult {
	if admission, ok := appconfig.AsAdmissionError(err); ok && (admission.Reason() == appconfig.ReasonCredentialKeyDetected || admission.Reason() == appconfig.ReasonCredentialValueDetected) {
		reason := string(admission.Reason())
		base.Config.Status, base.Config.Locality = "unsafe", "verified"
		base.Config.ReasonCodes = []string{reason}
		base.ConfigV3 = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{reason}}
		base.LocalConfiguration = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{reason}}
		base.ProviderIdentity = LocalDiagnosticCheck{Status: "unverifiable", ReasonCodes: []string{reason}}
		base.Readiness = LocalReadiness{State: "unsafe", ExitCode: 8, ReasonCodes: []string{reason}}
		base.Diagnostics = []LocalDiagnostic{{Code: reason, Category: "security", Message: "Project-local Mulgae configuration contains prohibited credential material.", Redacted: true}}
		return base
	}
	reason := "config_yaml_invalid"
	if admission, ok := appconfig.AsAdmissionError(err); ok {
		reason = string(admission.Reason())
	}
	base.Config.Status, base.Config.Locality = "invalid", "verified"
	base.Config.ReasonCodes = []string{reason}
	base.ConfigV3 = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{reason}}
	base.LocalConfiguration = LocalDiagnosticCheck{Status: "verified", ReasonCodes: []string{}}
	base.ProviderIdentity = LocalDiagnosticCheck{Status: "unverifiable", ReasonCodes: []string{reason}}
	if reason == string(appconfig.ReasonProviderIdentityInvalid) || reason == string(appconfig.ReasonRoleMappingInvalid) {
		base.ProviderIdentity = LocalDiagnosticCheck{Status: "failed", ReasonCodes: []string{reason}}
	}
	base.Readiness = LocalReadiness{State: "unverified", ExitCode: 4, ReasonCodes: []string{reason}}
	base.Diagnostics = []LocalDiagnostic{{Code: reason, Category: "configuration", Message: "Project-local Mulgae configuration is invalid.", Redacted: true}}
	return base
}

func configLocalityFailureCode(err error, fallback string) string {
	if reason, ok := ports.ConfigLocalityReasonFromError(err); ok {
		return string(reason)
	}
	return fallback
}

func localDoctorCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
