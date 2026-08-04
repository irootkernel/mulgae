// Package init implements create-once project-local configuration discovery and
// crash-truthful installation.
package init

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type SelectionMode string

const (
	SelectionAuto     SelectionMode = "auto"
	SelectionSelected SelectionMode = "selected"
)

var familyOrder = []string{"kimi", "zcode", "agy"}

type Selection struct {
	Mode        SelectionMode
	ProviderIDs []string
}
type Overrides struct {
	KimiExecutable      string
	KimiModel           string
	KimiDataHome        string
	ZCodeNodeExecutable string
	ZCodeLauncher       string
	AGYExecutable       string
	AGYPermissionMode   string
}
type InitializeProjectRequest struct {
	ProjectRoot           ports.AnchoredRoot
	ProjectName           string
	ContextPath           string
	ProjectKind           string
	ArtistBriefPath       string
	ArtistDesignSpecGlobs []string
	NativeHome            string
	// NativeHomeAsserted records whether --native-home was supplied and verified
	// equal to the installed account home by the command boundary.
	NativeHomeAsserted bool
	Selection          Selection
	RoleIDs            []string
	Overrides          Overrides
}

type DiscoveryRow struct {
	Family               string `json:"family"`
	Selected             bool   `json:"selected"`
	Candidate            bool   `json:"candidate"`
	Configured           bool   `json:"configured"`
	Status               string `json:"status"`
	Reason               string `json:"reason,omitempty"`
	ExecutableSource     string `json:"executable_source,omitempty"`
	ModelSource          string `json:"model_source,omitempty"`
	DataHomeSource       string `json:"data_home_source,omitempty"`
	NodeExecutableSource string `json:"node_executable_source,omitempty"`
	LauncherSource       string `json:"launcher_source,omitempty"`
	NativeHomeSource     string `json:"native_home_source,omitempty"`
	PermissionModeSource string `json:"permission_mode_source,omitempty"`
}
type InitializeProjectResult struct {
	Kind                  string                       `json:"kind"`
	ConfigURI             string                       `json:"config_uri"`
	ConfigSHA256          string                       `json:"config_sha256"`
	SelectedProviderIDs   []string                     `json:"selected_provider_ids"`
	CandidateProviderIDs  []string                     `json:"candidate_provider_ids"`
	ConfiguredProviderIDs []string                     `json:"configured_provider_ids"`
	ConfiguredRoleIDs     []string                     `json:"configured_role_ids"`
	WriteState            string                       `json:"write_state"`
	Committed             bool                         `json:"committed"`
	DestinationState      ports.ConfigDestinationState `json:"destination_state"`
	Discovery             []DiscoveryRow               `json:"discovery"`
}

type Failure struct {
	class     domain.FailureClass
	code      string
	message   string
	retryable bool
	cause     error
}

func (failure *Failure) Error() string {
	if failure == nil {
		return "initialization failed"
	}
	return failure.code
}
func (failure *Failure) Unwrap() error {
	if failure == nil {
		return nil
	}
	typed, err := domain.NewFailure("init", failure.class, failure.code, failure.cause)
	if err != nil {
		return failure.cause
	}
	return typed
}
func (failure *Failure) Class() domain.FailureClass {
	if failure == nil {
		return domain.FailureInternal
	}
	return failure.class
}
func (failure *Failure) Code() string {
	if failure == nil {
		return "internal_failure"
	}
	return failure.code
}
func (failure *Failure) Message() string {
	if failure == nil || failure.message == "" {
		return "The initialization could not be completed."
	}
	return failure.message
}
func (failure *Failure) Retryable() bool { return failure != nil && failure.retryable }

type Service struct {
	installer    ports.ConfigInstaller
	inspector    ports.EnvironmentInspector
	attestor     ports.ConfigLocalityAttestor
	prevalidator ResultPrevalidator
	clock        ports.Clock
	sources      ports.ConfigSourceFactory
	codec        appconfig.Codec
}

func NewService(installer ports.ConfigInstaller, inspector ports.EnvironmentInspector, attestor ports.ConfigLocalityAttestor, prevalidator ResultPrevalidator, clock ports.Clock, sources ports.ConfigSourceFactory, codec appconfig.Codec) (*Service, error) {
	if nilInterface(installer) || nilInterface(inspector) || nilInterface(attestor) || nilInterface(prevalidator) || nilInterface(clock) || nilInterface(sources) || nilInterface(codec) {
		return nil, fmt.Errorf("initialize project: missing dependency")
	}
	return &Service{installer: installer, inspector: inspector, attestor: attestor, prevalidator: prevalidator, clock: clock, sources: sources, codec: codec}, nil
}

func (service *Service) InitializeProject(ctx context.Context, request InitializeProjectRequest) (InitializeProjectResult, error) {
	result := baseResult(request)
	if ctx == nil || service == nil || !request.ProjectRoot.Valid() || request.ProjectName == "" || request.NativeHome == "" {
		return result, newFailure(domain.FailureConfiguration, "init_selection_invalid", false, nil)
	}
	selected, err := validateSelection(request.Selection, request.Overrides)
	if err != nil {
		return result, newFailure(domain.FailureConfiguration, "init_selection_invalid", false, err)
	}
	result.SelectedProviderIDs = selected
	roles, err := validateRoleSelection(request.RoleIDs)
	if err != nil {
		return result, newFailure(domain.FailureConfiguration, "init_selection_invalid", false, err)
	}
	result.ConfiguredRoleIDs = roles
	kind := request.ProjectKind
	if kind == "" {
		kind = appconfig.ProjectKindNonUI
	}
	if kind != appconfig.ProjectKindNonUI && kind != appconfig.ProjectKindUI || kind != appconfig.ProjectKindUI && contains(roles, "artist") {
		return result, newFailure(domain.FailureConfiguration, "init_selection_invalid", false, fmt.Errorf("project kind and artist selection disagree"))
	}
	source, err := service.sources.OpenConfigSource(request.ProjectRoot, true)
	if err != nil {
		return result, newFailure(domain.FailureSecurityPolicy, "config_locality_unsafe", false, err)
	}
	if source.Present() {
		result.WriteState = "existing_untouched"
		result.DestinationState = ports.ConfigDestinationPresent
		return result, newFailure(domain.FailureConfiguration, "init_destination_exists", false, nil)
	}
	proof, err := source.Proof()
	if err != nil {
		return result, newFailure(domain.FailureSecurityPolicy, "config_locality_unsafe", false, err)
	}
	localityRequest, _ := ports.NewConfigLocalityRequest(request.ProjectRoot, proof, nil, nil)
	initialContext, err := service.attestor.Attest(ctx, localityRequest)
	if err != nil {
		return result, newFailure(domain.FailureSecurityPolicy, localityFailureCode(err, "config_locality_unsafe"), false, err)
	}
	result.DestinationState = ports.ConfigDestinationAbsent
	candidates, discovery, err := service.discover(ctx, request)
	result.Discovery = discovery
	result.CandidateProviderIDs = candidateIDs(candidates)
	if err != nil {
		class := domain.FailureProviderUnavailable
		if errors.Is(err, errUnsafeDiscovery) {
			class = domain.FailureSecurityPolicy
		}
		return result, newFailure(class, discoveryReason(request.Selection, result.CandidateProviderIDs), true, err)
	}
	config := candidateConfig(request, candidates)
	canonical, err := RenderConfigYAML(service.codec, config)
	if err != nil {
		return result, newFailure(domain.FailureConfiguration, "config_yaml_invalid", false, err)
	}
	if err := service.revalidateLocality(ctx, source, localityRequest, initialContext); err != nil {
		return result, newFailure(domain.FailureSecurityPolicy, localityFailureCode(err, "config_locality_drifted"), false, err)
	}
	admitted, err := service.codec.Decode(canonical)
	if err != nil {
		code := "config_yaml_invalid"
		class := domain.FailureConfiguration
		if admission, ok := appconfig.AsAdmissionError(err); ok && (admission.Reason() == appconfig.ReasonCredentialKeyDetected || admission.Reason() == appconfig.ReasonCredentialValueDetected) {
			code = string(admission.Reason())
			class = domain.FailureSecurityPolicy
		}
		return result, newFailure(class, code, false, err)
	}
	roundTrip, err := service.codec.EncodeCanonical(admitted)
	if err != nil || !bytes.Equal(canonical, roundTrip) {
		return result, newFailure(domain.FailureInternal, "init_result_prevalidation_failed", false, err)
	}
	result.ConfigSHA256 = digest(canonical)
	result.ConfiguredProviderIDs = admitted.Providers.Families()
	markConfigured(result.Discovery, result.ConfiguredProviderIDs)
	if err := service.prevalidateMutationResults(ctx, result); err != nil {
		return baseResult(request), newFailure(domain.FailureInternal, "init_result_prevalidation_failed", false, err)
	}
	if err := service.revalidateLocality(ctx, source, localityRequest, initialContext); err != nil {
		return result, newFailure(domain.FailureSecurityPolicy, localityFailureCode(err, "config_locality_drifted"), false, err)
	}
	directory, err := service.installer.PrepareConfigDirectory(ctx, request.ProjectRoot)
	if err != nil {
		state, destination, code := prepareFailure(directory, err)
		return mutationFailure(result, state, destination, code, err)
	}
	preparedDirectory, ok := directory.Identity()
	if !ok {
		return directoryLocalityFailure(result, directory, ports.ConfigDestinationNotObserved, errors.New("prepared directory identity unavailable"))
	}
	preparedSource, err := service.sources.OpenConfigSource(request.ProjectRoot, true)
	if err != nil {
		return directoryLocalityFailure(result, directory, ports.ConfigDestinationNotObserved, err)
	}
	observedDirectory, err := preparedSource.DirectoryIdentity()
	if err != nil || !observedDirectory.Equal(preparedDirectory) {
		destination := ports.ConfigDestinationAbsent
		if preparedSource.Present() {
			destination = ports.ConfigDestinationPresent
		}
		return directoryLocalityFailure(result, directory, destination, errors.Join(err, errors.New("prepared directory identity changed")))
	}
	if preparedSource.Present() {
		return mutationFailure(result, "existing_untouched", ports.ConfigDestinationPresent, "init_destination_exists", nil)
	}
	preparedProof, err := preparedSource.Proof()
	if err != nil {
		return directoryLocalityFailure(result, directory, ports.ConfigDestinationAbsent, err)
	}
	preparedRequest, err := ports.NewConfigLocalityRequest(request.ProjectRoot, preparedProof, nil, nil)
	if err != nil {
		return directoryLocalityFailure(result, directory, ports.ConfigDestinationAbsent, err)
	}
	preparedContext, err := service.attestor.Attest(ctx, preparedRequest)
	if err != nil || !preparedContext.SameRepositoryEnvironment(initialContext) {
		return directoryLocalityFailure(result, directory, ports.ConfigDestinationAbsent, errors.Join(err, errors.New("prepared locality environment changed")))
	}
	if err := service.revalidateLocality(ctx, preparedSource, preparedRequest, preparedContext); err != nil {
		return directoryLocalityFailure(result, directory, ports.ConfigDestinationAbsent, err)
	}
	receipt, installErr := service.installer.InstallConfig(ctx, request.ProjectRoot, directory, canonical)
	if installErr != nil {
		result.DestinationState = destinationFromError(installErr)
		if installErrorStage(installErr) == ports.ConfigInstallStagePreparedIdentity {
			return directoryLocalityFailure(result, directory, result.DestinationState, installErr)
		}
		if receipt.Installed() {
			if result.DestinationState == ports.ConfigDestinationAbsent {
				result.DestinationState = ports.ConfigDestinationNotObserved
			}
			code := codeForInstallError(installErr)
			if code == "init_write_failed" {
				code = "init_commit_unconfirmed"
			}
			return mutationFailure(result, "installed_unconfirmed", result.DestinationState, code, installErr)
		}
		if result.DestinationState == ports.ConfigDestinationPresent {
			return mutationFailure(result, "existing_untouched", result.DestinationState, "init_destination_exists", installErr)
		}
		return mutationFailure(result, "not_committed", result.DestinationState, codeForInstallError(installErr), installErr)
	}
	finalSource, err := service.sources.OpenConfigSource(request.ProjectRoot, false)
	if err != nil {
		return mutationFailure(result, "installed_unconfirmed", ports.ConfigDestinationNotObserved, "config_locality_drifted", err)
	}
	finalBytes, finalObservation, err := finalSource.Read()
	if err != nil || !bytes.Equal(finalBytes, canonical) || !matchesInstallReceipt(finalObservation, receipt) {
		return mutationFailure(result, "installed_unconfirmed", ports.ConfigDestinationPresent, "config_locality_drifted", errors.Join(err, errors.New("installed config identity changed")))
	}
	finalProof, err := finalSource.Proof()
	if err != nil {
		return mutationFailure(result, "installed_unconfirmed", ports.ConfigDestinationPresent, "config_locality_drifted", err)
	}
	finalRequest, err := ports.NewConfigLocalityRequest(request.ProjectRoot, finalProof, nil, nil)
	if err != nil {
		return mutationFailure(result, "installed_unconfirmed", ports.ConfigDestinationPresent, "config_locality_drifted", err)
	}
	finalContext, err := service.attestor.Attest(ctx, finalRequest)
	if err != nil || !finalContext.SameRepositoryEnvironment(preparedContext) {
		cause := errors.Join(err, errors.New("final locality environment changed"))
		return mutationFailure(result, "installed_unconfirmed", ports.ConfigDestinationPresent, localityFailureCode(err, "config_locality_drifted"), cause)
	}
	if err := service.revalidateLocality(ctx, finalSource, finalRequest, finalContext); err != nil {
		return mutationFailure(result, "installed_unconfirmed", ports.ConfigDestinationPresent, localityFailureCode(err, "config_locality_drifted"), err)
	}
	result.Kind = "initialized"
	result.WriteState = "committed"
	result.Committed = true
	result.DestinationState = ports.ConfigDestinationPresent
	_ = service.clock.Now()
	return result, nil
}

func (service *Service) revalidateLocality(ctx context.Context, source ports.ConfigSource, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	if service == nil || source == nil {
		return fmt.Errorf("config locality: unavailable")
	}
	if err := source.Revalidate(); err != nil {
		return err
	}
	if err := service.attestor.Revalidate(ctx, request, expected); err != nil {
		return err
	}
	return source.Revalidate()
}

func (service *Service) prevalidateMutationResults(ctx context.Context, base InitializeProjectResult) error {
	for _, candidate := range MutationOutcomeSpecs() {
		result := cloneInitResult(base)
		result.Kind, result.WriteState, result.Committed, result.DestinationState = candidate.Kind, candidate.WriteState, candidate.Committed, candidate.Destination
		var failure *Failure
		if candidate.Code != "" {
			failure = &Failure{class: candidate.Class, code: candidate.Code, message: candidate.Message, retryable: candidate.Retryable}
		}
		outcome := PrevalidatedOutcome{Result: result, Failure: failure}
		if err := outcome.Validate(); err != nil {
			return err
		}
		if err := service.prevalidator.PrevalidateInitOutcome(ctx, outcome); err != nil {
			return err
		}
	}
	return nil
}

type MutationOutcomeSpec struct {
	Kind         string                       `json:"kind"`
	WriteState   string                       `json:"write_state"`
	Code         string                       `json:"code,omitempty"`
	Committed    bool                         `json:"committed"`
	Destination  ports.ConfigDestinationState `json:"destination_state"`
	Class        domain.FailureClass          `json:"class,omitempty"`
	Message      string                       `json:"message,omitempty"`
	Retryable    bool                         `json:"retryable"`
	DeliveryOnly bool                         `json:"delivery_only,omitempty"`
}

func MutationOutcomeSpecs() []MutationOutcomeSpec {
	result := []MutationOutcomeSpec{{Kind: "initialized", WriteState: "committed", Committed: true, Destination: ports.ConfigDestinationPresent}}
	add := func(writeState string, destinations []ports.ConfigDestinationState, class domain.FailureClass, code string, retryable bool) {
		for _, destination := range destinations {
			result = append(result, MutationOutcomeSpec{Kind: "initialization_failed", WriteState: writeState, Destination: destination, Class: class, Code: code, Message: initFailureMessage(code), Retryable: retryable})
		}
	}
	addLocality := func(writeState string, destinations []ports.ConfigDestinationState) {
		for _, code := range []string{"config_locality_drifted", string(ports.ConfigLocalityTargetPrivateConfigForbidden), string(ports.ConfigLocalityTargetPrivateNamespaceForbidden)} {
			add(writeState, destinations, domain.FailureSecurityPolicy, code, false)
		}
	}
	add("existing_untouched", []ports.ConfigDestinationState{ports.ConfigDestinationPresent}, domain.FailureConfiguration, "init_destination_exists", false)
	addLocality("existing_untouched", []ports.ConfigDestinationState{ports.ConfigDestinationPresent})
	add("not_committed", []ports.ConfigDestinationState{ports.ConfigDestinationAbsent, ports.ConfigDestinationNotObserved}, domain.FailureArtifact, "init_write_failed", true)
	add("not_committed", []ports.ConfigDestinationState{ports.ConfigDestinationNotObserved}, domain.FailureArtifact, "init_private_dir_raced", true)
	for _, state := range []string{"private_dir_created_unconfirmed", "private_dir_existing_unconfirmed"} {
		rootCode := "init_existing_private_dir_commit_unconfirmed"
		if state == "private_dir_created_unconfirmed" {
			rootCode = "init_private_dir_commit_unconfirmed"
		}
		rootDestinations := []ports.ConfigDestinationState{ports.ConfigDestinationAbsent, ports.ConfigDestinationPresent, ports.ConfigDestinationNotObserved}
		add(state, rootDestinations, domain.FailureArtifact, rootCode, true)
		addLocality(state, rootDestinations)
	}
	add("installed_unconfirmed", []ports.ConfigDestinationState{ports.ConfigDestinationPresent, ports.ConfigDestinationNotObserved}, domain.FailureArtifact, "init_commit_unconfirmed", true)
	addLocality("installed_unconfirmed", []ports.ConfigDestinationState{ports.ConfigDestinationPresent, ports.ConfigDestinationNotObserved})
	result = append(result, MutationOutcomeSpec{Kind: "initialized", WriteState: "committed", Committed: true, Destination: ports.ConfigDestinationPresent, Class: domain.FailureArtifact, Code: "init_result_delivery_failed", Message: initFailureMessage("init_result_delivery_failed"), Retryable: true, DeliveryOnly: true})
	return result
}

func mutationFailure(result InitializeProjectResult, writeState string, destination ports.ConfigDestinationState, code string, cause error) (InitializeProjectResult, error) {
	result.WriteState = writeState
	result.DestinationState = destination
	for _, candidate := range MutationOutcomeSpecs() {
		if candidate.Committed || candidate.DeliveryOnly || candidate.WriteState != writeState || candidate.Destination != destination || candidate.Code != code {
			continue
		}
		return result, newFailure(candidate.Class, candidate.Code, candidate.Retryable, cause)
	}
	return result, newFailure(domain.FailureInternal, "init_result_prevalidation_failed", false, errors.Join(cause, fmt.Errorf("unlisted post-mutation outcome %s/%s/%s", writeState, destination, code)))
}

var errUnsafeDiscovery = errors.New("unsafe provider discovery")

type candidates struct {
	kimi  *appconfig.KimiProviderConfig
	zcode *appconfig.ZCodeProviderConfig
	agy   *appconfig.AGYProviderConfig
}

func (service *Service) discover(ctx context.Context, request InitializeProjectRequest) (candidates, []DiscoveryRow, error) {
	wanted := map[string]bool{"zcode": request.Selection.Mode == SelectionAuto, "agy": request.Selection.Mode == SelectionAuto}
	for _, id := range request.Selection.ProviderIDs {
		wanted[id] = true
	}
	rows := make([]DiscoveryRow, 0, 3)
	var found candidates
	var discoveryErrors []error
	var securityErrors []error
	for _, family := range familyOrder {
		row := notSelectedDiscoveryRow(family)
		row.Selected = wanted[family]
		if !wanted[family] {
			rows = append(rows, row)
			continue
		}
		row.Status = "unavailable"
		switch family {
		case "kimi":
			executable := ""
			row.ExecutableSource = "not_discovered"
			profile, profileErr := reviewrun.DiscoverProviderProfileWithOverrides(ctx, service.inspector, reviewrun.FamilyKimi, request.Overrides.KimiExecutable, "")
			if request.Overrides.KimiExecutable != "" {
				row.ExecutableSource = "override"
			}
			if profileErr != nil {
				discoveryErrors = append(discoveryErrors, profileErr)
			} else if profile.Executable() != "" {
				executable = profile.Executable()
				if request.Overrides.KimiExecutable == "" {
					row.ExecutableSource = "startup_path"
				}
			}
			model := request.Overrides.KimiModel
			row.ModelSource = "override"
			if model == "" {
				model = appconfig.DefaultKimiModel
				row.ModelSource = "default_k3"
			}
			dataHome := request.Overrides.KimiDataHome
			row.DataHomeSource = "override"
			familyUnsafe := false
			if dataHome == "" {
				dataHome = appconfig.DefaultKimiDataHome(request.NativeHome)
				row.DataHomeSource = "native_home_default"
				if source, ok := service.inspector.(interface{ KimiCodeHome() (string, error) }); ok {
					startupHome, sourceErr := source.KimiCodeHome()
					if sourceErr != nil {
						securityErrors = append(securityErrors, sourceErr)
						row.DataHomeSource = "startup_environment"
						familyUnsafe = true
					}
					if startupHome != "" {
						dataHome = startupHome
						row.DataHomeSource = "startup_environment"
					}
				}
			}
			if !familyUnsafe && executable != "" {
				found.kimi = &appconfig.KimiProviderConfig{Executable: executable, Model: model, DataHome: dataHome, Timeout: appconfig.ProviderTimeoutText(appconfig.DefaultProviderTimeout)}
				row.Candidate = true
				row.Status = "candidate"
			}
		case "zcode":
			node, launcher := "", ""
			profile, profileErr := reviewrun.DiscoverProviderProfileWithOverrides(ctx, service.inspector, reviewrun.FamilyZCode, request.Overrides.ZCodeNodeExecutable, request.Overrides.ZCodeLauncher)
			if profileErr != nil {
				discoveryErrors = append(discoveryErrors, profileErr)
			} else {
				node, launcher = profile.Executable(), profile.Launcher()
			}
			row.NodeExecutableSource = "not_discovered"
			if request.Overrides.ZCodeNodeExecutable != "" {
				row.NodeExecutableSource = "override"
			} else if node != "" {
				row.NodeExecutableSource = "startup_path"
			}
			row.LauncherSource = "not_discovered"
			if request.Overrides.ZCodeLauncher != "" {
				row.LauncherSource = "override"
			} else if launcher != "" {
				row.LauncherSource = "bundled"
			}
			if node != "" && launcher != "" {
				found.zcode = &appconfig.ZCodeProviderConfig{NodeExecutable: node, Launcher: launcher, Timeout: appconfig.ProviderTimeoutText(appconfig.DefaultProviderTimeout)}
				row.Candidate = true
				row.Status = "candidate"
			}
		case "agy":
			executable := ""
			row.ExecutableSource = "not_discovered"
			profile, profileErr := reviewrun.DiscoverProviderProfileWithOverrides(ctx, service.inspector, reviewrun.FamilyAGY, request.Overrides.AGYExecutable, "")
			if request.Overrides.AGYExecutable != "" {
				row.ExecutableSource = "override"
			}
			if profileErr != nil {
				discoveryErrors = append(discoveryErrors, profileErr)
			} else if profile.Executable() != "" {
				executable = profile.Executable()
				if request.Overrides.AGYExecutable == "" {
					row.ExecutableSource = "startup_path"
				}
			}
			row.NativeHomeSource = "os_account"
			if request.NativeHomeAsserted {
				row.NativeHomeSource = "verified_equal_input"
			}
			mode := request.Overrides.AGYPermissionMode
			modeExplicit := mode != ""
			row.PermissionModeSource = "explicit"
			if mode == "" {
				mode = appconfig.DefaultAGYPermissionMode
				row.PermissionModeSource = "headless_default"
			}
			if executable != "" {
				found.agy = &appconfig.AGYProviderConfig{Executable: executable, PermissionMode: mode, PermissionModeExplicit: modeExplicit, Timeout: appconfig.ProviderTimeoutText(appconfig.DefaultProviderTimeout)}
				row.Candidate = true
				row.Status = "candidate"
			}
		}
		rows = append(rows, row)
	}
	ids := candidateIDs(found)
	if len(securityErrors) != 0 {
		return found, rows, errors.Join(append([]error{errUnsafeDiscovery}, securityErrors...)...)
	}
	if request.Selection.Mode == SelectionAuto && (!contains(ids, "zcode") || !contains(ids, "agy")) {
		return found, rows, errors.Join(append([]error{errors.New("auto selection requires both zcode and agy")}, discoveryErrors...)...)
	}
	if request.Selection.Mode == SelectionSelected {
		for _, id := range request.Selection.ProviderIDs {
			if !contains(ids, id) {
				return found, rows, errors.Join(append([]error{errors.New("selected provider unavailable")}, discoveryErrors...)...)
			}
		}
	}
	return found, rows, nil
}

func notSelectedDiscoveryRow(family string) DiscoveryRow {
	row := DiscoveryRow{Family: family, Status: "not_selected"}
	switch family {
	case "kimi":
		row.ExecutableSource = "not_selected"
		row.ModelSource = "not_selected"
		row.DataHomeSource = "not_selected"
	case "zcode":
		row.NodeExecutableSource = "not_selected"
		row.LauncherSource = "not_selected"
	case "agy":
		row.ExecutableSource = "not_selected"
		row.NativeHomeSource = "not_selected"
		row.PermissionModeSource = "not_selected"
	}
	return row
}

func candidateConfig(request InitializeProjectRequest, value candidates) appconfig.Config {
	providers := appconfig.ProvidersConfig{Kimi: value.kimi, ZCode: value.zcode, AGY: value.agy}
	selectedRoles, _ := validateRoleSelection(request.RoleIDs)
	roles, err := appconfig.CanonicalRolesConfigForSelection(providers.Families(), selectedRoles)
	if err != nil {
		return appconfig.Config{}
	}
	kind := request.ProjectKind
	if kind == "" {
		kind = appconfig.ProjectKindNonUI
	}
	if kind == appconfig.ProjectKindUI && contains(selectedRoles, "artist") {
		briefPath := request.ArtistBriefPath
		if briefPath == "" {
			briefPath = appconfig.DefaultArtistBriefPath
		}
		globs := append([]string(nil), request.ArtistDesignSpecGlobs...)
		if len(globs) == 0 {
			globs = append([]string(nil), appconfig.DefaultArtistDesignSpecGlobs...)
		}
		roles.Artist.Inputs = &appconfig.ArtistInputsConfig{TaskPath: briefPath, DesignSpecGlobs: globs}
	}
	return appconfig.Config{Version: appconfig.ConfigVersion, Project: appconfig.ProjectConfig{Name: request.ProjectName, Context: request.ContextPath, Kind: kind}, NativeUser: appconfig.NativeUserConfig{Home: request.NativeHome}, Providers: providers, Execution: appconfig.ExecutionConfig{WorkspaceAccess: "none"}, Roles: roles, Review: appconfig.ReviewConfig{RequiredRoles: []string{"logic"}, RequestChangesOn: []string{"high", "critical", "blocker"}}, Validation: appconfig.ValidationConfig{Evidence: appconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: appconfig.RepairConfig{Enabled: true, MaxAttempts: 1, SameProvider: true}}, Resources: resourceDefaults(value, len(selectedRoles)), CI: appconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true}}
}
func resourceDefaults(value candidates, roleCount int) appconfig.ResourcesConfig {
	count := len(candidateIDs(value))
	role := 2
	if count >= 2 {
		role = 4
	}
	run := role * roleCount
	return appconfig.ResourcesConfig{MaxActiveLanes: roleCount, PrimaryRepairAttempts: 1, FallbackRepairAttempts: 1, RoleMaxInvocations: role, RunMaxInvocations: run, RunTotalOutputCap: "64MiB"}
}

func validateRoleSelection(roles []string) ([]string, error) {
	fixed := []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"}
	if roles == nil {
		return []string{"logic"}, nil
	}
	if len(roles) < 1 || len(roles) > len(fixed) {
		return nil, fmt.Errorf("roles")
	}
	last := -1
	seen := make(map[string]bool, len(roles))
	for _, role := range roles {
		ordinal := -1
		for index, candidate := range fixed {
			if role == candidate {
				ordinal = index
				break
			}
		}
		if ordinal <= last {
			return nil, fmt.Errorf("roles")
		}
		seen[role], last = true, ordinal
	}
	if !seen["logic"] {
		return nil, fmt.Errorf("role floor")
	}
	return append([]string(nil), roles...), nil
}
func candidateIDs(value candidates) []string {
	ids := make([]string, 0, 3)
	if value.kimi != nil {
		ids = append(ids, "kimi")
	}
	if value.zcode != nil {
		ids = append(ids, "zcode")
	}
	if value.agy != nil {
		ids = append(ids, "agy")
	}
	return ids
}
func validateSelection(selection Selection, overrides Overrides) ([]string, error) {
	if selection.Mode != "auto" && selection.Mode != "selected" {
		return nil, fmt.Errorf("mode")
	}
	if selection.Mode == SelectionAuto {
		if len(selection.ProviderIDs) != 0 || overrides.KimiExecutable != "" || overrides.KimiModel != "" || overrides.KimiDataHome != "" {
			return nil, fmt.Errorf("auto members")
		}
		return []string{}, nil
	}
	if len(selection.ProviderIDs) == 0 {
		return nil, fmt.Errorf("empty selection")
	}
	selected := make([]string, 0, len(selection.ProviderIDs))
	for _, family := range familyOrder {
		if contains(selection.ProviderIDs, family) {
			selected = append(selected, family)
		}
	}
	if len(selected) != len(selection.ProviderIDs) {
		return nil, fmt.Errorf("unknown or duplicate selection")
	}
	if !contains(selected, "kimi") && (overrides.KimiExecutable != "" || overrides.KimiModel != "" || overrides.KimiDataHome != "") {
		return nil, fmt.Errorf("kimi override")
	}
	if !contains(selected, "zcode") && (overrides.ZCodeNodeExecutable != "" || overrides.ZCodeLauncher != "") {
		return nil, fmt.Errorf("zcode override")
	}
	if !contains(selected, "agy") && (overrides.AGYExecutable != "" || overrides.AGYPermissionMode != "") {
		return nil, fmt.Errorf("agy override")
	}
	return selected, nil
}
func baseResult(request InitializeProjectRequest) InitializeProjectResult {
	roles, _ := validateRoleSelection(request.RoleIDs)
	return InitializeProjectResult{Kind: "initialization_failed", ConfigURI: appconfig.ConfigRelativePath, SelectedProviderIDs: []string{}, CandidateProviderIDs: []string{}, ConfiguredProviderIDs: []string{}, ConfiguredRoleIDs: roles, WriteState: "not_attempted", DestinationState: ports.ConfigDestinationNotObserved, Discovery: []DiscoveryRow{}}
}
func markConfigured(rows []DiscoveryRow, ids []string) {
	for index := range rows {
		rows[index].Configured = contains(ids, rows[index].Family)
	}
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func digest(data []byte) string      { sum := sha256Sum(data); return fmt.Sprintf("sha256:%x", sum) }
func sha256Sum(data []byte) [32]byte { return sha256.Sum256(data) }
func discoveryReason(selection Selection, ids []string) string {
	if selection.Mode == SelectionAuto && (!contains(ids, "zcode") || !contains(ids, "agy")) {
		return "init_auto_provider_topology_unavailable"
	}
	return "init_provider_unavailable"
}
func newFailure(class domain.FailureClass, code string, retryable bool, cause error) error {
	return &Failure{class: class, code: code, message: initFailureMessage(code), retryable: retryable, cause: cause}
}

func initFailureMessage(code string) string {
	switch code {
	case "init_selection_invalid":
		return "The init selection is invalid."
	case "init_destination_exists":
		return "The project-local Mulgae configuration already exists."
	case "init_discovery_empty":
		return "No supported provider was discovered."
	case "init_auto_provider_topology_unavailable":
		return "Automatic initialization requires both ZCode and AGY."
	case "init_provider_unavailable":
		return "A selected provider is unavailable."
	case "init_private_dir_raced":
		return "The private Mulgae directory changed during initialization."
	case "init_private_dir_commit_unconfirmed":
		return "The private Mulgae directory could not be durably confirmed."
	case "init_existing_private_dir_commit_unconfirmed":
		return "The existing private Mulgae directory could not be durably confirmed."
	case "init_write_failed":
		return "The project-local Mulgae configuration could not be written."
	case "init_commit_unconfirmed":
		return "The installed Mulgae configuration could not be durably confirmed."
	case "init_result_prevalidation_failed":
		return "The init command result could not be prevalidated."
	case "init_result_delivery_failed":
		return "The init result could not be delivered after commit."
	case "init_native_account_unavailable":
		return "The native user account is unavailable."
	case "init_native_account_mismatch":
		return "The native user account does not match the effective user."
	case "init_native_home_mismatch":
		return "The asserted native home does not match the installed user."
	case "config_yaml_invalid":
		return "The project-local Mulgae configuration is invalid."
	case "config_locality_unsafe", "config_locality_drifted", string(ports.ConfigLocalityTargetPrivateConfigForbidden), string(ports.ConfigLocalityTargetPrivateNamespaceForbidden):
		return "The project-local Mulgae configuration failed locality admission."
	default:
		return "The initialization could not be completed."
	}
}
func prepareFailure(receipt ports.ConfigDirectoryReceipt, err error) (string, ports.ConfigDestinationState, string) {
	var typed *ports.ConfigInstallError
	if !errors.As(err, &typed) {
		return "not_committed", ports.ConfigDestinationNotObserved, "init_write_failed"
	}
	switch typed.Stage() {
	case ports.ConfigInstallStagePrivateDirRace:
		return "not_committed", typed.DestinationState(), "init_private_dir_raced"
	case ports.ConfigInstallStageRootSync:
		if receipt.CreatedByInvocation() {
			return "private_dir_created_unconfirmed", typed.DestinationState(), "init_private_dir_commit_unconfirmed"
		}
		return "private_dir_existing_unconfirmed", typed.DestinationState(), "init_existing_private_dir_commit_unconfirmed"
	case ports.ConfigInstallStageRootReattestation:
		state := "private_dir_existing_unconfirmed"
		if receipt.CreatedByInvocation() {
			state = "private_dir_created_unconfirmed"
		}
		return state, typed.DestinationState(), "config_locality_drifted"
	default:
		if typed.DestinationState() == ports.ConfigDestinationPresent {
			return "existing_untouched", ports.ConfigDestinationPresent, "init_destination_exists"
		}
		return "not_committed", typed.DestinationState(), "init_write_failed"
	}
}
func destinationFromError(err error) ports.ConfigDestinationState {
	var typed *ports.ConfigInstallError
	if errors.As(err, &typed) {
		return typed.DestinationState()
	}
	return ports.ConfigDestinationNotObserved
}
func installErrorStage(err error) ports.ConfigInstallStage {
	var typed *ports.ConfigInstallError
	if errors.As(err, &typed) {
		return typed.Stage()
	}
	return ""
}
func codeForInstallError(err error) string {
	var typed *ports.ConfigInstallError
	if errors.As(err, &typed) {
		switch typed.Stage() {
		case ports.ConfigInstallStageCollision:
			if typed.DestinationState() == ports.ConfigDestinationPresent {
				return "init_destination_exists"
			}
			return "init_write_failed"
		case ports.ConfigInstallStageDirectorySync:
			return "init_commit_unconfirmed"
		case ports.ConfigInstallStageFinalReattestation:
			return "config_locality_drifted"
		case ports.ConfigInstallStagePreparedIdentity:
			return "config_locality_drifted"
		}
	}
	return "init_write_failed"
}
func directoryLocalityFailure(result InitializeProjectResult, receipt ports.ConfigDirectoryReceipt, destination ports.ConfigDestinationState, cause error) (InitializeProjectResult, error) {
	code := localityFailureCode(cause, "config_locality_drifted")
	if destination == ports.ConfigDestinationPresent {
		return mutationFailure(result, "existing_untouched", destination, code, cause)
	}
	writeState := "private_dir_existing_unconfirmed"
	if receipt.CreatedByInvocation() {
		writeState = "private_dir_created_unconfirmed"
	}
	return mutationFailure(result, writeState, destination, code, cause)
}

func localityFailureCode(err error, fallback string) string {
	if reason, ok := ports.ConfigLocalityReasonFromError(err); ok {
		return string(reason)
	}
	return fallback
}
func matchesInstallReceipt(observation ports.ConfigFileIdentity, receipt ports.ConfigInstallReceipt) bool {
	config, ok := receipt.ConfigIdentity()
	return receipt.Installed() && ok && observation.Valid() && observation.Equal(config)
}
func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	ref := reflect.ValueOf(value)
	switch ref.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return ref.IsNil()
	}
	return false
}
