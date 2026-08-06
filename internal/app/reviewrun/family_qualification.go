package reviewrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type familyRuntimeProfileKey string

type familyQualificationGroup struct {
	key            familyRuntimeProfileKey
	family         Family
	candidates     []QualifiedRunCandidate
	roles          []domain.Role
	baseRole       domain.Role
	representative int
}

// familyRuntimeProfileKeyFor binds every capability-relevant runtime field that
// must match before same-command family qualification may be shared. Instance,
// timeout, concurrency key, profile id, and configured version are excluded so
// sibling role routes can share one probe; transport, argv, environment,
// working directory, output bounds, lifecycle, model, digests, and safety
// identity remain part of the share key.
func familyRuntimeProfileKeyFor(definition ports.ProviderRuntimeDefinition) familyRuntimeProfileKey {
	environment := definition.Environment()
	environmentValues := make([]string, len(environment))
	for index, variable := range environment {
		environmentValues[index] = variable.Name() + "=" + variable.Value()
	}
	sort.Strings(environmentValues)
	lifecycle, hasLifecycle := definition.PostOutputLifecycle()
	lifecycleFraming := ""
	var lifecycleStability, lifecycleTermination int64
	if hasLifecycle {
		lifecycleFraming = string(lifecycle.Framing())
		lifecycleStability = lifecycle.StabilityGrace().Nanoseconds()
		lifecycleTermination = lifecycle.TerminationGrace().Nanoseconds()
	}
	parts := []string{
		definition.Family(),
		definition.Executable(),
		definition.ExecutableSHA256(),
		definition.Launcher(),
		definition.LauncherSHA256(),
		definition.ProfileGeneration(),
		definition.RuntimeSafetyPolicyIdentity(),
		definition.KimiModel(),
		strings.Join(definition.BaseArgv(), "\x1e"),
		string(definition.TransportChannel()),
		definition.TransportReference(),
		strconv.Itoa(definition.TransportArgvIndex()),
		strings.Join(environmentValues, "\x1e"),
		definition.WorkingDirectory(),
		strconv.FormatInt(definition.MaxStdoutBytes(), 10),
		strconv.FormatInt(definition.MaxStderrBytes(), 10),
		strconv.FormatBool(hasLifecycle),
		lifecycleFraming,
		strconv.FormatInt(lifecycleStability, 10),
		strconv.FormatInt(lifecycleTermination, 10),
	}
	// AGY native-home/control evidence is instance-bound, so AGY instances never
	// share one family probe across provider instances.
	if definition.Family() == string(FamilyAGY) {
		parts = append(parts, definition.Instance())
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return familyRuntimeProfileKey("sha256:" + hex.EncodeToString(sum[:]))
}

func groupCandidatesByFamilyRuntimeProfile(candidates []QualifiedRunCandidate) ([]familyQualificationGroup, error) {
	groups := make([]familyQualificationGroup, 0, len(candidates))
	indexByKey := make(map[familyRuntimeProfileKey]int, len(candidates))
	for _, candidate := range candidates {
		definition := candidate.Definition
		key := familyRuntimeProfileKeyFor(definition)
		index, ok := indexByKey[key]
		if !ok {
			index = len(groups)
			indexByKey[key] = index
			groups = append(groups, familyQualificationGroup{
				key: key, family: Family(definition.Family()), representative: -1,
			})
		}
		group := &groups[index]
		group.candidates = append(group.candidates, candidate)
		group.roles = append(group.roles, candidate.SupportedRoles...)
	}
	for index := range groups {
		roles, err := canonicalQualificationRoles(qualificationBaseRole(groups[index].roles), uniqueRoles(groups[index].roles))
		if err != nil {
			return nil, fmt.Errorf("review run: invalid family qualification roles: %w", err)
		}
		groups[index].roles = roles
		groups[index].baseRole = qualificationBaseRole(roles)
		groups[index].representative = selectFamilyRepresentative(groups[index])
		if groups[index].representative < 0 {
			return nil, fmt.Errorf("review run: family qualification group missing representative")
		}
	}
	sort.SliceStable(groups, func(left, right int) bool {
		if groups[left].family != groups[right].family {
			return groups[left].family < groups[right].family
		}
		return groups[left].key < groups[right].key
	})
	return groups, nil
}

func uniqueRoles(roles []domain.Role) []domain.Role {
	seen := make(map[domain.Role]struct{}, len(roles))
	out := make([]domain.Role, 0, len(roles))
	for _, role := range roles {
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}
		out = append(out, role)
	}
	return out
}

func selectFamilyRepresentative(group familyQualificationGroup) int {
	for index, candidate := range group.candidates {
		if candidate.BaseRole == group.baseRole {
			for _, role := range candidate.SupportedRoles {
				if role == group.baseRole {
					return index
				}
			}
		}
	}
	if len(group.candidates) == 0 {
		return -1
	}
	return 0
}

func remapCurrentQualificationResult(result CurrentQualificationResult, identity Identity, roles []domain.Role, baseRole domain.Role) (CurrentQualificationResult, error) {
	if result.familyAuthority != nil {
		if result.familyDefinition == nil || identity.Instance != result.familyDefinition.Instance() ||
			identity.NamespaceGeneration != result.familyNamespaceGeneration {
			return CurrentQualificationResult{}, fmt.Errorf("authority remapping across runtimes is not permitted")
		}
	}
	for _, receipt := range result.Receipts {
		if receipt.authority != nil && (receipt.Identity.Instance != identity.Instance ||
			receipt.Identity.NamespaceGeneration != identity.NamespaceGeneration) {
			return CurrentQualificationResult{}, fmt.Errorf("authority remapping across runtimes is not permitted")
		}
	}
	remapped, err := remapCurrentQualificationResultWithoutAuthority(result, identity, roles, baseRole)
	if err != nil {
		return CurrentQualificationResult{}, err
	}
	remapped.familyAuthority = result.familyAuthority
	remapped.familyDefinition = result.familyDefinition
	remapped.familyNamespaceGeneration = result.familyNamespaceGeneration
	remapped.familyProvedRoles = append([]domain.Role(nil), result.familyProvedRoles...)
	return remapped, nil
}

// remapCurrentQualificationResultWithoutAuthority rewrites readiness receipt
// identities and supported roles. Authority-bearing receipts are kept only when
// already bound to the destination instance/namespace; otherwise they are
// omitted so an adapter-owned derivation can mint destination authority.
func remapCurrentQualificationResultWithoutAuthority(
	result CurrentQualificationResult,
	identity Identity,
	roles []domain.Role,
	baseRole domain.Role,
) (CurrentQualificationResult, error) {
	if !baseRole.Valid() || len(roles) == 0 {
		return CurrentQualificationResult{}, fmt.Errorf("invalid remapped qualification roles")
	}
	canonical, err := canonicalQualificationRoles(baseRole, roles)
	if err != nil {
		return CurrentQualificationResult{}, err
	}
	observed := identity
	observed.Version = result.Version
	receipts := make([]Receipt, 0, len(result.Receipts))
	for _, receipt := range result.Receipts {
		if receipt.authority != nil {
			if receipt.Identity.Instance != observed.Instance ||
				receipt.Identity.NamespaceGeneration != observed.NamespaceGeneration ||
				receipt.authority.identity.Instance != observed.Instance ||
				receipt.authority.identity.NamespaceGeneration != observed.NamespaceGeneration {
				continue
			}
			proof := *receipt.authority
			proof.identity = observed
			remapped := receipt
			remapped.Identity = observed
			remapped.authority = &proof
			receipts = append(receipts, remapped)
			continue
		}
		remapped := receipt
		remapped.Identity = observed
		receipts = append(receipts, remapped)
	}
	roleReceipts := make([]CurrentRoleReceipt, 0, len(canonical))
	for _, role := range canonical {
		roleReceipts = append(roleReceipts, CurrentRoleReceipt{Role: role, State: ReceiptPass, Identity: observed})
	}
	return CurrentQualificationResult{
		VersionArgv: append([]string(nil), result.VersionArgv...), Version: result.Version,
		KnownIncompatible: result.KnownIncompatible, Receipts: receipts,
		SupportedRoles: append([]domain.Role(nil), canonical...), RoleReceipts: roleReceipts,
		BaseRole: baseRole, Observations: append([]ProviderQualificationObservation(nil), result.Observations...),
	}, nil
}

type familyGroupAdmission struct {
	routes        []QualifiedRoute
	evidence      []qualifiedProviderEvidence
	failures      []ProviderQualificationFailure
	observations  []ProviderQualificationObservation
	admitted      map[string]QualifiedRunRegistry
	generations   map[string]string
	instances     []string
	closedReceipt map[string]ports.ProviderRunTerminalReceipt
}

func mergeFamilyGroupAdmissions(parts []familyGroupAdmission) familyGroupAdmission {
	merged := familyGroupAdmission{
		admitted:      make(map[string]QualifiedRunRegistry),
		generations:   make(map[string]string),
		closedReceipt: make(map[string]ports.ProviderRunTerminalReceipt),
	}
	for _, part := range parts {
		merged.routes = append(merged.routes, part.routes...)
		merged.evidence = append(merged.evidence, part.evidence...)
		merged.failures = append(merged.failures, part.failures...)
		merged.observations = append(merged.observations, part.observations...)
		merged.instances = append(merged.instances, part.instances...)
		for instance, registry := range part.admitted {
			merged.admitted[instance] = registry
		}
		for instance, generation := range part.generations {
			merged.generations[instance] = generation
		}
		for instance, receipt := range part.closedReceipt {
			merged.closedReceipt[instance] = receipt
		}
	}
	return merged
}

func scheduleFamilyQualificationGroups(groups []familyQualificationGroup) [][]familyQualificationGroup {
	if len(groups) == 0 {
		return nil
	}
	zcode := make([]familyQualificationGroup, 0, len(groups))
	agy := make([]familyQualificationGroup, 0, len(groups))
	remainder := make([]familyQualificationGroup, 0, len(groups))
	for _, group := range groups {
		switch group.family {
		case FamilyZCode:
			zcode = append(zcode, group)
		case FamilyAGY:
			agy = append(agy, group)
		default:
			remainder = append(remainder, group)
		}
	}
	batches := make([][]familyQualificationGroup, 0, len(groups))
	pairCount := len(zcode)
	if len(agy) < pairCount {
		pairCount = len(agy)
	}
	for index := 0; index < pairCount; index++ {
		batches = append(batches, []familyQualificationGroup{zcode[index], agy[index]})
	}
	for index := pairCount; index < len(zcode); index++ {
		batches = append(batches, []familyQualificationGroup{zcode[index]})
	}
	for index := pairCount; index < len(agy); index++ {
		batches = append(batches, []familyQualificationGroup{agy[index]})
	}
	for _, group := range remainder {
		batches = append(batches, []familyQualificationGroup{group})
	}
	return batches
}

func runFamilyQualificationBatches(
	ctx context.Context,
	batches [][]familyQualificationGroup,
	admit func(context.Context, familyQualificationGroup) (familyGroupAdmission, error),
) (familyGroupAdmission, error) {
	merged := familyGroupAdmission{
		admitted:      make(map[string]QualifiedRunRegistry),
		generations:   make(map[string]string),
		closedReceipt: make(map[string]ports.ProviderRunTerminalReceipt),
	}
	for _, batch := range batches {
		if len(batch) == 1 {
			part, err := admit(ctx, batch[0])
			if err != nil {
				return mergeFamilyGroupAdmissions([]familyGroupAdmission{merged, part}), err
			}
			merged = mergeFamilyGroupAdmissions([]familyGroupAdmission{merged, part})
			continue
		}
		parts := make([]familyGroupAdmission, len(batch))
		errs := make([]error, len(batch))
		var wait sync.WaitGroup
		for index, group := range batch {
			wait.Add(1)
			go func(index int, group familyQualificationGroup) {
				defer wait.Done()
				part, err := admit(ctx, group)
				parts[index] = part
				errs[index] = err
			}(index, group)
		}
		wait.Wait()
		for index := range batch {
			merged = mergeFamilyGroupAdmissions([]familyGroupAdmission{merged, parts[index]})
			if errs[index] != nil {
				return merged, errs[index]
			}
		}
	}
	return merged, nil
}
