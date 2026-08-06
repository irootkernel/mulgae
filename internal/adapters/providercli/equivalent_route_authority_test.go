package providercli

import (
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestDeriveEquivalentRouteDirectExecutionAuthorityRejectsTransportMutation(t *testing.T) {
	sourceDefinition, sourceAuthority := currentProbeAuthorityForDefinition(t)
	destination := sourceDefinition
	destination.instance = "kimi-sibling"
	destination.profileID = "kimi-sibling-profile"
	destination.baseArgv = append([]string(nil), sourceDefinition.baseArgv...)

	derived, err := DeriveEquivalentRouteDirectExecutionAuthority(
		sourceAuthority, sourceDefinition, destination, "1.2.3", "generation", "generation-sibling",
		[]domain.Role{domain.RoleLogic}, []domain.Role{domain.RoleSecurity},
	)
	if err != nil {
		t.Fatalf("equivalent sibling derivation failed: %v", err)
	}
	if derived.AuthorityID() == sourceAuthority.AuthorityID() {
		t.Fatal("derived authority reused source authority id")
	}
	if !derived.Matches(destination, "1.2.3", "generation-sibling", []domain.Role{domain.RoleSecurity}) {
		t.Fatal("derived authority did not match destination security role")
	}
	if derived.Matches(destination, "1.2.3", "generation-sibling", []domain.Role{domain.RoleLogic}) {
		t.Fatal("derived security-route authority still matched source logic role")
	}

	mutatedTransport, err := NewRuntimeTransport(ports.ProviderPacketChannelStdin, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	bleed := destination
	bleed.transport = mutatedTransport
	if _, err := DeriveEquivalentRouteDirectExecutionAuthority(
		sourceAuthority, sourceDefinition, bleed, "1.2.3", "generation", "generation-sibling",
		[]domain.Role{domain.RoleLogic}, []domain.Role{domain.RoleSecurity},
	); err == nil {
		t.Fatal("transport-mutated sibling received derived authority")
	}
}

func TestDeriveEquivalentRouteRejectsAGYCrossInstance(t *testing.T) {
	source := testProfile(t, FamilyAgy, "agy-logic", "agy-lane", "1.1.4", "sha256:"+repeatHex('a'))
	source.launcher = source.Executable()
	source.launcherSHA256 = source.ExecutableSHA256()
	source.profileID = "agy-logic"
	source.profileGeneration = "generation"
	proof := currentProbeDirectExecutionTestProof()
	proof.Family = FamilyAgy
	proof.ProviderInstance = source.Instance()
	proof.ProviderVersion = source.Version()
	proof.ObservedVersion = "1.2.3"
	proof.Executable = source.Executable()
	proof.ExecutableSHA256 = source.ExecutableSHA256()
	proof.Launcher = source.Launcher()
	proof.LauncherSHA256 = source.LauncherSHA256()
	proof.ProfileID = source.ProfileID()
	proof.ProfileGeneration = source.ProfileGeneration()
	proof.NamespaceGeneration = "namespace"
	proof.AGYExecutionPolicy = "sha256:execution"
	proof.TransportChannel = string(ports.ProviderPacketChannelPromptFile)
	proof.TransportPacketSHA256 = "sha256:packet"
	proof.TransportPacketLength = 1
	proof.TransportPreStartSHA256 = "sha256:pre"
	proof.TransportPreStartLength = 1
	proof.TransportPostEndSHA256 = "sha256:post"
	proof.TransportPostEndLength = 1
	proof.TransportReference = proof.NativeReference
	proof.TransportSnapshotCWD = proof.SnapshotPath
	proof.LifecycleFrameSHA256 = "sha256:frame"
	proof.LifecycleFrameLength = 1
	proof.LifecycleFraming = string(ports.ProcessOutputFramingTerminalJSONObject)
	proof.LifecycleProcessGroupAbsent = true
	proof.NamespaceEnvironmentSHA256 = "sha256:namespace-environment"
	proof.NativeHomePath = "/private/home"
	proof.NativeHomeDevice = 1
	proof.NativeHomeInode = 1
	proof.NativeHomeEffectiveUID = 1
	receipt, err := newCurrentProbeDirectExecutionAuthorityReceiptForDefinition(
		[]currentProbeDirectExecutionRoleProof{proof}, time.Unix(1_000, 0).UTC(), source,
	)
	if err != nil {
		t.Fatal(err)
	}
	destination := source
	destination.instance = "agy-security"
	destination.profileID = "agy-security"
	if _, err := DeriveEquivalentRouteDirectExecutionAuthority(
		receipt, source, destination, "1.2.3", "namespace", "namespace-sibling",
		[]domain.Role{domain.RoleLogic}, []domain.Role{domain.RoleSecurity},
	); err == nil {
		t.Fatal("AGY cross-instance derivation was permitted")
	}
}

func TestEquivalentFamilyRuntimeProfilesRequiresTransportIndex(t *testing.T) {
	left := testProfile(t, FamilyKimi, "kimi-left", "lane", "", "")
	right := left
	right.instance = "kimi-right"
	if !equivalentFamilyRuntimeProfiles(left, right) {
		t.Fatal("instance-only difference should remain shareable")
	}
	right.transport.argvIndex++
	if equivalentFamilyRuntimeProfiles(left, right) {
		t.Fatal("transport argv index mutation remained shareable")
	}
}

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

func TestDeriveEquivalentRouteAcceptsPointerAndValueAuthority(t *testing.T) {
	sourceDefinition, sourceAuthority := currentProbeAuthorityForDefinition(t)
	destination := sourceDefinition
	destination.instance = "kimi-sibling"
	destination.profileID = "kimi-sibling-profile"
	destination.baseArgv = append([]string(nil), sourceDefinition.baseArgv...)

	for name, source := range map[string]ports.ProviderDirectExecutionAuthority{
		"value":   sourceAuthority,
		"pointer": &sourceAuthority,
	} {
		t.Run(name, func(t *testing.T) {
			derived, err := DeriveEquivalentRouteDirectExecutionAuthority(
				source, sourceDefinition, destination, "1.2.3", "generation", "generation-sibling",
				[]domain.Role{domain.RoleLogic}, []domain.Role{domain.RoleSecurity},
			)
			if err != nil {
				t.Fatalf("derivation from %s authority failed: %v", name, err)
			}
			if !derived.Matches(destination, "1.2.3", "generation-sibling", []domain.Role{domain.RoleSecurity}) {
				t.Fatalf("derived authority from %s source did not match destination", name)
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
