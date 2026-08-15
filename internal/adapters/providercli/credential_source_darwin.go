//go:build darwin

package providercli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

// CredentialSourceFamily is the closed set of provider credential layouts.
type CredentialSourceFamily string

const (
	CredentialSourceKimi  CredentialSourceFamily = "kimi"
	CredentialSourceZCode CredentialSourceFamily = "zcode"
	CredentialSourceAGY   CredentialSourceFamily = "agy"
	CredentialSourceCodex CredentialSourceFamily = "codex"
)

type credentialProjectingNamespaceFactory struct {
	base             ports.ProviderNamespaceFactory
	runtimeHome      string
	homeIdentity     fileIdentity
	runtimeHomeInfo  os.FileInfo
	nativeHomes      map[string]nativeHomeAuthority
	instanceFamilies map[string]CredentialSourceFamily
	instancePolicies map[string]RuntimeSafetyPolicy
	configuredRoots  map[string]projectionRootAuthority
}

type projectionRootAuthority struct {
	path     string
	identity fileIdentity
	info     os.FileInfo
	uid      uint32
}

type nativeHomeAuthority struct {
	home            string
	identity        fileIdentity
	info            os.FileInfo
	uid             uint32
	launchAuthority ports.NativeHomeLaunchAuthority
}

type fileIdentity struct {
	device uint64
	inode  uint64
}

type credentialSource struct {
	destination ports.CredentialProjectionDestination
	components  []string
}
type credentialSourceAuthority struct {
	runtimeHome  string
	homeIdentity fileIdentity
	components   []string
	directoryIDs []fileIdentity
	sourceID     fileIdentity
}

var credentialSources = map[CredentialSourceFamily][]credentialSource{
	CredentialSourceKimi: {
		{ports.CredentialProjectionKimiConfig, []string{".kimi-code", "config.toml"}},
		{ports.CredentialProjectionKimiCredentials, []string{".kimi-code", "credentials", "kimi-code.json"}},
	},
	CredentialSourceZCode: {
		{ports.CredentialProjectionZCodeConfig, []string{".zcode", "cli", "config.json"}},
	},
	CredentialSourceAGY: {},
	CredentialSourceCodex: {
		{ports.CredentialProjectionCodexAuth, []string{".codex", "auth.json"}},
	},
}

var _ ports.ProviderNamespaceFactory = (*credentialProjectingNamespaceFactory)(nil)

// NewCredentialProjectingNamespaceFactory wraps base so every returned lease is
// seeded only from the declared, descriptor-anchored runtime home.
//
// This retained constructor supplies canonical defaults for projected-home
// families; AGY requires an explicit native-home binding.
func NewCredentialProjectingNamespaceFactory(base ports.ProviderNamespaceFactory, runtimeHome string, instanceFamilies map[string]CredentialSourceFamily) (ports.ProviderNamespaceFactory, error) {
	policies := make(map[string]RuntimeSafetyPolicy, len(instanceFamilies))
	for instance, family := range instanceFamilies {
		policy, err := RuntimeSafetyPolicyForFamily(family)
		if err != nil {
			return nil, err
		}
		policies[instance] = policy
	}
	return newCredentialProjectingNamespaceFactory(base, runtimeHome, instanceFamilies, policies, nil, nil)
}

// NewCredentialProjectingNamespaceFactoryWithPolicies wraps base with exact,
// immutable per-instance runtime safety policies for projected-home families. AGY
// requires NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes.
func NewCredentialProjectingNamespaceFactoryWithPolicies(base ports.ProviderNamespaceFactory, runtimeHome string, instanceFamilies map[string]CredentialSourceFamily, instancePolicies map[string]RuntimeSafetyPolicy) (ports.ProviderNamespaceFactory, error) {
	return newCredentialProjectingNamespaceFactory(base, runtimeHome, instanceFamilies, instancePolicies, nil, nil)
}

// NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes wraps base
// with immutable policies and exact per-AGY installed-user HOME bindings.
// nativeHomes must contain every and only AGY instance.
func NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes(base ports.ProviderNamespaceFactory, runtimeHome string, instanceFamilies map[string]CredentialSourceFamily, instancePolicies map[string]RuntimeSafetyPolicy, nativeHomes map[string]string) (ports.ProviderNamespaceFactory, error) {
	return newCredentialProjectingNamespaceFactory(base, runtimeHome, instanceFamilies, instancePolicies, nativeHomes, nil)
}

// NewCredentialProjectingNamespaceFactoryWithConfiguredSourceRoots binds
// provider-native read-only projection roots admitted from local
// configuration. Kimi entries name the exact data_home, Codex entries name the
// exact CODEX_HOME, and AGY has no projected credential source.
func NewCredentialProjectingNamespaceFactoryWithConfiguredSourceRoots(base ports.ProviderNamespaceFactory, runtimeHome string, instanceFamilies map[string]CredentialSourceFamily, instancePolicies map[string]RuntimeSafetyPolicy, nativeHomes, sourceRoots map[string]string) (ports.ProviderNamespaceFactory, error) {
	return newCredentialProjectingNamespaceFactory(base, runtimeHome, instanceFamilies, instancePolicies, nativeHomes, sourceRoots)
}

func newCredentialProjectingNamespaceFactory(base ports.ProviderNamespaceFactory, runtimeHome string, instanceFamilies map[string]CredentialSourceFamily, instancePolicies map[string]RuntimeSafetyPolicy, nativeHomes, sourceRoots map[string]string) (ports.ProviderNamespaceFactory, error) {
	if nilNamespaceFactory(base) || !canonicalAbsolutePath(runtimeHome) || len(instanceFamilies) == 0 || len(instanceFamilies) != len(instancePolicies) {
		return nil, fmt.Errorf("credential source factory: invalid configuration")
	}
	home, err := openAbsoluteDirectory(runtimeHome)
	if err != nil {
		return nil, fmt.Errorf("credential source factory: unsafe runtime home")
	}
	identity, err := identityOf(home)
	homeInfo, infoErr := home.Stat()
	_ = home.Close()
	if err != nil || infoErr != nil || !homeInfo.IsDir() {
		return nil, fmt.Errorf("credential source factory: unsafe runtime home")
	}

	families := make(map[string]CredentialSourceFamily, len(instanceFamilies))
	policies := make(map[string]RuntimeSafetyPolicy, len(instancePolicies))
	nativeAuthorities := make(map[string]nativeHomeAuthority)
	configuredRoots := make(map[string]projectionRootAuthority)
	for instance, family := range instanceFamilies {
		policy, ok := instancePolicies[instance]
		if !validCredentialSourceInstance(instance) || !validCredentialSourceFamily(family) || !ok || policy.family != family || !validRuntimeSafetyPolicy(policy) {
			return nil, fmt.Errorf("credential source factory: invalid configuration")
		}
		if family == CredentialSourceAGY {
			nativeHome, mapped := nativeHomes[instance]
			if !mapped {
				return nil, fmt.Errorf("credential source factory: missing AGY native home")
			}
			authority, authorityErr := captureNativeHome(nativeHome)
			if authorityErr != nil {
				return nil, fmt.Errorf("credential source factory: unsafe AGY native home")
			}
			nativeAuthorities[instance] = authority
		}
		if rootPath, mapped := sourceRoots[instance]; mapped {
			if family != CredentialSourceKimi && family != CredentialSourceCodex || !canonicalAbsolutePath(rootPath) {
				return nil, fmt.Errorf("credential source factory: invalid configured source root")
			}
			root, openErr := openAbsoluteDirectory(rootPath)
			if openErr != nil {
				return nil, fmt.Errorf("credential source factory: unsafe configured source root")
			}
			rootIdentity, identityErr := identityOf(root)
			rootInfo, infoErr := root.Stat()
			var rootStat unix.Stat_t
			statErr := unix.Fstat(int(root.Fd()), &rootStat)
			_ = root.Close()
			if identityErr != nil || infoErr != nil || statErr != nil || !rootInfo.IsDir() || family == CredentialSourceCodex && rootStat.Uid != uint32(unix.Geteuid()) {
				return nil, fmt.Errorf("credential source factory: unsafe configured source root")
			}
			configuredRoots[instance] = projectionRootAuthority{path: rootPath, identity: rootIdentity, info: rootInfo, uid: rootStat.Uid}
		}
		families[instance] = family
		policies[instance] = cloneRuntimeSafetyPolicy(policy)
	}
	for instance := range nativeHomes {
		if families[instance] != CredentialSourceAGY {
			return nil, fmt.Errorf("credential source factory: invalid AGY native home mapping")
		}
	}
	return &credentialProjectingNamespaceFactory{
		base:             base,
		runtimeHome:      runtimeHome,
		homeIdentity:     identity,
		runtimeHomeInfo:  homeInfo,
		nativeHomes:      nativeAuthorities,
		instanceFamilies: families,
		instancePolicies: policies,
		configuredRoots:  configuredRoots,
	}, nil
}

func (factory *credentialProjectingNamespaceFactory) AcquireProviderNamespace(ctx context.Context, instance string) (lease ports.ProviderNamespaceLease, err error) {
	if factory == nil || ctx == nil || ctx.Err() != nil || !validCredentialSourceInstance(instance) {
		return nil, fmt.Errorf("credential source factory: invalid request")
	}
	family, ok := factory.instanceFamilies[instance]
	if !ok {
		return nil, fmt.Errorf("credential source factory: unknown provider instance")
	}
	if family == CredentialSourceAGY {
		if err := factory.revalidateNativeHome(instance); err != nil {
			return nil, err
		}
	} else if err := factory.revalidateHome(instance); err != nil {
		return nil, err
	}
	lease, err = factory.base.AcquireProviderNamespace(ctx, instance)
	if err != nil {
		return nil, err
	}
	if lease == nil || lease.ProviderInstance() != instance || lease.Generation() == "" {
		if lease != nil {
			_, _ = lease.DrainTerminal(context.Background())
		}
		return nil, fmt.Errorf("credential source factory: invalid base lease")
	}
	concrete, ok := lease.(*namespaceLease)
	if !ok {
		_, _ = lease.DrainTerminal(context.Background())
		return nil, fmt.Errorf("credential source factory: base lease is not a concrete namespace")
	}
	policy, ok := factory.instancePolicies[instance]
	if !ok {
		_, _ = lease.DrainTerminal(context.Background())
		return nil, fmt.Errorf("credential source factory: missing runtime safety policy")
	}
	policy = cloneRuntimeSafetyPolicy(policy)
	if family == CredentialSourceAGY {
		authority, ok := factory.nativeHomes[instance]
		if !ok {
			_, _ = lease.DrainTerminal(context.Background())
			return nil, fmt.Errorf("credential source factory: missing AGY native home")
		}
		if err := concrete.bindRuntimeHome(authority.home, authority.info, authority.launchAuthority); err != nil {
			_, _ = lease.DrainTerminal(context.Background())
			return nil, err
		}
	}
	if err := concrete.installRuntimeSafetyPolicy(policy); err != nil {
		_, _ = lease.DrainTerminal(context.Background())
		return nil, err
	}
	acquired := lease
	defer func() {
		if err != nil {
			_, _ = acquired.DrainTerminal(context.Background())
			lease = nil
		}
	}()

	for _, source := range credentialSources[family] {
		if err := factory.project(ctx, lease, instance, family, source); err != nil {
			return nil, fmt.Errorf("credential source factory: projection failed")
		}
	}
	return lease, nil
}

func (factory *credentialProjectingNamespaceFactory) revalidateHome(instance string) error {
	home, err := openAbsoluteDirectory(factory.runtimeHome)
	if err != nil {
		return fmt.Errorf("credential source factory: runtime home drift")
	}
	defer home.Close()
	identity, err := identityOf(home)
	if err != nil || identity != factory.homeIdentity {
		return fmt.Errorf("credential source factory: runtime home drift")
	}
	if configured, ok := factory.configuredRoots[instance]; ok {
		root, openErr := openAbsoluteDirectory(configured.path)
		if openErr != nil {
			return fmt.Errorf("credential source factory: configured source root drift")
		}
		defer root.Close()
		actual, identityErr := identityOf(root)
		info, infoErr := root.Stat()
		var stat unix.Stat_t
		statErr := unix.Fstat(int(root.Fd()), &stat)
		if identityErr != nil || infoErr != nil || statErr != nil || actual != configured.identity || !os.SameFile(info, configured.info) || stat.Uid != configured.uid {
			return fmt.Errorf("credential source factory: configured source root drift")
		}
	}
	return nil
}
func (factory *credentialProjectingNamespaceFactory) revalidateNativeHome(instance string) error {
	authority, ok := factory.nativeHomes[instance]
	if !ok {
		return fmt.Errorf("credential source factory: missing AGY native home")
	}
	current, err := captureNativeHome(authority.home)
	if err != nil || current.identity != authority.identity || current.uid != authority.uid || !os.SameFile(current.info, authority.info) {
		return fmt.Errorf("credential source factory: AGY native home drift")
	}
	return nil
}

func captureNativeHome(path string) (nativeHomeAuthority, error) {
	if !canonicalAbsolutePath(path) {
		return nativeHomeAuthority{}, fmt.Errorf("invalid native home")
	}
	home, err := openAbsoluteDirectory(path)
	if err != nil {
		return nativeHomeAuthority{}, err
	}
	defer home.Close()
	identity, err := identityOf(home)
	info, infoErr := home.Stat()
	var stat unix.Stat_t
	statErr := unix.Fstat(int(home.Fd()), &stat)
	if err != nil || infoErr != nil || statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != uint32(unix.Geteuid()) {
		return nativeHomeAuthority{}, fmt.Errorf("unsafe native home")
	}
	launchAuthority, authorityErr := ports.NewNativeHomeLaunchAuthority(path, identity.device, identity.inode, stat.Uid)
	if authorityErr != nil {
		return nativeHomeAuthority{}, fmt.Errorf("unsafe native home")
	}
	return nativeHomeAuthority{home: path, identity: identity, info: info, uid: stat.Uid, launchAuthority: launchAuthority}, nil
}

func (factory *credentialProjectingNamespaceFactory) project(ctx context.Context, lease ports.ProviderNamespaceLease, instance string, family CredentialSourceFamily, source credentialSource) error {
	rootPath, rootIdentity := factory.runtimeHome, factory.homeIdentity
	components := append([]string(nil), source.components...)
	if configured, ok := factory.configuredRoots[instance]; ok && (family == CredentialSourceKimi || family == CredentialSourceCodex) {
		rootPath, rootIdentity = configured.path, configured.identity
		components = components[1:]
	}
	file, sourcePath, err := factory.openSource(rootPath, rootIdentity, components)
	if err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxProjectedCredentialBytes || family == CredentialSourceCodex && info.Mode().Perm() != 0600 {
		return fmt.Errorf("unsafe credential source")
	}
	digest, err := digestCredentialSource(file, info.Size())
	if err != nil {
		return fmt.Errorf("unsafe credential source")
	}
	sourceID, err := identityOf(file)
	if err != nil {
		return fmt.Errorf("unsafe credential source")
	}
	directoryIDs, err := credentialDirectoryIdentities(rootPath, rootIdentity, components)
	if err != nil {
		return fmt.Errorf("unsafe credential source")
	}
	authority := credentialSourceAuthority{runtimeHome: rootPath, homeIdentity: rootIdentity, components: components, directoryIDs: directoryIDs, sourceID: sourceID}
	request, err := ports.NewCredentialProjectionRequestWithAuthority(lease.ProviderInstance(), lease.Generation(), sourcePath, file, digest, info.Size(), info.Mode(), source.destination, authority)
	if err != nil {
		return fmt.Errorf("unsafe credential source")
	}
	transferred = true
	if _, err := lease.ProjectCredential(ctx, request); err != nil {
		return err
	}
	return nil
}

func (factory *credentialProjectingNamespaceFactory) openSource(rootPath string, rootIdentity fileIdentity, components []string) (*os.File, string, error) {
	home, err := openAbsoluteDirectory(rootPath)
	if err != nil {
		return nil, "", err
	}
	identity, err := identityOf(home)
	if err != nil || identity != rootIdentity {
		_ = home.Close()
		return nil, "", fmt.Errorf("runtime home drift")
	}
	current := home
	for _, component := range components[:len(components)-1] {
		next, openErr := openDirectoryAt(current, component)
		_ = current.Close()
		if openErr != nil {
			return nil, "", openErr
		}
		current = next
	}
	fd, openErr := unix.Openat(int(current.Fd()), components[len(components)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	_ = current.Close()
	if openErr != nil {
		return nil, "", openErr
	}
	return os.NewFile(uintptr(fd), "credential-source"), filepath.Join(append([]string{rootPath}, components...)...), nil
}
func (authority credentialSourceAuthority) ValidateCredentialSource(size int64, mode os.FileMode, sha256 string) error {
	directoryIDs, err := credentialDirectoryIdentities(authority.runtimeHome, authority.homeIdentity, authority.components)
	if err != nil || len(directoryIDs) != len(authority.directoryIDs) {
		return fmt.Errorf("credential source drift")
	}
	for index := range directoryIDs {
		if directoryIDs[index] != authority.directoryIDs[index] {
			return fmt.Errorf("credential source drift")
		}
	}
	file, err := openAnchoredCredentialSource(authority.runtimeHome, authority.homeIdentity, authority.components)
	if err != nil {
		return fmt.Errorf("credential source drift")
	}
	defer file.Close()
	identity, err := identityOf(file)
	if err != nil || identity != authority.sourceID {
		return fmt.Errorf("credential source drift")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size || info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("credential source drift")
	}
	digest, err := digestCredentialSource(file, size)
	if err != nil || digest != sha256 {
		return fmt.Errorf("credential source drift")
	}
	return nil
}

func credentialDirectoryIdentities(runtimeHome string, homeIdentity fileIdentity, components []string) ([]fileIdentity, error) {
	if len(components) == 0 {
		return nil, fmt.Errorf("invalid credential source")
	}
	current, err := openAbsoluteDirectory(runtimeHome)
	if err != nil {
		return nil, err
	}
	identity, err := identityOf(current)
	if err != nil || identity != homeIdentity {
		_ = current.Close()
		return nil, fmt.Errorf("runtime home drift")
	}
	identities := make([]fileIdentity, 0, len(components)-1)
	for _, component := range components[:len(components)-1] {
		next, openErr := openDirectoryAt(current, component)
		_ = current.Close()
		if openErr != nil {
			return nil, openErr
		}
		identity, identityErr := identityOf(next)
		if identityErr != nil {
			_ = next.Close()
			return nil, identityErr
		}
		identities = append(identities, identity)
		current = next
	}
	_ = current.Close()
	return identities, nil
}

func openAnchoredCredentialSource(runtimeHome string, homeIdentity fileIdentity, components []string) (*os.File, error) {
	if len(components) == 0 {
		return nil, fmt.Errorf("invalid credential source")
	}
	home, err := openAbsoluteDirectory(runtimeHome)
	if err != nil {
		return nil, err
	}
	identity, err := identityOf(home)
	if err != nil || identity != homeIdentity {
		_ = home.Close()
		return nil, fmt.Errorf("runtime home drift")
	}
	current := home
	for _, component := range components[:len(components)-1] {
		next, openErr := openDirectoryAt(current, component)
		_ = current.Close()
		if openErr != nil {
			return nil, openErr
		}
		current = next
	}
	fd, openErr := unix.Openat(int(current.Fd()), components[len(components)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	_ = current.Close()
	if openErr != nil {
		return nil, openErr
	}
	return os.NewFile(uintptr(fd), "credential-source"), nil
}

func openAbsoluteDirectory(path string) (*os.File, error) {
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(rootFD), "runtime-root")
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := openDirectoryAt(current, component)
		_ = current.Close()
		if openErr != nil {
			return nil, openErr
		}
		current = next
	}
	return current, nil
}

func openDirectoryAt(parent *os.File, component string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "credential-directory"), nil
}

func identityOf(file *os.File) (fileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func digestCredentialSource(file *os.File, size int64) (string, error) {
	if size < 0 || size > maxProjectedCredentialBytes {
		return "", fmt.Errorf("credential source size")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, size); err != nil {
		return "", err
	}
	var extra [1]byte
	count, err := file.Read(extra[:])
	if err != io.EOF || count != 0 {
		return "", fmt.Errorf("credential source drift")
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func canonicalAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validCredentialSourceFamily(family CredentialSourceFamily) bool {
	_, ok := credentialSources[family]
	return ok
}

func validCredentialSourceInstance(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func nilNamespaceFactory(factory ports.ProviderNamespaceFactory) bool {
	if factory == nil {
		return true
	}
	value := reflect.ValueOf(factory)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
