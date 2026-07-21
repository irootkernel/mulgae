//go:build !darwin

package providercli

import (
	"fmt"
	"path/filepath"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// CredentialSourceFamily is the closed set of provider credential layouts.
type CredentialSourceFamily string

const (
	CredentialSourceKimi  CredentialSourceFamily = "kimi"
	CredentialSourceZCode CredentialSourceFamily = "zcode"
	CredentialSourceAGY   CredentialSourceFamily = "agy"
)

// NewCredentialProjectingNamespaceFactory fails closed where descriptor-based
// nofollow traversal is not implemented.
func NewCredentialProjectingNamespaceFactory(ports.ProviderNamespaceFactory, string, map[string]CredentialSourceFamily) (ports.ProviderNamespaceFactory, error) {
	return nil, fmt.Errorf("credential source factory: unsupported platform")
}

// NewCredentialProjectingNamespaceFactoryWithPolicies fails closed where
// descriptor-based nofollow traversal is not implemented.
func NewCredentialProjectingNamespaceFactoryWithPolicies(ports.ProviderNamespaceFactory, string, map[string]CredentialSourceFamily, map[string]RuntimeSafetyPolicy) (ports.ProviderNamespaceFactory, error) {
	return nil, fmt.Errorf("credential source factory: unsupported platform")
}

// NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes fails
// closed where descriptor-based nofollow traversal is not implemented.
func NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes(ports.ProviderNamespaceFactory, string, map[string]CredentialSourceFamily, map[string]RuntimeSafetyPolicy, map[string]string) (ports.ProviderNamespaceFactory, error) {
	return nil, fmt.Errorf("credential source factory: unsupported platform")
}

func NewCredentialProjectingNamespaceFactoryWithConfiguredSourceRoots(ports.ProviderNamespaceFactory, string, map[string]CredentialSourceFamily, map[string]RuntimeSafetyPolicy, map[string]string, map[string]string) (ports.ProviderNamespaceFactory, error) {
	return nil, fmt.Errorf("credential source factory: unsupported platform")
}
func canonicalAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}
