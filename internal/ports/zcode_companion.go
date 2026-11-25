package ports

import "context"

// ZCodeCompanionObservation binds the installed companion and its offline
// Desktop diagnostics. The bundle remains an opaque launcher argument.
type ZCodeCompanionObservation struct {
	Executable, ExecutableSHA256, PackageSHA256 string
	Version, AppVersion, AppBundle              string
	BundleOverride, MinimumAppVersion           string
	DesktopBelowMinimum                         bool
}

// PackageVerified reports whether the resolver established the executable and
// complete runtime package identities, independently of the diagnostics.
func (o ZCodeCompanionObservation) PackageVerified() bool {
	executable, execErr := NewAnchoredRoot(o.Executable)
	return execErr == nil && validLivePolicyRoot(executable) &&
		validateSHA256(o.ExecutableSHA256) == nil && validateRawSHA256(o.PackageSHA256) == nil
}

func (o ZCodeCompanionObservation) Valid() bool {
	bundle, bundleErr := NewAnchoredRoot(o.AppBundle)
	return o.PackageVerified() && bundleErr == nil && validLivePolicyRoot(bundle) &&
		(o.BundleOverride == "" || o.BundleOverride == o.AppBundle) &&
		o.Version != "" && o.AppVersion != "" && o.MinimumAppVersion != ""
}

// ZCodeCompanionObserver performs only the trusted host diagnostics.
type ZCodeCompanionObserver interface {
	ObserveZCodeCompanion(context.Context, string, ...string) (ZCodeCompanionObservation, error)
}

// ProviderZCodeCompanionDefinition exposes companion provenance on ZCode routes.
type ProviderZCodeCompanionDefinition interface {
	ZCodeCompanion() ZCodeCompanionObservation
}
