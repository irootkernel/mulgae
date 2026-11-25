//go:build darwin && arm64

package environment

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/irootkernel/mulgae/internal/adapters/herdr"
	"github.com/irootkernel/mulgae/internal/ports"
)

var (
	_ ports.ZCodeCompanionObserver = (*Inspector)(nil)
	_ ports.ZCodeCompanionObserver = (*FrozenInspector)(nil)
)

func (*Inspector) ObserveZCodeCompanion(ctx context.Context, bundle string, excluded ...string) (ports.ZCodeCompanionObservation, error) {
	return observeZCodeCompanion(ctx, bundle, "", false, excluded)
}

func (inspector *FrozenInspector) ObserveZCodeCompanion(ctx context.Context, bundle string, excluded ...string) (ports.ZCodeCompanionObservation, error) {
	if inspector == nil || inspector.environment == nil || inspector.environment.pathErr != nil {
		return ports.ZCodeCompanionObservation{}, identitySecurity("frozen companion search authority unavailable")
	}
	dirs := make([]string, 0, len(inspector.environment.pathEntries))
	for _, entry := range inspector.environment.pathEntries {
		if err := inspector.environment.revalidatePathEntry(entry); err != nil {
			return ports.ZCodeCompanionObservation{}, identitySecurity("frozen companion search authority changed")
		}
		dirs = append(dirs, entry.path)
	}
	observed, err := observeZCodeCompanion(ctx, bundle, strings.Join(dirs, string(os.PathListSeparator)), true, excluded)
	if err != nil && !observed.PackageVerified() {
		return ports.ZCodeCompanionObservation{}, err
	}
	for _, entry := range inspector.environment.pathEntries {
		if err := inspector.environment.revalidatePathEntry(entry); err != nil {
			return ports.ZCodeCompanionObservation{}, identitySecurity("frozen companion search authority changed")
		}
	}
	return observed, err
}

func observeZCodeCompanion(ctx context.Context, bundle, frozenPath string, hasFrozenPath bool, excluded []string) (ports.ZCodeCompanionObservation, error) {
	if ctx == nil {
		return ports.ZCodeCompanionObservation{}, identityUnavailable("missing companion observation context")
	}
	if err := ctx.Err(); err != nil {
		return ports.ZCodeCompanionObservation{}, err
	}
	installed, err := InstalledUser()
	if err != nil || installed == nil {
		return ports.ZCodeCompanionObservation{}, identityUnavailable("installed user indiscoverable")
	}
	options := herdr.DefaultZCodeResolveOptions(installed.HomeDir, excluded...)
	if hasFrozenPath {
		options.PathEnv = frozenPath
	}
	pkg, err := herdr.ResolveZCodePackage(options)
	if errors.Is(err, herdr.ErrExecutableNotFound) {
		return ports.ZCodeCompanionObservation{}, nil
	}
	if err != nil {
		return ports.ZCodeCompanionObservation{}, identitySecurity("unsafe herdr-zcode package")
	}
	observed := ports.ZCodeCompanionObservation{
		Executable: pkg.Launcher.Path, ExecutableSHA256: pkg.Launcher.SHA256, PackageSHA256: pkg.PackageSHA256,
		BundleOverride: bundle,
	}
	if err := herdr.VerifyZCodeAppBundle(bundle, excluded...); err != nil {
		if errors.Is(err, herdr.ErrUnsafeExecutable) {
			return ports.ZCodeCompanionObservation{}, identitySecurity("unsafe configured ZCode bundle")
		}
		return observed, identityUnavailable("ZCode bundle unavailable")
	}
	desktop, err := herdr.ObserveZCodeCompanion(ctx, pkg, bundle)
	observed.Version = desktop.Version
	if err != nil {
		if ctx.Err() != nil {
			return ports.ZCodeCompanionObservation{}, ctx.Err()
		}
		if errors.Is(err, herdr.ErrUnsafeExecutable) {
			return ports.ZCodeCompanionObservation{}, identitySecurity("herdr-zcode package changed")
		}
		return observed, identityUnavailable("herdr-zcode or Desktop diagnostic failed")
	}
	observed.AppVersion, observed.AppBundle = desktop.AppVersion, desktop.AppBundle
	observed.MinimumAppVersion, observed.DesktopBelowMinimum = desktop.MinimumVersion, desktop.BelowMinimum
	return observed, nil
}
