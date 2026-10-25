package config

import (
	"context"
	"errors"
	"strconv"

	"github.com/irootkernel/mulgae/internal/ports"
)

// AccountObservation contains raw installed-account facts, without OS types or policy.
type AccountObservation struct {
	Available    bool
	Home         string
	UID          string
	EffectiveUID int
	Err          error
}

type AccountObserver interface{ ObserveAccount() AccountObservation }

// LocalitySelector chooses the existing Git or filesystem attestor at the caller's
// observation point. The boolean reports that independent Git binding is unavailable.
type LocalitySelector func(ports.AnchoredRoot, ports.ConfigLocalityAttestor) (ports.ConfigLocalityAttestor, bool, error)

// EffectiveAccountUID preserves the native-account comparison used by init and review.
func EffectiveAccountUID(account AccountObservation) (uint32, error) {
	uid, err := strconv.ParseUint(account.UID, 10, 32)
	if err != nil || int(uid) != account.EffectiveUID {
		return 0, errors.New("native user account does not match the effective user")
	}
	return uint32(uid), nil
}

func AdmitConfiguredNativeAccount(configuredHome string, account AccountObservation) (string, uint32, error) {
	if account.Err != nil || !account.Available || account.Home == "" || account.EffectiveUID < 0 {
		return "", 0, errors.New("native user account is unavailable")
	}
	uid, err := EffectiveAccountUID(account)
	if err != nil || configuredHome != account.Home {
		return "", 0, errors.New("configured native account does not match the effective user")
	}
	return account.Home, uid, nil
}

func SameNativeHomeAuthority(left, right ports.NativeHomeLaunchAuthority) bool {
	return left.Valid() && right.Valid() &&
		left.Path() == right.Path() && left.Device() == right.Device() &&
		left.Inode() == right.Inode() && left.EffectiveUID() == right.EffectiveUID()
}

// ConfirmLocality retains both source confirmations around attestor confirmation.
// Callers retain dependency checks and error projection; causes pass through unchanged.
func ConfirmLocality(ctx context.Context, source ports.ConfigSource, attestor ports.ConfigLocalityAttestor, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	if err := source.Revalidate(); err != nil {
		return err
	}
	if err := attestor.Revalidate(ctx, request, expected); err != nil {
		return err
	}
	return source.Revalidate()
}
