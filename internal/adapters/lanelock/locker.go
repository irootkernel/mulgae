// Package lanelock provides authoritative Darwin cross-process lane locking.
package lanelock

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/irootkernel/mulgae/internal/ports"
)

var (
	// ErrUnavailable identifies the narrow readiness class whose caller may
	// consider a separately configured fallback lane.
	ErrUnavailable = errors.New("lane lock unavailable")

	// ErrNilContext reports an invalid acquisition without a cancellation source.
	ErrNilContext = errors.New("lane lock: nil context")

	// ErrInvalidKey reports an acquisition attempted with an unvalidated key.
	ErrInvalidKey = errors.New("lane lock: invalid concurrency key")
)

var locksDirectory = mustSafeRelativePath("locks")

// AcquireError reports a closed, policy-relevant failure to establish
// authoritative lane serialization while preserving its underlying cause for
// local diagnostics.
type AcquireError struct {
	class     ports.LaneAcquisitionFailureClass
	operation string
	cause     error
}

func (err *AcquireError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf("lane lock %s: %v", err.operation, err.cause)
}

// Unwrap returns the filesystem or operating-system failure that prevented
// acquisition.
func (err *AcquireError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

// LaneAcquisitionFailureClass returns the safe policy-relevant acquisition class.
func (err *AcquireError) LaneAcquisitionFailureClass() ports.LaneAcquisitionFailureClass {
	if err == nil {
		return ports.LaneAcquisitionInternal
	}
	return err.class
}

// Is identifies only genuine readiness failures as unavailable without hiding
// the underlying operating-system error from errors.Is and errors.As.
func (err *AcquireError) Is(target error) bool {
	return target == ErrUnavailable && err != nil && err.class == ports.LaneAcquisitionUnavailable
}

// Locker acquires lock-file-backed operating-system locks beneath one approved
// root. The SecureFileWriter remains the authority for constructing the private
// lock directory; lock-file bytes are never interpreted as authority.
type Locker struct {
	root   ports.AnchoredRoot
	writer ports.SecureFileWriter
}

// New constructs a lane locker rooted beneath root. Creating and validating the
// private locks directory is deferred to Acquire so a canceled acquisition has
// no filesystem effects.
func New(root ports.AnchoredRoot, writer ports.SecureFileWriter) (*Locker, error) {
	if !root.Valid() {
		return nil, fmt.Errorf("lane lock: invalid anchored root")
	}
	if isNilInterface(writer) {
		return nil, fmt.Errorf("lane lock: nil secure file writer")
	}
	return &Locker{root: root, writer: writer}, nil
}

func acquisitionError(class ports.LaneAcquisitionFailureClass, operation string, cause error) error {
	if !class.Valid() {
		class = ports.LaneAcquisitionInternal
	}
	return &AcquireError{class: class, operation: operation, cause: cause}
}

func mustSafeRelativePath(value string) ports.SafeRelativePath {
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		panic(fmt.Sprintf("lane lock private directory contract: %v", err))
	}
	return path
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflectValue := reflect.ValueOf(value)
	switch reflectValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflectValue.IsNil()
	default:
		return false
	}
}
