package app

import (
	"context"
	"errors"

	"github.com/irootkernel/mulgae/internal/domain"
)

// FailureSelectionMode retains the two transport policies for raw observations.
type FailureSelectionMode uint8

const (
	FailureTypedOnly FailureSelectionMode = iota
	FailureCLIRawFallback
)

// FailureSelection identifies a class and the original observation that won.
// Selection does not wrap, replace or mutate that observation.
type FailureSelection struct {
	Class domain.FailureClass
	Cause error
}

// SelectFailure visits parents before causes and joined children in their
// original order. Equal-ranked observations retain the first visited cause.
// CLI raw fallback is suppressed below a typed single-cause wrapper, but each
// joined child starts an independent observation. Typed-only mode ignores raw
// leaves; both modes recognize bare cancellation and deadline leaves.
func SelectFailure(err error, mode FailureSelectionMode, fallback domain.FailureClass) (FailureSelection, bool) {
	selected := FailureSelection{}
	rank := -1
	observe := func(class domain.FailureClass, cause error) {
		if next := FailurePrecedence(class); next > rank {
			selected = FailureSelection{Class: class, Cause: cause}
			rank = next
		}
	}
	var visit func(error, bool)
	visit = func(current error, suppressRaw bool) {
		if current == nil {
			return
		}
		if typed, ok := current.(*domain.Failure); ok && typed != nil && typed.Class().Valid() {
			observe(typed.Class(), typed)
			visit(typed.Unwrap(), true)
			return
		}
		raw := func() {
			if mode == FailureCLIRawFallback && !suppressRaw {
				observe(fallback, current)
			}
		}
		switch nested := current.(type) {
		case interface{ Unwrap() []error }:
			children := nested.Unwrap()
			if len(children) == 0 {
				raw()
				return
			}
			for _, child := range children {
				visit(child, false)
			}
		case interface{ Unwrap() error }:
			child := nested.Unwrap()
			if child == nil {
				raw()
				return
			}
			visit(child, suppressRaw)
		default:
			if errors.Is(current, context.Canceled) || errors.Is(current, context.DeadlineExceeded) {
				observe(domain.FailureCancelled, current)
				return
			}
			raw()
		}
	}
	visit(err, false)
	if rank < 0 && mode == FailureCLIRawFallback {
		observe(fallback, nil)
	}
	return selected, rank >= 0
}
