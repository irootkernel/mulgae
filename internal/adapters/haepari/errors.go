//go:build darwin && arm64

package haepari

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/irootkernel/mulgae/internal/ports"
)

type wireIssue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Retry   string `json:"retry"`
}

func isMutatingLockOp(op ports.ReviewLockOperation) bool {
	return op == ports.ReviewLockOperationAcquire ||
		op == ports.ReviewLockOperationWait ||
		op == ports.ReviewLockOperationRenew ||
		op == ports.ReviewLockOperationRelease ||
		op == ports.ReviewLockOperationCancel
}

func mapTransportError(op ports.ReviewLockOperation, writeStarted bool, err error) error {
	if err == nil {
		return nil
	}
	var coordErr *ports.ReviewCoordinationError
	if errors.As(err, &coordErr) {
		return coordErr
	}

	var netOpErr *net.OpError
	if errors.As(err, &netOpErr) && netOpErr.Op == "dial" {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonContextCancelled,
				Operation: op,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: false,
				Message:   "context cancelled before controller connection",
				Cause:     err,
			}
		}
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonControllerUnreachable,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryWhenAvailable,
			Uncertain: false,
			Message:   "controller socket dial failed",
			Cause:     err,
		}
	}

	if !writeStarted && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonContextCancelled,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   "context cancelled before request transmission",
			Cause:     err,
		}
	}

	if op == ports.ReviewLockOperationAcquire {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireUncertain,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryInspectFirst,
			Uncertain: true,
			Message:   "transport interrupted after lock.acquire transmission started",
			Cause:     err,
		}
	}

	mutating := writeStarted && isMutatingLockOp(op)
	if !mutating && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonContextCancelled,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   "context cancelled during read operation",
			Cause:     err,
		}
	}

	return &ports.ReviewCoordinationError{
		Reason:    ports.ReviewCoordinationReasonControllerUnreachable,
		Operation: op,
		Retry:     ports.ReviewCoordinationRetryInspectFirst,
		Uncertain: mutating,
		Message:   "controller transport interrupted",
		Cause:     err,
	}
}

func mapNativeIssue(op ports.ReviewLockOperation, issue *wireIssue) error {
	mutating := isMutatingLockOp(op)
	if issue == nil || strings.TrimSpace(issue.Code) == "" {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: mutating,
			Message:   "missing native error issue code",
		}
	}
	nativeRetry := ports.ReviewLockNativeRetry(issue.Retry)
	if !nativeRetry.Valid() {
		return &ports.ReviewCoordinationError{
			Reason:     ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation:  op,
			NativeCode: issue.Code,
			Retry:      ports.ReviewCoordinationRetryNever,
			Uncertain:  mutating,
			Message:    "invalid native error retry value",
		}
	}

	msg := redactNativeMessage(issue.Message)
	switch issue.Code {
	case "PROTOCOL_UNSUPPORTED":
		return &ports.ReviewCoordinationError{
			Reason:      ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetryNever,
			Message:     msg,
		}
	case "UNSUPPORTED":
		reason := ports.ReviewCoordinationReasonCapabilityUnsupported
		if op == ports.ReviewLockOperationInspectResource {
			reason = ports.ReviewCoordinationReasonResourceInvalid
		}
		return &ports.ReviewCoordinationError{
			Reason:      reason,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetryNever,
			Message:     msg,
		}
	case "NOT_FOUND":
		reason := ports.ReviewCoordinationReasonLockNotFound
		if op == ports.ReviewLockOperationInspectResource || op == ports.ReviewLockOperationAcquire {
			reason = ports.ReviewCoordinationReasonResourceInvalid
		}
		return &ports.ReviewCoordinationError{
			Reason:      reason,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetryNever,
			Message:     msg,
		}
	case "CONFLICT":
		reason := ports.ReviewCoordinationReasonLockStateConflict
		if op == ports.ReviewLockOperationAcquire {
			reason = ports.ReviewCoordinationReasonAcquireConflict
		}
		return &ports.ReviewCoordinationError{
			Reason:      reason,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetryNever,
			Message:     msg,
		}
	case "NESTED_ACQUISITION_REJECTED", "NESTED_WAIT_REJECTED", "INVALID_REQUEST", "PREREQUISITE_UNAVAILABLE":
		reason := ports.ReviewCoordinationReasonAcquireInvalid
		if op == ports.ReviewLockOperationInspectResource {
			reason = ports.ReviewCoordinationReasonResourceInvalid
		}
		return &ports.ReviewCoordinationError{
			Reason:      reason,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetryNever,
			Message:     msg,
		}
	case "RESOURCE_BUSY", "RECOVERY_BLOCKED", "STALE_REVISION":
		return &ports.ReviewCoordinationError{
			Reason:      ports.ReviewCoordinationReasonAcquireOverloaded,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetryWhenAvailable,
			Message:     msg,
		}
	case "STORAGE_UNAVAILABLE":
		if op == ports.ReviewLockOperationAcquire {
			return &ports.ReviewCoordinationError{
				Reason:      ports.ReviewCoordinationReasonAcquireUncertain,
				Operation:   op,
				NativeCode:  issue.Code,
				NativeRetry: nativeRetry,
				Retry:       ports.ReviewCoordinationRetryReconcile,
				Uncertain:   true,
				Message:     msg,
			}
		}
		return &ports.ReviewCoordinationError{
			Reason:      ports.ReviewCoordinationReasonControllerUnreachable,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetryReconcile,
			Uncertain:   mutating,
			Message:     msg,
		}
	case "LOCK_EXPIRED":
		return &ports.ReviewCoordinationError{
			Reason:      ports.ReviewCoordinationReasonHoldExpired,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetryNever,
			Message:     msg,
		}
	case "WAIT_TIMEOUT":
		return &ports.ReviewCoordinationError{
			Reason:      ports.ReviewCoordinationReasonLockStateConflict,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetrySameKey,
			Message:     msg,
		}
	default:
		return &ports.ReviewCoordinationError{
			Reason:      ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation:   op,
			NativeCode:  issue.Code,
			NativeRetry: nativeRetry,
			Retry:       ports.ReviewCoordinationRetryNever,
			Uncertain:   mutating,
			Message:     "unrecognized native error code",
		}
	}
}

func redactNativeMessage(message string) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "/") {
		return "[redacted native message containing path]"
	}
	if len(trimmed) > 256 {
		return trimmed[:256]
	}
	return trimmed
}
