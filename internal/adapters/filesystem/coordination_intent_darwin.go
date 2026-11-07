//go:build darwin && arm64

package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/strictjson"
	"golang.org/x/sys/unix"
)

type CoordinationIntentStore struct {
	operations secureWriterOperations
}

var _ ports.ReviewCoordinationIntentStore = (*CoordinationIntentStore)(nil)

func NewCoordinationIntentStore() *CoordinationIntentStore {
	return &CoordinationIntentStore{
		operations: defaultSecureWriterOperations(),
	}
}

func (store *CoordinationIntentStore) operationSet() secureWriterOperations {
	if store == nil {
		return defaultSecureWriterOperations()
	}
	return store.operations.withDefaults()
}

func (store *CoordinationIntentStore) LoadIntent(
	ctx context.Context,
	root ports.AnchoredRoot,
	sessionID domain.SessionID,
	runID domain.RunID,
) (ports.ReviewLockRecord, bool, error) {
	if ctx == nil {
		return ports.ReviewLockRecord{}, false, fmt.Errorf("coordination intent load: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.ReviewLockRecord{}, false, err
	}
	if !root.Valid() {
		return ports.ReviewLockRecord{}, false, fmt.Errorf("coordination intent load: invalid root")
	}
	if _, err := domain.ParseSessionID(sessionID.String()); err != nil {
		return ports.ReviewLockRecord{}, false, fmt.Errorf("coordination intent load: %w", err)
	}
	if _, err := domain.ParseRunID(runID.String()); err != nil {
		return ports.ReviewLockRecord{}, false, fmt.Errorf("coordination intent load: %w", err)
	}
	if _, err := readSessionDiagnosticRunStatus(root, sessionID, runID); err != nil {
		return ports.ReviewLockRecord{}, false, fmt.Errorf("coordination intent load: require valid diagnostic run status: %w", err)
	}

	components := []string{"diagnostics", sessionID.String(), runID.String()}
	dirFD, err := walkPrivateDirectoryWithOperations(root, components, false, store.operationSet())
	if err != nil {
		return ports.ReviewLockRecord{}, false, fmt.Errorf("coordination intent load: open diagnostic directory: %w", err)
	}
	defer closeFD(dirFD)

	var stat unix.Stat_t
	if err := unix.Fstatat(dirFD, artifactwire.HaepariLockIntentFilename, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return ports.ReviewLockRecord{}, false, nil
		}
		return ports.ReviewLockRecord{}, false, fmt.Errorf("coordination intent load: stat intent file: %w", err)
	}

	data, err := readPrivateCoordinationIntentFile(dirFD, artifactwire.HaepariLockIntentFilename, ports.RuntimeDiagnosticStatusMaxBytes)
	if err != nil {
		return ports.ReviewLockRecord{}, false, fmt.Errorf("coordination intent load: read intent file: %w", err)
	}
	record, err := decodeCoordinationIntentWire(data, sessionID, runID)
	if err != nil {
		return ports.ReviewLockRecord{}, false, fmt.Errorf("coordination intent load: %w", err)
	}
	return record, true, nil
}

func (store *CoordinationIntentStore) PersistIntent(
	ctx context.Context,
	root ports.AnchoredRoot,
	record ports.ReviewLockRecord,
) (ports.ReviewLockRecord, error) {
	if ctx == nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent persist: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.ReviewLockRecord{}, err
	}
	if !root.Valid() {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent persist: invalid root")
	}
	if record.ObservedReceipt != nil || record.ObservedRequest != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent persist: initial intent must not carry post-acquire observation")
	}
	if err := record.Validate(); err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent persist: %w", err)
	}
	if _, err := readSessionDiagnosticRunStatus(root, record.SessionID, record.RunID); err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent persist: require valid diagnostic run status: %w", err)
	}

	data, err := encodeCoordinationIntentWire(record)
	if err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent persist: %w", err)
	}
	if err := store.installExclusiveIntentFile(root, record.SessionID, record.RunID, data); err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent persist: %w", err)
	}
	loaded, found, err := store.LoadIntent(ctx, root, record.SessionID, record.RunID)
	if err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent persist verify: %w", err)
	}
	if !found {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent persist verify: installed intent not found")
	}
	return loaded, nil
}

func (store *CoordinationIntentStore) UpdateObservation(
	ctx context.Context,
	root ports.AnchoredRoot,
	sessionID domain.SessionID,
	runID domain.RunID,
	reply ports.ReviewLockReply,
	updatedAt time.Time,
) (ports.ReviewLockRecord, error) {
	if ctx == nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.ReviewLockRecord{}, err
	}
	if !root.Valid() {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: invalid root")
	}
	if err := reply.Validate(""); err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: invalid reply: %w", err)
	}
	if updatedAt.IsZero() {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: missing updated_at")
	}

	existing, found, err := store.LoadIntent(ctx, root, sessionID, runID)
	if err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: %w", err)
	}
	if !found {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: existing intent absent")
	}
	if existing.ObservedRequest != nil && existing.ObservedRequest.RequestID != reply.Current.RequestID {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: observed request_id %q does not match existing %q", reply.Current.RequestID, existing.ObservedRequest.RequestID)
	}
	updatedUTC := updatedAt.UTC()
	if updatedUTC.Before(existing.PersistedAt) {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: updated_at precedes persisted_at")
	}

	receiptCopy := reply.Receipt
	currentCopy := cloneReviewLockRequest(reply.Current)
	updated := existing
	updated.UpdatedAt = updatedUTC
	updated.ObservedReceipt = &receiptCopy
	updated.ObservedRequest = &currentCopy
	if err := updated.Validate(); err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: %w", err)
	}

	data, err := encodeCoordinationIntentWire(updated)
	if err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: %w", err)
	}
	if err := store.replaceExistingIntentFile(root, sessionID, runID, data); err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update: %w", err)
	}
	loaded, found, err := store.LoadIntent(ctx, root, sessionID, runID)
	if err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update verify: %w", err)
	}
	if !found {
		return ports.ReviewLockRecord{}, fmt.Errorf("coordination intent update verify: updated intent absent")
	}
	return loaded, nil
}

func (store *CoordinationIntentStore) installExclusiveIntentFile(
	root ports.AnchoredRoot,
	sessionID domain.SessionID,
	runID domain.RunID,
	data []byte,
) error {
	operations := store.operationSet()
	components := []string{"diagnostics", sessionID.String(), runID.String()}
	dirFD, err := walkPrivateDirectoryWithOperations(root, components, false, operations)
	if err != nil {
		return err
	}
	defer closeFD(dirFD)

	dirIdentity, err := privateDirectoryIdentityForFD(dirFD)
	if err != nil {
		return err
	}
	tempFD, tempName, err := createPrivateTempFile(operations, dirFD)
	if err != nil {
		return err
	}
	cleanup := func(cause error) error {
		return errors.Join(cause, purgeTemporaryFile(operations, dirFD, &tempFD, &tempName))
	}
	if err := writeAllWith(tempFD, data, operations.write); err != nil {
		return cleanup(fmt.Errorf("write temporary intent file: %w", err))
	}
	if err := operations.fsync(tempFD); err != nil {
		return cleanup(fmt.Errorf("sync temporary intent file: %w", err))
	}
	tempIdentity, err := secureFileIdentityForFD(tempFD)
	if err != nil {
		return cleanup(fmt.Errorf("identify temporary intent file: %w", err))
	}
	if err := revalidatePrivateDirectory(root, components, dirIdentity, operations); err != nil {
		return cleanup(fmt.Errorf("diagnostic directory changed before intent install: %w", err))
	}
	if err := validateSecureFileAt(dirFD, tempName, tempIdentity); err != nil {
		return cleanup(fmt.Errorf("temporary intent file changed before install: %w", err))
	}
	if err := operations.renameatxNp(dirFD, tempName, dirFD, artifactwire.HaepariLockIntentFilename, unix.RENAME_EXCL); err != nil {
		return cleanup(fmt.Errorf("exclusive install intent file: %w", err))
	}
	tempName = ""
	sum := sha256.Sum256(data)
	if err := verifyInstalledFileAt(dirFD, artifactwire.HaepariLockIntentFilename, tempIdentity, sum[:], int64(len(data))); err != nil {
		_ = removeInstalledFile(operations, dirFD, artifactwire.HaepariLockIntentFilename, tempIdentity)
		_ = purgeTemporaryFile(operations, dirFD, &tempFD, &tempName)
		return fmt.Errorf("verify installed intent file: %w", err)
	}
	if err := operations.close(tempFD); err != nil {
		return fmt.Errorf("close temporary intent file: %w", err)
	}
	tempFD = -1
	if err := revalidatePrivateDirectory(root, components, dirIdentity, operations); err != nil {
		return fmt.Errorf("diagnostic directory changed after intent install: %w", err)
	}
	if err := operations.fsync(dirFD); err != nil {
		return fmt.Errorf("sync diagnostic directory after intent install: %w", err)
	}
	return nil
}

func (store *CoordinationIntentStore) replaceExistingIntentFile(
	root ports.AnchoredRoot,
	sessionID domain.SessionID,
	runID domain.RunID,
	data []byte,
) error {
	operations := store.operationSet()
	components := []string{"diagnostics", sessionID.String(), runID.String()}
	dirFD, err := walkPrivateDirectoryWithOperations(root, components, false, operations)
	if err != nil {
		return err
	}
	defer closeFD(dirFD)

	dirIdentity, err := privateDirectoryIdentityForFD(dirFD)
	if err != nil {
		return err
	}
	var existingStat unix.Stat_t
	if err := unix.Fstatat(dirFD, artifactwire.HaepariLockIntentFilename, &existingStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat existing intent file: %w", err)
	}
	existingIdentity := secureFileIdentity{device: uint64(existingStat.Dev), inode: uint64(existingStat.Ino)}
	if err := validateSecureFileAt(dirFD, artifactwire.HaepariLockIntentFilename, existingIdentity); err != nil {
		return fmt.Errorf("validate existing intent file: %w", err)
	}

	tempFD, tempName, err := createPrivateTempFile(operations, dirFD)
	if err != nil {
		return err
	}
	cleanup := func(cause error) error {
		return errors.Join(cause, purgeTemporaryFile(operations, dirFD, &tempFD, &tempName))
	}
	if err := writeAllWith(tempFD, data, operations.write); err != nil {
		return cleanup(fmt.Errorf("write replacement intent file: %w", err))
	}
	if err := operations.fsync(tempFD); err != nil {
		return cleanup(fmt.Errorf("sync replacement intent file: %w", err))
	}
	tempIdentity, err := secureFileIdentityForFD(tempFD)
	if err != nil {
		return cleanup(fmt.Errorf("identify replacement intent file: %w", err))
	}
	if err := revalidatePrivateDirectory(root, components, dirIdentity, operations); err != nil {
		return cleanup(fmt.Errorf("diagnostic directory changed before intent swap: %w", err))
	}
	if err := validateSecureFileAt(dirFD, tempName, tempIdentity); err != nil {
		return cleanup(fmt.Errorf("replacement intent file changed before swap: %w", err))
	}
	if err := validateSecureFileAt(dirFD, artifactwire.HaepariLockIntentFilename, existingIdentity); err != nil {
		return cleanup(fmt.Errorf("existing intent file changed before swap: %w", err))
	}
	if err := operations.renameatxNp(dirFD, tempName, dirFD, artifactwire.HaepariLockIntentFilename, unix.RENAME_SWAP); err != nil {
		return cleanup(fmt.Errorf("swap intent file: %w", err))
	}
	sum := sha256.Sum256(data)
	if err := verifyInstalledFileAt(dirFD, artifactwire.HaepariLockIntentFilename, tempIdentity, sum[:], int64(len(data))); err != nil {
		return cleanup(fmt.Errorf("verify swapped intent file: %w", err))
	}
	if err := validateSecureFileAt(dirFD, tempName, existingIdentity); err != nil {
		return cleanup(fmt.Errorf("verify displaced intent file before unlink: %w", err))
	}
	if err := operations.unlinkat(dirFD, tempName, 0); err != nil {
		return cleanup(fmt.Errorf("unlink displaced intent file: %w", err))
	}
	tempName = ""
	if err := operations.close(tempFD); err != nil {
		return fmt.Errorf("close replacement intent file: %w", err)
	}
	tempFD = -1
	if err := revalidatePrivateDirectory(root, components, dirIdentity, operations); err != nil {
		return fmt.Errorf("diagnostic directory changed after intent swap: %w", err)
	}
	if err := operations.fsync(dirFD); err != nil {
		return fmt.Errorf("sync diagnostic directory after intent swap: %w", err)
	}
	return nil
}

func encodeCoordinationIntentWire(record ports.ReviewLockRecord) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	var queueCopy *int64
	if record.Payload.QueueSeconds != nil {
		v := *record.Payload.QueueSeconds
		queueCopy = &v
	}
	wire := artifactwire.HaepariLockIntentWire{
		SchemaVersion:  record.SchemaVersion,
		SessionID:      record.SessionID.String(),
		RunID:          record.RunID.String(),
		InstallationID: record.InstallationID,
		ResourceID:     record.ResourceID,
		Payload: artifactwire.HaepariLockPayloadWire{
			LockID:       record.Payload.LockID,
			RequestKey:   record.Payload.RequestKey,
			Holder:       record.Payload.Holder,
			QueueSeconds: queueCopy,
		},
		PayloadJSON:   string(record.Payload.CanonicalJSON),
		PayloadSHA256: record.Payload.PayloadSHA256,
		PersistedAt:   record.PersistedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:     record.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if record.ObservedReceipt != nil && record.ObservedRequest != nil {
		wire.ObservedReceipt = &artifactwire.HaepariLockReceiptWire{
			Operation:  string(record.ObservedReceipt.Operation),
			RequestID:  record.ObservedReceipt.RequestID,
			GrantID:    record.ObservedReceipt.GrantID,
			State:      string(record.ObservedReceipt.State),
			RecordedAt: record.ObservedReceipt.RecordedAt.UTC().Format(time.RFC3339Nano),
			Force:      record.ObservedReceipt.Force,
			Reason:     record.ObservedReceipt.Reason,
		}
		req := record.ObservedRequest
		wire.ObservedRequest = &artifactwire.HaepariLockRequestWire{
			InstallationID:   req.InstallationID,
			LockID:           req.LockID,
			RequestID:        req.RequestID,
			RequestKey:       req.RequestKey,
			Holder:           req.Holder,
			State:            string(req.State),
			Sequence:         req.Sequence,
			GrantID:          req.GrantID,
			Generation:       req.Generation,
			Slot:             req.Slot,
			QueuedAt:         req.QueuedAt.UTC().Format(time.RFC3339Nano),
			QueueDeadline:    formatOptionalTimePtr(req.QueueDeadline),
			GrantedAt:        formatOptionalTimePtr(req.GrantedAt),
			LivenessDeadline: formatOptionalTimePtr(req.LivenessDeadline),
			MaxHoldDeadline:  formatOptionalTimePtr(req.MaxHoldDeadline),
			LivenessSeconds:  req.LivenessSeconds,
			MaxHoldSeconds:   req.MaxHoldSeconds,
			EndedAt:          formatOptionalTimePtr(req.EndedAt),
			Reason:           req.Reason,
			Forced:           req.Forced,
		}
	}
	return marshalDiagnosticStatus(wire)
}

func decodeCoordinationIntentWire(
	data []byte,
	expectedSessionID domain.SessionID,
	expectedRunID domain.RunID,
) (ports.ReviewLockRecord, error) {
	var wire artifactwire.HaepariLockIntentWire
	if err := strictjson.DecodeObject(data, &wire); err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("decode intent JSON: %w", err)
	}
	if wire.SchemaVersion != artifactwire.HaepariLockIntentSchemaV1 {
		return ports.ReviewLockRecord{}, fmt.Errorf("unexpected schema_version %q", wire.SchemaVersion)
	}
	if wire.SessionID != expectedSessionID.String() || wire.RunID != expectedRunID.String() {
		return ports.ReviewLockRecord{}, fmt.Errorf("intent identity (%q, %q) does not match expected (%q, %q)", wire.SessionID, wire.RunID, expectedSessionID.String(), expectedRunID.String())
	}
	persistedAt, err := parseCleanupDiagnosticTime(wire.PersistedAt)
	if err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("invalid persisted_at: %w", err)
	}
	updatedAt, err := parseCleanupDiagnosticTime(wire.UpdatedAt)
	if err != nil {
		return ports.ReviewLockRecord{}, fmt.Errorf("invalid updated_at: %w", err)
	}
	rawPayload := []byte(wire.PayloadJSON)
	sum := sha256.Sum256(rawPayload)
	nativeHex := hex.EncodeToString(sum[:])
	var queueCopy *int64
	if wire.Payload.QueueSeconds != nil {
		v := *wire.Payload.QueueSeconds
		queueCopy = &v
	}
	payload := ports.ReviewLockRequestPayload{
		LockID:              wire.Payload.LockID,
		RequestKey:          wire.Payload.RequestKey,
		Holder:              wire.Payload.Holder,
		QueueSeconds:        queueCopy,
		CanonicalJSON:       rawPayload,
		PayloadSHA256:       wire.PayloadSHA256,
		NativePayloadDigest: nativeHex,
	}
	record := ports.ReviewLockRecord{
		SchemaVersion:  wire.SchemaVersion,
		SessionID:      expectedSessionID,
		RunID:          expectedRunID,
		InstallationID: wire.InstallationID,
		ResourceID:     wire.ResourceID,
		Payload:        payload,
		PersistedAt:    persistedAt,
		UpdatedAt:      updatedAt,
	}
	if (wire.ObservedReceipt == nil) != (wire.ObservedRequest == nil) {
		return ports.ReviewLockRecord{}, fmt.Errorf("observed_receipt and observed_request must be present together")
	}
	if wire.ObservedReceipt != nil {
		recordedAt, err := parseCleanupDiagnosticTime(wire.ObservedReceipt.RecordedAt)
		if err != nil {
			return ports.ReviewLockRecord{}, fmt.Errorf("invalid observed_receipt.recorded_at: %w", err)
		}
		receipt := ports.ReviewLockReceipt{
			Operation:  ports.ReviewLockReceiptOperation(wire.ObservedReceipt.Operation),
			RequestID:  wire.ObservedReceipt.RequestID,
			GrantID:    wire.ObservedReceipt.GrantID,
			State:      ports.ReviewLockState(wire.ObservedReceipt.State),
			RecordedAt: recordedAt,
			Force:      wire.ObservedReceipt.Force,
			Reason:     wire.ObservedReceipt.Reason,
		}
		reqWire := wire.ObservedRequest
		queuedAt, err := parseCleanupDiagnosticTime(reqWire.QueuedAt)
		if err != nil {
			return ports.ReviewLockRecord{}, fmt.Errorf("invalid observed_request.queued_at: %w", err)
		}
		queueDeadline, err := parseOptionalTimePtr(reqWire.QueueDeadline)
		if err != nil {
			return ports.ReviewLockRecord{}, fmt.Errorf("invalid observed_request.queue_deadline: %w", err)
		}
		grantedAt, err := parseOptionalTimePtr(reqWire.GrantedAt)
		if err != nil {
			return ports.ReviewLockRecord{}, fmt.Errorf("invalid observed_request.granted_at: %w", err)
		}
		livenessDeadline, err := parseOptionalTimePtr(reqWire.LivenessDeadline)
		if err != nil {
			return ports.ReviewLockRecord{}, fmt.Errorf("invalid observed_request.liveness_deadline: %w", err)
		}
		maxHoldDeadline, err := parseOptionalTimePtr(reqWire.MaxHoldDeadline)
		if err != nil {
			return ports.ReviewLockRecord{}, fmt.Errorf("invalid observed_request.max_hold_deadline: %w", err)
		}
		endedAt, err := parseOptionalTimePtr(reqWire.EndedAt)
		if err != nil {
			return ports.ReviewLockRecord{}, fmt.Errorf("invalid observed_request.ended_at: %w", err)
		}
		req := ports.ReviewLockRequest{
			InstallationID:   reqWire.InstallationID,
			LockID:           reqWire.LockID,
			RequestID:        reqWire.RequestID,
			RequestKey:       reqWire.RequestKey,
			Holder:           reqWire.Holder,
			State:            ports.ReviewLockState(reqWire.State),
			Sequence:         reqWire.Sequence,
			GrantID:          reqWire.GrantID,
			Generation:       reqWire.Generation,
			Slot:             reqWire.Slot,
			QueuedAt:         queuedAt,
			QueueDeadline:    queueDeadline,
			GrantedAt:        grantedAt,
			LivenessDeadline: livenessDeadline,
			MaxHoldDeadline:  maxHoldDeadline,
			LivenessSeconds:  reqWire.LivenessSeconds,
			MaxHoldSeconds:   reqWire.MaxHoldSeconds,
			EndedAt:          endedAt,
			Reason:           reqWire.Reason,
			Forced:           reqWire.Forced,
		}
		record.ObservedReceipt = &receipt
		record.ObservedRequest = &req
	}
	if err := record.Validate(); err != nil {
		return ports.ReviewLockRecord{}, err
	}
	return record, nil
}

func formatOptionalTimePtr(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := value.UTC().Format(time.RFC3339Nano)
	return &formatted
}

func parseOptionalTimePtr(raw *string) (*time.Time, error) {
	if raw == nil {
		return nil, nil
	}
	parsed, err := parseCleanupDiagnosticTime(*raw)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func readPrivateCoordinationIntentFile(directoryFD int, name string, maxBytes int64) ([]byte, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open private intent file: %w", err)
	}
	defer closeFD(fd)
	if err := verifyPrivateRegularFile(fd); err != nil {
		return nil, fmt.Errorf("verify private intent file: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Size <= 0 || stat.Size > maxBytes {
		return nil, fmt.Errorf("invalid private intent file size")
	}
	data := make([]byte, int(stat.Size))
	for offset := 0; offset < len(data); {
		count, readErr := unix.Pread(fd, data[offset:], int64(offset))
		if count > 0 {
			offset += count
		}
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil || count == 0 {
			return nil, fmt.Errorf("read private intent file: %w", errors.Join(readErr, io.ErrUnexpectedEOF))
		}
	}
	return data, nil
}

func cloneReviewLockRequest(req ports.ReviewLockRequest) ports.ReviewLockRequest {
	out := req
	out.QueueDeadline = cloneTimePtr(req.QueueDeadline)
	out.GrantedAt = cloneTimePtr(req.GrantedAt)
	out.LivenessDeadline = cloneTimePtr(req.LivenessDeadline)
	out.MaxHoldDeadline = cloneTimePtr(req.MaxHoldDeadline)
	out.EndedAt = cloneTimePtr(req.EndedAt)
	return out
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
