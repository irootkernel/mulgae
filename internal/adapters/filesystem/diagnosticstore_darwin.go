//go:build darwin && arm64

package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

func (factory *DiagnosticStoreFactory) Open(ctx context.Context, request ports.RuntimeDiagnosticOpenRequest) (ports.RuntimeDiagnosticSink, error) {
	if ctx == nil {
		return nil, diagnosticPersistenceError(ports.DiagnosticPersistenceOpen, "nil_context", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if factory == nil || nilInterface(factory.writer) || nilInterface(factory.clock) || !request.Root().Valid() || !request.RunPath().Valid() {
		return nil, diagnosticPersistenceError(ports.DiagnosticPersistenceOpen, "invalid_request", errors.New("invalid factory or request"))
	}
	if err := factory.writer.EnsurePrivateDir(request.Root(), request.RunPath()); err != nil {
		return nil, diagnosticPersistenceError(ports.DiagnosticPersistenceOpen, "ensure_run_directory", err)
	}
	store := &DiagnosticStore{request: request, writer: factory.writer, clock: factory.clock, logFD: -1, operations: defaultDiagnosticStoreOperations()}
	if err := store.openOrCreateLog(ctx); err != nil {
		return nil, diagnosticPersistenceError(ports.DiagnosticPersistenceOpen, "open_runtime_log", err)
	}
	initial, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: request.SessionID(), RunID: request.RunID(), State: domain.RunRunning, StartedAt: request.StartedAt(), UpdatedAt: request.StartedAt(), LastSequence: store.sequence})
	if err != nil {
		store.closeLog()
		return nil, diagnosticPersistenceError(ports.DiagnosticPersistenceOpen, "initial_status", err)
	}
	if err := store.replaceRunStatusLocked(initial, store.sequence); err != nil {
		store.closeLog()
		return nil, diagnosticPersistenceError(ports.DiagnosticPersistenceOpen, "initial_status", err)
	}
	store.installed = true
	return store, nil
}

func (store *DiagnosticStore) openOrCreateLog(ctx context.Context) error {
	path, _ := ports.NewSafeRelativePath(store.request.RunPath().String() + "/kar-runtime.jsonl")
	parts, name, _ := splitDestination(path)
	directory, err := walkPrivateDirectory(store.request.Root(), parts, false)
	if err != nil {
		return err
	}
	fd, openErr := unix.Openat(directory, name, unix.O_RDWR|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	closeFD(directory)
	if errors.Is(openErr, unix.ENOENT) {
		writeRequest, requestErr := ports.NewSecureWriteRequest(store.request.Root(), path, "runtime_diagnostic_log", bytes.NewReader(nil), 1, []string{"kar_runtime"}, func(error) {})
		if requestErr != nil {
			return requestErr
		}
		if _, _, writeErr := store.writer.Write(ctx, writeRequest); writeErr != nil {
			return writeErr
		}
		directory, err = walkPrivateDirectory(store.request.Root(), parts, false)
		if err != nil {
			return err
		}
		fd, openErr = unix.Openat(directory, name, unix.O_RDWR|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeFD(directory)
	}
	if openErr != nil {
		return fmt.Errorf("open runtime log: %w", openErr)
	}
	if err := verifyPrivateRegularFile(fd); err != nil {
		closeFD(fd)
		return fmt.Errorf("verify runtime log: %w", err)
	}
	identity, err := secureFileIdentityForFD(fd)
	if err != nil {
		closeFD(fd)
		return err
	}
	store.logFD = fd
	store.logIdentity = diagnosticFileIdentity(identity)
	if err := store.recoverLog(); err != nil {
		store.closeLog()
		return err
	}
	return nil
}

func (store *DiagnosticStore) recoverLog() error {
	var stat unix.Stat_t
	if err := unix.Fstat(store.logFD, &stat); err != nil {
		return fmt.Errorf("stat runtime log: %w", err)
	}
	if stat.Size < 0 || stat.Size > ports.RuntimeDiagnosticLogMaxBytes {
		return fmt.Errorf("runtime log size is invalid")
	}
	data := make([]byte, int(stat.Size))
	offset := 0
	for offset < len(data) {
		count, err := unix.Pread(store.logFD, data[offset:], int64(offset))
		if count > 0 {
			offset += count
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read runtime log: %w", err)
		}
		if count == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	durableLength := len(data)
	if durableLength > 0 && data[durableLength-1] != '\n' {
		if last := bytes.LastIndexByte(data, '\n'); last >= 0 {
			durableLength = last + 1
		} else {
			durableLength = 0
		}
		if err := unix.Ftruncate(store.logFD, int64(durableLength)); err != nil {
			return fmt.Errorf("truncate partial runtime log: %w", err)
		}
		if err := store.operations.fsync(store.logFD); err != nil {
			return fmt.Errorf("sync recovered runtime log: %w", err)
		}
	}
	var previous uint64
	for _, line := range bytes.Split(data[:durableLength], []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var wire runtimeDiagnosticEventWire
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&wire); err != nil {
			return fmt.Errorf("decode durable runtime log: %w", err)
		}
		if wire.SchemaVersion != domain.RuntimeDiagnosticSchemaVersion || wire.SessionID != store.request.SessionID().String() || wire.RunID != store.request.RunID().String() || wire.Sequence != previous+1 {
			return fmt.Errorf("durable runtime log identity or sequence mismatch")
		}
		previous = wire.Sequence
		if wire.ElapsedMS < store.lastElapsed {
			return fmt.Errorf("durable runtime log elapsed time decreased")
		}
		store.lastElapsed = wire.ElapsedMS
	}
	store.sequence = previous
	store.logBytes = int64(durableLength)
	return nil
}

func (store *DiagnosticStore) Emit(ctx context.Context, draft domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	if ctx == nil {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "nil_context", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return domain.RuntimeDiagnosticEvent{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.appendEventLocked(draft)
}

func (store *DiagnosticStore) appendEventLocked(draft domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	if store.finalized || store.logFD < 0 {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "closed", errors.New("diagnostic store is closed"))
	}
	input := draft.Input()
	if input.SessionID != store.request.SessionID() || input.RunID != store.request.RunID() {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "identity_mismatch", errors.New("event identity does not match store"))
	}
	now := store.clock.Now()
	if now.IsZero() {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "clock", errors.New("clock returned zero time"))
	}
	now = now.UTC()
	elapsed := now.Sub(store.request.StartedAt())
	if elapsed < 0 {
		elapsed = 0
	}
	elapsedMS := uint64(elapsed / time.Millisecond)
	if elapsedMS < store.lastElapsed {
		elapsedMS = store.lastElapsed
	}
	event, err := domain.StampRuntimeDiagnosticEvent(draft, store.sequence+1, now, elapsedMS)
	if err != nil {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "invalid_event", err)
	}
	encoded, err := encodeRuntimeDiagnosticEvent(event)
	if err != nil {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "encode", err)
	}
	limit := ports.RuntimeDiagnosticLogMaxBytes - ports.RuntimeDiagnosticTailReserveBytes
	if mandatoryRuntimeDiagnosticEvent(input.Event) {
		limit = ports.RuntimeDiagnosticLogMaxBytes
	}
	if store.logBytes+int64(len(encoded)) > limit {
		if !mandatoryRuntimeDiagnosticEvent(input.Event) {
			if store.droppedEvents < ^uint64(0) {
				store.droppedEvents++
			}
			return domain.RuntimeDiagnosticEvent{}, ports.ErrRuntimeDiagnosticEventDropped
		}
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "log_cap", errors.New("runtime log cap exhausted"))
	}
	if err := store.validateLogPath(); err != nil {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "namespace_changed", err)
	}
	if err := writeAllWith(store.logFD, encoded, store.operations.write); err != nil {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "append", err)
	}
	if err := store.operations.fsync(store.logFD); err != nil {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "sync", err)
	}
	if err := store.validateLogPath(); err != nil {
		return domain.RuntimeDiagnosticEvent{}, diagnosticPersistenceError(ports.DiagnosticPersistenceEmit, "post_sync_verification", err)
	}
	store.sequence = event.Sequence()
	store.lastElapsed = event.ElapsedMillis()
	store.logBytes += int64(len(encoded))
	return event, nil
}

func (store *DiagnosticStore) validateLogPath() error {
	parts := strings.Split(store.request.RunPath().String(), "/")
	directory, err := walkPrivateDirectory(store.request.Root(), parts, false)
	if err != nil {
		return err
	}
	defer closeFD(directory)
	expected := secureFileIdentity{device: store.logIdentity.device, inode: store.logIdentity.inode}
	return validateSecureFileAt(directory, "kar-runtime.jsonl", expected)
}

func (store *DiagnosticStore) ReplaceRunStatus(ctx context.Context, status ports.RuntimeDiagnosticRunStatus) error {
	if ctx == nil {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "nil_context", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.finalized {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "closed", errors.New("diagnostic store is finalized"))
	}
	return store.replaceRunStatusLocked(status, status.LastSequence())
}
func (store *DiagnosticStore) replaceRunStatusLocked(status ports.RuntimeDiagnosticRunStatus, lastSequence uint64) error {
	if status.SessionID() != store.request.SessionID() || status.RunID() != store.request.RunID() || lastSequence > store.sequence {
		return errors.New("run status identity or sequence does not match store")
	}
	encoded, err := encodeRuntimeDiagnosticRunStatusAt(status, lastSequence, store.droppedEvents)
	if err != nil {
		return err
	}
	path, _ := ports.NewSafeRelativePath(store.request.RunPath().String() + "/status.json")
	return store.atomicReplace(path, encoded)
}

func (store *DiagnosticStore) ReplaceAttemptStatus(ctx context.Context, status ports.RuntimeDiagnosticAttemptStatus) error {
	if ctx == nil {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "nil_context", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.finalized || status.SessionID() != store.request.SessionID() || status.RunID() != store.request.RunID() || status.LastSequence() > store.sequence {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "invalid_attempt_status", errors.New("invalid attempt status"))
	}
	encoded, err := encodeRuntimeDiagnosticAttemptStatus(status)
	if err != nil {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "encode_attempt", err)
	}
	path, _ := ports.NewSafeRelativePath(fmt.Sprintf("%s/attempts/%s/status.json", store.request.RunPath().String(), status.AttemptID().String()))
	if err := store.atomicReplace(path, encoded); err != nil {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "replace_attempt", err)
	}
	return nil
}

func (store *DiagnosticStore) ReplaceInvocationStatus(ctx context.Context, status ports.RuntimeDiagnosticInvocationStatus) error {
	if ctx == nil {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "nil_context", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.finalized || status.SessionID() != store.request.SessionID() || status.RunID() != store.request.RunID() || status.LastSequence() > store.sequence {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "invalid_invocation_status", errors.New("invalid invocation status"))
	}
	encoded, err := encodeRuntimeDiagnosticInvocationStatus(status)
	if err != nil {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "encode_invocation", err)
	}
	path, _ := ports.NewSafeRelativePath(fmt.Sprintf("%s/attempts/%s/invocations/%03d-%s/status.json", store.request.RunPath().String(), status.AttemptID().String(), status.Ordinal(), status.Purpose()))
	if err := store.atomicReplace(path, encoded); err != nil {
		return diagnosticPersistenceError(ports.DiagnosticPersistenceStatus, "replace_invocation", err)
	}
	return nil
}

func (store *DiagnosticStore) atomicReplace(path ports.SafeRelativePath, data []byte) error {
	parts, name, err := splitDestination(path)
	if err != nil {
		return err
	}
	if len(parts) > 0 {
		parent, _ := ports.NewSafeRelativePath(strings.Join(parts, "/"))
		if err := store.writer.EnsurePrivateDir(store.request.Root(), parent); err != nil {
			return err
		}
	}
	directory, err := walkPrivateDirectory(store.request.Root(), parts, false)
	if err != nil {
		return err
	}
	defer closeFD(directory)
	directoryID, err := privateDirectoryIdentityForFD(directory)
	if err != nil {
		return err
	}
	operations := defaultSecureWriterOperations()
	temporaryFD, temporaryName, err := createPrivateTempFile(operations, directory)
	if err != nil {
		return err
	}
	cleanup := func(cause error) error {
		return errors.Join(cause, purgeTemporaryFile(operations, directory, &temporaryFD, &temporaryName))
	}
	if err := writeAll(temporaryFD, data); err != nil {
		return cleanup(err)
	}
	if err := operations.fsync(temporaryFD); err != nil {
		return cleanup(err)
	}
	identity, err := secureFileIdentityForFD(temporaryFD)
	if err != nil {
		return cleanup(err)
	}
	if err := revalidatePrivateDirectory(store.request.Root(), parts, directoryID, operations); err != nil {
		return cleanup(err)
	}
	if err := validateSecureFileAt(directory, temporaryName, identity); err != nil {
		return cleanup(err)
	}
	existingFD, openErr := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if openErr == nil {
		if err := verifyPrivateRegularFile(existingFD); err != nil {
			closeFD(existingFD)
			return cleanup(err)
		}
		closeFD(existingFD)
		if err := operations.renameatxNp(directory, temporaryName, directory, name, unix.RENAME_SWAP); err != nil {
			return cleanup(err)
		}
		if err := unix.Unlinkat(directory, temporaryName, 0); err != nil {
			temporaryName = ""
			return errors.Join(err, operations.close(temporaryFD))
		}
		temporaryName = ""
	} else if errors.Is(openErr, unix.ENOENT) {
		if err := operations.renameatxNp(directory, temporaryName, directory, name, unix.RENAME_EXCL); err != nil {
			return cleanup(err)
		}
		temporaryName = ""
	} else {
		return cleanup(openErr)
	}
	if err := validateSecureFileAt(directory, name, identity); err != nil {
		return errors.Join(err, operations.close(temporaryFD))
	}
	closeErr := operations.close(temporaryFD)
	temporaryFD = -1
	syncErr := operations.fsync(directory)
	return errors.Join(closeErr, syncErr)
}

func (store *DiagnosticStore) Finalize(ctx context.Context, request ports.RuntimeDiagnosticFinalizeRequest) (ports.RuntimeDiagnosticFinalizeResult, error) {
	if ctx == nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceFinalize, "nil_context", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.finalized {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceFinalize, "already_finalized", errors.New("diagnostic store already finalized"))
	}
	status := request.Status()
	if status.SessionID() != store.request.SessionID() || status.RunID() != store.request.RunID() {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceFinalize, "identity_mismatch", errors.New("final status identity mismatch"))
	}
	level := domain.RuntimeDiagnosticInfo
	closeEvent := domain.DiagnosticRunCompleted
	if request.State() == domain.RunFailed || request.State() == domain.RunCancelled {
		level = domain.RuntimeDiagnosticError
		closeEvent = domain.DiagnosticRunStopped
	}
	draft, err := domain.NewRuntimeDiagnosticEventDraft(domain.RuntimeDiagnosticEventInput{Level: level, Component: "runtime", Operation: "finalize", Event: closeEvent, SessionID: store.request.SessionID(), RunID: store.request.RunID(), Cause: request.Cause(), State: string(request.State())})
	if err != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceFinalize, "terminal_event", err)
	}
	if _, err := store.appendEventLocked(draft); err != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceFinalize, "terminal_event", err)
	}
	if err := store.replaceRunStatusLocked(status, store.sequence); err != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceFinalize, "terminal_status", err)
	}
	if err := store.operations.close(store.logFD); err != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceFinalize, "close_log", err)
	}
	store.logFD = -1
	store.finalized = true
	result, err := ports.NewRuntimeDiagnosticFinalizeResult(store.request.RunPath(), store.sequence)
	if err != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceFinalize, "result", err)
	}
	return result, nil
}

func (store *DiagnosticStore) closeLog() {
	if store.logFD >= 0 {
		closeFD(store.logFD)
		store.logFD = -1
	}
}

func defaultDiagnosticStoreOperations() diagnosticStoreOperations {
	return diagnosticStoreOperations{write: unix.Write, fsync: unix.Fsync, close: unix.Close}
}

func mandatoryRuntimeDiagnosticEvent(code domain.RuntimeDiagnosticEventCode) bool {
	switch code {
	case domain.DiagnosticRuntimeOpened, domain.DiagnosticRunStarted, domain.DiagnosticAttemptFailed,
		domain.DiagnosticProcessTimedOut, domain.DiagnosticProcessCancelled, domain.DiagnosticProcessTerminated,
		domain.DiagnosticOutputParseFailed, domain.DiagnosticValidationFailed, domain.DiagnosticRepairExhausted,
		domain.DiagnosticFallbackEligible, domain.DiagnosticFallbackScheduled, domain.DiagnosticFallbackProhibited,
		domain.DiagnosticRoleExhausted, domain.DiagnosticPublicationFailed, domain.DiagnosticRunCompleted,
		domain.DiagnosticRunStopped, domain.DiagnosticRuntimeClosed:
		return true
	default:
		return false
	}
}

func (store *DiagnosticStore) PersistRaw(ctx context.Context, request ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error) {
	if ctx == nil {
		return ports.RuntimeDiagnosticRawResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceRaw, "nil_context", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return ports.RuntimeDiagnosticRawResult{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.finalized {
		return ports.RuntimeDiagnosticRawResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceRaw, "closed", errors.New("diagnostic store is finalized"))
	}
	destination, err := ports.NewSafeRelativePath(fmt.Sprintf("%s/attempts/%s/invocations/%03d-%s/%s.raw", store.request.RunPath().String(), request.AttemptID().String(), request.Ordinal(), request.Purpose(), request.Stream()))
	if err != nil {
		return ports.RuntimeDiagnosticRawResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceRaw, "path", err)
	}
	writeRequest, err := ports.NewSecureWriteRequest(store.request.Root(), destination, "provider_"+string(request.Stream()), request.Source(), request.MaxBytes(), request.SourceIDs(), request.Abort())
	if err != nil {
		return ports.RuntimeDiagnosticRawResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceRaw, "request", err)
	}
	receipt, drop, writeErr := store.writer.Write(ctx, writeRequest)
	if drop != nil {
		result, resultErr := ports.NewRuntimeDiagnosticRawResult(request.Stream(), ports.SafeRelativePath{}, drop, 0)
		if resultErr != nil {
			return ports.RuntimeDiagnosticRawResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceRaw, "drop_result", errors.Join(writeErr, resultErr))
		}
		return result, ports.NewRuntimeDiagnosticSecurityRejectionError(*drop, writeErr)
	}
	if receipt.Destination().Valid() {
		result, resultErr := ports.NewRuntimeDiagnosticRawResult(request.Stream(), receipt.Destination(), nil, receipt.ByteLength())
		if resultErr != nil {
			return ports.RuntimeDiagnosticRawResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceRaw, "installed_result", errors.Join(writeErr, resultErr))
		}
		if writeErr != nil {
			return result, diagnosticPersistenceError(ports.DiagnosticPersistenceRaw, "installed_undurable", writeErr)
		}
		return result, nil
	}
	if writeErr == nil {
		writeErr = errors.New("secure writer returned no receipt or drop")
	}
	return ports.RuntimeDiagnosticRawResult{}, diagnosticPersistenceError(ports.DiagnosticPersistenceRaw, "write", writeErr)
}
