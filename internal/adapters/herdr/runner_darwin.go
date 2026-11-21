//go:build darwin && arm64

package herdr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	maxTerminalScreenCaptureBytes = 4 * 1024 * 1024
	idlePostSendPollInterval      = 50 * time.Millisecond
	postKillGraceDuration         = 150 * time.Millisecond
	internalRunNonceLabelKey      = "mulgae_run_nonce"
)

var emptyProviderStdinDigest = func() string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	return hex.EncodeToString(hash.Sum(nil))
}()

type processInspector interface {
	signalGroupZero(pid int) error
	signalGroupKill(pid int) error
	signalPIDKill(pid int) error
	sessionPIDs(sid int) ([]int, error)
	pgrpPIDs(pgid int) ([]int, error)
	getSID(pid int) (int, error)
	processInfo(pid int) (processInfo, error)
}

type darwinProcessInspector struct{}

func (darwinProcessInspector) signalGroupZero(pid int) error {
	return unix.Kill(-pid, 0)
}

func (darwinProcessInspector) signalGroupKill(pid int) error {
	return unix.Kill(-pid, unix.SIGKILL)
}

func (darwinProcessInspector) signalPIDKill(pid int) error {
	return unix.Kill(pid, unix.SIGKILL)
}

func (darwinProcessInspector) sessionPIDs(sid int) ([]int, error) {
	if sid <= 0 || sid > math.MaxInt32 {
		return nil, nil
	}
	// Modern macOS XNU disables sysctl KERN_PROC_SESSION (returning ENOENT).
	// Enumerate same-UID processes via kern.proc.uid and check unix.Getsid(pid)
	// == sid, which remains exact even after the session leader exits or when a
	// descendant moves to a distinct process group within the same session.
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.uid", unix.Geteuid())
	if err != nil {
		return nil, err
	}
	out := make([]int, 0)
	for _, kp := range procs {
		pid := int(kp.Proc.P_pid)
		if pid <= 0 {
			continue
		}
		if procSID, sidErr := unix.Getsid(pid); sidErr == nil && procSID == sid {
			out = append(out, pid)
		}
	}
	return out, nil
}

func (darwinProcessInspector) pgrpPIDs(pgid int) ([]int, error) {
	if pgid <= 0 || pgid > math.MaxInt32 {
		return nil, nil
	}
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]int, 0, len(procs))
	for _, kp := range procs {
		if int(kp.Eproc.Pgid) == pgid && kp.Proc.P_pid > 0 {
			out = append(out, int(kp.Proc.P_pid))
		}
	}
	return out, nil
}

func (darwinProcessInspector) getSID(pid int) (int, error) {
	return unix.Getsid(pid)
}

func (darwinProcessInspector) processInfo(pid int) (processInfo, error) {
	return inspectProcess(pid)
}

// RunTerminal executes one guarded provider pane inside this isolated
// herdr-core session. It always consumes and closes
// request.Process().LaunchDirectory() on every return path.
func (s *Session) RunTerminal(ctx context.Context, request ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
	launchDir, _, hasLaunchDir := request.Process().LaunchDirectory()
	launchDirClosed := false
	closeLaunchDir := func() {
		if hasLaunchDir && launchDir != nil && !launchDirClosed {
			launchDirClosed = true
			_ = launchDir.Close()
		}
	}
	defer closeLaunchDir()

	if s == nil {
		return ports.TerminalExecutionObservation{}, fmt.Errorf("herdr runner: nil session")
	}
	if ctx == nil {
		return ports.TerminalExecutionObservation{}, fmt.Errorf("herdr runner: nil context")
	}
	if !request.Valid() {
		return ports.TerminalExecutionObservation{}, fmt.Errorf("herdr runner: invalid terminal execution request")
	}
	procReq := request.Process()
	binding, hasBinding := procReq.ProviderPacketBinding()
	if !hasBinding || binding.Channel() != ports.ProviderPacketChannelTerminal {
		return ports.TerminalExecutionObservation{}, fmt.Errorf("herdr runner: terminal packet binding is required")
	}

	if err := s.ensureStarted(ctx); err != nil {
		if errors.Is(err, ErrUnsafeExecutable) {
			return processExecutionFailure(domain.DiagnosticCauseTransportVerificationFailed, "", nil, err)
		}
		return ports.TerminalExecutionObservation{}, err
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	stopSessionLink := context.AfterFunc(s.sessionCtx, cancelRun)
	defer stopSessionLink()

	s.mu.Lock()
	if s.state != sessionRunning || s.closeRequested {
		s.mu.Unlock()
		return ports.TerminalExecutionObservation{}, ErrSessionClosed
	}
	s.activeRuns++
	rpc := s.rpc
	identity := s.identity
	sessionDir := s.sessionDir
	socketPath := s.socketPath
	panesDir := s.panesDir
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.activeRuns--
		if s.activeRuns == 0 && s.runsIdleCh != nil {
			close(s.runsIdleCh)
			s.runsIdleCh = nil
		}
		s.mu.Unlock()
	}()

	startedAt := s.nowUTC()
	// Anchor total and startup budgets immediately after startedAt so launch
	// staging and terminal.run are accounted for inside the configured timeouts.
	anchorNow := time.Now()
	totalDeadline := anchorNow.Add(procReq.Timeout())
	startupDeadline := anchorNow.Add(request.StartupTimeout())
	if totalDeadline.Before(startupDeadline) {
		startupDeadline = totalDeadline
	}

	emptyStdin, err := ports.NewStdinWriteReceipt(0, 0, emptyProviderStdinDigest, true)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", nil, err)
	}

	euid := uint32(unix.Geteuid())
	promptPath := request.PromptFilePath().String()
	packetIdentity := binding.PacketIdentity()
	preStartFP, err := hashPromptFileIdentity(promptPath, packetIdentity, euid)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCausePromptFilePreStartFailed, "", nil,
			fmt.Errorf("herdr runner: verify prompt file before start: %w", err))
	}

	if err := runCtx.Err(); err != nil {
		return s.preStartContextFailure(err, startedAt, emptyStdin, identity, promptPath, packetIdentity, preStartFP, euid)
	}
	if !time.Now().Before(totalDeadline) {
		return s.preStartContextFailure(context.DeadlineExceeded, startedAt, emptyStdin, identity, promptPath, packetIdentity, preStartFP, euid)
	}

	paneDir, err := s.createPerPaneControlDir(panesDir, euid)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil,
			fmt.Errorf("herdr runner: create per-pane control dir: %w", err))
	}
	defer func() { _ = os.RemoveAll(paneDir) }()

	guardedProcReq, err := s.overlayControlPlane(procReq, sessionDir, socketPath, euid)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil,
			fmt.Errorf("herdr runner: overlay control plane: %w", err))
	}
	paneDirRoot, err := ports.NewAnchoredRoot(paneDir)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil, err)
	}
	launchReq, err := ports.NewPaneLaunchRequest(guardedProcReq, paneDirRoot)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil,
			fmt.Errorf("herdr runner: build pane launch request: %w", err))
	}
	buildCtx, cancelBuild := context.WithDeadline(runCtx, startupDeadline)
	paneSpec, err := s.launchBuilder.BuildPaneLaunch(buildCtx, launchReq)
	cancelBuild()
	closeLaunchDir()
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return s.preStartContextFailure(err, startedAt, emptyStdin, identity, promptPath, packetIdentity, preStartFP, euid)
		}
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil,
			fmt.Errorf("herdr runner: build pane launch spec: %w", err))
	}

	runNonce, err := randomHexBytes(8)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil,
			fmt.Errorf("herdr runner: generate run nonce: %w", err))
	}
	runLabels := cloneLabelsWithRunNonce(request.Labels(), runNonce)

	runParams := RunParams{
		Argv:     paneSpec.Argv(),
		CWD:      procReq.WorkingDirectory(),
		Labels:   runLabels,
		NoParent: true,
		NoNotify: true,
		Keep:     false,
		RM:       false,
		Wait:     false,
	}
	if request.Columns() > 0 && request.Rows() > 0 {
		runParams.Size = &InitialSize{
			Cols: uint16(request.Columns()),
			Rows: uint16(request.Rows()),
		}
	}

	runStartCtx, cancelRunStart := context.WithDeadline(runCtx, startupDeadline)
	term, runErr := rpc.TerminalRun(runStartCtx, runParams)
	cancelRunStart()
	if runErr != nil {
		// If terminal.run timed out, was cancelled, or hit a transport error,
		// the daemon may still have spawned the pane. Clean up any matching
		// run-nonce pane before returning so panes are never orphaned.
		if cleanupErr := s.cleanupOrphanedRunNonce(rpc, runNonce); cleanupErr != nil {
			return processExecutionFailure(
				domain.DiagnosticCauseProviderSpawnFailed,
				domain.DiagnosticCauseProcessGroupCleanupFailed,
				nil,
				errors.Join(fmt.Errorf("herdr runner: terminal.run: %w", runErr), cleanupErr),
			)
		}
		if errors.Is(runErr, context.Canceled) || (errors.Is(runErr, context.DeadlineExceeded) && (runCtx.Err() != nil || !time.Now().Before(startupDeadline))) {
			return s.preStartContextFailure(runErr, startedAt, emptyStdin, identity, promptPath, packetIdentity, preStartFP, euid)
		}
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil,
			fmt.Errorf("herdr runner: terminal.run: %w", runErr))
	}
	if !ports.ValidTerminalPaneID(term.Address) {
		_ = s.cleanupOrphanedRunNonce(rpc, runNonce)
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil,
			fmt.Errorf("herdr runner: invalid pane address %q", term.Address))
	}
	paneID := term.Address
	s.refreshHolders(context.Background())

	panePID := terminalPID(term)
	paneSID := s.capturePaneSID(panePID)
	var paneStartSec, paneStartUsec int64
	if term.State != "finished" {
		paneStartSec, paneStartUsec = s.capturePaneStartTime(panePID, term.CreatedMS)
	}
	s.recordTrackedPane(paneID, trackedPane{
		PID:       panePID,
		SID:       paneSID,
		StartSec:  paneStartSec,
		StartUsec: paneStartUsec,
		CreatedMS: term.CreatedMS,
	})

	checkIn := request.CheckInInterval()
	if checkIn <= 0 {
		checkIn = s.checkInInterval
	}

	state := &paneLifecycleState{
		paneID:          paneID,
		panePID:         panePID,
		paneSID:         paneSID,
		paneStartSec:    paneStartSec,
		paneStartUsec:   paneStartUsec,
		createdMS:       term.CreatedMS,
		lastTerminal:    term,
		reported:        term.Reported,
		turnCount:       int(term.Turn),
		totalDeadline:   totalDeadline,
		startupDeadline: startupDeadline,
		checkIn:         checkIn,
	}
	s.ingestTerminal(state, term)

	monitorErr := s.monitorPane(runCtx, rpc, request, state)

	teardownCtx, teardownCancel := context.WithTimeout(context.Background(), s.teardownTimeout)
	defer teardownCancel()
	teardownResult, teardownErr := s.teardownPane(teardownCtx, rpc, state)
	if teardownErr != nil {
		if monitorErr != nil {
			return processExecutionFailure(
				domain.DiagnosticCauseProviderProcessWaitFailed,
				domain.DiagnosticCauseProcessGroupCleanupFailed,
				teardownResult.screenCapture,
				errors.Join(monitorErr, teardownErr),
			)
		}
		return processExecutionFailure(
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			"",
			teardownResult.screenCapture,
			teardownErr,
		)
	}
	if monitorErr != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseProviderProcessWaitFailed,
			"",
			teardownResult.screenCapture,
			monitorErr,
		)
	}

	postEndFP, err := hashPromptFileIdentity(promptPath, packetIdentity, euid)
	if err != nil || postEndFP != preStartFP {
		if err == nil {
			err = fmt.Errorf("prompt file identity changed between pre-start and post-teardown")
		}
		return processExecutionFailure(
			domain.DiagnosticCausePromptFilePostEndFailed,
			"",
			teardownResult.screenCapture,
			fmt.Errorf("herdr runner: verify prompt file after teardown: %w", err),
		)
	}

	transportReceipt, err := ports.NewTerminalProviderPacketTransportReceipt(
		packetIdentity,
		preStartFP.identity,
		postEndFP.identity,
	)
	if err != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseTransportReceiptMismatch,
			"",
			teardownResult.screenCapture,
			err,
		)
	}

	lifecycleReceipt, err := ports.NewProcessLifecycleReceipt(
		teardownResult.finalTermination,
		true,
		teardownResult.signalRequests,
	)
	if err != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseLifecycleReceiptInvalid,
			"",
			teardownResult.screenCapture,
			err,
		)
	}

	disposition := ports.ProcessTerminationExited
	switch {
	case state.cancelled:
		disposition = ports.ProcessTerminationCancelled
	case state.timedOut:
		disposition = ports.ProcessTerminationTimedOut
	case teardownResult.residualEscalated:
		disposition = ports.ProcessTerminationResidualProcessGroup
	case teardownResult.finalTermination.Kind() == ports.ProcessFinalTerminationSignaled:
		disposition = ports.ProcessTerminationSignaled
	}

	endedAt := s.nowUTC()
	procObs, err := ports.NewStartedProviderProcessObservation(
		teardownResult.screenCapture,
		nil,
		disposition,
		emptyStdin,
		transportReceipt,
		lifecycleReceipt,
		startedAt,
		endedAt,
	)
	if err != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseObservationInvalid,
			"",
			teardownResult.screenCapture,
			err,
		)
	}

	obsInput := ports.TerminalExecutionObservationInput{
		Process:            procObs,
		RuntimeIdentity:    identity,
		Reported:           state.reported,
		ExitedBeforeReport: state.exitedBeforeReport,
		ScreenCapture:      teardownResult.screenCapture,
		PaneID:             paneID,
	}
	if state.reported {
		obsInput.ProgramStatus = state.programStatus
		if state.programStatus == ports.TerminalProgramStatusBlocked {
			obsInput.BlockedKind = state.blockedKind
		}
		obsInput.TurnCount = state.turnCount
	}

	obs, err := ports.NewTerminalExecutionObservation(obsInput)
	if err != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseObservationInvalid,
			"",
			teardownResult.screenCapture,
			err,
		)
	}
	return obs, nil
}

func cloneLabelsWithRunNonce(labels map[string]string, nonce string) map[string]string {
	out := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		out[k] = v
	}
	out[internalRunNonceLabelKey] = nonce
	return out
}

func (s *Session) cleanupOrphanedRunNonce(rpc *RPCClient, runNonce string) error {
	if rpc == nil || runNonce == "" {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), s.teardownTimeout)
	defer cancel()
	s.refreshHolders(cleanupCtx)
	return s.drainMatchingPanes(cleanupCtx, rpc, internalRunNonceLabelKey, runNonce)
}

// DrainLabeledPanes retryably kills, verifies ESRCH + session absence for, and
// removes ONLY panes matching labelKey=labelValue without ever calling
// server.stop.
func (s *Session) DrainLabeledPanes(ctx context.Context, labelKey, labelValue string) error {
	if s == nil {
		return fmt.Errorf("herdr runner: nil session")
	}
	if ctx == nil {
		return fmt.Errorf("herdr runner: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ports.ValidTerminalLabel(labelKey, labelValue) {
		return fmt.Errorf("herdr runner: invalid terminal label")
	}

	s.mu.Lock()
	if s.state == sessionIdle || s.state == sessionClosed || s.rpc == nil {
		s.mu.Unlock()
		return nil
	}
	rpc := s.rpc
	s.mu.Unlock()

	return s.drainMatchingPanes(ctx, rpc, labelKey, labelValue)
}

func (s *Session) drainMatchingPanes(ctx context.Context, rpc *RPCClient, labelKey, labelValue string) error {
	teardownDeadline := time.Now().Add(s.teardownTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(teardownDeadline) {
		teardownDeadline = ctxDeadline
	}
	drainCtx, cancelDrain := context.WithDeadline(ctx, teardownDeadline)
	defer cancelDrain()

	listRes, err := rpc.TerminalList(drainCtx, ListParams{
		All:    true,
		Labels: map[string]string{labelKey: labelValue},
	})
	if err != nil {
		return fmt.Errorf("herdr runner: list labeled panes: %w", err)
	}

	var errs []error
	for _, term := range listRes.Terminals {
		if term.Labels[labelKey] != labelValue {
			continue
		}
		paneID := term.Address
		if !ports.ValidTerminalPaneID(paneID) {
			errs = append(errs, fmt.Errorf("herdr runner: invalid pane address %q during drain", paneID))
			continue
		}

		tracked, isTracked := s.lookupTrackedPane(paneID)
		termPID := terminalPID(term)
		if term.State != "finished" {
			pane := mergeTrackedPane(tracked, termPID, 0, 0, 0, term.CreatedMS)
			if validTargetPID(pane.PID) {
				if pane.SID == 0 {
					pane.SID = s.capturePaneSID(pane.PID)
				}
				if !hasStartTime(pane.StartSec, pane.StartUsec) {
					pane.StartSec, pane.StartUsec = s.capturePaneStartTime(pane.PID, pane.CreatedMS)
				}
			}
			s.recordTrackedPane(paneID, pane)

			killed, killErr := rpc.TerminalKill(drainCtx, paneID)
			if killErr != nil && !IsRPCErrorKind(killErr, "not_found") {
				// Even when terminal.kill fails, force local SIGKILL + absence
				// verification so live panes are never orphaned.
				var localErr error
				if validTargetPID(pane.PID) {
					_, localErr = s.verifyPaneProcessGroupAndSessionAbsent(pane, teardownDeadline, true, 0)
				}
				errs = append(errs, errors.Join(fmt.Errorf("herdr runner: kill pane %s: %w", paneID, killErr), localErr))
				continue
			}
			if killErr == nil {
				if pane.CreatedMS == 0 && killed.CreatedMS > 0 {
					pane.CreatedMS = killed.CreatedMS
				}
				if p := terminalPID(killed); validTargetPID(p) && !validTargetPID(pane.PID) {
					pane.PID = p
					if pane.SID == 0 {
						pane.SID = s.capturePaneSID(p)
					}
					if killed.State != "finished" && !hasStartTime(pane.StartSec, pane.StartUsec) {
						pane.StartSec, pane.StartUsec = s.capturePaneStartTime(p, pane.CreatedMS)
					}
					s.recordTrackedPane(paneID, pane)
				}
			}
			grace := min(postKillGraceDuration, max(0, time.Until(teardownDeadline)/3))
			if _, verifyErr := s.verifyPaneProcessGroupAndSessionAbsent(pane, teardownDeadline, true, grace); verifyErr != nil {
				errs = append(errs, fmt.Errorf("herdr runner: drain pane %s (%s): %w", paneID, domain.DiagnosticCauseProcessGroupCleanupFailed, verifyErr))
				continue
			}
		} else {
			// Finished pane: still verify start-time-safe absence whenever
			// paneID remains tracked (unproven absence from an earlier drain
			// retry or failed RunTerminal teardown), or for untracked finished
			// panes carrying a pane PID bounded by start-time / CreatedMS.
			var pane trackedPane
			needVerify := false
			if isTracked {
				pane = mergeTrackedPane(tracked, termPID, 0, 0, 0, term.CreatedMS)
				needVerify = true
			} else if term.PID != nil {
				if !validTargetPID(termPID) {
					errs = append(errs, fmt.Errorf("herdr runner: drain pane %s (%s): unsafe pid %d",
						paneID, domain.DiagnosticCauseProcessGroupCleanupFailed, *term.PID))
					continue
				}
				pane = trackedPane{
					PID:       termPID,
					SID:       termPID,
					CreatedMS: term.CreatedMS,
				}
				needVerify = true
			}
			if needVerify {
				s.recordTrackedPane(paneID, pane)
				if _, verifyErr := s.verifyPaneProcessGroupAndSessionAbsent(pane, teardownDeadline, true, 0); verifyErr != nil {
					errs = append(errs, fmt.Errorf("herdr runner: drain pane %s (%s): %w", paneID, domain.DiagnosticCauseProcessGroupCleanupFailed, verifyErr))
					continue
				}
			}
		}

		if rmErr := removePaneWithRetry(drainCtx, rpc, paneID, teardownDeadline, nil); rmErr != nil {
			errs = append(errs, fmt.Errorf("herdr runner: remove pane %s: %w", paneID, rmErr))
			continue
		}
		s.clearTrackedPane(paneID)
	}
	return errors.Join(errs...)
}

func mergeTrackedPane(base trackedPane, pid, sid int, startSec, startUsec int64, createdMS uint64) trackedPane {
	if !validTargetPID(base.PID) && validTargetPID(pid) {
		base.PID = pid
	}
	if base.SID <= 1 && sid > 1 && sid <= math.MaxInt32 {
		base.SID = sid
	}
	if !hasStartTime(base.StartSec, base.StartUsec) && hasStartTime(startSec, startUsec) {
		base.StartSec = startSec
		base.StartUsec = startUsec
	}
	if base.CreatedMS == 0 && createdMS > 0 {
		base.CreatedMS = createdMS
	}
	return base
}

type paneLifecycleState struct {
	paneID             string
	panePID            int
	paneSID            int
	paneStartSec       int64
	paneStartUsec      int64
	createdMS          uint64
	lastTerminal       Terminal
	reported           bool
	exitedBeforeReport bool
	programStatus      ports.TerminalProgramStatus
	blockedKind        ports.TerminalBlockedKind
	turnCount          int
	naturalExit        bool
	timedOut           bool
	cancelled          bool
	totalDeadline      time.Time
	startupDeadline    time.Time
	checkIn            time.Duration
}

func (st *paneLifecycleState) trackedPane() trackedPane {
	return trackedPane{
		PID:       st.panePID,
		SID:       st.paneSID,
		StartSec:  st.paneStartSec,
		StartUsec: st.paneStartUsec,
		CreatedMS: st.createdMS,
	}
}

func (s *Session) ingestTerminal(st *paneLifecycleState, term Terminal) {
	st.lastTerminal = term
	if st.createdMS == 0 && term.CreatedMS > 0 {
		st.createdMS = term.CreatedMS
	}
	if p := terminalPID(term); validTargetPID(p) && !validTargetPID(st.panePID) {
		st.panePID = p
		if st.paneSID == 0 {
			st.paneSID = s.capturePaneSID(p)
		}
		if term.State != "finished" && !hasStartTime(st.paneStartSec, st.paneStartUsec) {
			st.paneStartSec, st.paneStartUsec = s.capturePaneStartTime(p, st.createdMS)
		}
		s.recordTrackedPane(st.paneID, st.trackedPane())
	}
	if term.Reported {
		st.reported = true
	}
	if int(term.Turn) > st.turnCount {
		st.turnCount = int(term.Turn)
	}
	if term.Reported && term.Status != nil {
		if mapped, ok := mapTerminalProgramStatus(term.Status.State); ok {
			st.programStatus = mapped
			if mapped == ports.TerminalProgramStatusBlocked {
				st.blockedKind = mapTerminalBlockedKind(term.Status.Kind)
			} else {
				st.blockedKind = ""
			}
		}
	}
	if term.State == "finished" {
		st.naturalExit = true
		if !st.reported {
			st.exitedBeforeReport = true
		}
	}
}

func (s *Session) monitorPane(ctx context.Context, rpc *RPCClient, request ports.TerminalExecutionRequest, st *paneLifecycleState) error {
	if request.RequireOSCReporting() {
		if err := s.waitForOSCStartupReady(ctx, rpc, st, request.InitialInput() != ""); err != nil {
			return err
		}
		if st.naturalExit || st.cancelled || st.timedOut {
			return nil
		}
		if st.programStatus == ports.TerminalProgramStatusBlocked || st.programStatus == ports.TerminalProgramStatusError {
			return nil
		}
		if request.InitialInput() == "" {
			if st.programStatus == ports.TerminalProgramStatusDone || st.programStatus == ports.TerminalProgramStatusIdle {
				return nil
			}
		} else if st.programStatus == ports.TerminalProgramStatusDone {
			return fmt.Errorf("herdr runner: pane reported done before initial input was sent")
		}
	}

	if request.InitialInput() != "" && !st.naturalExit && !st.cancelled && !st.timedOut {
		if !request.RequireOSCReporting() || (st.reported && st.programStatus == ports.TerminalProgramStatusIdle) {
			sendRes, preSendTurn, sent, err := s.sendInitialInput(ctx, rpc, request, st)
			if err != nil {
				return err
			}
			if !sent || st.naturalExit || st.cancelled || st.timedOut {
				return nil
			}

			term, getErr := s.refreshPaneState(ctx, rpc, st, st.totalDeadline)
			if getErr != nil {
				if handleContextTermination(ctx, getErr, st, st.totalDeadline) {
					return nil
				}
				return fmt.Errorf("herdr runner: terminal.get after send: %w", getErr)
			}
			s.ingestTerminal(st, term)

			if request.RequireOSCReporting() {
				return s.waitForOSCTurnComplete(ctx, rpc, st, preSendTurn, sendRes)
			}
		}
	}

	if !request.RequireOSCReporting() {
		return s.waitForPlainExit(ctx, rpc, st)
	}
	return nil
}

func (s *Session) sendInitialInput(
	ctx context.Context,
	rpc *RPCClient,
	request ports.TerminalExecutionRequest,
	st *paneLifecycleState,
) (SendResult, uint64, bool, error) {
	for {
		if st.naturalExit || st.cancelled || st.timedOut {
			return SendResult{}, 0, false, nil
		}
		if request.RequireOSCReporting() {
			if st.programStatus == ports.TerminalProgramStatusBlocked || st.programStatus == ports.TerminalProgramStatusError {
				return SendResult{}, 0, false, nil
			}
			if st.programStatus == ports.TerminalProgramStatusDone {
				return SendResult{}, 0, false, fmt.Errorf("herdr runner: pane reported done before initial input was sent")
			}
		}
		activeDeadline := st.totalDeadline
		if request.RequireOSCReporting() && st.startupDeadline.Before(activeDeadline) {
			activeDeadline = st.startupDeadline
		}
		remaining := time.Until(activeDeadline)
		if remaining <= 0 {
			st.timedOut = true
			return SendResult{}, 0, false, nil
		}
		preSendTurn := st.lastTerminal.Turn
		sendParams := SendParams{
			Terminal: st.paneID,
			Text:     request.InitialInput(),
			Force:    false,
			Wait:     false,
		}
		if request.RequireOSCReporting() {
			sendParams.If = "idle"
		}

		sendCtx, cancelSend := context.WithTimeout(ctx, remaining)
		sendRes, sendErr := rpc.TerminalSend(sendCtx, sendParams)
		cancelSend()
		if sendErr == nil {
			return sendRes, preSendTurn, true, nil
		}
		if handleContextTermination(ctx, sendErr, st, activeDeadline) {
			return SendResult{}, 0, false, nil
		}
		if IsRPCErrorKind(sendErr, "blocked") || IsRPCErrorKind(sendErr, "finished") {
			term, getErr := s.refreshPaneState(ctx, rpc, st, st.totalDeadline)
			if getErr != nil {
				if handleContextTermination(ctx, getErr, st, st.totalDeadline) {
					return SendResult{}, 0, false, nil
				}
				return SendResult{}, 0, false, fmt.Errorf("herdr runner: terminal.get after send %v: %w", sendErr, getErr)
			}
			s.ingestTerminal(st, term)
			if st.naturalExit || st.programStatus == ports.TerminalProgramStatusBlocked || st.programStatus == ports.TerminalProgramStatusError {
				return SendResult{}, 0, false, nil
			}
			if st.programStatus == ports.TerminalProgramStatusDone {
				return SendResult{}, 0, false, fmt.Errorf("herdr runner: pane reported done before initial input was sent")
			}
			return SendResult{}, 0, false, fmt.Errorf("herdr runner: terminal.send: %w", sendErr)
		}
		if IsRPCErrorKind(sendErr, "status_mismatch") {
			term, getErr := s.refreshPaneState(ctx, rpc, st, activeDeadline)
			if getErr != nil {
				if handleContextTermination(ctx, getErr, st, activeDeadline) {
					return SendResult{}, 0, false, nil
				}
				return SendResult{}, 0, false, fmt.Errorf("herdr runner: terminal.get after status_mismatch: %w", getErr)
			}
			s.ingestTerminal(st, term)
			if st.naturalExit || st.programStatus == ports.TerminalProgramStatusBlocked || st.programStatus == ports.TerminalProgramStatusError {
				return SendResult{}, 0, false, nil
			}
			if st.programStatus == ports.TerminalProgramStatusDone {
				return SendResult{}, 0, false, fmt.Errorf("herdr runner: pane reported done before initial input was sent")
			}
			if st.programStatus == ports.TerminalProgramStatusWorking {
				if err := s.waitForOSCStartupReady(ctx, rpc, st, true); err != nil {
					return SendResult{}, 0, false, err
				}
				continue
			}
			if !sleepContext(ctx, min(idlePostSendPollInterval, max(time.Millisecond, time.Until(activeDeadline))), st) {
				return SendResult{}, 0, false, nil
			}
			continue
		}
		return SendResult{}, 0, false, fmt.Errorf("herdr runner: terminal.send: %w", sendErr)
	}
}

func startupActiveDeadline(st *paneLifecycleState, hasInitialInput bool) time.Time {
	if !hasInitialInput && st.reported && st.programStatus == ports.TerminalProgramStatusWorking {
		return st.totalDeadline
	}
	if st.totalDeadline.Before(st.startupDeadline) {
		return st.totalDeadline
	}
	return st.startupDeadline
}

func (s *Session) waitForOSCStartupReady(ctx context.Context, rpc *RPCClient, st *paneLifecycleState, hasInitialInput bool) error {
	for {
		if st.naturalExit {
			return nil
		}
		if st.reported && st.programStatus != "" && st.programStatus != ports.TerminalProgramStatusWorking {
			return nil
		}
		if ctx.Err() != nil {
			recordContextTermination(ctx, st)
			return nil
		}
		activeDeadline := startupActiveDeadline(st, hasInitialInput)
		remaining := time.Until(activeDeadline)
		if remaining <= 0 {
			st.timedOut = true
			return nil
		}
		waitDur := min(st.checkIn, remaining)
		waitSec := waitDur.Seconds()
		callTimeout := waitDur + 2*time.Second
		if remaining+500*time.Millisecond < callTimeout {
			callTimeout = remaining + 500*time.Millisecond
		}
		waitCtx, cancelWait := context.WithTimeout(ctx, callTimeout)
		waitRes, waitErr := rpc.TerminalWait(waitCtx, WaitParams{
			Terminal: st.paneID,
			Timeout:  &waitSec,
		})
		cancelWait()
		if waitErr != nil {
			if handleContextTermination(ctx, waitErr, st, activeDeadline) {
				return nil
			}
			if !IsRPCErrorKind(waitErr, "not_found") {
				return fmt.Errorf("herdr runner: startup terminal.wait: %w", waitErr)
			}
		}
		refreshDeadline := activeDeadline
		if !hasInitialInput && st.totalDeadline.After(refreshDeadline) {
			// Still allow one final terminal.get at StartupTimeout when
			// InitialInput is empty so a pane that transitioned to working just
			// before StartupTimeout switches cleanly to totalDeadline.
			refreshDeadline = st.totalDeadline
		}
		term, getErr := s.refreshPaneState(ctx, rpc, st, refreshDeadline)
		if getErr != nil {
			if handleContextTermination(ctx, getErr, st, refreshDeadline) {
				return nil
			}
			return fmt.Errorf("herdr runner: startup terminal.get: %w", getErr)
		}
		s.ingestTerminal(st, term)

		ready := st.naturalExit || (st.reported && st.programStatus != "" && st.programStatus != ports.TerminalProgramStatusWorking)
		if !ready && waitErr == nil && waitRes.Reason == "status" {
			activeDeadline = startupActiveDeadline(st, hasInitialInput)
			rem := time.Until(activeDeadline)
			if rem <= 0 {
				st.timedOut = true
				return nil
			}
			if !sleepContext(ctx, min(idlePostSendPollInterval, rem), st) {
				return nil
			}
		}
	}
}

func (s *Session) waitForOSCTurnComplete(
	ctx context.Context,
	rpc *RPCClient,
	st *paneLifecycleState,
	preSendTurn uint64,
	sendRes SendResult,
) error {
	sendStarted := sendRes.Started != nil && *sendRes.Started
	sendTurnBaseline := preSendTurn
	if sendRes.Turn > sendTurnBaseline {
		sendTurnBaseline = sendRes.Turn
	}
	sawWorking := false

	for {
		if st.naturalExit {
			return nil
		}
		if st.reported && st.programStatus == ports.TerminalProgramStatusWorking {
			sawWorking = true
		}
		if st.reported {
			turnAdvanced := st.lastTerminal.Turn > preSendTurn && st.lastTerminal.Turn >= sendTurnBaseline
			if sendRes.Started != nil && !*sendRes.Started {
				// When terminal.send reported Started==false, require turn strictly
				// beyond both preSendTurn and sendRes.Turn (or an observed working
				// state transition) before treating idle/done as turn completion.
				turnAdvanced = st.lastTerminal.Turn > preSendTurn && st.lastTerminal.Turn > sendRes.Turn
			}
			switch st.programStatus {
			case ports.TerminalProgramStatusBlocked, ports.TerminalProgramStatusError:
				return nil
			case ports.TerminalProgramStatusDone:
				if turnAdvanced || sawWorking || (sendStarted && st.lastTerminal.Turn > preSendTurn) {
					return nil
				}
			case ports.TerminalProgramStatusIdle:
				if turnAdvanced || sawWorking {
					return nil
				}
			}
		}
		if ctx.Err() != nil {
			recordContextTermination(ctx, st)
			return nil
		}
		remaining := time.Until(st.totalDeadline)
		if remaining <= 0 {
			st.timedOut = true
			return nil
		}

		// While the program has not yet left pre-work idle/done, terminal.wait
		// would return immediately; sleep briefly before re-polling so we
		// neither busy-spin nor falsely treat pre-work state as completion.
		if st.reported && (st.programStatus == ports.TerminalProgramStatusIdle || st.programStatus == ports.TerminalProgramStatusDone) && !sawWorking {
			if !sleepContext(ctx, min(idlePostSendPollInterval, remaining), st) {
				return nil
			}
			term, getErr := s.refreshPaneState(ctx, rpc, st, st.totalDeadline)
			if getErr != nil {
				if handleContextTermination(ctx, getErr, st, st.totalDeadline) {
					return nil
				}
				return fmt.Errorf("herdr runner: post-send terminal.get: %w", getErr)
			}
			s.ingestTerminal(st, term)
			continue
		}

		waitDur := min(st.checkIn, remaining)
		waitSec := waitDur.Seconds()
		callTimeout := waitDur + 2*time.Second
		if remaining+500*time.Millisecond < callTimeout {
			callTimeout = remaining + 500*time.Millisecond
		}
		waitCtx, cancelWait := context.WithTimeout(ctx, callTimeout)
		_, waitErr := rpc.TerminalWait(waitCtx, WaitParams{
			Terminal: st.paneID,
			Timeout:  &waitSec,
		})
		cancelWait()
		if waitErr != nil {
			if handleContextTermination(ctx, waitErr, st, st.totalDeadline) {
				return nil
			}
			return fmt.Errorf("herdr runner: turn terminal.wait: %w", waitErr)
		}

		term, getErr := s.refreshPaneState(ctx, rpc, st, st.totalDeadline)
		if getErr != nil {
			if handleContextTermination(ctx, getErr, st, st.totalDeadline) {
				return nil
			}
			return fmt.Errorf("herdr runner: turn terminal.get: %w", getErr)
		}
		s.ingestTerminal(st, term)
	}
}

func (s *Session) waitForPlainExit(ctx context.Context, rpc *RPCClient, st *paneLifecycleState) error {
	for {
		if st.naturalExit {
			return nil
		}
		if ctx.Err() != nil {
			recordContextTermination(ctx, st)
			return nil
		}
		remaining := time.Until(st.totalDeadline)
		if remaining <= 0 {
			st.timedOut = true
			return nil
		}
		waitDur := min(st.checkIn, remaining)
		waitSec := waitDur.Seconds()
		callTimeout := waitDur + 2*time.Second
		if remaining+500*time.Millisecond < callTimeout {
			callTimeout = remaining + 500*time.Millisecond
		}
		waitCtx, cancelWait := context.WithTimeout(ctx, callTimeout)
		waitRes, waitErr := rpc.TerminalWait(waitCtx, WaitParams{
			Terminal: st.paneID,
			Timeout:  &waitSec,
		})
		cancelWait()
		if waitErr != nil {
			if handleContextTermination(ctx, waitErr, st, st.totalDeadline) {
				return nil
			}
			return fmt.Errorf("herdr runner: plain terminal.wait: %w", waitErr)
		}
		term, getErr := s.refreshPaneState(ctx, rpc, st, st.totalDeadline)
		if getErr != nil {
			if handleContextTermination(ctx, getErr, st, st.totalDeadline) {
				return nil
			}
			return fmt.Errorf("herdr runner: plain terminal.get: %w", getErr)
		}
		s.ingestTerminal(st, term)

		if !st.naturalExit && waitRes.Reason == "status" {
			rem := time.Until(st.totalDeadline)
			if rem <= 0 {
				st.timedOut = true
				return nil
			}
			if !sleepContext(ctx, min(idlePostSendPollInterval, rem), st) {
				return nil
			}
		}
	}
}

func sleepContext(ctx context.Context, d time.Duration, st *paneLifecycleState) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		recordContextTermination(ctx, st)
		return false
	case <-timer.C:
		return true
	}
}

func (s *Session) refreshPaneState(ctx context.Context, rpc *RPCClient, st *paneLifecycleState, activeDeadline time.Time) (Terminal, error) {
	rem := time.Until(activeDeadline)
	if rem <= 0 {
		return Terminal{}, context.DeadlineExceeded
	}
	getCtx, cancel := context.WithTimeout(ctx, min(2*time.Second, max(50*time.Millisecond, rem)))
	defer cancel()
	return rpc.TerminalGet(getCtx, st.paneID)
}

type paneTeardownResult struct {
	finalTermination  ports.ProcessFinalTermination
	signalRequests    []ports.ProcessGroupSignalRequestReceipt
	screenCapture     []byte
	residualEscalated bool
}

func (s *Session) teardownPane(ctx context.Context, rpc *RPCClient, st *paneLifecycleState) (paneTeardownResult, error) {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(s.teardownTimeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	baseReason := ports.ProcessGroupSignalRequestTerminalTeardown
	escalationReason := ports.ProcessGroupSignalRequestTerminalTeardownEscalation
	if st.cancelled {
		baseReason = ports.ProcessGroupSignalRequestCancellation
		escalationReason = ports.ProcessGroupSignalRequestCancellation
	} else if st.timedOut {
		baseReason = ports.ProcessGroupSignalRequestTimeout
		escalationReason = ports.ProcessGroupSignalRequestTimeout
	}

	var signalRequests []ports.ProcessGroupSignalRequestReceipt
	appendSignalRequest := func(reason ports.ProcessGroupSignalRequestReason, sigNum int) {
		sig, err := ports.NewProcessSignalFromNumber(sigNum)
		if err != nil {
			return
		}
		for _, existing := range signalRequests {
			if existing.Reason() == reason && existing.Signal() == sig {
				return
			}
		}
		if receipt, err := ports.NewAcceptedProcessGroupSignalRequestReceipt(reason, sig); err == nil {
			signalRequests = append(signalRequests, receipt)
		}
	}

	term := st.lastTerminal
	killIssued := false
	killNotFound := false
	if term.State != "finished" {
		killIssued = true
		killed, killErr := rpc.TerminalKill(ctx, st.paneID)
		if killErr != nil {
			if IsRPCErrorKind(killErr, "not_found") {
				killNotFound = true
			} else {
				// Still run local SIGKILL + absence verification so a live pane
				// is never orphaned when terminal.kill fails.
				var localErr error
				if validTargetPID(st.panePID) {
					_, localErr = s.verifyPaneProcessGroupAndSessionAbsent(st.trackedPane(), deadline, true, 0)
				}
				return paneTeardownResult{}, errors.Join(fmt.Errorf("herdr teardown: terminal.kill %s: %w", st.paneID, killErr), localErr)
			}
		} else {
			appendSignalRequest(baseReason, int(unix.SIGHUP))
			term = killed
			if st.createdMS == 0 && term.CreatedMS > 0 {
				st.createdMS = term.CreatedMS
			}
			if p := terminalPID(term); validTargetPID(p) && !validTargetPID(st.panePID) {
				st.panePID = p
				if st.paneSID == 0 {
					st.paneSID = s.capturePaneSID(p)
				}
				if term.State != "finished" && !hasStartTime(st.paneStartSec, st.paneStartUsec) {
					st.paneStartSec, st.paneStartUsec = s.capturePaneStartTime(p, st.createdMS)
				}
				s.recordTrackedPane(st.paneID, st.trackedPane())
			}
		}
	}

	// If panePID was absent on initial run result, attempt one refresh before
	// failing closed in verifyPaneProcessGroupAndSessionAbsent.
	if !validTargetPID(st.panePID) {
		if refreshed, err := rpc.TerminalGet(ctx, st.paneID); err == nil {
			term = refreshed
			if st.createdMS == 0 && refreshed.CreatedMS > 0 {
				st.createdMS = refreshed.CreatedMS
			}
			if p := terminalPID(refreshed); validTargetPID(p) {
				st.panePID = p
				if st.paneSID == 0 {
					st.paneSID = s.capturePaneSID(p)
				}
				if refreshed.State != "finished" && !hasStartTime(st.paneStartSec, st.paneStartUsec) {
					st.paneStartSec, st.paneStartUsec = s.capturePaneStartTime(p, st.createdMS)
				}
				s.recordTrackedPane(st.paneID, st.trackedPane())
			}
		}
	}

	grace := time.Duration(0)
	if killIssued && !killNotFound {
		grace = min(postKillGraceDuration, max(0, time.Until(deadline)/3))
	}
	escalated, verifyErr := s.verifyPaneProcessGroupAndSessionAbsent(st.trackedPane(), deadline, true, grace)
	if verifyErr != nil {
		screen := captureBoundedScreen(ctx, rpc, st.paneID)
		return paneTeardownResult{screenCapture: screen}, fmt.Errorf("herdr teardown: pane %s process group/session still alive: %w", st.paneID, verifyErr)
	}
	residualEscalated := !killIssued && escalated
	if escalated {
		if residualEscalated {
			appendSignalRequest(ports.ProcessGroupSignalRequestResidualGroup, int(unix.SIGKILL))
		} else {
			appendSignalRequest(escalationReason, int(unix.SIGKILL))
		}
	}

	// Capture bounded post-kill screen diagnostics strictly AFTER proven ESRCH.
	screenCapture := captureBoundedScreen(ctx, rpc, st.paneID)

	if rmErr := removePaneWithRetry(ctx, rpc, st.paneID, deadline, &term); rmErr != nil {
		return paneTeardownResult{screenCapture: screenCapture}, fmt.Errorf("herdr teardown: terminal.rm %s: %w", st.paneID, rmErr)
	}
	s.clearTrackedPane(st.paneID)

	finalTermination, err := buildFinalTermination(term, killIssued, killNotFound, escalated, baseReason, escalationReason, appendSignalRequest)
	if err != nil {
		return paneTeardownResult{screenCapture: screenCapture}, fmt.Errorf("herdr teardown: build final termination: %w", err)
	}

	return paneTeardownResult{
		finalTermination:  finalTermination,
		signalRequests:    signalRequests,
		screenCapture:     screenCapture,
		residualEscalated: residualEscalated,
	}, nil
}

func removePaneWithRetry(
	ctx context.Context,
	rpc *RPCClient,
	paneID string,
	deadline time.Time,
	refreshTerm *Terminal,
) error {
	callCtx := ctx
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	for {
		if refreshTerm != nil && (refreshTerm.State != "finished" || (refreshTerm.ExitCode == nil && refreshTerm.Signal == nil)) {
			if refreshed, err := rpc.TerminalGet(callCtx, paneID); err == nil {
				*refreshTerm = refreshed
			}
		}
		_, rmErr := rpc.TerminalRemove(callCtx, paneID)
		if rmErr == nil || IsRPCErrorKind(rmErr, "not_found") {
			return nil
		}
		if !IsRPCErrorKind(rmErr, "live") || (!deadline.IsZero() && !time.Now().Before(deadline)) {
			return rmErr
		}
		sleepDur := processProbeInterval
		if !deadline.IsZero() {
			sleepDur = min(processProbeInterval, max(time.Millisecond, time.Until(deadline)))
		}
		timer := time.NewTimer(sleepDur)
		select {
		case <-callCtx.Done():
			timer.Stop()
			return callCtx.Err()
		case <-timer.C:
		}
	}
}

func buildFinalTermination(
	term Terminal,
	killIssued bool,
	killNotFound bool,
	escalated bool,
	baseReason ports.ProcessGroupSignalRequestReason,
	escalationReason ports.ProcessGroupSignalRequestReason,
	recordSignal func(ports.ProcessGroupSignalRequestReason, int),
) (ports.ProcessFinalTermination, error) {
	if term.Signal != nil && *term.Signal > 0 {
		sigNum := int(*term.Signal)
		if killIssued && !killNotFound {
			switch unix.Signal(sigNum) {
			case unix.SIGHUP, unix.SIGTERM:
				recordSignal(baseReason, sigNum)
			case unix.SIGKILL:
				recordSignal(escalationReason, sigNum)
			}
		}
		sig, err := ports.NewProcessSignalFromNumber(sigNum)
		if err != nil {
			return ports.ProcessFinalTermination{}, err
		}
		return ports.NewSignaledProcessFinalTermination(sig)
	}
	if term.ExitCode != nil && *term.ExitCode >= 0 {
		return ports.NewExitedProcessFinalTermination(int(*term.ExitCode))
	}
	if killNotFound {
		return ports.ProcessFinalTermination{}, fmt.Errorf("terminal.kill returned not_found with no observable exit code or signal")
	}
	if escalated {
		sigNum := int(unix.SIGKILL)
		if killIssued {
			recordSignal(escalationReason, sigNum)
		} else {
			recordSignal(ports.ProcessGroupSignalRequestResidualGroup, sigNum)
		}
		sig, err := ports.NewProcessSignalFromNumber(sigNum)
		if err != nil {
			return ports.ProcessFinalTermination{}, err
		}
		return ports.NewSignaledProcessFinalTermination(sig)
	}
	if killIssued {
		sigNum := int(unix.SIGHUP)
		recordSignal(baseReason, sigNum)
		sig, err := ports.NewProcessSignalFromNumber(sigNum)
		if err != nil {
			return ports.ProcessFinalTermination{}, err
		}
		return ports.NewSignaledProcessFinalTermination(sig)
	}
	return ports.ProcessFinalTermination{}, fmt.Errorf("pane finished without observable exit code or signal")
}

func captureBoundedScreen(ctx context.Context, rpc *RPCClient, paneID string) []byte {
	readCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	res, err := rpc.TerminalRead(readCtx, ReadParams{Terminal: paneID, Lines: 0})
	if err != nil || res.Text == "" {
		return nil
	}
	raw := []byte(res.Text)
	if len(raw) > maxTerminalScreenCaptureBytes {
		raw = raw[:maxTerminalScreenCaptureBytes]
	}
	return raw
}

func (s *Session) verifyPaneProcessGroupAndSessionAbsent(
	pane trackedPane,
	deadline time.Time,
	allowEscalate bool,
	graceBeforeEscalate time.Duration,
) (bool, error) {
	if !validTargetPID(pane.PID) {
		return false, fmt.Errorf("invalid or unsafe pane pid %d", pane.PID)
	}
	selfSID, sidErr := s.inspector.getSID(os.Getpid())
	if sidErr != nil {
		return false, fmt.Errorf("resolve caller session id: %w", sidErr)
	}
	paneSID := pane.SID
	if paneSID <= 0 {
		paneSID = pane.PID
	}
	if paneSID <= 1 || paneSID > math.MaxInt32 || paneSID == selfSID {
		return false, fmt.Errorf("invalid or unsafe pane sid %d (caller sid=%d)", paneSID, selfSID)
	}

	escalated := false
	escalateAt := time.Now().Add(max(0, graceBeforeEscalate))

	for {
		leaderInfo, leaderErr := s.inspector.processInfo(pane.PID)
		if leaderErr != nil {
			return escalated, fmt.Errorf("inspect pane pid %d: %w", pane.PID, leaderErr)
		}
		leaderReused := false
		if leaderInfo.Exists {
			if !hasStartTime(pane.StartSec, pane.StartUsec) && pane.CreatedMS == 0 {
				return escalated, fmt.Errorf("cannot verify pane pid %d identity without start time or created_ms", pane.PID)
			}
			if hasStartTime(leaderInfo.StartSec, leaderInfo.StartUsec) {
				if hasStartTime(pane.StartSec, pane.StartUsec) {
					leaderReused = leaderInfo.StartSec != pane.StartSec || leaderInfo.StartUsec != pane.StartUsec
				} else if pane.CreatedMS > 0 {
					createdAt := time.UnixMilli(int64(pane.CreatedMS))
					procStart := time.Unix(leaderInfo.StartSec, leaderInfo.StartUsec*1000)
					switch {
					case procStart.After(createdAt.Add(5 * time.Second)):
						leaderReused = true
					case procStart.Before(createdAt.Add(-2 * time.Second)):
						return escalated, fmt.Errorf("pane pid %d start time (%s) precedes pane created_ms (%s); refusing to classify or signal",
							pane.PID, procStart.UTC().Format(time.RFC3339Nano), createdAt.UTC().Format(time.RFC3339Nano))
					}
				}
			}
		}

		killZeroErr := s.inspector.signalGroupZero(pane.PID)
		groupESRCH := errors.Is(killZeroErr, unix.ESRCH)

		rawPgrp, pgrpErr := s.inspector.pgrpPIDs(pane.PID)
		rawSess, sessErr := s.inspector.sessionPIDs(paneSID)
		if pgrpErr != nil {
			return escalated, fmt.Errorf("probe pgrp %d: %w", pane.PID, pgrpErr)
		}
		if sessErr != nil {
			return escalated, fmt.Errorf("probe session %d: %w", paneSID, sessErr)
		}

		pgrpMembers, pgrpFilterErr := s.filterPaneEraMembers(rawPgrp, pane, leaderReused, leaderInfo)
		if pgrpFilterErr != nil {
			return escalated, fmt.Errorf("filter pgrp %d members: %w", pane.PID, pgrpFilterErr)
		}
		sessMembers, sessFilterErr := s.filterPaneEraMembers(rawSess, pane, leaderReused, leaderInfo)
		if sessFilterErr != nil {
			return escalated, fmt.Errorf("filter session %d members: %w", paneSID, sessFilterErr)
		}

		leaderStillPresent := leaderInfo.Exists && !leaderReused
		if !leaderStillPresent && (groupESRCH || leaderReused) && len(pgrpMembers) == 0 && len(sessMembers) == 0 {
			return escalated, nil
		}

		if allowEscalate && (escalated || !time.Now().Before(escalateAt)) {
			escalated = true
			if !leaderReused {
				_ = s.inspector.signalGroupKill(pane.PID)
				if leaderStillPresent {
					_ = s.inspector.signalPIDKill(pane.PID)
				}
			}
			for _, pid := range sessMembers {
				if validTargetPID(pid) {
					_ = s.inspector.signalPIDKill(pid)
				}
			}
			for _, pid := range pgrpMembers {
				if validTargetPID(pid) {
					_ = s.inspector.signalPIDKill(pid)
				}
			}
		}

		if !time.Now().Before(deadline) {
			return escalated, fmt.Errorf("pane pid=%d sid=%d not absent (leaderPresent=%t leaderReused=%t kill0=%v pgrp=%v session=%v)",
				pane.PID, paneSID, leaderStillPresent, leaderReused, killZeroErr, pgrpMembers, sessMembers)
		}
		time.Sleep(min(processProbeInterval, max(time.Millisecond, time.Until(deadline))))
	}
}

func (s *Session) filterPaneEraMembers(members []int, pane trackedPane, leaderReused bool, leaderInfo processInfo) ([]int, error) {
	if len(members) == 0 {
		return nil, nil
	}
	hasLeaderStart := hasStartTime(pane.StartSec, pane.StartUsec)
	var minSec, minUsec int64
	hasEraLowerBound := false
	if hasLeaderStart {
		minSec, minUsec = pane.StartSec, pane.StartUsec
		hasEraLowerBound = true
	} else if pane.CreatedMS > 0 {
		floor := time.UnixMilli(int64(pane.CreatedMS)).Add(-2 * time.Second)
		minSec = floor.Unix()
		minUsec = int64(floor.Nanosecond() / 1000)
		hasEraLowerBound = true
	}

	out := make([]int, 0, len(members))
	for _, mpid := range members {
		if !validTargetPID(mpid) {
			continue
		}
		if leaderReused && mpid == pane.PID {
			continue
		}
		if hasEraLowerBound || leaderReused {
			mInfo, err := s.inspector.processInfo(mpid)
			if err != nil {
				return nil, err
			}
			if !mInfo.Exists {
				continue
			}
			if hasStartTime(mInfo.StartSec, mInfo.StartUsec) {
				if hasEraLowerBound && !startAtOrAfter(mInfo.StartSec, mInfo.StartUsec, minSec, minUsec) {
					continue
				}
				if leaderReused && hasStartTime(leaderInfo.StartSec, leaderInfo.StartUsec) &&
					!startStrictlyBefore(mInfo.StartSec, mInfo.StartUsec, leaderInfo.StartSec, leaderInfo.StartUsec) {
					continue
				}
			}
		}
		out = append(out, mpid)
	}
	return out, nil
}

func (s *Session) capturePaneSID(panePID int) int {
	if !validTargetPID(panePID) {
		return 0
	}
	// Mulgae panes are always their own setsid() session leaders (enforced by
	// __mulgae_paneexec_v1 and herdr-core PTY creation), so never adopt a
	// foreign session ID from a recycled or external process.
	return panePID
}

func (s *Session) capturePaneStartTime(panePID int, createdMS uint64) (int64, int64) {
	if !validTargetPID(panePID) {
		return 0, 0
	}
	info, err := s.inspector.processInfo(panePID)
	if err != nil || !info.Exists || !hasStartTime(info.StartSec, info.StartUsec) {
		return 0, 0
	}
	if createdMS > 0 && !startTimeWithinCreationWindow(info.StartSec, info.StartUsec, createdMS) {
		return 0, 0
	}
	return info.StartSec, info.StartUsec
}

func startTimeWithinCreationWindow(startSec, startUsec int64, createdMS uint64) bool {
	createdAt := time.UnixMilli(int64(createdMS))
	procStart := time.Unix(startSec, startUsec*1000)
	return !procStart.Before(createdAt.Add(-2*time.Second)) && !procStart.After(createdAt.Add(5*time.Second))
}

func (s *Session) createPerPaneControlDir(panesDir string, euid uint32) (string, error) {
	seq := s.paneSeq.Add(1)
	suffix, err := randomHexBytes(4)
	if err != nil {
		return "", err
	}
	dirPath := filepath.Join(panesDir, fmt.Sprintf("p%d-%s", seq, suffix))
	if err := createVerifiedPrivateDir(dirPath, euid); err != nil {
		return "", err
	}
	return dirPath, nil
}

func (s *Session) overlayControlPlane(procReq ports.ProcessRequest, sessionDir, socketPath string, euid uint32) (ports.ProcessRequest, error) {
	baseRoot, err := ports.NewAnchoredRoot(s.baseDir)
	if err != nil {
		return ports.ProcessRequest{}, fmt.Errorf("base dir control-plane root: %w", err)
	}
	sessionRoot, err := ports.NewAnchoredRoot(sessionDir)
	if err != nil {
		return ports.ProcessRequest{}, fmt.Errorf("session dir control-plane root: %w", err)
	}
	cpRoots, err := ports.DefaultControlPlaneRoots(s.nativeHome, euid, baseRoot, sessionRoot)
	if err != nil {
		return ports.ProcessRequest{}, err
	}
	var cpLiterals []ports.AnchoredRoot

	addSocket := func(label, rawPath string) error {
		if strings.TrimSpace(rawPath) != rawPath || !filepath.IsAbs(rawPath) || filepath.Clean(rawPath) != rawPath {
			return fmt.Errorf("%s (%q): must be a clean absolute path without surrounding whitespace", label, rawPath)
		}
		sockRoots, sockLiterals, sockErr := ports.ControlPlanePathsForSocket(rawPath, s.nativeHome)
		if sockErr != nil {
			return fmt.Errorf("%s (%q): %w", label, rawPath, sockErr)
		}
		cpRoots = append(cpRoots, sockRoots...)
		cpLiterals = append(cpLiterals, sockLiterals...)
		return nil
	}

	if err := addSocket("session socket", socketPath); err != nil {
		return ports.ProcessRequest{}, err
	}
	if s.inheritedHCSocket != "" {
		if err := addSocket("inherited HC_SOCKET", s.inheritedHCSocket); err != nil {
			return ports.ProcessRequest{}, err
		}
	}
	if s.ambientTerminalSocket != "" {
		if err := addSocket("ambient HC_TERMINAL_SOCKET", s.ambientTerminalSocket); err != nil {
			return ports.ProcessRequest{}, err
		}
	}
	return ports.WithProcessRequestControlPlane(procReq, cpRoots, cpLiterals)
}

func (s *Session) preStartContextFailure(
	err error,
	startedAt time.Time,
	emptyStdin ports.StdinWriteReceipt,
	identity ports.TerminalRuntimeIdentity,
	promptPath string,
	packetIdentity ports.ProviderPacketIdentity,
	preStartFP promptFileFingerprint,
	euid uint32,
) (ports.TerminalExecutionObservation, error) {
	postEndFP, promptErr := hashPromptFileIdentity(promptPath, packetIdentity, euid)
	if promptErr != nil || postEndFP != preStartFP {
		if promptErr == nil {
			promptErr = fmt.Errorf("prompt file identity changed before start failure")
		}
		return processExecutionFailure(
			domain.DiagnosticCausePromptFilePostEndFailed,
			"",
			nil,
			fmt.Errorf("herdr runner: verify prompt file on pre-start failure: %w", promptErr),
		)
	}
	transportReceipt, receiptErr := ports.NewTerminalProviderPacketTransportReceipt(
		packetIdentity,
		preStartFP.identity,
		postEndFP.identity,
	)
	if receiptErr != nil {
		return processExecutionFailure(domain.DiagnosticCauseTransportReceiptMismatch, "", nil, receiptErr)
	}

	termination := ports.ProcessTerminationCancelled
	if errors.Is(err, context.DeadlineExceeded) {
		termination = ports.ProcessTerminationTimedOut
	}
	endedAt := s.nowUTC()
	procObs, obsErr := ports.NewProviderProcessObservation(
		nil,
		nil,
		nil,
		termination,
		emptyStdin,
		transportReceipt,
		startedAt,
		endedAt,
	)
	if obsErr != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", nil, obsErr)
	}
	return ports.NewTerminalExecutionObservation(ports.TerminalExecutionObservationInput{
		Process:         procObs,
		RuntimeIdentity: identity,
	})
}

func (s *Session) nowUTC() time.Time {
	return s.clock.Now().UTC()
}

type promptFileFingerprint struct {
	identity ports.ProviderPacketIdentity
	dev      int32
	ino      uint64
}

func hashPromptFileIdentity(promptPath string, packetIdentity ports.ProviderPacketIdentity, euid uint32) (promptFileFingerprint, error) {
	if !validCanonicalAbsolutePath(promptPath) {
		return promptFileFingerprint{}, fmt.Errorf("prompt file path must be canonical and absolute")
	}
	fd, err := openAnchoredRegularFileNoFollow(promptPath)
	if err != nil {
		return promptFileFingerprint{}, err
	}
	file := os.NewFile(uintptr(fd), promptPath)
	defer file.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return promptFileFingerprint{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return promptFileFingerprint{}, fmt.Errorf("prompt file is not a regular file")
	}
	if st.Uid != euid {
		return promptFileFingerprint{}, fmt.Errorf("prompt file is not owned by effective user")
	}
	if st.Mode&0o7777 != 0o400 {
		return promptFileFingerprint{}, fmt.Errorf("prompt file mode %04o must be 0400", st.Mode&0o7777)
	}
	if st.Nlink != 1 {
		return promptFileFingerprint{}, fmt.Errorf("prompt file must not have hardlink aliases")
	}
	packetLen := int64(packetIdentity.ByteLength())
	if st.Size <= 0 || st.Size < packetLen {
		return promptFileFingerprint{}, fmt.Errorf("prompt file length %d is shorter than packet length %d", st.Size, packetLen)
	}

	fullHasher := sha256.New()
	_, _ = fullHasher.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = fullHasher.Write([]byte{0})

	prefixHasher := sha256.New()
	_, _ = prefixHasher.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = prefixHasher.Write([]byte{0})

	prefixWritten, err := io.CopyN(io.MultiWriter(fullHasher, prefixHasher), file, packetLen)
	if err != nil {
		return promptFileFingerprint{}, fmt.Errorf("read prompt file prefix: %w", err)
	}
	if prefixWritten != packetLen {
		return promptFileFingerprint{}, fmt.Errorf("prompt file prefix truncated")
	}
	if hex.EncodeToString(prefixHasher.Sum(nil)) != packetIdentity.CompleteSHA256() {
		return promptFileFingerprint{}, fmt.Errorf("prompt file prefix digest does not match packet identity")
	}

	tailWritten, err := io.Copy(fullHasher, file)
	if err != nil {
		return promptFileFingerprint{}, fmt.Errorf("read prompt file tail: %w", err)
	}
	written := prefixWritten + tailWritten
	if written != st.Size {
		return promptFileFingerprint{}, fmt.Errorf("prompt file size changed while reading")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Dev != st.Dev || after.Ino != st.Ino || after.Size != st.Size || after.Mode&0o7777 != 0o400 {
		return promptFileFingerprint{}, fmt.Errorf("prompt file identity drifted while reading")
	}
	identity, err := ports.NewProviderPacketIdentity(int(written), hex.EncodeToString(fullHasher.Sum(nil)))
	if err != nil {
		return promptFileFingerprint{}, err
	}
	if identity.ByteLength() == packetIdentity.ByteLength() && identity != packetIdentity {
		return promptFileFingerprint{}, fmt.Errorf("prompt file digest does not match packet identity")
	}
	return promptFileFingerprint{
		identity: identity,
		dev:      st.Dev,
		ino:      st.Ino,
	}, nil
}

func openAnchoredRegularFileNoFollow(path string) (int, error) {
	components := splitAbsoluteComponents(path)
	if len(components) == 0 {
		return -1, fmt.Errorf("invalid path")
	}
	dirFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(dirFD)
		if openErr != nil {
			return -1, openErr
		}
		dirFD = nextFD
	}
	fileFD, openErr := unix.Openat(dirFD, components[len(components)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	_ = unix.Close(dirFD)
	if openErr != nil {
		return -1, openErr
	}
	if err := descriptorPathMatches(fileFD, path); err != nil {
		_ = unix.Close(fileFD)
		return -1, err
	}
	return fileFD, nil
}

func processExecutionFailure(primary, cleanup domain.RuntimeDiagnosticCause, stdout []byte, err error) (ports.TerminalExecutionObservation, error) {
	execErr, buildErr := ports.NewProcessExecutionError(primary, cleanup, stdout, nil, err)
	if buildErr != nil {
		return ports.TerminalExecutionObservation{}, err
	}
	return ports.TerminalExecutionObservation{}, execErr
}

func terminalPID(term Terminal) int {
	if term.PID == nil {
		return 0
	}
	pid, ok := uint32ToValidPID(*term.PID)
	if !ok {
		return 0
	}
	return pid
}

func mapTerminalProgramStatus(raw string) (ports.TerminalProgramStatus, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "idle":
		return ports.TerminalProgramStatusIdle, true
	case "working":
		return ports.TerminalProgramStatusWorking, true
	case "done":
		return ports.TerminalProgramStatusDone, true
	case "blocked":
		return ports.TerminalProgramStatusBlocked, true
	case "error":
		return ports.TerminalProgramStatusError, true
	default:
		return "", false
	}
}

func mapTerminalBlockedKind(raw string) ports.TerminalBlockedKind {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auth":
		return ports.TerminalBlockedKindAuth
	case "quota":
		return ports.TerminalBlockedKindQuota
	case "rate_limit":
		return ports.TerminalBlockedKindRateLimit
	case "approval":
		return ports.TerminalBlockedKindApproval
	case "permission":
		return ports.TerminalBlockedKindPermission
	case "question", "input":
		return ports.TerminalBlockedKindInput
	default:
		return ports.TerminalBlockedKindUnknown
	}
}

func recordContextTermination(ctx context.Context, st *paneLifecycleState) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		st.timedOut = true
		return
	}
	if ctx.Err() != nil {
		st.cancelled = true
	}
}

func handleContextTermination(ctx context.Context, err error, st *paneLifecycleState, activeDeadline time.Time) bool {
	if ctx.Err() != nil {
		recordContextTermination(ctx, st)
		return true
	}
	if errors.Is(err, context.Canceled) {
		st.cancelled = true
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		if !activeDeadline.IsZero() && !time.Now().Before(activeDeadline) {
			st.timedOut = true
			return true
		}
		return false
	}
	return false
}
