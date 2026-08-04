//go:build darwin && arm64

package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	publicationLockDirectory     = "store/locks"
	publicationLockFile          = "store.lock"
	publicationReadBuffer        = 32 * 1024
	publicationMaximumReadBytes  = int64(32 * 1024 * 1024)
	publicationDirectoryEntryCap = 4096
)

var (
	errPublicationAbsent           = errors.New("publication file absent")
	errPublicationCap              = errors.New("publication file exceeds read cap")
	errPublicationMultiplePrepared = errors.New("multiple prepared composite members")
)

var _ ports.PublicationStore = (*PublicationStore)(nil)
var _ ports.PublicationEpochCommitStore = (*PublicationStore)(nil)

type publicationFileIdentity struct {
	device uint64
	inode  uint64
}
type publicationSchemaValidationError struct {
	cause             error
	documentViolation bool
}

func (err *publicationSchemaValidationError) Error() string { return err.cause.Error() }

func (err *publicationSchemaValidationError) Unwrap() error { return err.cause }

type publicationNamespaceUncertainError struct {
	cause error
}

func (err *publicationNamespaceUncertainError) Error() string { return err.cause.Error() }

func (err *publicationNamespaceUncertainError) Unwrap() error { return err.cause }

type publicationStoreLock struct {
	root         ports.AnchoredRoot
	rootFD       int
	rootIdentity privateDirectoryIdentity
	directory    int
	file         int
	identity     privateDirectoryIdentity
	fileID       publicationFileIdentity
}

type publicationTransactionContextKey struct{}

type publicationTransaction struct {
	store *PublicationStore
	root  ports.AnchoredRoot
	lock  *publicationStoreLock
}

type publicationStoreClassifiedError struct {
	class domain.FailureClass
	cause error
}

func (err *publicationStoreClassifiedError) Error() string { return err.cause.Error() }

func (err *publicationStoreClassifiedError) Unwrap() error { return err.cause }

func (err *publicationStoreClassifiedError) PublicationFailureClass() domain.FailureClass {
	return err.class
}

func classifiedPublicationStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrSecretDetected) {
		return &publicationStoreClassifiedError{class: domain.FailureSecurityPolicy, cause: err}
	}
	return err
}

// PartialCompositePreparationError preserves every exact immutable receipt
// installed before composite preparation stopped. Retrying the same request
// safely adopts these prefix members after revalidation.
type PartialCompositePreparationError struct {
	receipts []ports.SecureWriteReceipt
	cause    error
}

func (failure *PartialCompositePreparationError) Error() string {
	return fmt.Sprintf("partial composite preparation: %v", failure.cause)
}

func (failure *PartialCompositePreparationError) Unwrap() error { return failure.cause }

// Receipts returns caller-owned copies in canonical preparation order.
func (failure *PartialCompositePreparationError) Receipts() []ports.SecureWriteReceipt {
	if failure == nil {
		return nil
	}
	return append([]ports.SecureWriteReceipt(nil), failure.receipts...)
}

func partialCompositePreparationError(receipts []ports.SecureWriteReceipt, cause error) error {
	if len(receipts) == 0 {
		return cause
	}
	return &PartialCompositePreparationError{
		receipts: append([]ports.SecureWriteReceipt(nil), receipts...),
		cause:    cause,
	}
}

// IssueReviewID has no filesystem effect. Construction of the request proves
// the candidate's canonical SHA-256 before this method asks the generator.
func (store *PublicationStore) IssueReviewID(ctx context.Context, request ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
	if ctx == nil {
		return ports.IssuedReviewID{}, fmt.Errorf("issue review ID: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.IssuedReviewID{}, err
	}
	if err := store.valid(); err != nil {
		return ports.IssuedReviewID{}, err
	}
	if !request.Run().Valid() || !validPublicationSHA256(request.ValidatedCandidateSHA256()) {
		return ports.IssuedReviewID{}, fmt.Errorf("issue review ID: invalid request")
	}
	issued, err := store.ids.NewReviewID(store.clock.Now())
	if err != nil {
		return ports.IssuedReviewID{}, fmt.Errorf("issue review ID: generate: %w", err)
	}
	result, err := ports.NewIssuedReviewID(issued, request.ValidatedCandidateSHA256())
	if err != nil {
		return ports.IssuedReviewID{}, fmt.Errorf("issue review ID: generated invalid ID: %w", err)
	}
	return result, nil
}

// ResolveRun locates exactly one manifest-backed run without trusting directory
// ordering, names alone, or modification times.
func (store *PublicationStore) ResolveRun(ctx context.Context, request ports.ResolvePublicationRunRequest) (ports.PublicationRun, error) {
	if ctx == nil {
		return ports.PublicationRun{}, fmt.Errorf("resolve publication run: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.PublicationRun{}, err
	}
	if err := store.valid(); err != nil {
		return ports.PublicationRun{}, err
	}
	if !request.Root().Valid() || request.MaxReadBytes() <= 0 {
		return ports.PublicationRun{}, fmt.Errorf("resolve publication run: invalid request")
	}

	var resolved ports.PublicationRun
	err := store.withLock(ctx, request.Root(), func() error {
		sessionNames, err := listPublicationRoot(request.Root())
		if err != nil {
			return fmt.Errorf("resolve publication run: scan root: %w", err)
		}
		var matches []ports.PublicationRun
		for _, sessionName := range sessionNames {
			if !strings.HasPrefix(sessionName, "s_") {
				continue
			}
			sessionID, err := domain.ParseSessionID(sessionName)
			if err != nil {
				continue
			}
			runNames, present, err := listPublicationDirectory(request.Root(), mustPublicationSafePath(sessionName))
			if err != nil || !present {
				return fmt.Errorf("resolve publication run: session namespace %q: %w", sessionName, err)
			}
			for _, runName := range runNames {
				if runName != request.RunID().String() {
					continue
				}
				run, err := ports.NewPublicationRun(request.Root(), sessionID, request.RunID())
				if err != nil {
					return fmt.Errorf("resolve publication run: scope: %w", err)
				}
				manifest, err := readPublicationFile(request.Root(), publicationManifestPath(run), request.MaxReadBytes())
				if err != nil {
					return fmt.Errorf("resolve publication run: manifest: %w", err)
				}
				if err := store.validatePublicationSchema(ctx, store.manifestSchema, manifest.bytes); err != nil {
					return fmt.Errorf("resolve publication run: manifest schema: %w", err)
				}
				facts, err := parsePublicationManifestFacts(manifest.bytes)
				if err != nil {
					return fmt.Errorf("resolve publication run: manifest wire: %w", err)
				}
				if facts.sessionID != sessionID.String() || facts.runID != request.RunID().String() {
					return errors.New("resolve publication run: manifest identity mismatch")
				}
				matches = append(matches, run)
			}
		}
		if len(matches) == 0 {
			return errors.New("resolve publication run: no matching run")
		}
		if len(matches) != 1 {
			return errors.New("resolve publication run: multiple matching runs")
		}
		resolved = matches[0]
		return nil
	})
	if err != nil {
		return ports.PublicationRun{}, err
	}
	return resolved, nil
}

func (store *PublicationStore) ObserveRun(ctx context.Context, request ports.ObserveRunRequest) (ports.PublicationObservation, error) {
	if ctx == nil {
		return ports.PublicationObservation{}, fmt.Errorf("observe publication: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.PublicationObservation{}, err
	}
	if err := store.valid(); err != nil {
		return ports.PublicationObservation{}, err
	}
	if !request.Run().Valid() || request.MaxReadBytes() <= 0 {
		return ports.PublicationObservation{}, fmt.Errorf("observe publication: invalid request")
	}

	var result ports.PublicationObservation
	err := store.withLock(ctx, request.Run().Root(), func() error {
		observation, _, observeErr := store.observeLocked(ctx, request)
		result = observation
		return observeErr
	})
	if err != nil {
		return ports.PublicationObservation{}, err
	}
	return result, nil
}
func (store *PublicationStore) PersistValidatedCandidate(ctx context.Context, request ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
	if ctx == nil {
		return ports.PersistValidatedCandidateResult{}, fmt.Errorf("persist validated candidate: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.PersistValidatedCandidateResult{}, err
	}
	if err := store.valid(); err != nil {
		return ports.PersistValidatedCandidateResult{}, err
	}
	candidate := request.Candidate()
	canonical, err := ports.NewPersistValidatedCandidateRequest(request.Run(), candidate)
	if err != nil || canonical.Path() != request.Path() || int64(len(candidate.Bytes())) > publicationMaximumReadBytes {
		return ports.PersistValidatedCandidateResult{}, fmt.Errorf("persist validated candidate: invalid request")
	}

	var result ports.PersistValidatedCandidateResult
	err = store.withLock(ctx, request.Run().Root(), func() error {
		if err := store.validateFinalArtifact(ctx, request.Run(), candidate); err != nil {
			return fmt.Errorf("persist validated candidate: final: %w", err)
		}
		receipt, writeErr := store.writeValidatedFinalArtifact(ctx, request.Run(), candidate, request.Path(), "publication_validated_candidate")
		if writeErr != nil && !receipt.Destination().Valid() {
			return fmt.Errorf("persist validated candidate: secure write: %w", writeErr)
		}
		setUndurable := func(cause error) error {
			built, buildErr := ports.NewPersistValidatedCandidateResult(
				candidate,
				request.Path(),
				receipt,
				ports.ValidatedCandidateUndurable,
			)
			if buildErr != nil {
				return errors.Join(cause, fmt.Errorf("persist validated candidate: result: %w", buildErr))
			}
			result = built
			return cause
		}
		if writeErr != nil {
			var undurable *InstalledButUndurableError
			if !errors.As(writeErr, &undurable) {
				return fmt.Errorf("persist validated candidate: secure write: %w", writeErr)
			}
			return setUndurable(fmt.Errorf("persist validated candidate: installed but undurable: %w", writeErr))
		}
		file, err := readPublicationFile(request.Run().Root(), request.Path(), int64(len(candidate.Bytes())))
		if err != nil {
			return setUndurable(fmt.Errorf("persist validated candidate: re-read: %w", err))
		}
		if file.sha256 != candidate.Identity().SHA256() || !bytes.Equal(file.bytes, candidate.Bytes()) {
			return setUndurable(errors.New("persist validated candidate: installed bytes changed or hash mismatch"))
		}
		if err := store.validateFinalFile(ctx, request.Run(), candidate.Identity(), file); err != nil {
			return setUndurable(fmt.Errorf("persist validated candidate: re-read final: %w", err))
		}
		built, err := ports.NewPersistValidatedCandidateResult(
			candidate,
			request.Path(),
			receipt,
			ports.ValidatedCandidateDurable,
		)
		if err != nil {
			return fmt.Errorf("persist validated candidate: result: %w", err)
		}
		result = built
		return nil
	})
	if err != nil {
		if result.Valid() {
			if publicationPostEffectUncertain(err) {
				rebuilt, rebuildErr := ports.NewPersistValidatedCandidateResult(
					result.Candidate(),
					result.Path(),
					result.Receipt(),
					ports.ValidatedCandidateUndurable,
				)
				if rebuildErr != nil {
					return ports.PersistValidatedCandidateResult{}, errors.Join(err, rebuildErr)
				}
				result = rebuilt
			}
			return result, err
		}
		return ports.PersistValidatedCandidateResult{}, err
	}
	return result, nil
}

func (store *PublicationStore) PersistAuxiliaryArtifact(ctx context.Context, request ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	if ctx == nil {
		return ports.PersistAuxiliaryArtifactResult{}, fmt.Errorf("persist auxiliary artifact: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.PersistAuxiliaryArtifactResult{}, err
	}
	if err := store.valid(); err != nil {
		return ports.PersistAuxiliaryArtifactResult{}, err
	}
	artifact := request.Artifact()
	canonical, err := ports.NewPersistRunSupportArtifactRequest(request.Run(), artifact)
	if err != nil || canonical.Kind() != request.Kind() {
		return ports.PersistAuxiliaryArtifactResult{}, fmt.Errorf("persist auxiliary artifact: invalid request")
	}

	var result ports.PersistAuxiliaryArtifactResult
	err = store.withLock(ctx, request.Run().Root(), func() error {
		write := publicationWriteOperation(store.writer.Write)
		if authorizedUnscannedRunSupportKind(canonical.Kind()) {
			write = store.writeAuthorizedRunSupport
		}
		receipt, writeErr := store.writeImmutableUsing(ctx, request.Run(), artifact, "publication_auxiliary_artifact", write)
		if writeErr != nil && !receipt.Destination().Valid() {
			return fmt.Errorf("persist auxiliary artifact: secure write: %w", writeErr)
		}
		setUndurable := func(cause error) error {
			built, buildErr := ports.NewPersistAuxiliaryArtifactResult(
				artifact,
				receipt,
				ports.AuxiliaryArtifactUndurable,
			)
			if buildErr != nil {
				return errors.Join(cause, fmt.Errorf("persist auxiliary artifact: result: %w", buildErr))
			}
			result = built
			return cause
		}
		if writeErr != nil {
			var undurable *InstalledButUndurableError
			if !errors.As(writeErr, &undurable) {
				return fmt.Errorf("persist auxiliary artifact: secure write: %w", writeErr)
			}
			return setUndurable(fmt.Errorf("persist auxiliary artifact: installed but undurable: %w", writeErr))
		}
		file, err := readPublicationFile(request.Run().Root(), artifact.Path(), int64(len(artifact.Bytes())))
		if err != nil {
			return setUndurable(fmt.Errorf("persist auxiliary artifact: re-read: %w", err))
		}
		if file.sha256 != artifact.SHA256() || !bytes.Equal(file.bytes, artifact.Bytes()) {
			return setUndurable(errors.New("persist auxiliary artifact: installed bytes changed or hash mismatch"))
		}
		built, err := ports.NewPersistAuxiliaryArtifactResult(
			artifact,
			receipt,
			ports.AuxiliaryArtifactDurable,
		)
		if err != nil {
			return fmt.Errorf("persist auxiliary artifact: result: %w", err)
		}
		result = built
		return nil
	})
	if err != nil {
		if result.Valid() {
			if publicationPostEffectUncertain(err) {
				rebuilt, rebuildErr := ports.NewPersistAuxiliaryArtifactResult(
					result.Artifact(),
					result.Receipt(),
					ports.AuxiliaryArtifactUndurable,
				)
				if rebuildErr != nil {
					return ports.PersistAuxiliaryArtifactResult{}, errors.Join(err, rebuildErr)
				}
				result = rebuilt
			}
			return result, err
		}
		return ports.PersistAuxiliaryArtifactResult{}, err
	}
	return result, nil
}

func authorizedUnscannedRunSupportKind(kind ports.RunSupportArtifactKind) bool {
	switch kind {
	case ports.RunSupportArtifactExcerpt,
		ports.RunSupportArtifactTargetBytes,
		ports.RunSupportArtifactTargetManifest,
		ports.RunSupportArtifactCapturedArchive,
		ports.RunSupportArtifactArtistBrief,
		ports.RunSupportArtifactArtistVisuals,
		ports.RunSupportArtifactPromptStdin,
		ports.RunSupportArtifactPromptManifest:
		return true
	default:
		return false
	}
}

func (store *PublicationStore) ReadAuxiliaryArtifact(ctx context.Context, request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	if ctx == nil {
		return ports.ImmutablePublicationArtifact{}, fmt.Errorf("read auxiliary artifact: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	if err := store.valid(); err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	expectedSHA256, hasExpectedSHA256 := request.ExpectedSHA256()
	if _, err := ports.NewReadRunSupportArtifactRequest(request.Run(), request.Path(), expectedSHA256, request.MaxReadBytes()); err != nil {
		return ports.ImmutablePublicationArtifact{}, fmt.Errorf("read auxiliary artifact: invalid request")
	}

	var result ports.ImmutablePublicationArtifact
	err := store.withLock(ctx, request.Run().Root(), func() error {
		file, err := readPublicationFile(request.Run().Root(), request.Path(), request.MaxReadBytes())
		if err != nil {
			if errors.Is(err, errPublicationAbsent) {
				return fmt.Errorf("read auxiliary artifact: file: %w", fs.ErrNotExist)
			}
			return fmt.Errorf("read auxiliary artifact: file: %w", err)
		}
		if hasExpectedSHA256 && file.sha256 != expectedSHA256 {
			return errors.New("read auxiliary artifact: hash mismatch")
		}
		artifact, err := ports.NewImmutablePublicationArtifact(request.Path(), file.sha256, file.bytes)
		if err != nil {
			return fmt.Errorf("read auxiliary artifact: result: %w", err)
		}
		result = artifact
		return nil
	})
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	return result, nil
}

func (store *PublicationStore) PrepareComposite(ctx context.Context, request ports.PrepareCompositeRequest) (ports.PreparedComposite, error) {
	if ctx == nil {
		return ports.PreparedComposite{}, fmt.Errorf("prepare composite: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.PreparedComposite{}, err
	}
	if err := store.valid(); err != nil {
		return ports.PreparedComposite{}, err
	}
	if err := validatePrepareCompositeRequest(request); err != nil {
		return ports.PreparedComposite{}, fmt.Errorf("prepare composite: invalid request: %w", err)
	}

	var result ports.PreparedComposite
	err := store.withLock(ctx, request.Composite().Run().Root(), func() error {
		composite := request.Composite()
		observe, err := ports.NewObserveRunRequest(composite.Run(), publicationMaximumReadBytes)
		if err != nil {
			return fmt.Errorf("prepare composite: immutable observation request: %w", err)
		}
		_, _, _, p2Present, p2Err := store.discoverImmutableP2(ctx, observe)
		if p2Present {
			if p2Err != nil {
				return fmt.Errorf("prepare composite: immutable P2 namespace is unsafe: %w", p2Err)
			}
			return errors.New("prepare composite: immutable P2 is already committed")
		}
		candidatePath, err := ports.ValidatedCandidatePath(composite.Run())
		if err != nil {
			return fmt.Errorf("prepare composite: candidate path: %w", err)
		}
		candidateFile, err := readPublicationFile(composite.Run().Root(), candidatePath, publicationMaximumReadBytes)
		if err != nil {
			return fmt.Errorf("prepare composite: read validated candidate: %w", err)
		}
		if err := store.validateFinalFile(ctx, composite.Run(), composite.Final(), candidateFile); err != nil {
			return fmt.Errorf("prepare composite: validated candidate: %w", err)
		}
		if err := store.validateCompositePayload(ctx, composite, candidateFile.bytes); err != nil {
			return err
		}

		stagedManifest, err := ports.NewImmutablePublicationArtifact(request.StagedManifestPath(), composite.Manifest().SHA256(), composite.Manifest().Bytes())
		if err != nil {
			return fmt.Errorf("prepare composite: staged manifest: %w", err)
		}
		stagedLineage, err := ports.NewImmutablePublicationArtifact(request.StagedLineageEdgePath(), composite.LineageEdge().SHA256(), composite.LineageEdge().Bytes())
		if err != nil {
			return fmt.Errorf("prepare composite: staged lineage edge: %w", err)
		}
		stagedEpoch, err := ports.NewImmutablePublicationArtifact(request.StagedEpochPath(), composite.Epoch().Record().SHA256(), composite.Epoch().Record().Bytes())
		if err != nil {
			return fmt.Errorf("prepare composite: staged epoch: %w", err)
		}
		staged := []struct {
			artifact ports.ImmutablePublicationArtifact
			channel  string
		}{
			{stagedManifest, "publication_prepared_manifest"},
			{stagedLineage, "publication_prepared_lineage_edge"},
			{stagedEpoch, "publication_prepared_epoch"},
		}
		receipts := make([]ports.SecureWriteReceipt, 0, len(staged))
		var durabilityErrors []error
		for _, member := range staged {
			receipt, writeErr := store.writePreparedImmutable(ctx, composite.Run(), member.artifact, member.channel)
			if writeErr != nil && !receipt.Destination().Valid() {
				return partialCompositePreparationError(
					receipts,
					fmt.Errorf("prepare composite: %s: %w", member.channel, writeErr),
				)
			}
			if !receipt.Destination().Valid() {
				return partialCompositePreparationError(
					receipts,
					fmt.Errorf("prepare composite: %s returned no receipt", member.channel),
				)
			}
			receipts = append(receipts, receipt)
			if writeErr != nil {
				var undurable *InstalledButUndurableError
				if !errors.As(writeErr, &undurable) {
					return partialCompositePreparationError(
						receipts,
						fmt.Errorf("prepare composite: %s: %w", member.channel, writeErr),
					)
				}
				durabilityErrors = append(durabilityErrors, writeErr)
			}
		}
		durability := ports.CompositePreparationDurable
		if len(durabilityErrors) != 0 {
			durability = ports.CompositePreparationUndurable
		}
		built, err := ports.NewPreparedComposite(request, stagedManifest, stagedLineage, stagedEpoch, receipts, durability)
		if err != nil {
			return partialCompositePreparationError(
				receipts,
				fmt.Errorf("prepare composite: result: %w", err),
			)
		}
		result = built
		if len(durabilityErrors) != 0 {
			return fmt.Errorf("prepare composite: installed but undurable: %w", errors.Join(durabilityErrors...))
		}
		return nil
	})
	if err != nil {
		if result.Valid() {
			if publicationPostEffectUncertain(err) {
				rebuilt, rebuildErr := ports.NewPreparedComposite(
					result.Request(),
					result.StagedManifest(),
					result.StagedLineageEdge(),
					result.StagedEpoch(),
					result.Receipts(),
					ports.CompositePreparationUndurable,
				)
				if rebuildErr != nil {
					return ports.PreparedComposite{}, errors.Join(err, rebuildErr)
				}
				result = rebuilt
			}
			return result, err
		}
		return ports.PreparedComposite{}, err
	}
	return result, nil
}

func (store *PublicationStore) StageFinal(ctx context.Context, request ports.StageFinalRequest) (ports.StageFinalResult, error) {
	if ctx == nil {
		return ports.StageFinalResult{}, fmt.Errorf("stage final: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.StageFinalResult{}, err
	}
	if err := store.valid(); err != nil {
		return ports.StageFinalResult{}, err
	}
	canonical, err := ports.NewStageFinalRequest(
		request.Run(),
		request.StagedPath(),
		request.Binding(),
		request.Source(),
		request.MaxBytes(),
		request.SourceIDs(),
		request.Abort(),
	)
	if err != nil || canonical.StagedPath() != request.StagedPath() ||
		canonical.Binding() != request.Binding() || request.MaxBytes() > publicationMaximumReadBytes {
		return ports.StageFinalResult{}, fmt.Errorf("stage final: invalid request")
	}
	document, err := store.readStagedFinalBytes(ctx, request)
	if err != nil {
		return ports.StageFinalResult{}, classifiedPublicationStoreError(err)
	}
	defer zeroBytes(document)

	var result ports.StageFinalResult
	err = store.withLock(ctx, request.Run().Root(), func() error {
		artifact, err := ports.NewFinalReviewArtifact(request.Final(), document)
		if err != nil {
			return fmt.Errorf("stage final: validated artifact identity: %w", err)
		}
		if err := store.validateFinalArtifact(ctx, request.Run(), artifact); err != nil {
			return fmt.Errorf("stage final: validated artifact: %w", err)
		}
		secureRequest, err := ports.NewSecureWriteRequest(
			request.Run().Root(),
			request.StagedPath(),
			"publication_final",
			bytes.NewReader(document),
			int64(len(document)),
			request.SourceIDs(),
			request.Abort(),
		)
		if err != nil {
			return fmt.Errorf("stage final: secure write request: %w", err)
		}
		receipt, _, writeErr := store.writeValidatedFinal(ctx, secureRequest)
		writeErr = classifiedPublicationStoreError(writeErr)
		if writeErr != nil && !receipt.Destination().Valid() {
			return fmt.Errorf("stage final: secure write: %w", writeErr)
		}
		if receipt.Root() != request.Run().Root() ||
			receipt.Destination() != request.StagedPath() ||
			receipt.SHA256() != request.Final().SHA256() ||
			receipt.ByteLength() != int64(len(document)) {
			return fmt.Errorf("stage final: installed bytes do not match final identity")
		}
		setUndurable := func(cause error) error {
			built, buildErr := ports.NewStageFinalResult(
				request.StagedPath(),
				request.Final(),
				receipt,
				ports.StageFinalUndurable,
			)
			if buildErr != nil {
				return errors.Join(cause, fmt.Errorf("stage final: result: %w", buildErr))
			}
			result = built
			return cause
		}
		if writeErr != nil {
			var undurable *InstalledButUndurableError
			if !errors.As(writeErr, &undurable) {
				return fmt.Errorf("stage final: secure write: %w", writeErr)
			}
			return setUndurable(fmt.Errorf("stage final: installed but undurable: %w", writeErr))
		}
		file, err := readPublicationFile(request.Run().Root(), request.StagedPath(), int64(len(document)))
		if err != nil {
			return setUndurable(fmt.Errorf("stage final: re-read staged file: %w", err))
		}
		if file.sha256 != request.Final().SHA256() ||
			file.length != receipt.ByteLength() ||
			!bytes.Equal(file.bytes, document) {
			return setUndurable(errors.New("stage final: staged bytes changed or hash mismatch"))
		}
		if err := store.validateFinalFile(ctx, request.Run(), request.Final(), file); err != nil {
			return setUndurable(fmt.Errorf("stage final: staged final: %w", err))
		}
		built, err := ports.NewStageFinalResult(
			request.StagedPath(),
			request.Final(),
			receipt,
			ports.StageFinalDurable,
		)
		if err != nil {
			return fmt.Errorf("stage final: result: %w", err)
		}
		result = built
		return nil
	})
	if err != nil {
		if result.Valid() {
			if publicationPostEffectUncertain(err) {
				rebuilt, rebuildErr := ports.NewStageFinalResult(
					result.StagedPath(),
					result.Final(),
					result.Receipt(),
					ports.StageFinalUndurable,
				)
				if rebuildErr != nil {
					return ports.StageFinalResult{}, errors.Join(err, rebuildErr)
				}
				result = rebuilt
			}
			return result, err
		}
		return ports.StageFinalResult{}, err
	}
	return result, nil
}

func (store *PublicationStore) readStagedFinalBytes(
	ctx context.Context,
	request ports.StageFinalRequest,
) ([]byte, error) {
	document := make([]byte, 0, publicationReadBuffer)
	buffer := make([]byte, publicationReadBuffer)
	defer zeroBytes(buffer)
	reject := func(cause error) error {
		zeroBytes(document)
		return errors.Join(cause, invokeAbort(request.Abort(), cause))
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, reject(err)
		}
		remaining := request.MaxBytes() - int64(len(document))
		readSize := int64(len(buffer))
		if remaining < readSize {
			readSize = remaining + 1
		}
		readN, readErr := request.Source().Read(buffer[:readSize])
		if readN < 0 || readN > int(readSize) {
			zeroBytes(buffer)
			return nil, reject(ErrSourceRead)
		}
		if err := ctx.Err(); err != nil {
			zeroBytes(buffer[:readN])
			return nil, reject(err)
		}
		if int64(readN) > remaining {
			zeroBytes(buffer[:readN])
			return nil, reject(ErrMaxBytesExceeded)
		}
		if readN > 0 {
			document = append(document, buffer[:readN]...)
			zeroBytes(buffer[:readN])
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, reject(ErrSourceRead)
		}
		if readN == 0 {
			return nil, reject(ErrSourceRead)
		}
	}
	artifact, err := ports.NewFinalReviewArtifact(request.Final(), document)
	if err != nil {
		return nil, reject(fmt.Errorf("stage final: streamed final identity: %w", err))
	}
	if err := store.validateFinalArtifact(ctx, request.Run(), artifact); err != nil {
		return nil, reject(fmt.Errorf("stage final: streamed final: %w", err))
	}
	return document, nil
}

func (store *PublicationStore) AdoptStagedFinal(
	ctx context.Context,
	request ports.AdoptStagedFinalRequest,
) (ports.StageFinalResult, error) {
	if ctx == nil {
		return ports.StageFinalResult{}, fmt.Errorf("adopt staged final: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.StageFinalResult{}, err
	}
	if err := store.valid(); err != nil {
		return ports.StageFinalResult{}, err
	}
	final := request.Final()
	canonical, err := ports.NewAdoptStagedFinalRequest(
		request.Run(),
		request.StagedPath(),
		request.Binding(),
		final,
		request.MaxBytes(),
	)
	if err != nil || canonical.StagedPath() != request.StagedPath() ||
		canonical.Binding() != request.Binding() || request.MaxBytes() > publicationMaximumReadBytes {
		return ports.StageFinalResult{}, fmt.Errorf("adopt staged final: invalid request")
	}

	var result ports.StageFinalResult
	err = store.withLock(ctx, request.Run().Root(), func() error {
		if err := store.validateFinalArtifact(ctx, request.Run(), final); err != nil {
			return fmt.Errorf("adopt staged final: expected final: %w", err)
		}
		staged, err := ports.NewImmutablePublicationArtifact(
			request.StagedPath(),
			final.Identity().SHA256(),
			final.Bytes(),
		)
		if err != nil {
			return fmt.Errorf("adopt staged final: staged identity: %w", err)
		}
		receipt, exists, err := store.durableExistingImmutable(
			request.Run(),
			staged,
			"publication_final",
		)
		if err != nil {
			return fmt.Errorf("adopt staged final: durability proof: %w", err)
		}
		if !exists {
			return fmt.Errorf("adopt staged final: staged file is absent")
		}
		built, err := ports.NewStageFinalResult(
			request.StagedPath(),
			final.Identity(),
			receipt,
			ports.StageFinalDurable,
		)
		if err != nil {
			return fmt.Errorf("adopt staged final: result: %w", err)
		}
		result = built
		return nil
	})
	if err != nil {
		if result.Valid() {
			if publicationPostEffectUncertain(err) {
				rebuilt, rebuildErr := ports.NewStageFinalResult(
					result.StagedPath(),
					result.Final(),
					result.Receipt(),
					ports.StageFinalUndurable,
				)
				if rebuildErr != nil {
					return ports.StageFinalResult{}, errors.Join(err, rebuildErr)
				}
				result = rebuilt
			}
			return result, err
		}
		return ports.StageFinalResult{}, err
	}
	return result, nil
}

func (store *PublicationStore) InstallFinal(ctx context.Context, request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
	if ctx == nil {
		return ports.InstallFinalResult{}, fmt.Errorf("install final: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.InstallFinalResult{}, err
	}
	if err := store.valid(); err != nil {
		return ports.InstallFinalResult{}, err
	}
	canonical, err := ports.NewInstallFinalRequest(request.Run(), request.Staged())
	if err != nil || canonical.Run() != request.Run() ||
		request.Staged().Receipt().ByteLength() > publicationMaximumReadBytes {
		return ports.InstallFinalResult{}, fmt.Errorf("install final: invalid request")
	}

	var result ports.InstallFinalResult
	err = store.withLock(ctx, request.Run().Root(), func() error {
		staged := request.Staged()
		operations := store.publicationOperations()
		final := staged.Final()
		file, err := readPublicationFile(request.Run().Root(), staged.StagedPath(), staged.Receipt().ByteLength())
		if err != nil {
			return fmt.Errorf("install final: read staged file: %w", err)
		}
		if file.sha256 != final.SHA256() || file.length != staged.Receipt().ByteLength() {
			return fmt.Errorf("install final: staged bytes do not match receipt")
		}
		if err := store.validateFinalFile(ctx, request.Run(), final, file); err != nil {
			return fmt.Errorf("install final: staged final: %w", err)
		}

		sourceParts, sourceName, err := splitDestination(staged.StagedPath())
		if err != nil {
			return fmt.Errorf("install final: staged path: %w", err)
		}
		destinationParts, destinationName, err := splitDestination(final.Path())
		if err != nil {
			return fmt.Errorf("install final: final path: %w", err)
		}
		rootFD, err := openAnchoredRoot(request.Run().Root())
		if err != nil {
			return fmt.Errorf("install final: open root: %w", err)
		}
		defer closeFD(rootFD)
		rootID, err := privateDirectoryIdentityForFD(rootFD)
		if err != nil {
			return fmt.Errorf("install final: root identity: %w", err)
		}
		sourceDirectory, err := walkPrivateDirectory(request.Run().Root(), sourceParts, false)
		if err != nil {
			return fmt.Errorf("install final: open staged directory: %w", err)
		}
		defer closeFD(sourceDirectory)
		destinationDirectory, err := walkPrivateDirectory(request.Run().Root(), destinationParts, false)
		if err != nil {
			return fmt.Errorf("install final: open final directory: %w", err)
		}
		defer closeFD(destinationDirectory)
		sourceDirectoryID, err := privateDirectoryIdentityForFD(sourceDirectory)
		if err != nil {
			return fmt.Errorf("install final: staged directory identity: %w", err)
		}
		destinationDirectoryID, err := privateDirectoryIdentityForFD(destinationDirectory)
		if err != nil {
			return fmt.Errorf("install final: final directory identity: %w", err)
		}
		if err := validatePublicationFileHashAt(sourceDirectory, sourceName, file.identity, file.sha256); err != nil {
			return fmt.Errorf("install final: staged file changed: %w", err)
		}
		if err := errors.Join(
			revalidatePrivateDirectory(request.Run().Root(), nil, rootID, defaultSecureWriterOperations()),
			revalidatePrivateDirectory(request.Run().Root(), sourceParts, sourceDirectoryID, defaultSecureWriterOperations()),
			revalidatePrivateDirectory(request.Run().Root(), destinationParts, destinationDirectoryID, defaultSecureWriterOperations()),
		); err != nil {
			return fmt.Errorf("install final: namespace changed before rename: %w", err)
		}
		if err := operations.renameatxNp(sourceDirectory, sourceName, destinationDirectory, destinationName, unix.RENAME_EXCL); err != nil {
			return fmt.Errorf("install final: no-replace rename: %w", err)
		}
		if err := errors.Join(
			publicationValidateInstalledMove(
				request.Run().Root(),
				rootID,
				sourceParts,
				sourceDirectoryID,
				destinationParts,
				destinationDirectoryID,
				destinationDirectory,
				destinationName,
				file.identity,
			),
			validatePublicationFileHashAt(destinationDirectory, destinationName, file.identity, file.sha256),
		); err != nil {
			rollbackErr := publicationRollbackInstalledMove(
				sourceDirectory,
				sourceName,
				sourceDirectoryID,
				destinationDirectory,
				destinationName,
				destinationDirectoryID,
				file.identity,
				operations,
			)
			return fmt.Errorf("install final: namespace uncertain after rename: %w", errors.Join(err, rollbackErr))
		}
		receipt, err := publicationReceiptFor(final.Path(), staged.Receipt(), "publication_final_install")
		if err != nil {
			return fmt.Errorf("install final: receipt: %w", err)
		}
		postRenameErr := publicationSyncInstalledFinal(
			request.Run().Root(),
			rootID,
			sourceParts,
			sourceDirectoryID,
			sourceDirectory,
			destinationParts,
			destinationDirectoryID,
			destinationDirectory,
			destinationName,
			file.identity,
			file.sha256,
			operations,
		)
		var namespaceUncertain *publicationNamespaceUncertainError
		if errors.As(postRenameErr, &namespaceUncertain) {
			rollbackErr := publicationRollbackInstalledMove(
				sourceDirectory,
				sourceName,
				sourceDirectoryID,
				destinationDirectory,
				destinationName,
				destinationDirectoryID,
				file.identity,
				operations,
			)
			return fmt.Errorf("install final: namespace uncertain after sync: %w", errors.Join(postRenameErr, rollbackErr))
		}
		durability := ports.InstallFinalDurable
		if postRenameErr != nil {
			durability = ports.InstallFinalUndurable
		}
		built, err := ports.NewInstallFinalResult(final, receipt, durability)
		if err != nil {
			return fmt.Errorf("install final: result: %w", err)
		}
		result = built
		if postRenameErr != nil {
			return fmt.Errorf("install final: installed but undurable: %w", postRenameErr)
		}
		return nil
	})
	if err != nil {
		if result.Valid() {
			if publicationPostEffectUncertain(err) {
				rebuilt, rebuildErr := ports.NewInstallFinalResult(
					result.Final(),
					result.Receipt(),
					ports.InstallFinalUndurable,
				)
				if rebuildErr != nil {
					return ports.InstallFinalResult{}, errors.Join(err, rebuildErr)
				}
				result = rebuilt
			}
			return result, err
		}
		return ports.InstallFinalResult{}, err
	}
	return result, nil
}

func (store *PublicationStore) ReplaceMutable(ctx context.Context, request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
	if ctx == nil {
		return ports.MutableReplaceResult{}, fmt.Errorf("replace mutable: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.MutableReplaceResult{}, err
	}
	if err := store.valid(); err != nil {
		return ports.MutableReplaceResult{}, err
	}
	canonical, err := ports.NewMutableReplaceRequest(
		request.Run(),
		request.Document(),
		request.Path(),
		request.ExpectedPrior(),
		request.Replacement(),
		request.SHA256(),
	)
	if err != nil || canonical.Path() != request.Path() || int64(len(request.Replacement())) > publicationMaximumReadBytes {
		return ports.MutableReplaceResult{}, fmt.Errorf("replace mutable: invalid request")
	}

	var result ports.MutableReplaceResult
	err = store.withLock(ctx, request.Run().Root(), func() error {
		parts, name, err := splitDestination(request.Path())
		if err != nil {
			return fmt.Errorf("replace mutable: path: %w", err)
		}
		if len(parts) > 0 {
			if err := store.writer.EnsurePrivateDir(request.Run().Root(), parentPath(parts)); err != nil {
				return fmt.Errorf("replace mutable: ensure directory: %w", err)
			}
		}
		rootFD, err := openAnchoredRoot(request.Run().Root())
		if err != nil {
			return fmt.Errorf("replace mutable: open root: %w", err)
		}
		defer closeFD(rootFD)
		rootID, err := privateDirectoryIdentityForFD(rootFD)
		if err != nil {
			return fmt.Errorf("replace mutable: root identity: %w", err)
		}
		directory, err := walkPrivateDirectory(request.Run().Root(), parts, false)
		if err != nil {
			return fmt.Errorf("replace mutable: open directory: %w", err)
		}
		defer closeFD(directory)
		directoryID, err := privateDirectoryIdentityForFD(directory)
		if err != nil {
			return fmt.Errorf("replace mutable: directory identity: %w", err)
		}
		operations := store.publicationOperations()
		temporaryFD, temporaryName, err := createPrivateTempFile(defaultSecureWriterOperations(), directory)
		if err != nil {
			return fmt.Errorf("replace mutable: temporary file: %w", err)
		}
		cleanup := func(cause error) error {
			return errors.Join(cause, purgeTemporaryFile(defaultSecureWriterOperations(), directory, &temporaryFD, &temporaryName))
		}
		closePinned := func(cause error) error {
			if temporaryFD < 0 {
				return cause
			}
			closeErr := unix.Close(temporaryFD)
			temporaryFD = -1
			return errors.Join(cause, closeErr)
		}
		setUndurable := func() error {
			if result.Valid() {
				return nil
			}
			receipt, err := ports.NewSecureWriteReceipt(
				request.Run().Root(),
				request.Path(),
				request.SHA256(),
				int64(len(request.Replacement())),
				"publication_mutable",
				[]string{"mutable_" + string(request.Document())},
			)
			if err != nil {
				return fmt.Errorf("replace mutable: receipt: %w", err)
			}
			built, err := ports.NewMutableReplaceResult(request, receipt, ports.MutableReplaceUndurable)
			if err != nil {
				return fmt.Errorf("replace mutable: undurable result: %w", err)
			}
			result = built
			return nil
		}
		replacement := request.Replacement()
		if err := writeAll(temporaryFD, replacement); err != nil {
			return cleanup(fmt.Errorf("replace mutable: write temporary: %w", err))
		}
		if err := unix.Fsync(temporaryFD); err != nil {
			return cleanup(fmt.Errorf("replace mutable: sync temporary: %w", err))
		}
		replacementID, err := publicationFileIdentityForFD(temporaryFD)
		if err != nil {
			return cleanup(fmt.Errorf("replace mutable: temporary identity: %w", err))
		}
		if err := errors.Join(
			revalidatePrivateDirectory(request.Run().Root(), nil, rootID, defaultSecureWriterOperations()),
			revalidatePrivateDirectory(request.Run().Root(), parts, directoryID, defaultSecureWriterOperations()),
			validatePublicationFileAt(directory, temporaryName, replacementID),
		); err != nil {
			return cleanup(fmt.Errorf("replace mutable: namespace changed before replace: %w", err))
		}
		var expectedPrior publicationMutableFile
		if !request.ExpectedPrior().MustBeAbsent() {
			observed, exists, err := observePublicationMutableFile(directory, name)
			if err != nil {
				return cleanup(fmt.Errorf("replace mutable: inspect expected prior: %w", err))
			}
			if !exists {
				return cleanup(fmt.Errorf("%w: prior file is absent", ports.ErrMutableCASConflict))
			}
			wanted, _ := request.ExpectedPrior().ExpectedSHA256()
			if observed.sha256 != wanted {
				return cleanup(fmt.Errorf("%w: prior hash differs", ports.ErrMutableCASConflict))
			}
			expectedPrior = observed
		}
		if !request.ExpectedPrior().MustBeAbsent() {
			if err := errors.Join(
				revalidatePrivateDirectory(request.Run().Root(), nil, rootID, defaultSecureWriterOperations()),
				revalidatePrivateDirectory(request.Run().Root(), parts, directoryID, defaultSecureWriterOperations()),
				validatePublicationFileAt(directory, name, expectedPrior.identity),
			); err != nil {
				return cleanup(fmt.Errorf("replace mutable: namespace changed before swap: %w", err))
			}
		}

		if request.ExpectedPrior().MustBeAbsent() {
			if err := operations.renameatxNp(directory, temporaryName, directory, name, unix.RENAME_EXCL); err != nil {
				if errors.Is(err, unix.EEXIST) {
					return cleanup(fmt.Errorf("%w: prior file exists", ports.ErrMutableCASConflict))
				}
				return cleanup(fmt.Errorf("replace mutable: no-replace rename: %w", err))
			}
			temporaryName = ""
			if err := errors.Join(
				publicationValidateMutableReplacement(request.Run().Root(), rootID, parts, directoryID, directory, name, replacementID),
				validatePublicationFileHashAt(directory, name, replacementID, request.SHA256()),
			); err != nil {
				rollbackErr := publicationRollbackMutableAbsentInstall(
					directoryID,
					directory,
					name,
					replacementID,
					request.SHA256(),
					operations,
				)
				return closePinned(fmt.Errorf("replace mutable: namespace uncertain after no-replace install: %w", errors.Join(err, rollbackErr)))
			}
			if err := setUndurable(); err != nil {
				return closePinned(err)
			}
		} else {
			if err := operations.renameatxNp(directory, temporaryName, directory, name, unix.RENAME_SWAP); err != nil {
				if errors.Is(err, unix.ENOENT) {
					return cleanup(fmt.Errorf("%w: prior file is absent", ports.ErrMutableCASConflict))
				}
				return cleanup(fmt.Errorf("replace mutable: swap rename: %w", err))
			}
			displaced, exists, observedErr := observePublicationMutableFile(directory, temporaryName)
			if observedErr != nil {
				return closePinned(&publicationNamespaceUncertainError{
					cause: fmt.Errorf("inspect displaced prior: %w", observedErr),
				})
			}
			if !exists {
				return closePinned(&publicationNamespaceUncertainError{
					cause: errors.New("displaced prior is absent"),
				})
			}
			if displaced.identity != expectedPrior.identity || displaced.sha256 != expectedPrior.sha256 {
				conflict := fmt.Errorf("%w: prior changed before swap", ports.ErrMutableCASConflict)
				rollbackErr := publicationRollbackMutableSwap(
					directoryID,
					directory,
					name,
					temporaryName,
					replacementID,
					displaced,
					operations,
				)
				if rollbackErr == nil {
					temporaryName = ""
				}
				return closePinned(errors.Join(conflict, rollbackErr))
			}
			if err := errors.Join(
				publicationValidateMutableReplacement(request.Run().Root(), rootID, parts, directoryID, directory, name, replacementID),
				validatePublicationFileAt(directory, temporaryName, displaced.identity),
				validatePublicationFileHashAt(directory, name, replacementID, request.SHA256()),
			); err != nil {
				rollbackErr := publicationRollbackMutableSwap(
					directoryID,
					directory,
					name,
					temporaryName,
					replacementID,
					displaced,
					operations,
				)
				if rollbackErr == nil {
					temporaryName = ""
				}
				return closePinned(fmt.Errorf("replace mutable: namespace uncertain after swap: %w", errors.Join(err, rollbackErr)))
			}
			if err := setUndurable(); err != nil {
				return closePinned(err)
			}
			if err := unix.Unlinkat(directory, temporaryName, 0); err != nil {
				return closePinned(fmt.Errorf("replace mutable: remove displaced prior: %w", err))
			}
			temporaryName = ""
		}

		if err := errors.Join(
			publicationValidateMutableReplacement(
				request.Run().Root(),
				rootID,
				parts,
				directoryID,
				directory,
				name,
				replacementID,
			),
			validatePublicationFileHashAt(directory, name, replacementID, request.SHA256()),
		); err != nil {
			return closePinned(fmt.Errorf("replace mutable: replacement changed after install: %w", err))
		}
		syncErr := operations.fsync(directory)
		if err := errors.Join(
			publicationValidateMutableReplacement(
				request.Run().Root(),
				rootID,
				parts,
				directoryID,
				directory,
				name,
				replacementID,
			),
			validatePublicationFileHashAt(directory, name, replacementID, request.SHA256()),
		); err != nil {
			return closePinned(fmt.Errorf("replace mutable: namespace changed after sync: %w", errors.Join(syncErr, err)))
		}
		if err := closePinned(nil); err != nil {
			return fmt.Errorf("replace mutable: close replacement: %w", err)
		}
		if syncErr != nil {
			return fmt.Errorf("replace mutable: replaced but undurable: %w", syncErr)
		}
		built, err := ports.NewMutableReplaceResult(request, result.Receipt(), ports.MutableReplaceDurable)
		if err != nil {
			return fmt.Errorf("replace mutable: durable result: %w", err)
		}
		result = built
		return nil
	})
	if err != nil {
		if result.Valid() {
			if publicationPostEffectUncertain(err) {
				rebuilt, rebuildErr := ports.NewMutableReplaceResult(
					request,
					result.Receipt(),
					ports.MutableReplaceUndurable,
				)
				if rebuildErr != nil {
					return ports.MutableReplaceResult{}, errors.Join(err, rebuildErr)
				}
				result = rebuilt
			}
			return result, err
		}
		return ports.MutableReplaceResult{}, err
	}
	return result, nil
}

func (store *PublicationStore) CommitPreparedComposite(ctx context.Context, prepared ports.PreparedComposite) (ports.CompositeCommitResult, error) {
	if ctx == nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("commit prepared composite: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.CompositeCommitResult{}, err
	}
	if err := store.valid(); err != nil {
		return ports.CompositeCommitResult{}, err
	}
	if err := validatePreparedCompositeRequest(prepared); err != nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("commit prepared composite: invalid prepared composite: %w", err)
	}

	var result ports.CompositeCommitResult
	err := store.withLock(ctx, prepared.Composite().Run().Root(), func() error {
		composite := prepared.Composite()
		finalFile, err := readPublicationFile(composite.Run().Root(), composite.Final().Path(), publicationMaximumReadBytes)
		if err != nil {
			return fmt.Errorf("commit prepared composite: read final: %w", err)
		}
		if err := store.validateFinalFile(ctx, composite.Run(), composite.Final(), finalFile); err != nil {
			return fmt.Errorf("commit prepared composite: final: %w", err)
		}

		members := []publicationPreparedMoveMember{
			{
				staged:      prepared.StagedManifest(),
				destination: composite.Manifest(),
				receipt:     prepared.Receipts()[0],
				channel:     "publication_manifest",
			},
			{
				staged:      prepared.StagedLineageEdge(),
				destination: composite.LineageEdge(),
				receipt:     prepared.Receipts()[1],
				channel:     "publication_lineage_edge",
			},
			{
				staged:      prepared.StagedEpoch(),
				destination: composite.Epoch().Record(),
				receipt:     prepared.Receipts()[2],
				channel:     "publication_epoch",
			},
		}
		if err := store.validateCompositePayload(ctx, composite, finalFile.bytes); err != nil {
			return err
		}
		moved, moveErr := store.resumePreparedComposite(composite.Run(), members)
		if moved.Valid() {
			result = moved
		}
		return moveErr
	})
	if err != nil {
		if result.Valid() {
			if publicationPostEffectUncertain(err) && result.Phase() == ports.CompositeCommittedDurable {
				rebuilt, rebuildErr := ports.NewCompositeCommitResult(
					ports.CompositeEpochInstalledUndurable,
					result.Receipts(),
				)
				if rebuildErr != nil {
					return ports.CompositeCommitResult{}, errors.Join(err, rebuildErr)
				}
				result = rebuilt
			}
			return result, err
		}
		return ports.CompositeCommitResult{}, err
	}
	return result, nil
}

type publicationPreparedMoveMember struct {
	staged      ports.ImmutablePublicationArtifact
	destination ports.ImmutablePublicationArtifact
	receipt     ports.SecureWriteReceipt
	channel     string
	file        publicationFile
	sourceName  string
	targetName  string
	targetParts []string
	targetFD    int
	targetID    privateDirectoryIdentity
}

func (store *PublicationStore) resumePreparedComposite(
	run ports.PublicationRun,
	members []publicationPreparedMoveMember,
) (ports.CompositeCommitResult, error) {
	if len(members) != 3 {
		return ports.CompositeCommitResult{}, errors.New("resume prepared composite: requires three members")
	}
	receipts := make([]ports.SecureWriteReceipt, 0, len(members))
	installed := 0
	for index := range members {
		member := &members[index]
		receipt, exists, err := store.durableExistingImmutable(run, member.destination, member.channel)
		if err != nil {
			return ports.CompositeCommitResult{}, fmt.Errorf("resume prepared composite: inspect %s destination: %w", member.channel, err)
		}
		if exists {
			if index != installed {
				return ports.CompositeCommitResult{}, errors.New("resume prepared composite: installed members are not a canonical prefix")
			}
			if _, err := readPublicationFile(run.Root(), member.staged.Path(), int64(len(member.staged.Bytes()))); err == nil {
				return ports.CompositeCommitResult{}, fmt.Errorf("resume prepared composite: %s exists at both staged and destination paths", member.channel)
			} else if !errors.Is(err, errPublicationAbsent) {
				return ports.CompositeCommitResult{}, fmt.Errorf("resume prepared composite: inspect staged %s: %w", member.channel, err)
			}
			receipts = append(receipts, receipt)
			installed++
			continue
		}
		file, err := readPublicationFile(run.Root(), member.staged.Path(), int64(len(member.staged.Bytes())))
		if err != nil {
			return ports.CompositeCommitResult{}, fmt.Errorf("resume prepared composite: re-read staged %s: %w", member.channel, err)
		}
		if file.sha256 != member.staged.SHA256() || !bytes.Equal(file.bytes, member.staged.Bytes()) {
			return ports.CompositeCommitResult{}, fmt.Errorf("resume prepared composite: staged %s bytes changed or hash mismatch", member.channel)
		}
		member.file = file
	}
	if installed == len(members) {
		result, err := ports.NewCompositeCommitResult(ports.CompositeCommittedDurable, receipts)
		if err != nil {
			return ports.CompositeCommitResult{}, fmt.Errorf("resume prepared composite: committed result: %w", err)
		}
		return result, nil
	}
	return store.movePreparedComposite(run, members, installed, receipts)
}

func (store *PublicationStore) movePreparedComposite(
	run ports.PublicationRun,
	members []publicationPreparedMoveMember,
	installed int,
	receipts []ports.SecureWriteReceipt,
) (ports.CompositeCommitResult, error) {
	if len(members) != 3 || installed < 0 || installed > 2 || len(receipts) != installed {
		return ports.CompositeCommitResult{}, errors.New("move prepared composite: invalid member state")
	}
	initialInstalled := installed
	operations := store.publicationOperations()
	rootFD, err := openAnchoredRoot(run.Root())
	if err != nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: open root: %w", err)
	}
	defer closeFD(rootFD)
	rootID, err := privateDirectoryIdentityForFD(rootFD)
	if err != nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: root identity: %w", err)
	}
	sourceParts, _, err := splitDestination(members[0].staged.Path())
	if err != nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: manifest source: %w", err)
	}
	sourceDirectory, err := walkPrivateDirectory(run.Root(), sourceParts, false)
	if err != nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: open source directory: %w", err)
	}
	defer closeFD(sourceDirectory)
	sourceID, err := privateDirectoryIdentityForFD(sourceDirectory)
	if err != nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: source directory identity: %w", err)
	}

	for index := installed; index < len(members); index++ {
		member := &members[index]
		parts, name, err := splitDestination(member.staged.Path())
		if err != nil {
			return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: source %s: %w", member.channel, err)
		}
		if strings.Join(parts, "/") != strings.Join(sourceParts, "/") {
			return ports.CompositeCommitResult{}, errors.New("move prepared composite: staged sources do not share one directory")
		}
		member.sourceName = name
		targetParts, targetName, err := splitDestination(member.destination.Path())
		if err != nil {
			return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: target %s: %w", member.channel, err)
		}
		if len(targetParts) > 0 {
			if err := store.writer.EnsurePrivateDir(run.Root(), parentPath(targetParts)); err != nil {
				return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: ensure target %s directory: %w", member.channel, err)
			}
		}
		targetFD, err := walkPrivateDirectory(run.Root(), targetParts, false)
		if err != nil {
			return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: open target %s directory: %w", member.channel, err)
		}
		member.targetFD = targetFD
		member.targetParts = targetParts
		member.targetName = targetName
		member.targetID, err = privateDirectoryIdentityForFD(targetFD)
		if err != nil {
			closeFD(targetFD)
			member.targetFD = -1
			return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: target %s identity: %w", member.channel, err)
		}
		defer closeFD(targetFD)
	}

	if installed == 0 {
		member := &members[0]
		if err := publicationMovePreparedMember(run, rootID, sourceParts, sourceID, sourceDirectory, member, operations); err != nil {
			return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: manifest: %w", err)
		}
		receipt, err := publicationReceiptFor(member.destination.Path(), member.receipt, member.channel)
		if err != nil {
			return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: manifest receipt: %w", err)
		}
		receipts = append(receipts, receipt)
		installed = 1
	}
	manifestResult, err := ports.NewCompositeCommitResult(ports.CompositeManifestInstalled, receipts[:1])
	if err != nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: manifest result: %w", err)
	}

	if installed == 1 {
		member := &members[1]
		if err := publicationMovePreparedMember(run, rootID, sourceParts, sourceID, sourceDirectory, member, operations); err != nil {
			return manifestResult, fmt.Errorf("move prepared composite: lineage edge: %w", err)
		}
		receipt, err := publicationReceiptFor(member.destination.Path(), member.receipt, member.channel)
		if err != nil {
			return manifestResult, fmt.Errorf("move prepared composite: lineage receipt: %w", err)
		}
		receipts = append(receipts, receipt)
	}
	membersResult, err := ports.NewCompositeCommitResult(ports.CompositeMembersInstalled, receipts[:2])
	if err != nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: members result: %w", err)
	}
	if initialInstalled < 2 {
		moved := members[initialInstalled:2]
		if err := publicationSyncMovedDirectories(
			run.Root(),
			rootID,
			sourceParts,
			sourceID,
			sourceDirectory,
			moved,
			operations,
		); err != nil {
			var namespaceUncertain *publicationNamespaceUncertainError
			if errors.As(err, &namespaceUncertain) {
				rollbackErr := publicationRollbackPreparedMembers(sourceDirectory, sourceID, moved, operations)
				if initialInstalled == 0 {
					return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: member namespace uncertain: %w", errors.Join(err, rollbackErr))
				}
				return manifestResult, fmt.Errorf("move prepared composite: lineage namespace uncertain: %w", errors.Join(err, rollbackErr))
			}
			return membersResult, fmt.Errorf("move prepared composite: members installed but undurable: %w", err)
		}
	}

	epoch := &members[2]
	if err := publicationMovePreparedMember(run, rootID, sourceParts, sourceID, sourceDirectory, epoch, operations); err != nil {
		return membersResult, fmt.Errorf("move prepared composite: epoch: %w", err)
	}
	epochReceipt, err := publicationReceiptFor(epoch.destination.Path(), epoch.receipt, epoch.channel)
	if err != nil {
		return membersResult, fmt.Errorf("move prepared composite: epoch receipt: %w", err)
	}
	receipts = append(receipts, epochReceipt)
	if err := publicationSyncMovedDirectories(
		run.Root(),
		rootID,
		sourceParts,
		sourceID,
		sourceDirectory,
		[]publicationPreparedMoveMember{*epoch},
		operations,
	); err != nil {
		var namespaceUncertain *publicationNamespaceUncertainError
		if errors.As(err, &namespaceUncertain) {
			rollbackErr := publicationRollbackPreparedMembers(sourceDirectory, sourceID, []publicationPreparedMoveMember{*epoch}, operations)
			return membersResult, fmt.Errorf("move prepared composite: epoch namespace uncertain: %w", errors.Join(err, rollbackErr))
		}
		built, buildErr := ports.NewCompositeCommitResult(ports.CompositeEpochInstalledUndurable, receipts)
		if buildErr != nil {
			return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: epoch result: %w", buildErr)
		}
		return built, fmt.Errorf("move prepared composite: epoch installed but undurable: %w", err)
	}
	built, err := ports.NewCompositeCommitResult(ports.CompositeCommittedDurable, receipts)
	if err != nil {
		return ports.CompositeCommitResult{}, fmt.Errorf("move prepared composite: committed result: %w", err)
	}
	return built, nil
}

func publicationMovePreparedMember(
	run ports.PublicationRun,
	rootID privateDirectoryIdentity,
	sourceParts []string,
	sourceID privateDirectoryIdentity,
	sourceDirectory int,
	member *publicationPreparedMoveMember,
	operations publicationStoreOperations,
) error {
	if err := errors.Join(
		revalidatePrivateDirectory(run.Root(), nil, rootID, defaultSecureWriterOperations()),
		revalidatePrivateDirectory(run.Root(), sourceParts, sourceID, defaultSecureWriterOperations()),
		revalidatePrivateDirectory(run.Root(), member.targetParts, member.targetID, defaultSecureWriterOperations()),
		validatePublicationFileHashAt(sourceDirectory, member.sourceName, member.file.identity, member.staged.SHA256()),
	); err != nil {
		return fmt.Errorf("source or target namespace changed before rename: %w", err)
	}
	if err := operations.renameatxNp(sourceDirectory, member.sourceName, member.targetFD, member.targetName, unix.RENAME_EXCL); err != nil {
		return fmt.Errorf("no-replace rename: %w", err)
	}
	if err := errors.Join(
		publicationValidateInstalledMove(
			run.Root(),
			rootID,
			sourceParts,
			sourceID,
			member.targetParts,
			member.targetID,
			member.targetFD,
			member.targetName,
			member.file.identity,
		),
		validatePublicationFileHashAt(member.targetFD, member.targetName, member.file.identity, member.staged.SHA256()),
	); err != nil {
		rollbackErr := publicationRollbackInstalledMove(
			sourceDirectory,
			member.sourceName,
			sourceID,
			member.targetFD,
			member.targetName,
			member.targetID,
			member.file.identity,
			operations,
		)
		return fmt.Errorf("target namespace uncertain after rename: %w", errors.Join(err, rollbackErr))
	}
	return nil
}

func publicationRollbackPreparedMembers(
	sourceDirectory int,
	sourceID privateDirectoryIdentity,
	members []publicationPreparedMoveMember,
	operations publicationStoreOperations,
) error {
	var rollbackErr error
	for index := len(members) - 1; index >= 0; index-- {
		member := members[index]
		rollbackErr = errors.Join(rollbackErr, publicationRollbackInstalledMove(
			sourceDirectory,
			member.sourceName,
			sourceID,
			member.targetFD,
			member.targetName,
			member.targetID,
			member.file.identity,
			operations,
		))
	}
	return rollbackErr
}

func publicationSyncMovedDirectories(
	root ports.AnchoredRoot,
	rootID privateDirectoryIdentity,
	sourceParts []string,
	sourceID privateDirectoryIdentity,
	sourceFD int,
	members []publicationPreparedMoveMember,
	operations publicationStoreOperations,
) error {
	if err := publicationValidateMovedDirectories(root, rootID, sourceParts, sourceID, sourceFD, members); err != nil {
		return &publicationNamespaceUncertainError{cause: err}
	}
	syncErrors := []error{operations.fsync(sourceFD)}
	for _, member := range members {
		syncErrors = append(syncErrors, operations.fsync(member.targetFD))
	}
	syncErr := errors.Join(syncErrors...)
	if err := publicationValidateMovedDirectories(root, rootID, sourceParts, sourceID, sourceFD, members); err != nil {
		return &publicationNamespaceUncertainError{cause: errors.Join(syncErr, err)}
	}
	return syncErr
}

func publicationValidateMovedDirectories(
	root ports.AnchoredRoot,
	rootID privateDirectoryIdentity,
	sourceParts []string,
	sourceID privateDirectoryIdentity,
	sourceFD int,
	members []publicationPreparedMoveMember,
) error {
	errorsToJoin := []error{
		revalidatePrivateDirectory(root, nil, rootID, defaultSecureWriterOperations()),
		revalidatePrivateDirectory(root, sourceParts, sourceID, defaultSecureWriterOperations()),
		privateDirectoryIdentityMatches(sourceFD, sourceID),
	}
	for _, member := range members {
		errorsToJoin = append(
			errorsToJoin,
			revalidatePrivateDirectory(root, member.targetParts, member.targetID, defaultSecureWriterOperations()),
			privateDirectoryIdentityMatches(member.targetFD, member.targetID),
			validatePublicationFileHashAt(member.targetFD, member.targetName, member.file.identity, member.staged.SHA256()),
		)
	}
	return errors.Join(errorsToJoin...)
}

func (store *PublicationStore) publicationOperations() publicationStoreOperations {
	operations := store.operations
	if operations.fsync == nil {
		operations.fsync = unix.Fsync
	}
	if operations.renameatxNp == nil {
		operations.renameatxNp = unix.RenameatxNp
	}
	return operations
}

func (store *PublicationStore) ReadCommittedSnapshot(ctx context.Context, request ports.ReadCommittedSnapshotRequest) (ports.CommittedPublicationSnapshot, error) {
	if ctx == nil {
		return ports.CommittedPublicationSnapshot{}, fmt.Errorf("read committed snapshot: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	if err := store.valid(); err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	if !request.Run().Valid() || request.MaxReadBytes() <= 0 {
		return ports.CommittedPublicationSnapshot{}, fmt.Errorf("read committed snapshot: invalid request")
	}

	var result ports.CommittedPublicationSnapshot
	err := store.withLock(ctx, request.Run().Root(), func() error {
		observe, err := ports.NewObserveRunRequest(request.Run(), request.MaxReadBytes())
		if err != nil {
			return fmt.Errorf("read committed snapshot: observation request: %w", err)
		}
		observation, snapshot, err := store.observeLocked(ctx, observe)
		if err != nil {
			return err
		}
		if observation.ClassifierInput().Observation() != domain.DurableObservationP2Committed || snapshot == nil {
			return fmt.Errorf("read committed snapshot: P2 composite is absent")
		}
		result = *snapshot
		return nil
	})
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	return result, nil
}

func (store *PublicationStore) WriteCorruptionDiagnostic(ctx context.Context, request ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
	if ctx == nil {
		return ports.CorruptionDiagnosticResult{}, fmt.Errorf("write corruption diagnostic: nil context")
	}
	if err := ctx.Err(); err != nil {
		return ports.CorruptionDiagnosticResult{}, err
	}
	if err := store.valid(); err != nil {
		return ports.CorruptionDiagnosticResult{}, err
	}
	if !request.Valid() ||
		int64(len(request.Diagnostic().Bytes())) > publicationMaximumReadBytes {
		return ports.CorruptionDiagnosticResult{}, fmt.Errorf("write corruption diagnostic: invalid request")
	}

	var result ports.CorruptionDiagnosticResult
	err := store.withLock(ctx, request.Run().Root(), func() error {
		observeRequest, err := ports.NewObserveRunRequest(
			request.Run(),
			publicationMaximumReadBytes,
		)
		if err != nil {
			return fmt.Errorf("write corruption diagnostic: observation request: %w", err)
		}
		current, _, err := store.observeLocked(ctx, observeRequest)
		if err != nil {
			return fmt.Errorf("write corruption diagnostic: re-observe: %w", err)
		}
		if !request.Observation().Matches(current) {
			return fmt.Errorf(
				"write corruption diagnostic: %w",
				ports.ErrCorruptionObservationStale,
			)
		}
		receipt, exists, err := store.durableExistingImmutable(request.Run(), request.Diagnostic(), "publication_corruption_diagnostic")
		if err != nil {
			return fmt.Errorf("write corruption diagnostic: existing artifact: %w", err)
		}
		if exists {
			result, err = ports.NewCorruptionDiagnosticResult(
				request.Diagnostic(),
				receipt,
				ports.CorruptionDiagnosticDurable,
			)
			if err != nil {
				return fmt.Errorf("write corruption diagnostic: existing result: %w", err)
			}
			return nil
		}
		receipt, writeErr := store.writeImmutable(ctx, request.Run(), request.Diagnostic(), "publication_corruption_diagnostic")
		if writeErr != nil && !receipt.Destination().Valid() {
			return fmt.Errorf("write corruption diagnostic: %w", writeErr)
		}
		durability := ports.CorruptionDiagnosticDurable
		if writeErr != nil {
			var undurable *InstalledButUndurableError
			if !errors.As(writeErr, &undurable) {
				return fmt.Errorf("write corruption diagnostic: %w", writeErr)
			}
			durability = ports.CorruptionDiagnosticUndurable
		}
		built, err := ports.NewCorruptionDiagnosticResult(request.Diagnostic(), receipt, durability)
		if err != nil {
			return fmt.Errorf("write corruption diagnostic: result: %w", err)
		}
		result = built
		if writeErr != nil {
			return fmt.Errorf("write corruption diagnostic: installed but undurable: %w", writeErr)
		}
		return nil
	})
	if err != nil {
		if result.Valid() {
			if publicationPostEffectUncertain(err) {
				rebuilt, rebuildErr := ports.NewCorruptionDiagnosticResult(
					result.Diagnostic(),
					result.Receipt(),
					ports.CorruptionDiagnosticUndurable,
				)
				if rebuildErr != nil {
					return ports.CorruptionDiagnosticResult{}, errors.Join(err, rebuildErr)
				}
				result = rebuilt
			}
			return result, err
		}
		return ports.CorruptionDiagnosticResult{}, err
	}
	return result, nil
}

func (store *PublicationStore) valid() error {
	if store == nil || nilInterface(store.validator) || nilInterface(store.clock) || nilInterface(store.ids) || nilInterface(store.writer) || !store.finalSchema.Valid() || !store.manifestSchema.Valid() {
		return errors.New("publication store: invalid store")
	}
	return nil
}

type publicationPostEffectError struct {
	cause error
}

func (err *publicationPostEffectError) Error() string {
	return fmt.Sprintf("publication effect completed but lock confirmation failed: %v", err.cause)
}

func (err *publicationPostEffectError) Unwrap() error { return err.cause }

func publicationPostEffectUncertain(err error) bool {
	var postEffect *publicationPostEffectError
	return errors.As(err, &postEffect)
}

// WithNextPublicationEpoch serializes epoch selection and publication for one
// root. Store operations called by publish reuse this transaction's lock.
func (store *PublicationStore) WithNextPublicationEpoch(
	ctx context.Context,
	root ports.AnchoredRoot,
	publish func(context.Context, uint64) error,
) error {
	if ctx == nil {
		return errors.New("next publication epoch: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.valid(); err != nil {
		return err
	}
	if publish == nil {
		return errors.New("next publication epoch: nil callback")
	}
	return store.withLockContext(ctx, root, func(commitCtx context.Context) error {
		epoch, err := nextPublicationEpoch(root)
		if err != nil {
			return fmt.Errorf("next publication epoch: scan: %w", err)
		}
		return publish(commitCtx, epoch)
	})
}

func (store *PublicationStore) withLock(ctx context.Context, root ports.AnchoredRoot, callback func() error) error {
	return store.withLockContext(ctx, root, func(context.Context) error {
		return callback()
	})
}

func (store *PublicationStore) withLockContext(ctx context.Context, root ports.AnchoredRoot, callback func(context.Context) error) error {
	if ctx == nil {
		return errors.New("publication store: nil context")
	}
	if transaction, ok := ctx.Value(publicationTransactionContextKey{}).(*publicationTransaction); ok {
		if transaction == nil || transaction.store != store || transaction.root != root {
			return errors.New("publication store: transaction lock store or root mismatch")
		}
		if err := transaction.lock.validate(); err != nil {
			return fmt.Errorf("publication store: transaction lock namespace changed: %w", err)
		}
		return callback(ctx)
	}
	if !root.Valid() {
		return errors.New("publication store: invalid root")
	}
	publicationStoreProcessMu.Lock()
	defer publicationStoreProcessMu.Unlock()
	lock, err := store.acquireLock(ctx, root)
	if err != nil {
		return err
	}
	transactionCtx := context.WithValue(ctx, publicationTransactionContextKey{}, &publicationTransaction{
		store: store,
		root:  root,
		lock:  lock,
	})
	callbackErr := callback(transactionCtx)
	teardownErr := errors.Join(lock.validate(), lock.Release())
	if callbackErr != nil {
		return errors.Join(callbackErr, teardownErr)
	}
	if teardownErr != nil {
		return &publicationPostEffectError{cause: teardownErr}
	}
	return nil
}

func nextPublicationEpoch(root ports.AnchoredRoot) (uint64, error) {
	epochsPath, err := ports.NewSafeRelativePath("store/epochs")
	if err != nil {
		return 0, fmt.Errorf("epoch directory path: %w", err)
	}
	directory, err := walkPrivateDirectory(root, strings.Split(epochsPath.String(), "/"), false)
	if errors.Is(err, unix.ENOENT) {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open epoch directory: %w", err)
	}
	defer closeFD(directory)

	identity, err := privateDirectoryIdentityForFD(directory)
	if err != nil {
		return 0, fmt.Errorf("epoch directory identity: %w", err)
	}
	scanFD, err := unix.Dup(directory)
	if err != nil {
		return 0, fmt.Errorf("duplicate epoch directory: %w", err)
	}
	file := os.NewFile(uintptr(scanFD), epochsPath.String())
	entries, readErr := readPublicationDirectoryEntries(file)
	closeErr := file.Close()
	if readErr != nil {
		return 0, fmt.Errorf("read epoch directory: %w", readErr)
	}
	if closeErr != nil {
		return 0, fmt.Errorf("close epoch directory: %w", closeErr)
	}

	var highest uint64
	for _, entry := range entries {
		name := entry.Name()
		epoch, err := parsePublicationEpochFilename(name)
		if err != nil {
			return 0, err
		}
		fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return 0, fmt.Errorf("open epoch member %q: %w", name, err)
		}
		_, validationErr := publicationFileIdentityForFD(fd)
		closeErr := unix.Close(fd)
		if validationErr != nil {
			return 0, fmt.Errorf("validate epoch member %q: %w", name, validationErr)
		}
		if closeErr != nil {
			return 0, fmt.Errorf("close epoch member %q: %w", name, closeErr)
		}
		if epoch == 0 {
			return 0, fmt.Errorf("malformed epoch member %q", name)
		}
		if epoch > highest {
			highest = epoch
		}
	}
	if highest == ^uint64(0) {
		return 0, errors.New("epoch overflow")
	}
	next := highest + 1
	candidate := fmt.Sprintf("epoch_%020d.json", next)
	var stat unix.Stat_t
	if err := unix.Fstatat(directory, candidate, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return 0, fmt.Errorf("epoch collision at %q", candidate)
	} else if !errors.Is(err, unix.ENOENT) {
		return 0, fmt.Errorf("stat next epoch %q: %w", candidate, err)
	}
	if err := revalidatePrivateDirectory(root, strings.Split(epochsPath.String(), "/"), identity, defaultSecureWriterOperations()); err != nil {
		return 0, fmt.Errorf("epoch directory namespace changed: %w", err)
	}
	return next, nil
}

func parsePublicationEpochFilename(name string) (uint64, error) {
	const prefix = "epoch_"
	const suffix = ".json"
	if len(name) != len(prefix)+20+len(suffix) ||
		!strings.HasPrefix(name, prefix) ||
		!strings.HasSuffix(name, suffix) {
		return 0, fmt.Errorf("malformed epoch member %q", name)
	}
	digits := name[len(prefix) : len(name)-len(suffix)]
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("malformed epoch member %q", name)
		}
	}
	epoch, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || epoch == 0 {
		return 0, fmt.Errorf("malformed epoch member %q", name)
	}
	return epoch, nil
}

func (store *PublicationStore) acquireLock(ctx context.Context, root ports.AnchoredRoot) (*publicationStoreLock, error) {
	rootFD, err := openAnchoredRoot(root)
	if err != nil {
		return nil, fmt.Errorf("acquire publication lock: open root: %w", err)
	}
	retainRootFD := false
	defer func() {
		if !retainRootFD {
			closeFD(rootFD)
		}
	}()
	rootIdentity, err := privateDirectoryIdentityForFD(rootFD)
	if err != nil {
		return nil, fmt.Errorf("acquire publication lock: root identity: %w", err)
	}
	lockPath, err := ports.NewSafeRelativePath(publicationLockDirectory)
	if err != nil {
		return nil, fmt.Errorf("acquire publication lock: lock path: %w", err)
	}
	if err := store.writer.EnsurePrivateDir(root, lockPath); err != nil {
		return nil, fmt.Errorf("acquire publication lock: ensure directory: %w", err)
	}
	directory, err := walkPrivateDirectory(root, strings.Split(publicationLockDirectory, "/"), false)
	if err != nil {
		return nil, fmt.Errorf("acquire publication lock: open directory: %w", err)
	}
	identity, err := privateDirectoryIdentityForFD(directory)
	if err != nil {
		closeFD(directory)
		return nil, fmt.Errorf("acquire publication lock: directory identity: %w", err)
	}
	file, err := unix.Openat(directory, publicationLockFile, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, privateFileMode)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		file, err = unix.Openat(directory, publicationLockFile, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		closeFD(directory)
		return nil, fmt.Errorf("acquire publication lock: open lock file: %w", err)
	}
	if created {
		if err := unix.Fsync(directory); err != nil {
			closeFD(file)
			closeFD(directory)
			return nil, fmt.Errorf("acquire publication lock: sync created lock file: %w", err)
		}
	}
	fileID, err := publicationFileIdentityForFD(file)
	if err != nil {
		closeFD(file)
		closeFD(directory)
		return nil, fmt.Errorf("acquire publication lock: validate lock file: %w", err)
	}
	lock := &publicationStoreLock{root: root, rootFD: rootFD, rootIdentity: rootIdentity, directory: directory, file: file, identity: identity, fileID: fileID}
	retainRootFD = true
	if err := lock.validate(); err != nil {
		_ = lock.Release()
		return nil, fmt.Errorf("acquire publication lock: namespace changed: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = lock.Release()
			return nil, err
		}
		err := unix.Flock(file, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			_ = lock.Release()
			return nil, fmt.Errorf("acquire publication lock: flock: %w", err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = lock.Release()
			return nil, ctx.Err()
		case <-timer.C:
		}
		if err := lock.validate(); err != nil {
			_ = lock.Release()
			return nil, fmt.Errorf("acquire publication lock: namespace changed while waiting: %w", err)
		}
	}
	if err := lock.validate(); err != nil {
		_ = lock.Release()
		return nil, fmt.Errorf("acquire publication lock: namespace changed after flock: %w", err)
	}
	return lock, nil
}

func (lock *publicationStoreLock) validate() error {
	if lock == nil || lock.rootFD < 0 || lock.directory < 0 || lock.file < 0 {
		return errors.New("invalid publication lock")
	}
	rootIdentity, err := privateDirectoryIdentityForFD(lock.rootFD)
	if err != nil {
		return fmt.Errorf("validate retained root: %w", err)
	}
	if rootIdentity != lock.rootIdentity {
		return errors.New("retained root identity changed")
	}
	if err := revalidatePrivateDirectory(lock.root, nil, lock.rootIdentity, defaultSecureWriterOperations()); err != nil {
		return err
	}
	if err := revalidatePrivateDirectory(lock.root, strings.Split(publicationLockDirectory, "/"), lock.identity, defaultSecureWriterOperations()); err != nil {
		return err
	}
	return validatePublicationFileAt(lock.directory, publicationLockFile, lock.fileID)
}

func (lock *publicationStoreLock) Release() error {
	if lock == nil {
		return nil
	}
	var releaseErr error
	if lock.file >= 0 {
		releaseErr = errors.Join(releaseErr, unix.Flock(lock.file, unix.LOCK_UN), unix.Close(lock.file))
		lock.file = -1
	}
	if lock.directory >= 0 {
		releaseErr = errors.Join(releaseErr, unix.Close(lock.directory))
		lock.directory = -1
	}
	if lock.rootFD >= 0 {
		releaseErr = errors.Join(releaseErr, unix.Close(lock.rootFD))
		lock.rootFD = -1
	}
	return releaseErr
}

func parentPath(parts []string) ports.SafeRelativePath {
	path, err := ports.NewSafeRelativePath(strings.Join(parts, "/"))
	if err != nil {
		panic(fmt.Sprintf("publication parent path invariant: %v", err))
	}
	return path
}

func publicationFileIdentityForFD(fd int) (publicationFileIdentity, error) {
	if err := verifyPrivateRegularFile(fd); err != nil {
		return publicationFileIdentity{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return publicationFileIdentity{}, fmt.Errorf("stat private file: %w", err)
	}
	return publicationFileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func validatePublicationFileAt(directory int, name string, expected publicationFileIdentity) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(directory, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat private file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("private file is not regular")
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != privateFileMode {
		return errors.New("private file owner or mode changed")
	}
	actual := publicationFileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}
	if actual != expected {
		return errors.New("private file namespace changed")
	}
	return nil
}
func publicationValidateInstalledMove(
	root ports.AnchoredRoot,
	rootID privateDirectoryIdentity,
	sourceParts []string,
	sourceID privateDirectoryIdentity,
	destinationParts []string,
	destinationID privateDirectoryIdentity,
	destinationFD int,
	destinationName string,
	installed publicationFileIdentity,
) error {
	return errors.Join(
		revalidatePrivateDirectory(root, nil, rootID, defaultSecureWriterOperations()),
		revalidatePrivateDirectory(root, sourceParts, sourceID, defaultSecureWriterOperations()),
		revalidatePrivateDirectory(root, destinationParts, destinationID, defaultSecureWriterOperations()),
		validatePublicationFileAt(destinationFD, destinationName, installed),
	)
}
func publicationSourceNameAbsent(directory int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(directory, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat move source: %w", err)
	}
	return errors.New("move source was replaced")
}

func publicationRollbackInstalledMove(
	sourceDirectory int,
	sourceName string,
	sourceID privateDirectoryIdentity,
	destinationDirectory int,
	destinationName string,
	destinationID privateDirectoryIdentity,
	installed publicationFileIdentity,
	operations publicationStoreOperations,
) error {
	if err := errors.Join(
		privateDirectoryIdentityMatches(sourceDirectory, sourceID),
		privateDirectoryIdentityMatches(destinationDirectory, destinationID),
		publicationSourceNameAbsent(sourceDirectory, sourceName),
		validatePublicationFileAt(destinationDirectory, destinationName, installed),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: err}
	}
	if err := operations.renameatxNp(destinationDirectory, destinationName, sourceDirectory, sourceName, unix.RENAME_EXCL); err != nil {
		return &publicationNamespaceUncertainError{cause: fmt.Errorf("rollback moved file: %w", err)}
	}
	if err := errors.Join(
		privateDirectoryIdentityMatches(sourceDirectory, sourceID),
		privateDirectoryIdentityMatches(destinationDirectory, destinationID),
		validatePublicationFileAt(sourceDirectory, sourceName, installed),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: err}
	}
	var syncErr error
	if sourceID == destinationID {
		syncErr = operations.fsync(sourceDirectory)
	} else {
		syncErr = errors.Join(operations.fsync(sourceDirectory), operations.fsync(destinationDirectory))
	}
	if err := errors.Join(
		privateDirectoryIdentityMatches(sourceDirectory, sourceID),
		privateDirectoryIdentityMatches(destinationDirectory, destinationID),
		validatePublicationFileAt(sourceDirectory, sourceName, installed),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: errors.Join(syncErr, err)}
	}
	return syncErr
}

func privateDirectoryIdentityMatches(directory int, expected privateDirectoryIdentity) error {
	actual, err := privateDirectoryIdentityForFD(directory)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("retained private directory identity changed")
	}
	return nil
}

func publicationSyncInstalledFinal(
	root ports.AnchoredRoot,
	rootID privateDirectoryIdentity,
	sourceParts []string,
	sourceID privateDirectoryIdentity,
	sourceFD int,
	destinationParts []string,
	destinationID privateDirectoryIdentity,
	destinationFD int,
	destinationName string,
	installed publicationFileIdentity,
	expectedSHA256 string,
	operations publicationStoreOperations,
) error {
	if err := errors.Join(
		publicationValidateInstalledMove(
			root,
			rootID,
			sourceParts,
			sourceID,
			destinationParts,
			destinationID,
			destinationFD,
			destinationName,
			installed,
		),
		validatePublicationFileHashAt(destinationFD, destinationName, installed, expectedSHA256),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: err}
	}
	var syncErr error
	if sourceID == destinationID {
		syncErr = operations.fsync(sourceFD)
	} else {
		syncErr = errors.Join(operations.fsync(sourceFD), operations.fsync(destinationFD))
	}
	if err := errors.Join(
		publicationValidateInstalledMove(
			root,
			rootID,
			sourceParts,
			sourceID,
			destinationParts,
			destinationID,
			destinationFD,
			destinationName,
			installed,
		),
		validatePublicationFileHashAt(destinationFD, destinationName, installed, expectedSHA256),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: errors.Join(syncErr, err)}
	}
	return syncErr
}

type publicationFile struct {
	bytes    []byte
	sha256   string
	length   int64
	identity publicationFileIdentity
}

func readPublicationFile(root ports.AnchoredRoot, path ports.SafeRelativePath, maximum int64) (publicationFile, error) {
	if !root.Valid() || !path.Valid() || maximum <= 0 || maximum > publicationMaximumReadBytes {
		return publicationFile{}, errors.New("invalid publication file read")
	}
	parts, name, err := splitDestination(path)
	if err != nil {
		return publicationFile{}, err
	}
	directory, err := walkPrivateDirectory(root, parts, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return publicationFile{}, errPublicationAbsent
		}
		return publicationFile{}, fmt.Errorf("open private directory: %w", err)
	}
	defer closeFD(directory)
	directoryID, err := privateDirectoryIdentityForFD(directory)
	if err != nil {
		return publicationFile{}, err
	}
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return publicationFile{}, errPublicationAbsent
		}
		return publicationFile{}, fmt.Errorf("open private file: %w", err)
	}
	identity, err := publicationFileIdentityForFD(fd)
	if err != nil {
		closeFD(fd)
		return publicationFile{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		closeFD(fd)
		return publicationFile{}, fmt.Errorf("stat private file: %w", err)
	}
	if stat.Size < 0 || stat.Size > maximum {
		closeFD(fd)
		return publicationFile{}, errPublicationCap
	}
	file := os.NewFile(uintptr(fd), name)
	reader := io.LimitReader(file, maximum+1)
	data, readErr := io.ReadAll(reader)
	closeErr := file.Close()
	if readErr != nil {
		return publicationFile{}, fmt.Errorf("read private file: %w", readErr)
	}
	if closeErr != nil {
		return publicationFile{}, fmt.Errorf("close private file: %w", closeErr)
	}
	if int64(len(data)) > maximum {
		return publicationFile{}, errPublicationCap
	}
	if err := validatePublicationFileAt(directory, name, identity); err != nil {
		return publicationFile{}, err
	}
	if err := revalidatePrivateDirectory(root, parts, directoryID, defaultSecureWriterOperations()); err != nil {
		return publicationFile{}, err
	}
	return publicationFile{bytes: data, sha256: publicationSHA256(data), length: int64(len(data)), identity: identity}, nil
}

func listPublicationDirectory(root ports.AnchoredRoot, path ports.SafeRelativePath) ([]string, bool, error) {
	if !root.Valid() || !path.Valid() {
		return nil, false, errors.New("invalid publication directory")
	}
	directory, err := walkPrivateDirectory(root, strings.Split(path.String(), "/"), false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil
		}
		return nil, false, err
	}
	identity, err := privateDirectoryIdentityForFD(directory)
	if err != nil {
		closeFD(directory)
		return nil, false, err
	}
	file := os.NewFile(uintptr(directory), path.String())
	entries, readErr := readPublicationDirectoryEntries(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, false, fmt.Errorf("read private directory: %w", readErr)
	}
	if closeErr != nil {
		return nil, false, fmt.Errorf("close private directory: %w", closeErr)
	}
	if err := revalidatePrivateDirectory(root, strings.Split(path.String(), "/"), identity, defaultSecureWriterOperations()); err != nil {
		return nil, false, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() != "." && entry.Name() != ".." {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, true, nil
}
func listPublicationRoot(root ports.AnchoredRoot) ([]string, error) {
	directory, err := openAnchoredRoot(root)
	if err != nil {
		return nil, err
	}
	var before unix.Stat_t
	if err := unix.Fstat(directory, &before); err != nil {
		closeFD(directory)
		return nil, fmt.Errorf("stat anchored root: %w", err)
	}
	file := os.NewFile(uintptr(directory), root.String())
	entries, readErr := readPublicationDirectoryEntries(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read anchored root: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close anchored root: %w", closeErr)
	}
	reopened, err := openAnchoredRoot(root)
	if err != nil {
		return nil, fmt.Errorf("reopen anchored root: %w", err)
	}
	var after unix.Stat_t
	statErr := unix.Fstat(reopened, &after)
	closeFD(reopened)
	if statErr != nil {
		return nil, fmt.Errorf("restat anchored root: %w", statErr)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		return nil, errors.New("anchored root namespace changed")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() != "." && entry.Name() != ".." {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
func readPublicationDirectoryEntries(directory *os.File) ([]os.DirEntry, error) {
	entries, err := directory.ReadDir(publicationDirectoryEntryCap + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > publicationDirectoryEntryCap {
		return nil, fmt.Errorf("publication directory exceeds entry cap %d", publicationDirectoryEntryCap)
	}
	return entries, nil
}

func publicationSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validPublicationSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func publicationReceiptFor(destination ports.SafeRelativePath, source ports.SecureWriteReceipt, channel string) (ports.SecureWriteReceipt, error) {
	return ports.NewSecureWriteReceipt(source.Root(), destination, source.SHA256(), source.ByteLength(), channel, source.SourceIDs())
}

type publicationMutableFile struct {
	identity publicationFileIdentity
	sha256   string
}

func observePublicationMutableFile(directory int, name string) (publicationMutableFile, bool, error) {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return publicationMutableFile{}, false, nil
	}
	if err != nil {
		return publicationMutableFile{}, false, fmt.Errorf("replace mutable: open prior file: %w", err)
	}
	identity, verifyErr := publicationFileIdentityForFD(fd)
	if verifyErr != nil {
		closeFD(fd)
		return publicationMutableFile{}, false, fmt.Errorf("replace mutable: validate prior file: %w", verifyErr)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		closeFD(fd)
		return publicationMutableFile{}, false, fmt.Errorf("replace mutable: stat prior file: %w", err)
	}
	if stat.Size < 0 || stat.Size > publicationMaximumReadBytes {
		closeFD(fd)
		return publicationMutableFile{}, false, errPublicationCap
	}
	file := os.NewFile(uintptr(fd), name)
	hash := sha256.New()
	read, copyErr := io.CopyBuffer(
		hash,
		io.LimitReader(file, publicationMaximumReadBytes+1),
		make([]byte, publicationReadBuffer),
	)
	closeErr := file.Close()
	if read > publicationMaximumReadBytes {
		return publicationMutableFile{}, false, errPublicationCap
	}
	if copyErr != nil {
		return publicationMutableFile{}, false, fmt.Errorf("replace mutable: hash prior file: %w", copyErr)
	}
	if closeErr != nil {
		return publicationMutableFile{}, false, fmt.Errorf("replace mutable: close prior file: %w", closeErr)
	}
	if err := validatePublicationFileAt(directory, name, identity); err != nil {
		return publicationMutableFile{}, false, fmt.Errorf("replace mutable: prior file changed: %w", err)
	}
	return publicationMutableFile{
		identity: identity,
		sha256:   "sha256:" + hex.EncodeToString(hash.Sum(nil)),
	}, true, nil
}
func validatePublicationFileHashAt(
	directory int,
	name string,
	expected publicationFileIdentity,
	expectedSHA256 string,
) error {
	observed, exists, err := observePublicationMutableFile(directory, name)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("private file is absent")
	}
	if observed.identity != expected {
		return errors.New("private file namespace changed")
	}
	if observed.sha256 != expectedSHA256 {
		return errors.New("private file bytes changed")
	}
	return nil
}

func publicationValidateMutableReplacement(
	root ports.AnchoredRoot,
	rootID privateDirectoryIdentity,
	parts []string,
	directoryID privateDirectoryIdentity,
	directory int,
	name string,
	replacement publicationFileIdentity,
) error {
	return errors.Join(
		revalidatePrivateDirectory(root, nil, rootID, defaultSecureWriterOperations()),
		revalidatePrivateDirectory(root, parts, directoryID, defaultSecureWriterOperations()),
		validatePublicationFileAt(directory, name, replacement),
	)
}

func publicationRollbackMutableSwap(
	directoryID privateDirectoryIdentity,
	directory int,
	name string,
	temporaryName string,
	replacement publicationFileIdentity,
	displaced publicationMutableFile,
	operations publicationStoreOperations,
) error {
	if err := errors.Join(
		privateDirectoryIdentityMatches(directory, directoryID),
		validatePublicationFileAt(directory, name, replacement),
		validatePublicationFileAt(directory, temporaryName, displaced.identity),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: err}
	}
	if err := operations.renameatxNp(directory, temporaryName, directory, name, unix.RENAME_SWAP); err != nil {
		return &publicationNamespaceUncertainError{cause: fmt.Errorf("rollback swap: %w", err)}
	}
	if err := errors.Join(
		privateDirectoryIdentityMatches(directory, directoryID),
		validatePublicationFileAt(directory, name, displaced.identity),
		validatePublicationFileAt(directory, temporaryName, replacement),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: err}
	}
	if err := unix.Unlinkat(directory, temporaryName, 0); err != nil {
		return &publicationNamespaceUncertainError{cause: fmt.Errorf("rollback remove replacement: %w", err)}
	}
	if syncErr := operations.fsync(directory); syncErr != nil {
		if err := errors.Join(
			privateDirectoryIdentityMatches(directory, directoryID),
			validatePublicationFileAt(directory, name, displaced.identity),
		); err != nil {
			return &publicationNamespaceUncertainError{cause: errors.Join(syncErr, err)}
		}
		return syncErr
	}
	if err := errors.Join(
		privateDirectoryIdentityMatches(directory, directoryID),
		validatePublicationFileAt(directory, name, displaced.identity),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: err}
	}
	return nil
}

func publicationRollbackMutableAbsentInstall(
	directoryID privateDirectoryIdentity,
	directory int,
	name string,
	replacement publicationFileIdentity,
	expectedSHA256 string,
	operations publicationStoreOperations,
) error {
	if err := errors.Join(
		privateDirectoryIdentityMatches(directory, directoryID),
		validatePublicationFileHashAt(directory, name, replacement, expectedSHA256),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: err}
	}
	if err := unix.Unlinkat(directory, name, 0); err != nil {
		return &publicationNamespaceUncertainError{cause: fmt.Errorf("rollback remove replacement: %w", err)}
	}
	if syncErr := operations.fsync(directory); syncErr != nil {
		if err := errors.Join(
			privateDirectoryIdentityMatches(directory, directoryID),
			publicationSourceNameAbsent(directory, name),
		); err != nil {
			return &publicationNamespaceUncertainError{cause: errors.Join(syncErr, err)}
		}
		return syncErr
	}
	if err := errors.Join(
		privateDirectoryIdentityMatches(directory, directoryID),
		publicationSourceNameAbsent(directory, name),
	); err != nil {
		return &publicationNamespaceUncertainError{cause: err}
	}
	return nil
}

func (store *PublicationStore) validateFinal(ctx context.Context, document []byte) error {
	if len(document) == 0 {
		return errors.New("empty final review")
	}
	return store.validatePublicationSchema(ctx, store.finalSchema, document)
}

func (store *PublicationStore) validatePublicationSchema(
	ctx context.Context,
	schema ports.AssetID,
	document []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.validator.Validate(ctx, schema, append([]byte(nil), document...)); err != nil {
		var violation interface {
			DocumentViolation() bool
		}
		return &publicationSchemaValidationError{
			cause:             err,
			documentViolation: errors.As(err, &violation) && violation.DocumentViolation(),
		}
	}
	return nil
}

func publicationImmutableValidationOperational(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var validation *publicationSchemaValidationError
	return errors.As(err, &validation) && !validation.documentViolation
}
func (store *PublicationStore) validateFinalArtifact(ctx context.Context, run ports.PublicationRun, artifact ports.FinalReviewArtifact) error {
	if !artifact.Valid() {
		return errors.New("invalid final artifact")
	}
	if _, err := ports.NewPersistValidatedCandidateRequest(run, artifact); err != nil {
		return fmt.Errorf("final identity: %w", err)
	}
	if err := store.validateFinal(ctx, artifact.Bytes()); err != nil {
		return err
	}
	facts, err := parsePublicationFinalFacts(artifact.Bytes())
	if err != nil {
		return fmt.Errorf("final wire: %w", err)
	}
	if facts.sessionID != run.SessionID().String() || facts.runID != run.RunID().String() || facts.reviewID != artifact.Identity().ReviewID().String() {
		return errors.New("final IDs do not match artifact identity")
	}
	return nil
}

func (store *PublicationStore) validateFinalFile(
	ctx context.Context,
	run ports.PublicationRun,
	identity ports.FinalReviewIdentity,
	file publicationFile,
) error {
	if file.sha256 != identity.SHA256() || file.length == 0 {
		return errors.New("final hash mismatch")
	}
	artifact, err := ports.NewFinalReviewArtifact(identity, file.bytes)
	if err != nil {
		return err
	}
	return store.validateFinalArtifact(ctx, run, artifact)
}

func validatePrepareCompositeRequest(request ports.PrepareCompositeRequest) error {
	composite := request.Composite()
	canonical, err := ports.NewPrepareCompositeRequest(composite)
	if err != nil {
		return err
	}
	if canonical.StagedManifestPath() != request.StagedManifestPath() ||
		canonical.StagedLineageEdgePath() != request.StagedLineageEdgePath() ||
		canonical.StagedEpochPath() != request.StagedEpochPath() {
		return errors.New("staged paths are not canonical")
	}
	for _, artifact := range []ports.ImmutablePublicationArtifact{
		composite.Manifest(),
		composite.LineageEdge(),
		composite.Epoch().Record(),
	} {
		if int64(len(artifact.Bytes())) > publicationMaximumReadBytes {
			return errPublicationCap
		}
	}
	return nil
}

func validatePreparedCompositeRequest(prepared ports.PreparedComposite) error {
	if !prepared.Valid() {
		return errors.New("prepared composite is invalid")
	}
	if err := validatePrepareCompositeRequest(prepared.Request()); err != nil {
		return err
	}
	composite := prepared.Composite()
	if !bytes.Equal(prepared.StagedManifest().Bytes(), composite.Manifest().Bytes()) ||
		!bytes.Equal(prepared.StagedLineageEdge().Bytes(), composite.LineageEdge().Bytes()) ||
		!bytes.Equal(prepared.StagedEpoch().Bytes(), composite.Epoch().Record().Bytes()) {
		return errors.New("prepared bytes do not match composite")
	}
	for _, receipt := range prepared.Receipts() {
		if receipt.Root() != composite.Run().Root() {
			return errors.New("prepared receipt root does not match run")
		}
	}
	return nil
}

func (store *PublicationStore) durableExistingImmutable(
	run ports.PublicationRun,
	artifact ports.ImmutablePublicationArtifact,
	channel string,
) (ports.SecureWriteReceipt, bool, error) {
	if !run.Valid() || !artifact.Valid() {
		return ports.SecureWriteReceipt{}, false, errors.New("invalid existing immutable request")
	}
	payload := artifact.Bytes()
	if int64(len(payload)) > publicationMaximumReadBytes {
		return ports.SecureWriteReceipt{}, false, errPublicationCap
	}
	file, err := readPublicationFile(run.Root(), artifact.Path(), int64(len(payload)))
	if errors.Is(err, errPublicationAbsent) {
		return ports.SecureWriteReceipt{}, false, nil
	}
	if err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	if file.sha256 != artifact.SHA256() || !bytes.Equal(file.bytes, payload) {
		return ports.SecureWriteReceipt{}, false, errors.New("existing immutable artifact differs")
	}

	parts, name, err := splitDestination(artifact.Path())
	if err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	directory, err := walkPrivateDirectory(run.Root(), parts, false)
	if err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	defer closeFD(directory)
	directoryID, err := privateDirectoryIdentityForFD(directory)
	if err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	identity, err := publicationFileIdentityForFD(fd)
	if err != nil {
		closeFD(fd)
		return ports.SecureWriteReceipt{}, false, err
	}
	if identity != file.identity {
		closeFD(fd)
		return ports.SecureWriteReceipt{}, false, errors.New("existing immutable namespace changed")
	}
	operations := store.publicationOperations()
	syncErr := operations.fsync(fd)
	closeErr := unix.Close(fd)
	if syncErr != nil || closeErr != nil {
		return ports.SecureWriteReceipt{}, false, errors.Join(syncErr, closeErr)
	}
	if err := validatePublicationFileAt(directory, name, identity); err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	if err := revalidatePrivateDirectory(run.Root(), parts, directoryID, defaultSecureWriterOperations()); err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	if err := operations.fsync(directory); err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	if err := revalidatePrivateDirectory(run.Root(), parts, directoryID, defaultSecureWriterOperations()); err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	receipt, err := ports.NewSecureWriteReceipt(
		run.Root(),
		artifact.Path(),
		artifact.SHA256(),
		int64(len(payload)),
		channel,
		[]string{channel},
	)
	if err != nil {
		return ports.SecureWriteReceipt{}, false, err
	}
	return receipt, true, nil
}
func (store *PublicationStore) writePreparedImmutable(
	ctx context.Context,
	run ports.PublicationRun,
	artifact ports.ImmutablePublicationArtifact,
	channel string,
) (ports.SecureWriteReceipt, error) {
	if receipt, exists, err := store.durableExistingImmutable(run, artifact, channel); err != nil {
		return ports.SecureWriteReceipt{}, err
	} else if exists {
		return receipt, nil
	}
	return store.writeImmutable(ctx, run, artifact, channel)
}

func (store *PublicationStore) writeImmutable(ctx context.Context, run ports.PublicationRun, artifact ports.ImmutablePublicationArtifact, channel string) (ports.SecureWriteReceipt, error) {
	return store.writeImmutableUsing(ctx, run, artifact, channel, store.writer.Write)
}

func (store *PublicationStore) writeValidatedFinalArtifact(
	ctx context.Context,
	run ports.PublicationRun,
	artifact ports.FinalReviewArtifact,
	destination ports.SafeRelativePath,
	channel string,
) (ports.SecureWriteReceipt, error) {
	if err := store.validateFinalArtifact(ctx, run, artifact); err != nil {
		return ports.SecureWriteReceipt{}, err
	}
	immutable, err := ports.NewImmutablePublicationArtifact(destination, artifact.Identity().SHA256(), artifact.Bytes())
	if err != nil {
		return ports.SecureWriteReceipt{}, err
	}
	return store.writeImmutableUsing(ctx, run, immutable, channel, store.writeValidatedFinal)
}

type publicationWriteOperation func(context.Context, ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error)

func (store *PublicationStore) writeImmutableUsing(ctx context.Context, run ports.PublicationRun, artifact ports.ImmutablePublicationArtifact, channel string, write publicationWriteOperation) (ports.SecureWriteReceipt, error) {
	if !artifact.Valid() {
		return ports.SecureWriteReceipt{}, errors.New("invalid immutable artifact")
	}
	if write == nil {
		return ports.SecureWriteReceipt{}, errors.New("immutable writer is unavailable")
	}
	payload := artifact.Bytes()
	if int64(len(payload)) > publicationMaximumReadBytes {
		return ports.SecureWriteReceipt{}, errPublicationCap
	}
	parts, _, err := splitDestination(artifact.Path())
	if err != nil {
		return ports.SecureWriteReceipt{}, err
	}
	if len(parts) > 0 {
		if err := store.writer.EnsurePrivateDir(run.Root(), parentPath(parts)); err != nil {
			return ports.SecureWriteReceipt{}, fmt.Errorf("ensure immutable directory: %w", err)
		}
	}
	request, err := ports.NewSecureWriteRequest(run.Root(), artifact.Path(), channel, bytes.NewReader(payload), int64(len(payload)), []string{channel}, func(error) {})
	if err != nil {
		return ports.SecureWriteReceipt{}, err
	}
	receipt, _, writeErr := write(ctx, request)
	writeErr = classifiedPublicationStoreError(writeErr)
	if writeErr != nil && !receipt.Destination().Valid() {
		return ports.SecureWriteReceipt{}, writeErr
	}
	if receipt.Root() != run.Root() || receipt.Destination() != artifact.Path() || receipt.SHA256() != artifact.SHA256() || receipt.ByteLength() != int64(len(payload)) {
		return ports.SecureWriteReceipt{}, errors.New("immutable receipt does not match artifact")
	}
	file, err := readPublicationFile(run.Root(), artifact.Path(), int64(len(payload)))
	if err != nil {
		return receipt, &InstalledButUndurableError{
			receipt: receipt,
			cause: errors.Join(
				writeErr,
				fmt.Errorf("re-read immutable artifact: %w", err),
			),
		}
	}
	if file.sha256 != artifact.SHA256() || !bytes.Equal(file.bytes, payload) {
		return receipt, &InstalledButUndurableError{
			receipt: receipt,
			cause: errors.Join(
				writeErr,
				errors.New("immutable artifact changed after installation"),
			),
		}
	}
	return receipt, writeErr
}

func (store *PublicationStore) writeValidatedFinal(ctx context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	writer, ok := store.writer.(validatedFinalSecureWriter)
	if !ok {
		// Test doubles and alternate writers retain the stricter public writer
		// contract. The production SecureWriter supplies the validated-final
		// capability.
		return store.writer.Write(ctx, request)
	}
	return writer.writeValidatedFinal(ctx, request)
}

func (store *PublicationStore) writeAuthorizedRunSupport(ctx context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	writer, ok := store.writer.(authorizedRunSupportSecureWriter)
	if !ok {
		return store.writer.Write(ctx, request)
	}
	return writer.writeAuthorizedRunSupport(ctx, request)
}

type publicationArtifactWire struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type publicationRestartWire struct {
	SessionID                string                  `json:"session_id"`
	RunID                    string                  `json:"run_id"`
	PersistedJournalState    string                  `json:"persisted_journal_state"`
	ExpectedStaged           publicationArtifactWire `json:"expected_staged"`
	ExpectedFinal            publicationArtifactWire `json:"expected_final"`
	ValidatedCandidateSHA256 string                  `json:"validated_candidate_sha256"`
	StoreEpoch               uint64                  `json:"store_epoch"`
	NormalExit               int                     `json:"normal_exit"`
	ManifestPath             string                  `json:"manifest_path"`
	LineageEdgePath          string                  `json:"lineage_edge_path"`
	EpochPath                string                  `json:"epoch_path"`
}

type publicationJournalWire struct {
	SchemaVersion string `json:"schema_version"`
	publicationRestartWire
}

type publicationEpochWire struct {
	SchemaVersion string                  `json:"schema_version"`
	StoreEpoch    uint64                  `json:"store_epoch"`
	Manifest      publicationArtifactWire `json:"manifest"`
	LineageEdge   publicationArtifactWire `json:"lineage_edge"`
	FinalReview   publicationArtifactWire `json:"final_review"`
}

type publicationLineageChildWire struct {
	SessionID string `json:"session_id"`
	RunID     string `json:"run_id"`
	ReviewID  string `json:"review_id"`
}

type publicationLineageWire struct {
	SchemaVersion    string                      `json:"schema_version"`
	EdgeID           string                      `json:"edge_id"`
	Child            publicationLineageChildWire `json:"child"`
	ParentRunID      *string                     `json:"parent_run_id"`
	SourceRunID      *string                     `json:"source_run_id"`
	SourceReviewID   *string                     `json:"source_review_id"`
	SourceFindingRef *string                     `json:"source_finding_ref"`
	ReplayMode       *string                     `json:"replay_mode"`
}

type publicationJournalFacts struct {
	state                    domain.PersistedJournalState
	sessionID                string
	runID                    string
	reviewID                 domain.ReviewID
	stagedPath               ports.SafeRelativePath
	finalPath                ports.SafeRelativePath
	manifest                 ports.SafeRelativePath
	lineageEdge              ports.SafeRelativePath
	epoch                    ports.SafeRelativePath
	finalSHA256              string
	validatedCandidateSHA256 string
	storeEpoch               uint64
	normalExit               domain.OperationalExitCode
}

type publicationManifestFacts struct {
	sessionID     string
	runID         string
	finalReviewID string
	finalPath     string
	finalSHA256   string
	lineagePath   string
	lineageSHA256 string
	manifestPath  string
	epochPath     string
	exitCode      int
	committed     bool
}

type publicationObservationFiles struct {
	journal *ports.ObservedMutablePublicationDocument
	status  *ports.ObservedMutablePublicationDocument
	facts   *publicationJournalFacts
}

func (store *PublicationStore) discoverImmutableP2(
	ctx context.Context,
	request ports.ObserveRunRequest,
) (
	ports.PublicationObservation,
	*ports.CommittedPublicationSnapshot,
	publicationObservationFiles,
	bool,
	error,
) {
	manifestPath := publicationManifestPath(request.Run())
	manifestFile, err := readPublicationFile(request.Run().Root(), manifestPath, request.MaxReadBytes())
	if errors.Is(err, errPublicationAbsent) {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, false, nil
	}
	if err != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, err
	}
	manifestFacts, err := parsePublicationManifestFacts(manifestFile.bytes)
	if err != nil || !manifestFacts.committed ||
		manifestFacts.sessionID != request.Run().SessionID().String() ||
		manifestFacts.runID != request.Run().RunID().String() {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, errors.New("invalid committed manifest")
	}
	reviewID, err := domain.ParseReviewID(manifestFacts.finalReviewID)
	if err != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, err
	}
	finalPath, err := ports.NewSafeRelativePath(manifestFacts.finalPath)
	if err != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, err
	}
	lineagePath, err := ports.NewSafeRelativePath(manifestFacts.lineagePath)
	if err != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, err
	}
	epochPath, err := ports.NewSafeRelativePath(manifestFacts.epochPath)
	if err != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, err
	}
	recordedManifestPath, err := ports.NewSafeRelativePath(manifestFacts.manifestPath)
	if err != nil || recordedManifestPath != manifestPath {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, errors.New("manifest path is not canonical")
	}
	normalExit := domain.OperationalExitCode(manifestFacts.exitCode)
	if normalExit != domain.ExitCommittedPass &&
		normalExit != domain.ExitCommittedCIRejected &&
		normalExit != domain.ExitIncompleteCoverage {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, errors.New("invalid committed exit")
	}

	finalNames, finalErr := publicationFinalNames(request.Run())
	stagedNames, stagedErr := publicationStagedNames(request.Run())
	if finalErr != nil || stagedErr != nil || len(finalNames) != 1 ||
		finalNames[0] != safeBasename(finalPath) || len(stagedNames) != 0 {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, errors.New("committed final namespace is ambiguous")
	}
	finalFile, finalErr := readPublicationFile(request.Run().Root(), finalPath, request.MaxReadBytes())
	edgeFile, edgeErr := readPublicationFile(request.Run().Root(), lineagePath, request.MaxReadBytes())
	epochFile, epochErr := readPublicationFile(request.Run().Root(), epochPath, request.MaxReadBytes())
	for _, readErr := range []error{finalErr, edgeErr, epochErr} {
		if errors.Is(readErr, errPublicationAbsent) {
			return ports.PublicationObservation{}, nil, publicationObservationFiles{}, false, nil
		}
		if readErr != nil {
			return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, readErr
		}
	}
	preparedCount, preparedErr := publicationPreparedMemberCount(request.Run(), request.MaxReadBytes())
	if preparedErr != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, fmt.Errorf("prepared namespace: %w", preparedErr)
	}
	if preparedCount != 0 {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, errors.New("prepared members remain beside immutable P2")
	}
	epochWire, err := parsePublicationEpoch(epochFile.bytes)
	if err != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, true, err
	}
	facts := publicationJournalFacts{
		state:       domain.JournalCollecting,
		sessionID:   request.Run().SessionID().String(),
		runID:       request.Run().RunID().String(),
		reviewID:    reviewID,
		finalPath:   finalPath,
		manifest:    manifestPath,
		lineageEdge: lineagePath,
		epoch:       epochPath,
		finalSHA256: manifestFacts.finalSHA256,
		storeEpoch:  epochWire.StoreEpoch,
		normalExit:  normalExit,
	}
	snapshot, err := store.validateCommittedSnapshot(
		ctx,
		request.Run(),
		facts,
		finalFile,
		manifestFile,
		edgeFile,
		epochFile,
	)
	if err != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{facts: &facts}, true, err
	}
	if _, err := ports.NewCommitCompositeRequest(
		request.Run(),
		snapshot.Final().Identity(),
		snapshot.Manifest(),
		snapshot.LineageEdge(),
		snapshot.Epoch(),
	); err != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{facts: &facts}, true, err
	}
	if err := store.adoptCommittedSnapshot(request.Run(), snapshot); err != nil {
		return ports.PublicationObservation{}, nil, publicationObservationFiles{}, false, nil
	}
	files, err := observeP2MutableDocuments(request)
	if err != nil {
		return ports.PublicationObservation{}, nil, files, true, err
	}
	if files.journal.Present() {
		if _, observedFacts, parseErr := parsePublicationJournal(
			request.Run(),
			files.journal.Path(),
			files.journal.Bytes(),
		); parseErr == nil {
			facts.state = observedFacts.state
		}
	}
	files.facts = &facts
	material, err := ports.NewPublicationRecoveryMaterialWithCommittedSnapshot(
		snapshot.Final(),
		*files.journal,
		*files.status,
		snapshot,
	)
	if err != nil {
		return ports.PublicationObservation{}, nil, files, true, err
	}
	exit := normalExit
	observation, err := ports.NewPublicationObservationWithRecovery(
		facts.state,
		domain.DurableObservationP2Committed,
		&exit,
		nil,
		facts.storeEpoch,
		material,
	)
	if err != nil {
		return ports.PublicationObservation{}, nil, files, true, err
	}
	return observation, &snapshot, files, true, nil
}

func observeP2MutableDocuments(
	request ports.ObserveRunRequest,
) (publicationObservationFiles, error) {
	files := publicationObservationFiles{}
	journalPath := publicationJournalPath(request.Run())
	journalFile, journalErr := readPublicationFile(request.Run().Root(), journalPath, request.MaxReadBytes())
	var journal ports.ObservedMutablePublicationDocument
	var err error
	switch {
	case journalErr == nil:
		journal, err = ports.NewObservedMutablePublicationDocument(
			ports.MutablePublicationJournal,
			journalPath,
			journalFile.sha256,
			journalFile.bytes,
		)
	default:
		journal, err = ports.NewMissingMutablePublicationDocument(
			ports.MutablePublicationJournal,
			journalPath,
		)
	}
	if err != nil {
		return files, err
	}
	files.journal = &journal

	statusPath := publicationStatusPath(request.Run())
	statusFile, statusErr := readPublicationFile(request.Run().Root(), statusPath, request.MaxReadBytes())
	var status ports.ObservedMutablePublicationDocument
	switch {
	case statusErr == nil:
		status, err = ports.NewObservedMutablePublicationDocument(
			ports.MutablePublicationStatus,
			statusPath,
			statusFile.sha256,
			statusFile.bytes,
		)
	default:
		status, err = ports.NewMissingMutablePublicationDocument(
			ports.MutablePublicationStatus,
			statusPath,
		)
	}
	if err != nil {
		return files, err
	}
	files.status = &status
	return files, nil
}

func (store *PublicationStore) observeLocked(ctx context.Context, request ports.ObserveRunRequest) (ports.PublicationObservation, *ports.CommittedPublicationSnapshot, error) {
	observation, snapshot, immutableFiles, complete, immutableErr := store.discoverImmutableP2(ctx, request)
	if complete {
		if immutableErr != nil {
			if publicationImmutableValidationOperational(immutableErr) {
				return ports.PublicationObservation{}, nil, immutableErr
			}
			return publicationAmbiguity(immutableFiles, []string{"composite_mismatch"})
		}
		return observation, snapshot, nil
	}
	files, reasons := store.readPublicationJournal(request)
	if len(reasons) != 0 {
		return publicationAmbiguity(files, reasons)
	}
	if files.facts == nil {
		return store.observeWithoutJournal(ctx, request, files)
	}
	return store.observeWithJournal(ctx, request, files)
}

func (store *PublicationStore) readPublicationJournal(request ports.ObserveRunRequest) (publicationObservationFiles, []string) {
	journalPath := publicationJournalPath(request.Run())
	statusPath := publicationStatusPath(request.Run())
	journalFile, journalErr := readPublicationFile(request.Run().Root(), journalPath, request.MaxReadBytes())
	if journalErr != nil {
		if errors.Is(journalErr, errPublicationAbsent) {
			statusFile, statusErr := readPublicationFile(request.Run().Root(), statusPath, request.MaxReadBytes())
			if statusErr == nil {
				_ = statusFile
				return publicationObservationFiles{}, []string{"status_without_journal"}
			}
			if !errors.Is(statusErr, errPublicationAbsent) {
				return publicationObservationFiles{}, []string{"status_unsafe"}
			}
			return publicationObservationFiles{}, nil
		}
		return publicationObservationFiles{}, []string{"journal_unsafe"}
	}
	journal, facts, err := parsePublicationJournal(request.Run(), journalPath, journalFile.bytes)
	if err != nil {
		return publicationObservationFiles{}, []string{"journal_invalid"}
	}
	result := publicationObservationFiles{journal: &journal, facts: &facts}

	statusFile, statusErr := readPublicationFile(request.Run().Root(), statusPath, request.MaxReadBytes())
	if statusErr != nil {
		if errors.Is(statusErr, errPublicationAbsent) {
			return result, nil
		}
		return publicationObservationFiles{}, []string{"status_unsafe"}
	}
	status, err := ports.NewObservedMutablePublicationDocument(
		ports.MutablePublicationStatus,
		statusPath,
		statusFile.sha256,
		statusFile.bytes,
	)
	if err != nil {
		return publicationObservationFiles{}, []string{"status_observation_invalid"}
	}
	result.status = &status
	return result, nil
}

func (store *PublicationStore) observeWithoutJournal(ctx context.Context, request ports.ObserveRunRequest, files publicationObservationFiles) (ports.PublicationObservation, *ports.CommittedPublicationSnapshot, error) {
	finals, finalErr := publicationFinalNames(request.Run())
	staged, stagedErr := publicationStagedNames(request.Run())
	if finalErr != nil || stagedErr != nil {
		return publicationAmbiguity(files, []string{"artifact_namespace_unsafe"})
	}
	manifest, manifestErr := readPublicationFile(request.Run().Root(), publicationManifestPath(request.Run()), request.MaxReadBytes())
	if manifestErr != nil && !errors.Is(manifestErr, errPublicationAbsent) {
		return publicationAmbiguity(files, []string{"manifest_unsafe"})
	}
	if len(finals) != 0 || len(staged) != 0 || manifestErr == nil {
		_ = manifest
		return publicationAmbiguity(files, []string{"unjournaled_artifact"})
	}
	candidatePath, err := ports.ValidatedCandidatePath(request.Run())
	if err != nil {
		return publicationAmbiguity(files, []string{"candidate_path_invalid"})
	}
	candidateCount, candidateCountErr := publicationCandidateMemberCount(request.Run())
	if candidateCountErr != nil {
		return publicationAmbiguity(files, []string{"candidate_unsafe"})
	}
	if candidateCount > 1 {
		return publicationAmbiguity(files, []string{"multiple_candidate"})
	}
	candidate, candidateErr := readPublicationFile(request.Run().Root(), candidatePath, request.MaxReadBytes())
	if candidateErr != nil && !errors.Is(candidateErr, errPublicationAbsent) {
		return publicationAmbiguity(files, []string{"candidate_unsafe"})
	}
	if candidateErr == nil {
		if err := store.validateUnjournaledCandidate(ctx, request.Run(), candidate); err != nil {
			if publicationImmutableValidationOperational(err) {
				return ports.PublicationObservation{}, nil, err
			}
			return publicationAmbiguity(files, []string{"candidate_invalid"})
		}
	}
	preparedCount, preparedErr := publicationPreparedMemberCount(request.Run(), request.MaxReadBytes())
	if preparedErr != nil {
		if errors.Is(preparedErr, errPublicationMultiplePrepared) {
			return publicationAmbiguity(files, []string{"multiple_prepared_composite"})
		}
		return publicationAmbiguity(files, []string{"prepared_namespace_unsafe"})
	}
	if preparedCount != 0 {
		return publicationAmbiguity(files, []string{"unjournaled_prepared_composite"})
	}
	observation, err := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	if err != nil {
		return ports.PublicationObservation{}, nil, fmt.Errorf("observe publication: P0 none: %w", err)
	}
	return observation, nil, nil
}

func (store *PublicationStore) observeWithJournal(ctx context.Context, request ports.ObserveRunRequest, files publicationObservationFiles) (ports.PublicationObservation, *ports.CommittedPublicationSnapshot, error) {
	facts := *files.facts
	finalNames, finalErr := publicationFinalNames(request.Run())
	stagedNames, stagedErr := publicationStagedNames(request.Run())
	if finalErr != nil || stagedErr != nil {
		return publicationAmbiguity(files, []string{"artifact_namespace_unsafe"})
	}
	if len(finalNames) > 1 {
		return publicationAmbiguity(files, []string{"multiple_final"})
	}
	if len(stagedNames) > 1 {
		return publicationAmbiguity(files, []string{"multiple_staged"})
	}
	expectedFinalName := safeBasename(facts.finalPath)
	expectedStagedName := safeBasename(facts.stagedPath)
	if len(finalNames) == 1 && finalNames[0] != expectedFinalName {
		return publicationAmbiguity(files, []string{"unjournaled_final"})
	}
	if len(stagedNames) == 1 && stagedNames[0] != expectedStagedName {
		return publicationAmbiguity(files, []string{"unjournaled_staged"})
	}
	if len(finalNames) == 1 && len(stagedNames) == 1 {
		return publicationAmbiguity(files, []string{"staged_final_conflict"})
	}

	var finalFile publicationFile
	var finalPresent bool
	if len(finalNames) == 1 {
		file, err := readPublicationFile(request.Run().Root(), facts.finalPath, request.MaxReadBytes())
		if err != nil {
			return publicationAmbiguity(files, []string{"final_unsafe"})
		}
		identity, err := ports.NewFinalReviewIdentity(facts.reviewID, facts.finalPath, facts.finalSHA256)
		if err != nil {
			return publicationAmbiguity(files, []string{"final_mismatch"})
		}
		if err := store.validateFinalFile(ctx, request.Run(), identity, file); err != nil {
			if publicationImmutableValidationOperational(err) {
				return ports.PublicationObservation{}, nil, err
			}
			return publicationAmbiguity(files, []string{"final_mismatch"})
		}
		finalFile, finalPresent = file, true
	}
	var stagedFile publicationFile
	var stagedPresent bool
	if len(stagedNames) == 1 {
		file, err := readPublicationFile(request.Run().Root(), facts.stagedPath, request.MaxReadBytes())
		if err != nil {
			return publicationAmbiguity(files, []string{"staged_unsafe"})
		}
		identity, err := ports.NewFinalReviewIdentity(facts.reviewID, facts.finalPath, facts.finalSHA256)
		if err != nil {
			return publicationAmbiguity(files, []string{"staged_mismatch"})
		}
		if err := store.validateFinalFile(ctx, request.Run(), identity, file); err != nil {
			if publicationImmutableValidationOperational(err) {
				return ports.PublicationObservation{}, nil, err
			}
			return publicationAmbiguity(files, []string{"staged_mismatch"})
		}
		stagedFile, stagedPresent = file, true
	}

	manifestFile, manifestErr := readPublicationFile(request.Run().Root(), facts.manifest, request.MaxReadBytes())
	edgeFile, edgeErr := readPublicationFile(request.Run().Root(), facts.lineageEdge, request.MaxReadBytes())
	epochFile, epochErr := readPublicationFile(request.Run().Root(), facts.epoch, request.MaxReadBytes())
	presentComposite := 0
	for _, err := range []error{manifestErr, edgeErr, epochErr} {
		if err == nil {
			presentComposite++
		} else if !errors.Is(err, errPublicationAbsent) {
			return publicationAmbiguity(files, []string{"composite_namespace_unsafe"})
		}
	}
	if presentComposite != 0 && presentComposite != 3 {
		manifestPresent := manifestErr == nil
		lineagePresent := edgeErr == nil
		epochPresent := epochErr == nil
		if stagedPresent || !finalPresent || !manifestPresent || (epochPresent && !lineagePresent) {
			return publicationAmbiguity(files, []string{"partial_composite"})
		}
		material, err := store.recoverCompositeMaterial(
			ctx,
			request,
			facts,
			files,
			finalFile,
			[]publicationFile{manifestFile, edgeFile, epochFile},
			[]bool{manifestErr == nil, edgeErr == nil, epochErr == nil},
		)
		if err != nil {
			if publicationImmutableValidationOperational(err) {
				return ports.PublicationObservation{}, nil, err
			}
			return publicationAmbiguity(files, []string{publicationRecoveryReason(err)})
		}
		observation, err := ports.NewPublicationObservationWithRecovery(
			facts.state,
			domain.DurableObservationP1Installed,
			nil,
			nil,
			facts.storeEpoch,
			material,
		)
		if err != nil {
			return ports.PublicationObservation{}, nil, fmt.Errorf("observe publication: partial composite P1: %w", err)
		}
		return observation, nil, nil
	}
	if presentComposite == 3 {
		if stagedPresent || !finalPresent {
			return publicationAmbiguity(files, []string{"composite_final_conflict"})
		}
		snapshot, err := store.validateCommittedSnapshot(ctx, request.Run(), facts, finalFile, manifestFile, edgeFile, epochFile)
		if err != nil {
			if publicationImmutableValidationOperational(err) {
				return ports.PublicationObservation{}, nil, err
			}
			return publicationAmbiguity(files, []string{"composite_mismatch"})
		}
		if err := store.adoptCommittedSnapshot(request.Run(), snapshot); err != nil {
			material, materialErr := store.recoverCompositeMaterial(
				ctx,
				request,
				facts,
				files,
				finalFile,
				[]publicationFile{manifestFile, edgeFile, epochFile},
				[]bool{true, true, true},
			)
			if materialErr != nil {
				if publicationImmutableValidationOperational(materialErr) {
					return ports.PublicationObservation{}, nil, materialErr
				}
				return publicationAmbiguity(files, []string{publicationRecoveryReason(materialErr)})
			}
			observation, observationErr := ports.NewPublicationObservationWithRecovery(
				facts.state,
				domain.DurableObservationP1Installed,
				nil,
				nil,
				facts.storeEpoch,
				material,
			)
			if observationErr != nil {
				return ports.PublicationObservation{}, nil, fmt.Errorf("observe publication: undurable composite P1: %w", observationErr)
			}
			return observation, nil, nil
		}
		material, err := ports.NewPublicationRecoveryMaterialWithCommittedSnapshot(snapshot.Final(), *files.journal, *files.status, snapshot)
		if err != nil {
			return publicationAmbiguity(files, []string{"p2_mutable_material_invalid"})
		}
		exit := facts.normalExit
		observation, err := ports.NewPublicationObservationWithRecovery(
			facts.state,
			domain.DurableObservationP2Committed,
			&exit,
			nil,
			facts.storeEpoch,
			material,
		)
		if err != nil {
			return ports.PublicationObservation{}, nil, fmt.Errorf("observe publication: P2: %w", err)
		}
		return observation, &snapshot, nil
	}
	if finalPresent {
		material, err := store.recoveryMaterial(ctx, request, facts, files, nil, &finalFile)
		if err != nil {
			if publicationImmutableValidationOperational(err) {
				return ports.PublicationObservation{}, nil, err
			}
			return publicationAmbiguity(files, []string{publicationRecoveryReason(err)})
		}
		observation, err := ports.NewPublicationObservationWithRecovery(facts.state, domain.DurableObservationP1Installed, nil, nil, facts.storeEpoch, material)
		if err != nil {
			return ports.PublicationObservation{}, nil, fmt.Errorf("observe publication: P1: %w", err)
		}
		return observation, nil, nil
	}
	if stagedPresent {
		stagedPath := facts.stagedPath
		material, err := store.recoveryMaterial(ctx, request, facts, files, &stagedPath, &stagedFile)
		if err != nil {
			if publicationImmutableValidationOperational(err) {
				return ports.PublicationObservation{}, nil, err
			}
			return publicationAmbiguity(files, []string{publicationRecoveryReason(err)})
		}
		observation, err := ports.NewPublicationObservationWithRecovery(facts.state, domain.DurableObservationP0Staged, nil, nil, facts.storeEpoch, material)
		if err != nil {
			return ports.PublicationObservation{}, nil, fmt.Errorf("observe publication: P0 staged: %w", err)
		}
		return observation, nil, nil
	}
	if facts.state == domain.JournalCollecting {
		preparedCount, err := publicationPreparedMemberCount(request.Run(), request.MaxReadBytes())
		if err != nil {
			if errors.Is(err, errPublicationMultiplePrepared) {
				return publicationAmbiguity(files, []string{"multiple_prepared_composite"})
			}
			return publicationAmbiguity(files, []string{"prepared_namespace_unsafe"})
		}
		if preparedCount != 0 {
			return publicationAmbiguity(files, []string{"prepared_unexpected_state"})
		}
		observation, err := ports.NewPublicationObservation(facts.state, domain.DurableObservationP0None, nil, nil, facts.storeEpoch)
		if err != nil {
			return ports.PublicationObservation{}, nil, fmt.Errorf("observe publication: P0 none: %w", err)
		}
		return observation, nil, nil
	}
	if facts.state == domain.JournalContentValidated || facts.state == domain.JournalFinalStaged {
		material, err := store.recoveryMaterial(ctx, request, facts, files, nil, nil)
		if err != nil {
			if publicationImmutableValidationOperational(err) {
				return ports.PublicationObservation{}, nil, err
			}
			return publicationAmbiguity(files, []string{publicationRecoveryReason(err)})
		}
		observation, err := ports.NewPublicationObservationWithRecovery(facts.state, domain.DurableObservationP0None, nil, nil, facts.storeEpoch, material)
		if err != nil {
			return ports.PublicationObservation{}, nil, fmt.Errorf("observe publication: P0 none recovery: %w", err)
		}
		return observation, nil, nil
	}
	return publicationAmbiguity(files, []string{"high_hint_p0_none"})
}

type publicationRecoveryError struct {
	reason string
	cause  error
}

func (err *publicationRecoveryError) Error() string {
	if err == nil || err.cause == nil {
		return err.reason
	}
	return fmt.Sprintf("%s: %v", err.reason, err.cause)
}

func (err *publicationRecoveryError) Unwrap() error { return err.cause }

func publicationRecoveryFailure(reason string, cause error) error {
	return &publicationRecoveryError{reason: reason, cause: cause}
}

func publicationRecoveryReason(err error) string {
	var recovery *publicationRecoveryError
	if errors.As(err, &recovery) && recovery.reason != "" {
		return recovery.reason
	}
	return "recovery_material_invalid"
}

func (store *PublicationStore) recoveryMaterial(
	ctx context.Context,
	request ports.ObserveRunRequest,
	facts publicationJournalFacts,
	files publicationObservationFiles,
	stagedPath *ports.SafeRelativePath,
	observed *publicationFile,
) (ports.PublicationRecoveryMaterial, error) {
	if files.journal == nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("recovery_journal_missing", nil)
	}
	candidate, err := store.readValidatedCandidate(ctx, request.Run(), facts, request.MaxReadBytes())
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, err
	}
	if observed != nil && !bytes.Equal(observed.bytes, candidate.Bytes()) {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("candidate_final_mismatch", nil)
	}
	prepared, err := store.readPreparedComposite(ctx, request.Run(), facts, candidate, request.MaxReadBytes())
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, err
	}
	material, err := ports.NewPublicationRecoveryMaterialWithPrepared(candidate, stagedPath, *files.journal, files.status, candidate, prepared)
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("recovery_material_invalid", err)
	}
	return material, nil
}
func (store *PublicationStore) recoverCompositeMaterial(
	ctx context.Context,
	request ports.ObserveRunRequest,
	facts publicationJournalFacts,
	files publicationObservationFiles,
	finalFile publicationFile,
	destinationFiles []publicationFile,
	destinationPresent []bool,
) (ports.PublicationRecoveryMaterial, error) {
	if files.journal == nil || len(destinationFiles) != 3 || len(destinationPresent) != 3 {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("recovery_journal_or_composite_missing", nil)
	}
	candidate, err := store.readValidatedCandidate(ctx, request.Run(), facts, request.MaxReadBytes())
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, err
	}
	if !bytes.Equal(candidate.Bytes(), finalFile.bytes) {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("candidate_final_mismatch", nil)
	}

	destinationPaths := []ports.SafeRelativePath{facts.manifest, facts.lineageEdge, facts.epoch}
	stagedPaths := publicationPreparedPaths(request.Run())
	artifacts := make([]ports.ImmutablePublicationArtifact, len(destinationPaths))
	for index := range destinationPaths {
		file := destinationFiles[index]
		if destinationPresent[index] {
			if _, err := readPublicationFile(request.Run().Root(), stagedPaths[index], request.MaxReadBytes()); err == nil {
				return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("composite_staged_destination_conflict", nil)
			} else if !errors.Is(err, errPublicationAbsent) {
				return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_namespace_unsafe", err)
			}
		} else {
			file, err = readPublicationFile(request.Run().Root(), stagedPaths[index], request.MaxReadBytes())
			if err != nil {
				if errors.Is(err, errPublicationAbsent) {
					return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_missing", nil)
				}
				return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_namespace_unsafe", err)
			}
		}
		artifact, err := ports.NewImmutablePublicationArtifact(destinationPaths[index], file.sha256, file.bytes)
		if err != nil {
			return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_member_invalid", err)
		}
		artifacts[index] = artifact
	}
	epoch, err := ports.NewPublicationEpoch(facts.storeEpoch, artifacts[2])
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_epoch_invalid", err)
	}
	composite, err := ports.NewCommitCompositeRequest(request.Run(), candidate.Identity(), artifacts[0], artifacts[1], epoch)
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_composite_mismatch", err)
	}
	if err := store.validateCompositePayload(ctx, composite, candidate.Bytes()); err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_composite_mismatch", err)
	}
	prepareRequest, err := ports.NewPrepareCompositeRequest(composite)
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_path_invalid", err)
	}
	stagedManifest, err := ports.NewImmutablePublicationArtifact(
		prepareRequest.StagedManifestPath(),
		artifacts[0].SHA256(),
		artifacts[0].Bytes(),
	)
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_manifest_invalid", err)
	}
	stagedLineage, err := ports.NewImmutablePublicationArtifact(
		prepareRequest.StagedLineageEdgePath(),
		artifacts[1].SHA256(),
		artifacts[1].Bytes(),
	)
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_lineage_invalid", err)
	}
	stagedEpoch, err := ports.NewImmutablePublicationArtifact(
		prepareRequest.StagedEpochPath(),
		artifacts[2].SHA256(),
		artifacts[2].Bytes(),
	)
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_epoch_invalid", err)
	}
	receipts, err := publicationRecoveredPreparedReceipts(request.Run(), stagedManifest, stagedLineage, stagedEpoch)
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_receipt_invalid", err)
	}
	prepared, err := ports.NewPreparedComposite(
		prepareRequest,
		stagedManifest,
		stagedLineage,
		stagedEpoch,
		receipts,
		ports.CompositePreparationDurable,
	)
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("prepared_composite_mismatch", err)
	}
	material, err := ports.NewPublicationRecoveryMaterialWithPrepared(
		candidate,
		nil,
		*files.journal,
		files.status,
		candidate,
		prepared,
	)
	if err != nil {
		return ports.PublicationRecoveryMaterial{}, publicationRecoveryFailure("recovery_material_invalid", err)
	}
	return material, nil
}

func (store *PublicationStore) adoptCommittedSnapshot(
	run ports.PublicationRun,
	snapshot ports.CommittedPublicationSnapshot,
) error {
	final := snapshot.Final()
	finalArtifact, err := ports.NewImmutablePublicationArtifact(final.Identity().Path(), final.Identity().SHA256(), final.Bytes())
	if err != nil {
		return err
	}
	for _, member := range []struct {
		artifact ports.ImmutablePublicationArtifact
		channel  string
	}{
		{finalArtifact, "publication_final_install"},
		{snapshot.Manifest(), "publication_manifest"},
		{snapshot.LineageEdge(), "publication_lineage_edge"},
		{snapshot.Epoch().Record(), "publication_epoch"},
	} {
		if _, exists, err := store.durableExistingImmutable(run, member.artifact, member.channel); err != nil {
			return fmt.Errorf("adopt %s: %w", member.channel, err)
		} else if !exists {
			return fmt.Errorf("adopt %s: immutable member disappeared", member.channel)
		}
	}
	return nil
}

func (store *PublicationStore) readValidatedCandidate(
	ctx context.Context,
	run ports.PublicationRun,
	facts publicationJournalFacts,
	maximum int64,
) (ports.FinalReviewArtifact, error) {
	path, err := ports.ValidatedCandidatePath(run)
	if err != nil {
		return ports.FinalReviewArtifact{}, publicationRecoveryFailure("candidate_path_invalid", err)
	}
	candidateCount, err := publicationCandidateMemberCount(run)
	if err != nil {
		return ports.FinalReviewArtifact{}, publicationRecoveryFailure("candidate_unsafe", err)
	}
	if candidateCount == 0 {
		return ports.FinalReviewArtifact{}, publicationRecoveryFailure("candidate_missing", nil)
	}
	if candidateCount != 1 {
		return ports.FinalReviewArtifact{}, publicationRecoveryFailure("multiple_candidate", nil)
	}
	file, err := readPublicationFile(run.Root(), path, maximum)
	if err != nil {
		if errors.Is(err, errPublicationAbsent) {
			return ports.FinalReviewArtifact{}, publicationRecoveryFailure("candidate_missing", nil)
		}
		return ports.FinalReviewArtifact{}, publicationRecoveryFailure("candidate_unsafe", err)
	}
	identity, err := ports.NewFinalReviewIdentity(facts.reviewID, facts.finalPath, facts.finalSHA256)
	if err != nil {
		return ports.FinalReviewArtifact{}, publicationRecoveryFailure("candidate_identity_invalid", err)
	}
	if err := store.validateFinalFile(ctx, run, identity, file); err != nil {
		return ports.FinalReviewArtifact{}, publicationRecoveryFailure("candidate_mismatch", err)
	}
	candidate, err := ports.NewFinalReviewArtifact(identity, file.bytes)
	if err != nil {
		return ports.FinalReviewArtifact{}, publicationRecoveryFailure("candidate_mismatch", err)
	}
	return candidate, nil
}

func (store *PublicationStore) readPreparedComposite(
	ctx context.Context,
	run ports.PublicationRun,
	facts publicationJournalFacts,
	candidate ports.FinalReviewArtifact,
	maximum int64,
) (ports.PreparedComposite, error) {
	preparedCount, err := publicationPreparedMemberCount(run, maximum)
	if err != nil {
		if errors.Is(err, errPublicationMultiplePrepared) {
			return ports.PreparedComposite{}, publicationRecoveryFailure("multiple_prepared_composite", err)
		}
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_namespace_unsafe", err)
	}
	if preparedCount == 0 {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_missing", nil)
	}
	if preparedCount != len(publicationPreparedPaths(run)) {
		return ports.PreparedComposite{}, publicationRecoveryFailure("partial_prepared_composite", nil)
	}
	paths := publicationPreparedPaths(run)
	files := make([]publicationFile, len(paths))
	present := 0
	for index, path := range paths {
		file, err := readPublicationFile(run.Root(), path, maximum)
		if err != nil {
			if errors.Is(err, errPublicationAbsent) {
				continue
			}
			return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_namespace_unsafe", err)
		}
		files[index] = file
		present++
	}
	if present == 0 {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_missing", nil)
	}
	if present != len(paths) {
		return ports.PreparedComposite{}, publicationRecoveryFailure("partial_prepared_composite", nil)
	}

	manifest, err := ports.NewImmutablePublicationArtifact(facts.manifest, files[0].sha256, files[0].bytes)
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_manifest_invalid", err)
	}
	lineage, err := ports.NewImmutablePublicationArtifact(facts.lineageEdge, files[1].sha256, files[1].bytes)
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_lineage_invalid", err)
	}
	epochRecord, err := ports.NewImmutablePublicationArtifact(facts.epoch, files[2].sha256, files[2].bytes)
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_epoch_invalid", err)
	}
	epoch, err := ports.NewPublicationEpoch(facts.storeEpoch, epochRecord)
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_epoch_invalid", err)
	}
	composite, err := ports.NewCommitCompositeRequest(run, candidate.Identity(), manifest, lineage, epoch)
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_composite_mismatch", err)
	}
	if err := store.validateCompositePayload(ctx, composite, candidate.Bytes()); err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_composite_mismatch", err)
	}
	request, err := ports.NewPrepareCompositeRequest(composite)
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_path_invalid", err)
	}
	stagedManifest, err := ports.NewImmutablePublicationArtifact(request.StagedManifestPath(), manifest.SHA256(), manifest.Bytes())
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_manifest_invalid", err)
	}
	stagedLineage, err := ports.NewImmutablePublicationArtifact(request.StagedLineageEdgePath(), lineage.SHA256(), lineage.Bytes())
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_lineage_invalid", err)
	}
	stagedEpoch, err := ports.NewImmutablePublicationArtifact(request.StagedEpochPath(), epochRecord.SHA256(), epochRecord.Bytes())
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_epoch_invalid", err)
	}
	receipts, err := publicationRecoveredPreparedReceipts(run, stagedManifest, stagedLineage, stagedEpoch)
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_receipt_invalid", err)
	}
	prepared, err := ports.NewPreparedComposite(request, stagedManifest, stagedLineage, stagedEpoch, receipts, ports.CompositePreparationDurable)
	if err != nil {
		return ports.PreparedComposite{}, publicationRecoveryFailure("prepared_composite_mismatch", err)
	}
	return prepared, nil
}

func (store *PublicationStore) validateUnjournaledCandidate(ctx context.Context, run ports.PublicationRun, file publicationFile) error {
	facts, err := parsePublicationFinalFacts(file.bytes)
	if err != nil {
		return err
	}
	reviewID, err := domain.ParseReviewID(facts.reviewID)
	if err != nil {
		return err
	}
	path := mustPublicationSafePath(run.SessionID().String() + "/" + run.RunID().String() + "/review_" + reviewID.String() + ".json")
	identity, err := ports.NewFinalReviewIdentity(reviewID, path, file.sha256)
	if err != nil {
		return err
	}
	return store.validateFinalFile(ctx, run, identity, file)
}

func publicationRecoveredPreparedReceipts(
	run ports.PublicationRun,
	manifest ports.ImmutablePublicationArtifact,
	lineage ports.ImmutablePublicationArtifact,
	epoch ports.ImmutablePublicationArtifact,
) ([]ports.SecureWriteReceipt, error) {
	members := []struct {
		artifact ports.ImmutablePublicationArtifact
		channel  string
	}{
		{manifest, "publication_prepared_manifest"},
		{lineage, "publication_prepared_lineage_edge"},
		{epoch, "publication_prepared_epoch"},
	}
	receipts := make([]ports.SecureWriteReceipt, 0, len(members))
	for _, member := range members {
		receipt, err := ports.NewSecureWriteReceipt(
			run.Root(),
			member.artifact.Path(),
			member.artifact.SHA256(),
			int64(len(member.artifact.Bytes())),
			member.channel,
			[]string{member.channel},
		)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func publicationCandidateMemberCount(run ports.PublicationRun) (int, error) {
	path, err := ports.ValidatedCandidatePath(run)
	if err != nil {
		return 0, err
	}
	parts, expectedName, err := splitDestination(path)
	if err != nil {
		return 0, err
	}
	names, present, err := listPublicationDirectory(run.Root(), parentPath(parts))
	if err != nil || !present {
		return 0, err
	}
	count := 0
	for _, name := range names {
		if strings.HasPrefix(name, "final-candidate") {
			count++
			if name != expectedName {
				count++
			}
		}
	}
	return count, nil
}
func publicationPreparedMemberCount(run ports.PublicationRun, maximum int64) (int, error) {
	paths := publicationPreparedPaths(run)
	names, present, err := listPublicationDirectory(run.Root(), publicationStagedDirectory(run))
	if err != nil || !present {
		return 0, err
	}
	expected := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		expected[safeBasename(path)] = struct{}{}
	}
	for _, name := range names {
		if _, exists := expected[name]; exists {
			continue
		}
		if strings.HasPrefix(name, "manifest.json.tmp") ||
			strings.HasPrefix(name, "lineage-edge.json.tmp") ||
			strings.HasPrefix(name, "epoch.json.tmp") {
			return 0, errPublicationMultiplePrepared
		}
	}
	count := 0
	for _, path := range paths {
		if _, err := readPublicationFile(run.Root(), path, maximum); err != nil {
			if errors.Is(err, errPublicationAbsent) {
				continue
			}
			return 0, err
		}
		count++
	}
	return count, nil
}

func publicationPreparedPaths(run ports.PublicationRun) []ports.SafeRelativePath {
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/publication/staged/"
	return []ports.SafeRelativePath{
		mustPublicationSafePath(prefix + "manifest.json.tmp"),
		mustPublicationSafePath(prefix + "lineage-edge.json.tmp"),
		mustPublicationSafePath(prefix + "epoch.json.tmp"),
	}
}

func publicationAmbiguity(files publicationObservationFiles, reasons []string) (ports.PublicationObservation, *ports.CommittedPublicationSnapshot, error) {
	state := domain.JournalCollecting
	epoch := uint64(1)
	if files.facts != nil {
		state = files.facts.state
		epoch = files.facts.storeEpoch
	}
	observation, err := ports.NewPublicationObservation(state, domain.DurableObservationAmbiguousOrMismatch, nil, publicationReasonSet(reasons), epoch)
	if err != nil {
		return ports.PublicationObservation{}, nil, fmt.Errorf("observe publication: ambiguity: %w", err)
	}
	return observation, nil, nil
}

func publicationReasonSet(reasons []string) []string {
	seen := make(map[string]struct{}, len(reasons))
	result := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		if _, exists := seen[reason]; !exists {
			seen[reason] = struct{}{}
			result = append(result, reason)
		}
	}
	sort.Strings(result)
	return result
}

func samePublicationReasonSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func publicationFinalNames(run ports.PublicationRun) ([]string, error) {
	names, present, err := listPublicationDirectory(run.Root(), publicationRunDirectory(run))
	if err != nil || !present {
		return nil, err
	}
	results := make([]string, 0)
	for _, name := range names {
		if strings.HasPrefix(name, "review_") && strings.HasSuffix(name, ".json") {
			results = append(results, name)
		}
	}
	return results, nil
}

func publicationStagedNames(run ports.PublicationRun) ([]string, error) {
	names, present, err := listPublicationDirectory(run.Root(), publicationStagedDirectory(run))
	if err != nil || !present {
		return nil, err
	}
	results := make([]string, 0)
	for _, name := range names {
		if strings.HasPrefix(name, "review_") && strings.HasSuffix(name, ".json.tmp") {
			results = append(results, name)
		}
	}
	return results, nil
}

func publicationRunDirectory(run ports.PublicationRun) ports.SafeRelativePath {
	return mustPublicationSafePath(run.SessionID().String() + "/" + run.RunID().String())
}

func publicationStagedDirectory(run ports.PublicationRun) ports.SafeRelativePath {
	return mustPublicationSafePath(run.SessionID().String() + "/" + run.RunID().String() + "/publication/staged")
}

func publicationJournalPath(run ports.PublicationRun) ports.SafeRelativePath {
	return mustPublicationSafePath(run.SessionID().String() + "/" + run.RunID().String() + "/publication/journal.json")
}

func publicationStatusPath(run ports.PublicationRun) ports.SafeRelativePath {
	return mustPublicationSafePath(run.SessionID().String() + "/" + run.RunID().String() + "/status.json")
}

func publicationManifestPath(run ports.PublicationRun) ports.SafeRelativePath {
	return mustPublicationSafePath(run.SessionID().String() + "/" + run.RunID().String() + "/manifest.json")
}

func mustPublicationSafePath(value string) ports.SafeRelativePath {
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		panic(fmt.Sprintf("publication path invariant: %v", err))
	}
	return path
}

func safeBasename(path ports.SafeRelativePath) string {
	parts := strings.Split(path.String(), "/")
	return parts[len(parts)-1]
}

func parsePublicationJournal(run ports.PublicationRun, path ports.SafeRelativePath, documentBytes []byte) (ports.ObservedMutablePublicationDocument, publicationJournalFacts, error) {
	var wire publicationJournalWire
	if err := strictDecodePublicationJSON(documentBytes, &wire); err != nil {
		return ports.ObservedMutablePublicationDocument{}, publicationJournalFacts{}, err
	}
	if wire.SchemaVersion != "mulgae-publication-journal.v1" {
		return ports.ObservedMutablePublicationDocument{}, publicationJournalFacts{}, errors.New("unknown journal schema")
	}
	facts, err := parsePublicationRestart(run, wire.publicationRestartWire)
	if err != nil {
		return ports.ObservedMutablePublicationDocument{}, publicationJournalFacts{}, err
	}
	document, err := ports.NewObservedMutablePublicationDocument(ports.MutablePublicationJournal, path, publicationSHA256(documentBytes), documentBytes)
	if err != nil {
		return ports.ObservedMutablePublicationDocument{}, publicationJournalFacts{}, err
	}
	return document, facts, nil
}

func parsePublicationRestart(run ports.PublicationRun, wire publicationRestartWire) (publicationJournalFacts, error) {
	if wire.SessionID != run.SessionID().String() || wire.RunID != run.RunID().String() {
		return publicationJournalFacts{}, errors.New("restart IDs do not match run")
	}
	state := domain.PersistedJournalState(wire.PersistedJournalState)
	if !state.Valid() || wire.StoreEpoch == 0 {
		return publicationJournalFacts{}, errors.New("invalid restart state or epoch")
	}
	if !validPublicationSHA256(wire.ExpectedStaged.SHA256) || !validPublicationSHA256(wire.ExpectedFinal.SHA256) ||
		!validPublicationSHA256(wire.ValidatedCandidateSHA256) || wire.ExpectedStaged.SHA256 != wire.ExpectedFinal.SHA256 {
		return publicationJournalFacts{}, errors.New("restart hashes do not agree")
	}
	stagedPath, err := ports.NewSafeRelativePath(wire.ExpectedStaged.Path)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("staged path: %w", err)
	}
	finalPath, err := ports.NewSafeRelativePath(wire.ExpectedFinal.Path)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("final path: %w", err)
	}
	manifestPath, err := ports.NewSafeRelativePath(wire.ManifestPath)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("manifest path: %w", err)
	}
	lineagePath, err := ports.NewSafeRelativePath(wire.LineageEdgePath)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("lineage path: %w", err)
	}
	epochPath, err := ports.NewSafeRelativePath(wire.EpochPath)
	if err != nil {
		return publicationJournalFacts{}, fmt.Errorf("epoch path: %w", err)
	}
	reviewID, err := reviewIDFromFinalPath(run, finalPath)
	if err != nil {
		return publicationJournalFacts{}, err
	}
	if stagedPath != mustPublicationSafePath(run.SessionID().String()+"/"+run.RunID().String()+"/publication/staged/review_"+reviewID.String()+".json.tmp") ||
		manifestPath != publicationManifestPath(run) ||
		lineagePath != mustPublicationSafePath("store/lineage-edges/e_"+reviewID.String()+".json") ||
		epochPath != mustPublicationSafePath(fmt.Sprintf("store/epochs/epoch_%020d.json", wire.StoreEpoch)) {
		return publicationJournalFacts{}, errors.New("restart path is not canonical")
	}
	normalExit := domain.OperationalExitCode(wire.NormalExit)
	if normalExit != domain.ExitCommittedPass && normalExit != domain.ExitCommittedCIRejected && normalExit != domain.ExitIncompleteCoverage {
		return publicationJournalFacts{}, errors.New("invalid stored normal exit")
	}
	return publicationJournalFacts{
		state: state, sessionID: wire.SessionID, runID: wire.RunID, reviewID: reviewID, stagedPath: stagedPath, finalPath: finalPath,
		manifest: manifestPath, lineageEdge: lineagePath, epoch: epochPath, finalSHA256: wire.ExpectedFinal.SHA256,
		validatedCandidateSHA256: wire.ValidatedCandidateSHA256, storeEpoch: wire.StoreEpoch, normalExit: normalExit,
	}, nil
}

func reviewIDFromFinalPath(run ports.PublicationRun, finalPath ports.SafeRelativePath) (domain.ReviewID, error) {
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/review_"
	if !strings.HasPrefix(finalPath.String(), prefix) || !strings.HasSuffix(finalPath.String(), ".json") {
		return domain.ReviewID{}, errors.New("final path is not canonical")
	}
	value := strings.TrimSuffix(strings.TrimPrefix(finalPath.String(), prefix), ".json")
	if strings.Contains(value, "/") {
		return domain.ReviewID{}, errors.New("final path contains extra component")
	}
	return domain.ParseReviewID(value)
}
func strictDecodePublicationJSON(document []byte, destination any) error {
	if len(document) == 0 {
		return errors.New("empty JSON document")
	}
	if err := rejectDuplicatePublicationJSONKeys(document); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := requirePublicationJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func rejectDuplicatePublicationJSONKeys(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := consumePublicationJSONValue(decoder); err != nil {
		return err
	}
	return requirePublicationJSONEOF(decoder)
}

func consumePublicationJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, objectOrArray := token.(json.Delim)
	if !objectOrArray {
		return nil
	}
	var closing json.Delim
	switch delimiter {
	case '{':
		closing = '}'
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumePublicationJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		closing = ']'
		for decoder.More() {
			if err := consumePublicationJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delimiter)
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if end != closing {
		return errors.New("unbalanced JSON document")
	}
	return nil
}

func requirePublicationJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("trailing JSON value")
	}
	return err
}

func publicationJSONObject(document []byte) (map[string]json.RawMessage, error) {
	if err := rejectDuplicatePublicationJSONKeys(document); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if err := requirePublicationJSONEOF(decoder); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("JSON object is required")
	}
	return object, nil
}

func requiredPublicationJSON[T any](object map[string]json.RawMessage, key string) (T, error) {
	var value T
	raw, exists := object[key]
	if !exists {
		return value, fmt.Errorf("missing JSON field %q", key)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("JSON field %q: %w", key, err)
	}
	if err := requirePublicationJSONEOF(decoder); err != nil {
		return value, fmt.Errorf("JSON field %q: %w", key, err)
	}
	return value, nil
}

type publicationFinalFacts struct {
	sessionID string
	runID     string
	reviewID  string
}

func parsePublicationFinalFacts(document []byte) (publicationFinalFacts, error) {
	object, err := publicationJSONObject(document)
	if err != nil {
		return publicationFinalFacts{}, err
	}
	schema, err := requiredPublicationJSON[string](object, "schema_version")
	if err != nil || schema != "mulgae-review-artifact.v1" {
		return publicationFinalFacts{}, errors.New("invalid final review schema version")
	}
	sessionID, err := requiredPublicationJSON[string](object, "session_id")
	if err != nil {
		return publicationFinalFacts{}, err
	}
	runID, err := requiredPublicationJSON[string](object, "run_id")
	if err != nil {
		return publicationFinalFacts{}, err
	}
	reviewID, err := requiredPublicationJSON[string](object, "review_id")
	if err != nil {
		return publicationFinalFacts{}, err
	}
	if _, err := domain.ParseSessionID(sessionID); err != nil {
		return publicationFinalFacts{}, err
	}
	if _, err := domain.ParseRunID(runID); err != nil {
		return publicationFinalFacts{}, err
	}
	if _, err := domain.ParseReviewID(reviewID); err != nil {
		return publicationFinalFacts{}, err
	}
	return publicationFinalFacts{sessionID: sessionID, runID: runID, reviewID: reviewID}, nil
}

func parsePublicationManifestFacts(document []byte) (publicationManifestFacts, error) {
	object, err := publicationJSONObject(document)
	if err != nil {
		return publicationManifestFacts{}, err
	}
	schema, err := requiredPublicationJSON[string](object, "schema_version")
	if err != nil || schema != "mulgae-run-manifest.v1" {
		return publicationManifestFacts{}, errors.New("invalid manifest schema version")
	}
	sessionID, err := requiredPublicationJSON[string](object, "session_id")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	runID, err := requiredPublicationJSON[string](object, "run_id")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	publicationStatus, err := requiredPublicationJSON[string](object, "publication_status")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	durableClass, err := requiredPublicationJSON[string](object, "durable_observation_class")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	derivedStatus, err := requiredPublicationJSON[string](object, "derived_publication_status")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	authority, err := requiredPublicationJSON[string](object, "publication_authority")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	finalReview, err := requiredPublicationJSON[struct {
		ReviewID string `json:"review_id"`
		Path     string `json:"path"`
		SHA256   string `json:"sha256"`
	}](object, "final_review")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	lineage, err := requiredPublicationJSON[struct {
		LineageEdgePath   string `json:"lineage_edge_path"`
		LineageEdgeSHA256 string `json:"lineage_edge_sha256"`
	}](object, "immutable_lineage")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	composite, err := requiredPublicationJSON[struct {
		Manifest struct {
			Path string `json:"path"`
		} `json:"manifest"`
		LineageEdge publicationArtifactWire `json:"lineage_edge"`
		Epoch       struct {
			Path string `json:"path"`
		} `json:"epoch"`
	}](object, "composite_identity")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	exitCode, err := requiredPublicationJSON[int](object, "exit_code")
	if err != nil {
		return publicationManifestFacts{}, err
	}
	if _, err := domain.ParseSessionID(sessionID); err != nil {
		return publicationManifestFacts{}, err
	}
	if _, err := domain.ParseRunID(runID); err != nil {
		return publicationManifestFacts{}, err
	}
	if _, err := domain.ParseReviewID(finalReview.ReviewID); err != nil {
		return publicationManifestFacts{}, err
	}
	if !validPublicationSHA256(finalReview.SHA256) || !validPublicationSHA256(lineage.LineageEdgeSHA256) ||
		composite.LineageEdge.Path != lineage.LineageEdgePath || composite.LineageEdge.SHA256 != lineage.LineageEdgeSHA256 {
		return publicationManifestFacts{}, errors.New("manifest artifact identities are invalid")
	}
	committed := publicationStatus == string(domain.PublicationCommitted) &&
		durableClass == string(domain.DurableObservationP2Committed) &&
		derivedStatus == string(domain.PublicationCommitted) &&
		authority == string(domain.PublicationAuthorityP2)
	return publicationManifestFacts{
		sessionID: sessionID, runID: runID, finalReviewID: finalReview.ReviewID, finalPath: finalReview.Path,
		finalSHA256: finalReview.SHA256, lineagePath: lineage.LineageEdgePath, lineageSHA256: lineage.LineageEdgeSHA256,
		manifestPath: composite.Manifest.Path, epochPath: composite.Epoch.Path, exitCode: exitCode, committed: committed,
	}, nil
}

func parsePublicationLineage(document []byte) (publicationLineageWire, error) {
	var wire publicationLineageWire
	if err := strictDecodePublicationJSON(document, &wire); err != nil {
		return publicationLineageWire{}, err
	}
	if wire.SchemaVersion != "mulgae-lineage-edge.v1" || wire.EdgeID == "" ||
		wire.Child.SessionID == "" || wire.Child.RunID == "" || wire.Child.ReviewID == "" {
		return publicationLineageWire{}, errors.New("invalid lineage edge")
	}
	if _, err := domain.ParseSessionID(wire.Child.SessionID); err != nil {
		return publicationLineageWire{}, err
	}
	if _, err := domain.ParseRunID(wire.Child.RunID); err != nil {
		return publicationLineageWire{}, err
	}
	if _, err := domain.ParseReviewID(wire.Child.ReviewID); err != nil {
		return publicationLineageWire{}, err
	}
	return wire, nil
}

func parsePublicationEpoch(document []byte) (publicationEpochWire, error) {
	var wire publicationEpochWire
	if err := strictDecodePublicationJSON(document, &wire); err != nil {
		return publicationEpochWire{}, err
	}
	if wire.SchemaVersion != "mulgae-publication-epoch.v1" || wire.StoreEpoch == 0 ||
		!validPublicationSHA256(wire.Manifest.SHA256) || !validPublicationSHA256(wire.LineageEdge.SHA256) || !validPublicationSHA256(wire.FinalReview.SHA256) {
		return publicationEpochWire{}, errors.New("invalid epoch record")
	}
	for _, artifact := range []publicationArtifactWire{wire.Manifest, wire.LineageEdge, wire.FinalReview} {
		if _, err := ports.NewSafeRelativePath(artifact.Path); err != nil {
			return publicationEpochWire{}, err
		}
	}
	return wire, nil
}
func (store *PublicationStore) validateCommittedSnapshot(
	ctx context.Context,
	run ports.PublicationRun,
	journal publicationJournalFacts,
	finalFile publicationFile,
	manifestFile publicationFile,
	edgeFile publicationFile,
	epochFile publicationFile,
) (ports.CommittedPublicationSnapshot, error) {
	if finalFile.sha256 != journal.finalSHA256 {
		return ports.CommittedPublicationSnapshot{}, errors.New("final digest does not match journal")
	}
	if err := store.validateFinal(ctx, finalFile.bytes); err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	if err := store.validatePublicationSchema(ctx, store.manifestSchema, manifestFile.bytes); err != nil {
		return ports.CommittedPublicationSnapshot{}, fmt.Errorf("manifest schema: %w", err)
	}
	finalFacts, err := parsePublicationFinalFacts(finalFile.bytes)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	manifestFacts, err := parsePublicationManifestFacts(manifestFile.bytes)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	lineage, err := parsePublicationLineage(edgeFile.bytes)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	epoch, err := parsePublicationEpoch(epochFile.bytes)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	if finalFacts.sessionID != run.SessionID().String() || finalFacts.runID != run.RunID().String() || finalFacts.reviewID != journal.reviewID.String() ||
		!manifestFacts.committed || manifestFacts.sessionID != run.SessionID().String() || manifestFacts.runID != run.RunID().String() ||
		manifestFacts.finalReviewID != journal.reviewID.String() || manifestFacts.finalPath != journal.finalPath.String() || manifestFacts.finalSHA256 != finalFile.sha256 ||
		manifestFacts.lineagePath != journal.lineageEdge.String() || manifestFacts.lineageSHA256 != edgeFile.sha256 ||
		manifestFacts.manifestPath != journal.manifest.String() || manifestFacts.epochPath != journal.epoch.String() || manifestFacts.exitCode != int(journal.normalExit) ||
		lineage.Child.SessionID != run.SessionID().String() || lineage.Child.RunID != run.RunID().String() || lineage.Child.ReviewID != journal.reviewID.String() ||
		epoch.StoreEpoch != journal.storeEpoch ||
		epoch.Manifest.Path != journal.manifest.String() || epoch.Manifest.SHA256 != manifestFile.sha256 ||
		epoch.LineageEdge.Path != journal.lineageEdge.String() || epoch.LineageEdge.SHA256 != edgeFile.sha256 ||
		epoch.FinalReview.Path != journal.finalPath.String() || epoch.FinalReview.SHA256 != finalFile.sha256 {
		return ports.CommittedPublicationSnapshot{}, errors.New("committed cross-hashes or identities do not agree")
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(journal.reviewID, journal.finalPath, finalFile.sha256)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, finalFile.bytes)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	manifest, err := ports.NewImmutablePublicationArtifact(journal.manifest, manifestFile.sha256, manifestFile.bytes)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	edge, err := ports.NewImmutablePublicationArtifact(journal.lineageEdge, edgeFile.sha256, edgeFile.bytes)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	epochRecord, err := ports.NewImmutablePublicationArtifact(journal.epoch, epochFile.sha256, epochFile.bytes)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	epochValue, err := ports.NewPublicationEpoch(journal.storeEpoch, epochRecord)
	if err != nil {
		return ports.CommittedPublicationSnapshot{}, err
	}
	return ports.NewCommittedPublicationSnapshot(final, manifest, edge, epochValue)
}

func (store *PublicationStore) validateComposite(ctx context.Context, request ports.CommitCompositeRequest, finalBytes []byte) error {
	return store.validateCompositePayload(ctx, request, finalBytes)
}

func (store *PublicationStore) validateCompositePayload(ctx context.Context, request ports.CommitCompositeRequest, finalBytes []byte) error {
	if err := store.validatePublicationSchema(ctx, store.manifestSchema, request.Manifest().Bytes()); err != nil {
		return fmt.Errorf("commit composite: manifest schema: %w", err)
	}
	finalFacts, err := parsePublicationFinalFacts(finalBytes)
	if err != nil {
		return fmt.Errorf("commit composite: final wire: %w", err)
	}
	manifestFacts, err := parsePublicationManifestFacts(request.Manifest().Bytes())
	if err != nil {
		return fmt.Errorf("commit composite: manifest wire: %w", err)
	}
	lineage, err := parsePublicationLineage(request.LineageEdge().Bytes())
	if err != nil {
		return fmt.Errorf("commit composite: lineage wire: %w", err)
	}
	epoch, err := parsePublicationEpoch(request.Epoch().Record().Bytes())
	if err != nil {
		return fmt.Errorf("commit composite: epoch wire: %w", err)
	}
	if !manifestFacts.committed || finalFacts.sessionID != request.Run().SessionID().String() || finalFacts.runID != request.Run().RunID().String() ||
		finalFacts.reviewID != request.Final().ReviewID().String() ||
		manifestFacts.sessionID != request.Run().SessionID().String() || manifestFacts.runID != request.Run().RunID().String() ||
		manifestFacts.finalReviewID != request.Final().ReviewID().String() || manifestFacts.finalPath != request.Final().Path().String() ||
		manifestFacts.finalSHA256 != request.Final().SHA256() || manifestFacts.lineagePath != request.LineageEdge().Path().String() ||
		manifestFacts.lineageSHA256 != request.LineageEdge().SHA256() || manifestFacts.manifestPath != request.Manifest().Path().String() ||
		manifestFacts.epochPath != request.Epoch().Record().Path().String() ||
		lineage.Child.SessionID != request.Run().SessionID().String() || lineage.Child.RunID != request.Run().RunID().String() ||
		lineage.Child.ReviewID != request.Final().ReviewID().String() ||
		epoch.StoreEpoch != request.Epoch().Value() || epoch.Manifest.Path != request.Manifest().Path().String() ||
		epoch.Manifest.SHA256 != request.Manifest().SHA256() || epoch.LineageEdge.Path != request.LineageEdge().Path().String() ||
		epoch.LineageEdge.SHA256 != request.LineageEdge().SHA256() || epoch.FinalReview.Path != request.Final().Path().String() ||
		epoch.FinalReview.SHA256 != request.Final().SHA256() {
		return errors.New("commit composite: cross-hashes or IDs do not agree")
	}
	return nil
}
