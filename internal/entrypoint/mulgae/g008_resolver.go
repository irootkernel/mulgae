package mulgae

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const defaultG008StdinLimit int64 = 0

// G008RunEnumerator is the filesystem-only namespace projection used to find
// possible runs. It deliberately has no P2 interpretation authority.
type G008RunEnumerator interface {
	Enumerate(context.Context, ports.AnchoredRoot) ([]filesystem.RunCandidate, []filesystem.RunSelectorDiagnostic, error)
}

// G008RequestResolver resolves CLI selectors using the P2 query service. Its
// captured stdin is owned by this resolver and is never kept in package state.
type G008RequestResolver struct {
	artifactRoot ports.AnchoredRoot
	queries      *appquery.Service
	enumerator   G008RunEnumerator
	reader       io.Reader
	stdinLimit   int64

	captureOnce  sync.Once
	captureMu    sync.Mutex
	captured     []byte
	captureToken string
	captureErr   error

	diagnosticsMu sync.Mutex
	diagnostics   []string
}

// NewG008RequestResolver constructs the production selector resolver. The
// optional positive limit supports bounded integration fixtures; production
// capture has no fixed source-size ceiling.
func NewG008RequestResolver(artifactRoot ports.AnchoredRoot, queries *appquery.Service, enumerator G008RunEnumerator, reader io.Reader, limit ...int64) (*G008RequestResolver, error) {
	if !artifactRoot.Valid() {
		return nil, fmt.Errorf("G008 request resolver: invalid artifact root")
	}
	if queries == nil {
		return nil, fmt.Errorf("G008 request resolver: query service is required")
	}
	if enumerator == nil {
		return nil, fmt.Errorf("G008 request resolver: run enumerator is required")
	}
	if reader == nil {
		return nil, fmt.Errorf("G008 request resolver: stdin reader is required")
	}
	stdinLimit := defaultG008StdinLimit
	if len(limit) > 1 || len(limit) == 1 && limit[0] <= 0 {
		return nil, fmt.Errorf("G008 request resolver: stdin limit must be positive")
	}
	if len(limit) == 1 {
		stdinLimit = limit[0]
	}
	return &G008RequestResolver{artifactRoot: artifactRoot, queries: queries, enumerator: enumerator, reader: reader, stdinLimit: stdinLimit}, nil
}

// ResolveRun resolves an explicit canonical ID through the query boundary, or
// selects latest strictly from fresh P2 committed observations.
func (resolver *G008RequestResolver) ResolveRun(ctx context.Context, selector string) (string, error) {
	if err := resolver.preflight(ctx); err != nil {
		return "", err
	}
	if selector != "latest" {
		runID, err := domain.ParseRunID(selector)
		if err != nil {
			return "", fmt.Errorf("resolve run: invalid run ID: %w", err)
		}
		if err := resolver.requireArtifactRoot(); err != nil {
			return "", err
		}
		run, err := resolver.queries.ResolveRun(ctx, resolver.artifactRoot, runID)
		if err != nil {
			return "", fmt.Errorf("resolve run: %w", err)
		}
		if !run.Valid() || run.Root() != resolver.artifactRoot || run.RunID() != runID {
			return "", fmt.Errorf("resolve run: query returned an invalid run scope")
		}
		return run.RunID().String(), nil
	}

	candidates, enumerationDiagnostics, err := resolver.enumerator.Enumerate(ctx, resolver.artifactRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: Mulgae artifact root is unavailable", ErrProjectRootMismatch)
		}
		return "", fmt.Errorf("resolve latest run: enumerate candidates: %w", err)
	}
	diagnostics := make([]string, 0, len(enumerationDiagnostics)+len(candidates))
	for _, diagnostic := range enumerationDiagnostics {
		diagnostics = append(diagnostics, diagnostic.Path+": "+diagnostic.Reason)
	}
	var latest latestCommittedRun
	found := false
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		run, resolveErr := resolver.queries.ResolveRun(ctx, resolver.artifactRoot, candidate.RunID)
		if resolveErr != nil {
			if candidateIsCorruptRun(resolveErr) {
				diagnostics = append(diagnostics, candidatePath(candidate)+": cannot resolve canonical run")
				continue
			}
			return "", fmt.Errorf("resolve latest run candidate %s: %w", candidatePath(candidate), resolveErr)
		}
		if !run.Valid() || run.Root() != resolver.artifactRoot || run.SessionID() != candidate.SessionID || run.RunID() != candidate.RunID {
			return "", fmt.Errorf("resolve latest run candidate %s: query returned an invalid run scope", candidatePath(candidate))
		}
		review, readErr := resolver.queries.ReadCommitted(ctx, run)
		if readErr != nil {
			if candidateIsNotP2Committed(readErr) {
				diagnostics = append(diagnostics, candidatePath(candidate)+": not P2 committed")
				continue
			}
			return "", fmt.Errorf("resolve latest committed candidate %s: %w", candidatePath(candidate), readErr)
		}
		createdAt, createdErr := committedCreatedAt(review.ManifestBytes())
		if createdErr != nil {
			diagnostics = append(diagnostics, candidatePath(candidate)+": committed manifest has invalid created_at")
			continue
		}
		current := latestCommittedRun{runID: run.RunID(), createdAt: createdAt}
		if !found || current.after(latest) {
			latest, found = current, true
		}
	}
	sort.Strings(diagnostics)
	resolver.setDiagnostics(diagnostics)
	if !found {
		return "", fmt.Errorf("%w: no P2 committed candidates%s", ErrSelectorUnavailable, diagnosticSuffix(diagnostics))
	}
	return latest.runID.String(), nil
}

func candidateIsCorruptRun(err error) bool {
	var failure *domain.Failure
	return errors.As(err, &failure) &&
		failure.Class() == domain.FailureArtifact &&
		failure.Reason() == "publication run resolution failed"
}
func candidateIsNotP2Committed(err error) bool {
	var failure *domain.Failure
	return errors.As(err, &failure) &&
		failure.Class() == domain.FailureArtifact &&
		failure.Reason() == "committed review is unavailable without P2 authority"
}

func attemptSelectorIsUnavailable(err error) bool {
	var failure *domain.Failure
	return errors.As(err, &failure) &&
		failure.Class() == domain.FailureArtifact &&
		failure.Reason() == "attempt selector does not resolve exactly one committed attempt"
}

// ResolvePublicationRun resolves an explicit canonical run within this
// resolver's artifact root. It shares the resolver's P2 query authority and
// deliberately does not enumerate the run namespace.
func (resolver *G008RequestResolver) ResolvePublicationRun(ctx context.Context, root ports.AnchoredRoot, runID domain.RunID) (ports.PublicationRun, error) {
	if err := resolver.preflight(ctx); err != nil {
		return ports.PublicationRun{}, err
	}
	if root != resolver.artifactRoot {
		return ports.PublicationRun{}, fmt.Errorf("resolve publication run: root does not match resolver")
	}
	run, err := resolver.queries.ResolveRun(ctx, root, runID)
	if err != nil {
		return ports.PublicationRun{}, fmt.Errorf("resolve publication run: %w", err)
	}
	if !run.Valid() || run.Root() != root || run.RunID() != runID {
		return ports.PublicationRun{}, fmt.Errorf("resolve publication run: query returned an invalid run scope")
	}
	return run, nil
}

// ResolveAttempt delegates exact role/provider uniqueness to query.Service.
func (resolver *G008RequestResolver) ResolveAttempt(ctx context.Context, runSelector, roleSelector, provider string) (string, error) {
	if err := resolver.preflight(ctx); err != nil {
		return "", err
	}
	runID, err := domain.ParseRunID(runSelector)
	if err != nil {
		return "", fmt.Errorf("resolve attempt: invalid run ID: %w", err)
	}
	role := domain.Role(roleSelector)
	if !role.Valid() || strings.TrimSpace(provider) == "" {
		return "", fmt.Errorf("resolve attempt: invalid role/provider selector")
	}
	if err := resolver.requireArtifactRoot(); err != nil {
		return "", err
	}
	run, err := resolver.queries.ResolveRun(ctx, resolver.artifactRoot, runID)
	if err != nil {
		return "", fmt.Errorf("resolve attempt: resolve run: %w", err)
	}
	attempt, err := resolver.queries.ResolveCommittedAttempt(ctx, run, role, provider)
	if err != nil {
		if attemptSelectorIsUnavailable(err) {
			return "", fmt.Errorf("%w: committed attempt selector did not resolve exactly once", ErrSelectorUnavailable)
		}
		return "", fmt.Errorf("resolve attempt: %w", err)
	}
	return attempt.AttemptID().String(), nil
}

// CaptureTarget reads the injected stdin exactly once, freezes the successful
// bytes behind an invocation-scoped opaque token, and returns that token on
// every call. The token contains no review input bytes or input-derived data.
func (resolver *G008RequestResolver) CaptureTarget(ctx context.Context) (string, error) {
	if resolver == nil || ctx == nil {
		return "", fmt.Errorf("capture stdin: invalid resolver or context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	resolver.captureOnce.Do(func() {
		captured, err := readFrozenStdin(ctx, resolver.reader, resolver.stdinLimit)
		if err != nil {
			resolver.captureErr = err
			return
		}
		token, err := newCapturedStdinToken()
		if err != nil {
			zeroBytes(captured)
			resolver.captureErr = err
			return
		}
		resolver.captureMu.Lock()
		resolver.captured = captured
		resolver.captureToken = token
		resolver.captureMu.Unlock()
	})
	if resolver.captureErr != nil {
		return "", resolver.captureErr
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	resolver.captureMu.Lock()
	defer resolver.captureMu.Unlock()
	if resolver.captureToken == "" {
		return "", fmt.Errorf("capture stdin: unavailable")
	}
	return resolver.captureToken, nil
}

// TakeCapturedStdin transfers a defensive copy of a captured stdin value once.
// It removes and zeroes the resolver-owned input before returning.
func (resolver *G008RequestResolver) TakeCapturedStdin(ctx context.Context, token string) ([]byte, error) {
	if resolver == nil || ctx == nil {
		return nil, fmt.Errorf("take captured stdin: invalid resolver or context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolver.captureMu.Lock()
	defer resolver.captureMu.Unlock()
	if token == "" || token != resolver.captureToken || resolver.captured == nil {
		return nil, fmt.Errorf("take captured stdin: unknown or already-used token")
	}
	captured := append([]byte(nil), resolver.captured...)
	zeroBytes(resolver.captured)
	resolver.captured = nil
	resolver.captureToken = ""
	return captured, nil
}

// Diagnostics returns a defensive copy of deterministic latest-selection
// exclusions from the most recent latest resolution.
func (resolver *G008RequestResolver) Diagnostics() []string {
	if resolver == nil {
		return nil
	}
	resolver.diagnosticsMu.Lock()
	defer resolver.diagnosticsMu.Unlock()
	return append([]string(nil), resolver.diagnostics...)
}

type latestCommittedRun struct {
	runID     domain.RunID
	createdAt time.Time
}

func (candidate latestCommittedRun) after(other latestCommittedRun) bool {
	if !candidate.createdAt.Equal(other.createdAt) {
		return candidate.createdAt.After(other.createdAt)
	}
	return candidate.runID.String() > other.runID.String()
}

func (resolver *G008RequestResolver) preflight(ctx context.Context) error {
	if resolver == nil || resolver.queries == nil || resolver.enumerator == nil || !resolver.artifactRoot.Valid() {
		return fmt.Errorf("G008 request resolver: unavailable")
	}
	if ctx == nil {
		return fmt.Errorf("G008 request resolver: nil context")
	}
	return ctx.Err()
}

func (resolver *G008RequestResolver) requireArtifactRoot() error {
	if _, err := os.Lstat(resolver.artifactRoot.String()); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: Mulgae artifact root is unavailable", ErrProjectRootMismatch)
		}
		return fmt.Errorf("resolve Mulgae artifact root: %w", err)
	}
	return nil
}

func (resolver *G008RequestResolver) setDiagnostics(diagnostics []string) {
	resolver.diagnosticsMu.Lock()
	defer resolver.diagnosticsMu.Unlock()
	resolver.diagnostics = append(resolver.diagnostics[:0], diagnostics...)
}

func candidatePath(candidate filesystem.RunCandidate) string {
	return candidate.SessionID.String() + "/" + candidate.RunID.String()
}

func committedCreatedAt(manifest []byte) (time.Time, error) {
	var wire struct {
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(manifest, &wire); err != nil {
		return time.Time{}, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil || createdAt.Location() != time.UTC || createdAt.UTC().Format(time.RFC3339Nano) != wire.CreatedAt {
		return time.Time{}, fmt.Errorf("invalid created_at")
	}
	return createdAt, nil
}

func readFrozenStdin(ctx context.Context, reader io.Reader, limit int64) ([]byte, error) {
	if reader == nil || limit < 0 {
		return nil, fmt.Errorf("capture stdin: invalid input")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var source io.Reader = reader
	if limit > 0 {
		source = io.LimitReader(reader, limit+1)
	}
	bytes, err := io.ReadAll(source)
	if err != nil {
		return nil, fmt.Errorf("capture stdin: read: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(bytes) == 0 {
		return nil, fmt.Errorf("capture stdin: empty input")
	}
	if limit > 0 && int64(len(bytes)) > limit {
		return nil, fmt.Errorf("capture stdin: input exceeds %d bytes", limit)
	}
	if containsNUL(bytes) {
		return nil, fmt.Errorf("capture stdin: input contains NUL")
	}
	if !utf8.Valid(bytes) {
		return nil, fmt.Errorf("capture stdin: input is not valid UTF-8")
	}
	return append([]byte(nil), bytes...), nil
}
func newCapturedStdinToken() (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("capture stdin: generate token: %w", err)
	}
	return stdinCaptureTokenPrefix + hex.EncodeToString(random), nil
}

func containsNUL(bytes []byte) bool {
	for _, byte := range bytes {
		if byte == 0 {
			return true
		}
	}
	return false
}
func zeroBytes(bytes []byte) {
	for index := range bytes {
		bytes[index] = 0
	}
}

func diagnosticSuffix(diagnostics []string) string {
	if len(diagnostics) == 0 {
		return ""
	}
	return "; diagnostics: " + strings.Join(diagnostics, "; ")
}

var (
	_ RequestResolver          = (*G008RequestResolver)(nil)
	_ ports.CapturedStdinStore = (*G008RequestResolver)(nil)
)
