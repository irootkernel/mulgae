package mulgae

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// G008RunEnumerator is the filesystem-only namespace projection used to find
// possible runs. It deliberately has no P2 interpretation authority.
type G008RunEnumerator interface {
	Enumerate(context.Context, ports.AnchoredRoot) ([]filesystem.RunCandidate, []filesystem.RunSelectorDiagnostic, error)
}

// G008RequestResolver resolves CLI selectors using the P2 query service. Its
// stored-publication reads never create or capture source execution state.
type G008RequestResolver struct {
	artifactRoot  ports.AnchoredRoot
	queries       *appquery.Service
	enumerator    G008RunEnumerator
	diagnosticsMu sync.Mutex
	diagnostics   []string
}

// NewG008RequestResolver constructs a provider-free publication selector resolver.
func NewG008RequestResolver(artifactRoot ports.AnchoredRoot, queries *appquery.Service, enumerator G008RunEnumerator) (*G008RequestResolver, error) {
	if !artifactRoot.Valid() || queries == nil || enumerator == nil {
		return nil, fmt.Errorf("G008 request resolver: invalid publication dependencies")
	}
	return &G008RequestResolver{artifactRoot: artifactRoot, queries: queries, enumerator: enumerator}, nil
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

// CaptureTarget reads the injected stdin exactly once, freezes the successful
// bytes behind an invocation-scoped opaque token, and returns that token on
// every call. The token contains no review input bytes or input-derived data.

// TakeCapturedStdin transfers a defensive copy of a captured stdin value once.
// It removes and zeroes the resolver-owned input before returning.

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

func diagnosticSuffix(diagnostics []string) string {
	if len(diagnostics) == 0 {
		return ""
	}
	return "; diagnostics: " + strings.Join(diagnostics, "; ")
}

var (
	_ RequestResolver = (*G008RequestResolver)(nil)
)
