package providercli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	probeFixtureReference = "roadmap.md"
	probeFixtureLinkPath  = "docs/linked.md"
)
const probeFixtureCleanupTimeout = time.Second

// ProbeNonceGenerator supplies a fresh cryptographically secure nonce for each
// fixture acquisition. Implementations must never return a reused nonce.
type ProbeNonceGenerator interface {
	NewProbeNonce() (string, error)
}

// SecureProbeNonceGenerator creates one unpredictable 256-bit fixture nonce.
type SecureProbeNonceGenerator struct{}

func (SecureProbeNonceGenerator) NewProbeNonce() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("probe nonce: %w", err)
	}
	return hex.EncodeToString(value), nil
}

// ProbeWorkspace is the only materialized-workspace authority exposed by a
// probe fixture. It deliberately does not expose a filesystem path.
type ProbeWorkspace interface {
	ports.WorkspaceExecutionAuthority
	DrainTerminal(context.Context) (ports.QualificationWorkspaceTerminalReceipt, error)
}

// ProbeFixture is the immutable native-reference evidence and snapshot identity
// expected from one role-bound qualification fixture.
type ProbeFixture interface {
	Reference() string
	Nonce() string
	Link() string
	Packet() []byte
	WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity
	Validate() error
}

// ProbeFixtureLease binds immutable fixture data to one ephemeral qualification
// workspace. It exposes bytes captured for the provider, never ambient files.
type ProbeFixtureLease interface {
	ProbeFixture
	Workspace() ProbeWorkspace
	Packet() []byte
	PacketSHA256() string
	Role() domain.Role
	RevalidateForExecution() (ports.WorkspaceExecutionGuard, error)
	DrainTerminal(context.Context) (ports.QualificationWorkspaceTerminalReceipt, error)
}

// ProbeFixtureLeaseFactory creates one independently materialized fixture per
// qualification acquisition.
type ProbeFixtureLeaseFactory struct {
	workspaces ports.QualificationWorkspaceLeaseFactory
	nonces     ProbeNonceGenerator
}

// NewProbeFixtureLeaseFactory constructs the dedicated fixture authority.
func NewProbeFixtureLeaseFactory(workspaces ports.QualificationWorkspaceLeaseFactory, nonces ProbeNonceGenerator) (*ProbeFixtureLeaseFactory, error) {
	if workspaces == nil || nonces == nil {
		return nil, fmt.Errorf("probe fixture lease factory: workspace factory and nonce generator are required")
	}
	return &ProbeFixtureLeaseFactory{workspaces: workspaces, nonces: nonces}, nil
}

// Acquire materializes an exact, role-bound fixture set. The packet is the
// roadmap bytes and its identity is the SHA-256 identity of those exact bytes.
func (factory *ProbeFixtureLeaseFactory) Acquire(ctx context.Context, role domain.Role) (ProbeFixtureLease, error) {
	if factory == nil || factory.workspaces == nil || factory.nonces == nil || ctx == nil || !role.Valid() {
		return nil, fmt.Errorf("probe fixture lease factory: invalid acquisition authority")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nonce, err := factory.nonces.NewProbeNonce()
	if err != nil || !validProbeNonce(nonce) {
		return nil, fmt.Errorf("probe fixture lease factory: unavailable fresh nonce")
	}
	link, err := factory.nonces.NewProbeNonce()
	if err != nil || !validProbeNonce(link) || link == nonce {
		return nil, fmt.Errorf("probe fixture lease factory: unavailable fresh linked nonce")
	}
	fixture, request, err := newProbeFixture(role, nonce, link)
	if err != nil {
		return nil, err
	}
	workspace, err := factory.workspaces.MaterializeQualificationLease(ctx, request)
	if err != nil {
		materializeErr := fmt.Errorf("probe fixture lease factory: materialize fixture: %w", err)
		if workspace != nil {
			return nil, cleanupInvalidProbeFixtureWorkspace(workspace, materializeErr)
		}
		return nil, materializeErr
	}
	if workspace == nil || !workspace.WorkspaceSnapshotIdentity().Valid() {
		return nil, cleanupInvalidProbeFixtureWorkspace(workspace, fmt.Errorf("probe fixture lease factory: invalid materialized workspace"))
	}
	fixture.workspace = workspace
	fixture.identity = workspace.WorkspaceSnapshotIdentity()
	if err := fixture.Validate(); err != nil {
		return nil, cleanupInvalidProbeFixtureWorkspace(workspace, fmt.Errorf("probe fixture lease factory: invalid fixture binding: %w", err))
	}
	return fixture, nil
}

func cleanupInvalidProbeFixtureWorkspace(workspace ports.QualificationWorkspaceLease, cause error) error {
	if workspace == nil {
		return cause
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeFixtureCleanupTimeout)
	defer cancel()
	if _, err := workspace.DrainTerminal(ctx); err != nil {
		return errors.Join(cause, fmt.Errorf("probe fixture lease factory: drain invalid materialized workspace: %w", err))
	}
	return cause
}

type probeFixtureLease struct {
	workspace ports.QualificationWorkspaceLease
	identity  ports.WorkspaceSnapshotIdentity
	role      domain.Role
	reference string
	nonce     string
	link      string
	packet    []byte
	packetID  string
}

func newProbeFixture(role domain.Role, nonce, link string) (*probeFixtureLease, ports.WorkspaceSnapshotRequest, error) {
	roadmap := []byte("Return only one strict JSON object and no other text.\n" +
		"The object must contain exactly root, link, and role string fields.\n" +
		"root must be " + nonce + "; link must be " + link + "; role must be " + string(role) + ".\n")
	linked := []byte(link)
	files, err := probeFixtureFiles(roadmap, linked)
	if err != nil {
		return nil, ports.WorkspaceSnapshotRequest{}, err
	}
	request, err := ports.NewWorkspaceSnapshotRequest(files, "current-qualification-fixture-v2")
	if err != nil {
		return nil, ports.WorkspaceSnapshotRequest{}, fmt.Errorf("probe fixture: snapshot request: %w", err)
	}
	digest := sha256.Sum256(roadmap)
	return &probeFixtureLease{
		role: role, reference: probeFixtureReference, nonce: nonce, link: link, packet: append([]byte(nil), roadmap...),
		packetID: "sha256:" + hex.EncodeToString(digest[:]),
	}, request, nil
}

func probeFixtureFiles(roadmap, linked []byte) ([]ports.WorkspaceSnapshotFile, error) {
	values := []struct {
		path  string
		bytes []byte
	}{
		{probeFixtureLinkPath, linked},
		{probeFixtureReference, roadmap},
	}
	files := make([]ports.WorkspaceSnapshotFile, 0, len(values))
	for _, value := range values {
		path, err := ports.NewSafeRelativePath(value.path)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(value.bytes)
		file, err := ports.NewWorkspaceSnapshotFile(path, value.bytes, "sha256:"+hex.EncodeToString(digest[:]))
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	ports.SortWorkspaceSnapshotFiles(files)
	return files, nil
}

func (fixture *probeFixtureLease) Reference() string         { return fixture.reference }
func (fixture *probeFixtureLease) Nonce() string             { return fixture.nonce }
func (fixture *probeFixtureLease) Link() string              { return fixture.link }
func (fixture *probeFixtureLease) Workspace() ProbeWorkspace { return fixture.workspace }
func (fixture *probeFixtureLease) Packet() []byte            { return append([]byte(nil), fixture.packet...) }
func (fixture *probeFixtureLease) PacketSHA256() string      { return fixture.packetID }
func (fixture *probeFixtureLease) Role() domain.Role         { return fixture.role }
func (fixture *probeFixtureLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return fixture.identity
}
func (fixture *probeFixtureLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	if fixture == nil || fixture.workspace == nil {
		return nil, fmt.Errorf("probe fixture lease: unavailable workspace authority")
	}
	return fixture.workspace.RevalidateForExecution()
}
func (fixture *probeFixtureLease) DrainTerminal(ctx context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	if fixture == nil || fixture.workspace == nil || ctx == nil {
		return ports.QualificationWorkspaceTerminalReceipt{}, fmt.Errorf("probe fixture lease: unavailable terminal authority")
	}
	return fixture.workspace.DrainTerminal(ctx)
}

func (fixture *probeFixtureLease) Validate() error {
	if fixture == nil || fixture.workspace == nil || !fixture.role.Valid() || fixture.reference != probeFixtureReference ||
		!validProbeNonce(fixture.nonce) || !validProbeNonce(fixture.link) || fixture.nonce == fixture.link ||
		!fixture.identity.Valid() || fixture.identity != fixture.workspace.WorkspaceSnapshotIdentity() ||
		!validRelativeNativeReference(fixture.reference) {
		return fmt.Errorf("invalid immutable probe fixture")
	}
	digest := sha256.Sum256(fixture.packet)
	if fixture.packetID != "sha256:"+hex.EncodeToString(digest[:]) {
		return fmt.Errorf("invalid immutable probe fixture packet")
	}
	return nil
}

func validProbeNonce(value string) bool {
	return value != "" && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}
