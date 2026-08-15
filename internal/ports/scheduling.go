package ports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
)

// ProviderRoute identifies one safe provider instance. It contains no
// provider-family, scheduling, or live-runtime authority.
type ProviderRoute struct {
	providerInstance string
}

// NewProviderRoute validates an immutable provider identity.
func NewProviderRoute(providerInstance string) (ProviderRoute, error) {
	if !validProviderInstanceID(providerInstance) {
		return ProviderRoute{}, fmt.Errorf("provider route: invalid provider instance %q", providerInstance)
	}
	return ProviderRoute{providerInstance: providerInstance}, nil
}

// ProviderInstance returns the safe provider instance identifier.
func (route ProviderRoute) ProviderInstance() string { return route.providerInstance }

// Valid reports whether route contains a valid provider identity.
func (route ProviderRoute) Valid() bool {
	return validProviderInstanceID(route.providerInstance)
}

// EnvironmentVariable is one explicit, portable process-environment entry.
type EnvironmentVariable struct {
	name  string
	value string
}

// NewEnvironmentVariable validates a portable environment name and NUL-free
// value. The value is otherwise opaque to this provider-neutral port.
func NewEnvironmentVariable(name, value string) (EnvironmentVariable, error) {
	if err := validateEnvironmentVariable(name, value); err != nil {
		return EnvironmentVariable{}, fmt.Errorf("environment variable: %w", err)
	}
	return EnvironmentVariable{name: name, value: value}, nil
}

// Name returns the portable environment name.
func (variable EnvironmentVariable) Name() string { return variable.name }

// Value returns the NUL-free environment value.
func (variable EnvironmentVariable) Value() string { return variable.value }

// Valid reports whether variable has a portable name and NUL-free value.
func (variable EnvironmentVariable) Valid() bool {
	return validateEnvironmentVariable(variable.name, variable.value) == nil
}

// ProviderNamespaceFactory allocates one isolated, run-scoped namespace for
// each configured provider instance. Its environment must not inherit ambient
// host state. A family-specific factory may inject a startup-frozen,
// identity-revalidated authentication HOME, but the resulting lease must not
// receive cleanup authority over that external HOME.
type ProviderNamespaceFactory interface {
	AcquireProviderNamespace(context.Context, string) (ProviderNamespaceLease, error)
}

// CredentialProjectionDestination is the closed set of provider-owned files
// that may be seeded into an isolated namespace.
type CredentialProjectionDestination string

const (
	CredentialProjectionKimiConfig      CredentialProjectionDestination = "kimi_config"
	CredentialProjectionKimiCredentials CredentialProjectionDestination = "kimi_credentials"
	CredentialProjectionZCodeConfig     CredentialProjectionDestination = "zcode_config"
)

func (destination CredentialProjectionDestination) Valid() bool {
	switch destination {
	case CredentialProjectionKimiConfig, CredentialProjectionKimiCredentials, CredentialProjectionZCodeConfig:
		return true
	default:
		return false
	}
}

// CredentialProjectionRequest declares exactly one already-opened credential or
// settings source. Source is transferred to ProjectCredential, which closes it
// on every return path. The source path is canonical and absolute; destination
// is a closed provider-owned name rather than a caller-selected path.
// CredentialSourceAuthority revalidates a credential source without trusting
// its ambient path resolution. Implementations retain their own source anchor.
type CredentialSourceAuthority interface {
	ValidateCredentialSource(size int64, mode os.FileMode, sha256 string) error
}

type CredentialProjectionRequest struct {
	providerInstance string
	generation       string
	sourcePath       string
	source           *os.File
	sha256           string
	size             int64
	mode             os.FileMode
	destination      CredentialProjectionDestination
	authority        CredentialSourceAuthority
}

func NewCredentialProjectionRequest(providerInstance, generation, sourcePath string, source *os.File, sha256 string, size int64, mode os.FileMode, destination CredentialProjectionDestination) (CredentialProjectionRequest, error) {
	if !validProviderInstanceID(providerInstance) || generation == "" || !filepath.IsAbs(sourcePath) ||
		filepath.Clean(sourcePath) != sourcePath || source == nil || validateRawSHA256(sha256) != nil ||
		size < 0 || mode&os.ModeType != 0 || !destination.Valid() {
		return CredentialProjectionRequest{}, fmt.Errorf("credential projection: invalid request")
	}
	return newCredentialProjectionRequest(providerInstance, generation, sourcePath, source, sha256, size, mode, destination, nil)
}

// NewCredentialProjectionRequestWithAuthority creates a request whose source
// can be revalidated through a retained descriptor-anchored authority.
func NewCredentialProjectionRequestWithAuthority(providerInstance, generation, sourcePath string, source *os.File, sha256 string, size int64, mode os.FileMode, destination CredentialProjectionDestination, authority CredentialSourceAuthority) (CredentialProjectionRequest, error) {
	if authority == nil {
		return CredentialProjectionRequest{}, fmt.Errorf("credential projection: invalid authority")
	}
	return newCredentialProjectionRequest(providerInstance, generation, sourcePath, source, sha256, size, mode, destination, authority)
}

func newCredentialProjectionRequest(providerInstance, generation, sourcePath string, source *os.File, sha256 string, size int64, mode os.FileMode, destination CredentialProjectionDestination, authority CredentialSourceAuthority) (CredentialProjectionRequest, error) {
	if !validProviderInstanceID(providerInstance) || generation == "" || !filepath.IsAbs(sourcePath) ||
		filepath.Clean(sourcePath) != sourcePath || source == nil || validateRawSHA256(sha256) != nil ||
		size < 0 || mode&os.ModeType != 0 || !destination.Valid() {
		return CredentialProjectionRequest{}, fmt.Errorf("credential projection: invalid request")
	}
	return CredentialProjectionRequest{providerInstance: providerInstance, generation: generation, sourcePath: sourcePath, source: source, sha256: sha256, size: size, mode: mode, destination: destination, authority: authority}, nil
}

func (request CredentialProjectionRequest) ProviderInstance() string { return request.providerInstance }
func (request CredentialProjectionRequest) Generation() string       { return request.generation }
func (request CredentialProjectionRequest) SourcePath() string       { return request.sourcePath }
func (request CredentialProjectionRequest) SHA256() string           { return request.sha256 }
func (request CredentialProjectionRequest) Size() int64              { return request.size }
func (request CredentialProjectionRequest) Mode() os.FileMode        { return request.mode }
func (request CredentialProjectionRequest) Source() *os.File         { return request.source }
func (request CredentialProjectionRequest) Destination() CredentialProjectionDestination {
	return request.destination
}
func (request CredentialProjectionRequest) SourceAuthority() CredentialSourceAuthority {
	return request.authority
}

// CredentialProjectionReceipt reports a completed seed without exposing its
// source, destination path, bytes, or content identity.
type CredentialProjectionReceipt struct {
	destination CredentialProjectionDestination
}

func NewCredentialProjectionReceipt(destination CredentialProjectionDestination) (CredentialProjectionReceipt, error) {
	if !destination.Valid() {
		return CredentialProjectionReceipt{}, fmt.Errorf("credential projection: invalid receipt")
	}
	return CredentialProjectionReceipt{destination: destination}, nil
}

func (receipt CredentialProjectionReceipt) Destination() CredentialProjectionDestination {
	return receipt.destination
}

// ProviderNamespaceLease is the authority for all provider process launches in
// one namespace generation. It owns cleanup only for that namespace; an
// injected startup-frozen, identity-revalidated authentication HOME remains
// external and outside its cleanup authority. ValidateForSpawn must fail closed
// when the lease is expired, closed, or its namespace has drifted. DrainTerminal
// is idempotent: every caller receives the same terminal receipt and the adapter
// performs terminal cleanup at most once.
type ProviderNamespaceLease interface {
	ProviderInstance() string
	Generation() string
	Environment() []EnvironmentVariable
	ProjectCredential(context.Context, CredentialProjectionRequest) (CredentialProjectionReceipt, error)
	ValidateForSpawn() error
	DrainTerminal(context.Context) (ProviderNamespaceTerminalReceipt, error)
}

// ProviderNamespaceTerminalReceipt records complete terminal cleanup for one
// namespace generation. It intentionally contains no credentials or paths.
type ProviderNamespaceTerminalReceipt struct {
	providerInstance  string
	generation        string
	drained           bool
	credentialsZeroed bool
	unlinked          bool
	tornDown          bool
}

// ProviderNamespaceTerminalDrain completes one acquired namespace's terminal
// effects and returns its acquisition-bound receipt.
type ProviderNamespaceTerminalDrain func(context.Context) (ProviderNamespaceTerminalReceipt, error)

// ProviderNamespaceTerminalBinding is supplied only while an acquisition is in
// progress. Its zero value cannot bind terminal authority.
type ProviderNamespaceTerminalBinding struct {
	state *providerNamespaceTerminalBindingState
}

type providerNamespaceTerminalBindingState struct {
	mu               sync.Mutex
	open             bool
	bound            bool
	acquired         bool
	providerInstance string
	generation       string
	drained          bool
	receipt          ProviderNamespaceTerminalReceipt
}

// ProviderNamespaceAcquisition creates one concrete namespace lease and binds
// its terminal effects before returning it.
type ProviderNamespaceAcquisition func(context.Context, string, ProviderNamespaceTerminalBinding) (ProviderNamespaceLease, error)

// AcquireProviderNamespaceLease binds terminal receipt authority to a single
// successful namespace acquisition without wrapping the concrete lease.
func AcquireProviderNamespaceLease(ctx context.Context, providerInstance string, acquire ProviderNamespaceAcquisition) (ProviderNamespaceLease, error) {
	if ctx == nil {
		return nil, fmt.Errorf("provider namespace acquisition: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validProviderInstanceID(providerInstance) || acquire == nil {
		return nil, fmt.Errorf("provider namespace acquisition: invalid request")
	}
	state := &providerNamespaceTerminalBindingState{open: true, providerInstance: providerInstance}
	lease, err := acquire(ctx, providerInstance, ProviderNamespaceTerminalBinding{state: state})
	state.mu.Lock()
	defer state.mu.Unlock()
	state.open = false
	if err != nil {
		return nil, err
	}
	if isNilProviderNamespaceLease(lease) || !state.bound || !validProviderInstanceID(state.providerInstance) ||
		state.generation == "" || strings.IndexByte(state.generation, 0) >= 0 ||
		lease.ProviderInstance() != state.providerInstance || lease.Generation() != state.generation {
		return nil, fmt.Errorf("provider namespace acquisition: terminal binding mismatch")
	}
	state.acquired = true
	return lease, nil
}

// Bind associates terminal effects with this acquisition's exact generation.
// The returned drain issues a receipt only after effects complete successfully.
func (binding ProviderNamespaceTerminalBinding) Bind(generation string, drainAndVerify func(context.Context) error) (ProviderNamespaceTerminalDrain, error) {
	if binding.state == nil || generation == "" || strings.IndexByte(generation, 0) >= 0 || drainAndVerify == nil {
		return nil, fmt.Errorf("provider namespace terminal binding: invalid request")
	}
	state := binding.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.open || state.bound || !validProviderInstanceID(state.providerInstance) {
		return nil, fmt.Errorf("provider namespace terminal binding: unavailable")
	}
	state.generation = generation
	state.bound = true
	return func(ctx context.Context) (ProviderNamespaceTerminalReceipt, error) {
		if ctx == nil {
			return ProviderNamespaceTerminalReceipt{}, fmt.Errorf("provider namespace terminal drain: nil context")
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		if !state.acquired || !state.bound {
			return ProviderNamespaceTerminalReceipt{}, fmt.Errorf("provider namespace terminal drain: unavailable")
		}
		if state.drained {
			return state.receipt, nil
		}
		if err := drainAndVerify(ctx); err != nil {
			return ProviderNamespaceTerminalReceipt{}, err
		}
		state.receipt = newProviderNamespaceTerminalReceipt(state.providerInstance, state.generation)
		state.drained = true
		return state.receipt, nil
	}, nil
}

func newProviderNamespaceTerminalReceipt(providerInstance, generation string) ProviderNamespaceTerminalReceipt {
	return ProviderNamespaceTerminalReceipt{
		providerInstance:  providerInstance,
		generation:        generation,
		drained:           true,
		credentialsZeroed: true,
		unlinked:          true,
		tornDown:          true,
	}
}

func isNilProviderNamespaceLease(lease ProviderNamespaceLease) bool {
	if lease == nil {
		return true
	}
	value := reflect.ValueOf(lease)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (receipt ProviderNamespaceTerminalReceipt) ProviderInstance() string {
	return receipt.providerInstance
}
func (receipt ProviderNamespaceTerminalReceipt) Generation() string { return receipt.generation }
func (receipt ProviderNamespaceTerminalReceipt) Drained() bool      { return receipt.drained }
func (receipt ProviderNamespaceTerminalReceipt) CredentialsZeroed() bool {
	return receipt.credentialsZeroed
}
func (receipt ProviderNamespaceTerminalReceipt) Unlinked() bool { return receipt.unlinked }
func (receipt ProviderNamespaceTerminalReceipt) TornDown() bool { return receipt.tornDown }

// ReceiptID returns the canonical domain-separated identity of this exact
// namespace cleanup receipt.
func (receipt ProviderNamespaceTerminalReceipt) ReceiptID() string {
	if !receipt.Valid() {
		return ""
	}
	sum := sha256.Sum256([]byte("mulgae-provider-namespace-terminal-v1\x00" +
		receipt.providerInstance + "\x00" + receipt.generation +
		"\x00drained\x00credentials-zeroed\x00unlinked\x00torn-down"))
	return "provider-namespace-terminal:v1:sha256:" + hex.EncodeToString(sum[:])
}

// Valid reports whether receipt proves the complete terminal cleanup sequence.
func (receipt ProviderNamespaceTerminalReceipt) Valid() bool {
	return validProviderInstanceID(receipt.providerInstance) &&
		receipt.generation != "" &&
		strings.IndexByte(receipt.generation, 0) < 0 &&
		receipt.drained &&
		receipt.credentialsZeroed &&
		receipt.unlinked &&
		receipt.tornDown
}

// ProviderRunTerminalReceipt proves complete terminal cleanup for every
// namespace owned by one run. Receipts are ordered canonically by provider
// instance and contain no credentials or paths.
type ProviderRunTerminalReceipt struct {
	receipts     []ProviderNamespaceTerminalReceipt
	noNamespaces bool
}

// NewEmptyProviderRunTerminalReceipt proves that a failed run acquired no
// provider namespace. It is distinct from an incomplete drain.
func NewEmptyProviderRunTerminalReceipt() ProviderRunTerminalReceipt {
	return ProviderRunTerminalReceipt{noNamespaces: true}
}

// NewProviderRunTerminalReceipt constructs aggregate terminal cleanup evidence.
// Every receipt must be valid and represent a distinct provider instance.
func NewProviderRunTerminalReceipt(receipts []ProviderNamespaceTerminalReceipt) (ProviderRunTerminalReceipt, error) {
	if len(receipts) == 0 {
		return ProviderRunTerminalReceipt{}, fmt.Errorf("provider run terminal receipt: no namespace receipts")
	}
	copied := append([]ProviderNamespaceTerminalReceipt(nil), receipts...)
	sort.Slice(copied, func(left, right int) bool {
		return copied[left].ProviderInstance() < copied[right].ProviderInstance()
	})
	for index, receipt := range copied {
		if !receipt.Valid() {
			return ProviderRunTerminalReceipt{}, fmt.Errorf("provider run terminal receipt: invalid namespace receipt")
		}
		if index > 0 && copied[index-1].ProviderInstance() == receipt.ProviderInstance() {
			return ProviderRunTerminalReceipt{}, fmt.Errorf("provider run terminal receipt: duplicate provider instance %q", receipt.ProviderInstance())
		}
	}
	return ProviderRunTerminalReceipt{receipts: copied}, nil
}

// NamespaceReceipts returns a caller-owned copy in canonical instance order.
func (receipt ProviderRunTerminalReceipt) NamespaceReceipts() []ProviderNamespaceTerminalReceipt {
	return append([]ProviderNamespaceTerminalReceipt(nil), receipt.receipts...)
}

// NoNamespaces reports explicit proof that no provider namespace was acquired.
func (receipt ProviderRunTerminalReceipt) NoNamespaces() bool {
	return receipt.noNamespaces && len(receipt.receipts) == 0
}

// Valid reports whether receipt proves either that no namespace was acquired or
// complete cleanup of a duplicate-free canonical namespace set.
func (receipt ProviderRunTerminalReceipt) Valid() bool {
	if receipt.NoNamespaces() {
		return true
	}
	if receipt.noNamespaces {
		return false
	}
	rebuilt, err := NewProviderRunTerminalReceipt(receipt.receipts)
	if err != nil || len(receipt.receipts) != len(rebuilt.receipts) {
		return false
	}
	for index := range receipt.receipts {
		if receipt.receipts[index] != rebuilt.receipts[index] {
			return false
		}
	}
	return true
}

// Equal reports whether two aggregate receipts prove the same canonical cleanup.
func (receipt ProviderRunTerminalReceipt) Equal(other ProviderRunTerminalReceipt) bool {
	if !receipt.Valid() || !other.Valid() || receipt.noNamespaces != other.noNamespaces || len(receipt.receipts) != len(other.receipts) {
		return false
	}
	for index := range receipt.receipts {
		if receipt.receipts[index] != other.receipts[index] {
			return false
		}
	}
	return true
}

// ProviderPacketChannel is the sole transport selected for a provider packet.
type ProviderPacketChannel string

const (
	ProviderPacketChannelArgvLiteral ProviderPacketChannel = "argv_literal"
	ProviderPacketChannelStdin       ProviderPacketChannel = "stdin"
	ProviderPacketChannelPromptFile  ProviderPacketChannel = "prompt_file"
)

func (channel ProviderPacketChannel) Valid() bool {
	return channel == ProviderPacketChannelArgvLiteral ||
		channel == ProviderPacketChannelStdin ||
		channel == ProviderPacketChannelPromptFile
}

// ProviderPacketBinding binds one packet to exactly one child-process channel.
type ProviderPacketBinding struct {
	channel     ProviderPacketChannel
	packet      ProviderPacket
	argvIndex   int
	promptFile  string
	snapshotCWD string
}

func NewArgvLiteralProviderPacketBinding(packet ProviderPacket, argvIndex int) (ProviderPacketBinding, error) {
	if !packet.Valid() || argvIndex < 0 {
		return ProviderPacketBinding{}, fmt.Errorf("provider packet binding: invalid packet or argv index")
	}
	if strings.ContainsRune(string(packet.Bytes()), 0) {
		return ProviderPacketBinding{}, fmt.Errorf("provider packet binding: argv packet must not contain NUL")
	}
	return ProviderPacketBinding{channel: ProviderPacketChannelArgvLiteral, packet: packet, argvIndex: argvIndex}, nil
}

func NewStdinProviderPacketBinding(packet ProviderPacket) (ProviderPacketBinding, error) {
	if !packet.Valid() {
		return ProviderPacketBinding{}, fmt.Errorf("provider packet binding: invalid packet")
	}
	return ProviderPacketBinding{channel: ProviderPacketChannelStdin, packet: packet, argvIndex: -1}, nil
}

func NewPromptFileProviderPacketBinding(packet ProviderPacket, argvIndex int, reference, snapshotCWD string) (ProviderPacketBinding, error) {
	if !packet.Valid() || argvIndex < 0 || !validPromptFileReference(reference) || !validCanonicalSnapshotCWD(snapshotCWD) {
		return ProviderPacketBinding{}, fmt.Errorf("provider packet binding: invalid packet, prompt file reference, snapshot CWD, or argv index")
	}
	return ProviderPacketBinding{channel: ProviderPacketChannelPromptFile, packet: packet, argvIndex: argvIndex, promptFile: reference, snapshotCWD: snapshotCWD}, nil
}

func (binding ProviderPacketBinding) Channel() ProviderPacketChannel { return binding.channel }
func (binding ProviderPacketBinding) Packet() ProviderPacket {
	packet, _ := NewProviderPacket(binding.packet.Bytes(), binding.packet.Identity().CompleteSHA256())
	return packet
}
func (binding ProviderPacketBinding) PacketIdentity() ProviderPacketIdentity {
	return binding.packet.Identity()
}
func (binding ProviderPacketBinding) ArgvIndex() int              { return binding.argvIndex }
func (binding ProviderPacketBinding) PromptFileReference() string { return binding.promptFile }
func (binding ProviderPacketBinding) SnapshotCWD() string         { return binding.snapshotCWD }
func (binding ProviderPacketBinding) Valid() bool {
	switch binding.channel {
	case ProviderPacketChannelArgvLiteral:
		_, err := NewArgvLiteralProviderPacketBinding(binding.packet, binding.argvIndex)
		return err == nil
	case ProviderPacketChannelStdin:
		_, err := NewStdinProviderPacketBinding(binding.packet)
		return err == nil
	case ProviderPacketChannelPromptFile:
		_, err := NewPromptFileProviderPacketBinding(binding.packet, binding.argvIndex, binding.promptFile, binding.snapshotCWD)
		return err == nil
	default:
		return false
	}
}

// ProcessRequest is the complete direct-execution request for one child
// process. Its fields deliberately exclude shell commands, TTY settings, and
// inherited environment state. Environment is the complete environment actually
// supplied through exec.Cmd.Env. Slice accessors return caller-owned copies.
type ProcessRequest struct {
	executable                   string
	argv                         []string
	environment                  []EnvironmentVariable
	workingDirectory             string
	boundLaunchDirectory         *os.File
	boundWorkspaceRoot           ValidatedWorkspaceRoot
	hasBoundLaunchDirectory      bool
	nativeHomeLaunchAuthority    NativeHomeLaunchAuthority
	hasNativeHomeLaunchAuthority bool
	stdin                        []byte
	timeout                      time.Duration
	providerPacketBinding        ProviderPacketBinding
	hasProviderPacketBinding     bool
	postOutputLifecycle          BoundedPostOutputLifecycle
	hasPostOutputLifecycle       bool
	spoolStdout                  bool
}

// NewSpooledStdoutProcessRequest marks a provider request whose stdout is
// primary report content retained in file-backed temporary storage.
func NewSpooledStdoutProcessRequest(request ProcessRequest) (ProcessRequest, error) {
	if !request.Valid() || !request.hasProviderPacketBinding {
		return ProcessRequest{}, fmt.Errorf("spooled stdout process request: invalid provider request")
	}
	request.spoolStdout = true
	if err := validateProcessRequest(request); err != nil {
		return ProcessRequest{}, fmt.Errorf("spooled stdout process request: %w", err)
	}
	return request, nil
}

// NewProcessRequest validates a direct child-process request and retains
// defensive copies of argv, environment, and stdin. Environment entries are
// completed with the exact working-directory PWD, sorted by portable name, and
// must be unique.
func NewProcessRequest(
	executable string,
	argv []string,
	environment []EnvironmentVariable,
	workingDirectory string,
	stdin []byte,
	timeout time.Duration,
) (ProcessRequest, error) {
	if err := validateAbsoluteWorkingDirectory(workingDirectory); err != nil {
		return ProcessRequest{}, fmt.Errorf("process request: working directory: %w", err)
	}

	canonicalEnvironment := cloneEnvironmentVariables(environment)
	hasPWD := false
	for _, variable := range canonicalEnvironment {
		if variable.name != "PWD" {
			continue
		}
		if variable.value != workingDirectory {
			return ProcessRequest{}, fmt.Errorf("process request: environment: PWD must exactly equal working directory")
		}
		hasPWD = true
	}
	if !hasPWD {
		canonicalEnvironment = append(canonicalEnvironment, EnvironmentVariable{
			name:  "PWD",
			value: workingDirectory,
		})
	}
	sort.Slice(canonicalEnvironment, func(left, right int) bool {
		return canonicalEnvironment[left].name < canonicalEnvironment[right].name
	})

	request := ProcessRequest{
		executable:       executable,
		argv:             cloneStrings(argv),
		environment:      canonicalEnvironment,
		workingDirectory: workingDirectory,
		stdin:            cloneBytes(stdin),
		timeout:          timeout,
	}
	if err := validateProcessRequest(request); err != nil {
		return ProcessRequest{}, fmt.Errorf("process request: %w", err)
	}
	return request, nil
}

// NewProviderProcessRequest builds a generic request from one fail-closed packet binding.
func NewProviderProcessRequest(
	executable string, argv []string, environment []EnvironmentVariable, workingDirectory string,
	binding ProviderPacketBinding, timeout time.Duration,
) (ProcessRequest, error) {
	var stdin []byte
	if binding.Channel() == ProviderPacketChannelStdin {
		stdin = binding.Packet().Bytes()
	}
	request, err := NewProcessRequest(
		executable,
		argv,
		environment,
		workingDirectory,
		stdin,
		timeout,
	)
	if err != nil {
		return ProcessRequest{}, err
	}
	if err := validateProviderPacketRequestBinding(request, binding); err != nil {
		return ProcessRequest{}, fmt.Errorf("provider process request: %w", err)
	}
	request.providerPacketBinding = binding
	request.hasProviderPacketBinding = true
	return request, nil
}

// NewProviderProcessRequestWithPostOutputLifecycle enables the opt-in strict
// output lifecycle for one provider packet request.
func NewProviderProcessRequestWithPostOutputLifecycle(
	executable string, argv []string, environment []EnvironmentVariable, workingDirectory string,
	binding ProviderPacketBinding, lifecycle BoundedPostOutputLifecycle, timeout time.Duration,
) (ProcessRequest, error) {
	request, err := NewProviderProcessRequest(
		executable, argv, environment, workingDirectory, binding, timeout,
	)
	if err != nil {
		return ProcessRequest{}, err
	}
	request.postOutputLifecycle = lifecycle
	request.hasPostOutputLifecycle = true
	if err := validateProcessRequest(request); err != nil {
		return ProcessRequest{}, fmt.Errorf("provider process request: %w", err)
	}
	return request, nil
}

// NewBoundProcessRequest transfers a caller-owned launch-directory descriptor
// into an immutable request. The descriptor is consumed and closed by the
// process runner; callers must not use it after this constructor succeeds.
func NewBoundProcessRequest(request ProcessRequest, root ValidatedWorkspaceRoot, launchDirectory *os.File) (ProcessRequest, error) {
	if !request.Valid() || !root.Valid() || request.WorkingDirectory() != root.Path() || launchDirectory == nil || launchDirectory.Fd() == ^uintptr(0) {
		return ProcessRequest{}, fmt.Errorf("bound process request: invalid request, workspace root, or launch directory")
	}
	request.boundLaunchDirectory = launchDirectory
	request.boundWorkspaceRoot = root
	request.hasBoundLaunchDirectory = true
	if err := validateProcessRequest(request); err != nil {
		return ProcessRequest{}, fmt.Errorf("bound process request: %w", err)
	}
	return request, nil
}

// NewBoundProcessRequestWithNativeHomeAuthority binds an exact installed-user
// HOME identity to a descriptor-bound launch. The authority is launch-only and
// never becomes part of the child environment or process evidence.
func NewBoundProcessRequestWithNativeHomeAuthority(request ProcessRequest, root ValidatedWorkspaceRoot, launchDirectory *os.File, authority NativeHomeLaunchAuthority) (ProcessRequest, error) {
	request, err := NewBoundProcessRequest(request, root, launchDirectory)
	if err != nil {
		return ProcessRequest{}, err
	}
	if !authority.Valid() {
		return ProcessRequest{}, fmt.Errorf("bound process request: invalid native home launch authority")
	}
	hasHome := false
	for _, variable := range request.environment {
		if variable.name == "HOME" {
			hasHome = variable.value == authority.Path()
			break
		}
	}
	if !hasHome {
		return ProcessRequest{}, fmt.Errorf("bound process request: native home does not match HOME")
	}
	request.nativeHomeLaunchAuthority = authority
	request.hasNativeHomeLaunchAuthority = true
	if err := validateProcessRequest(request); err != nil {
		return ProcessRequest{}, fmt.Errorf("bound process request: %w", err)
	}
	return request, nil
}
func validateProviderPacketRequestBinding(request ProcessRequest, binding ProviderPacketBinding) error {
	if !binding.Valid() {
		return fmt.Errorf("invalid packet binding")
	}
	packetBytes := binding.Packet().Bytes()
	packet := string(packetBytes)
	packetOccurrences := 0
	for _, argument := range request.argv {
		if argument == packet {
			packetOccurrences++
		}
	}
	switch binding.Channel() {
	case ProviderPacketChannelArgvLiteral:
		if len(request.stdin) != 0 {
			return fmt.Errorf("argv packet transport must have empty stdin")
		}
		if binding.ArgvIndex() >= len(request.argv) || request.argv[binding.ArgvIndex()] != packet || packetOccurrences != 1 {
			return fmt.Errorf("packet must occur exactly once at argv binding index")
		}
	case ProviderPacketChannelStdin:
		if packetOccurrences != 0 || !bytes.Equal(request.stdin, packetBytes) {
			return fmt.Errorf("stdin packet must occur exactly once on stdin")
		}
	case ProviderPacketChannelPromptFile:
		if len(request.stdin) != 0 {
			return fmt.Errorf("prompt-file packet transport must have empty stdin")
		}
		if request.workingDirectory != binding.SnapshotCWD() {
			return fmt.Errorf("prompt-file working directory must equal snapshot CWD")
		}
		if binding.ArgvIndex() >= len(request.argv) || request.argv[binding.ArgvIndex()] != binding.PromptFileReference() {
			return fmt.Errorf("prompt-file reference must occur at argv binding index")
		}
		references := 0
		for _, argument := range request.argv {
			if argument == binding.PromptFileReference() {
				references++
			}
		}
		if references != 1 || packetOccurrences != 0 {
			return fmt.Errorf("prompt-file packet binding is duplicated or has literal packet")
		}
	default:
		return fmt.Errorf("unsupported packet channel")
	}
	return nil
}

// Executable returns the absolute, canonical resolved executable path.
func (request ProcessRequest) Executable() string { return request.executable }

// Argv returns a caller-owned copy of the exact direct-execution argv.
func (request ProcessRequest) Argv() []string { return cloneStrings(request.argv) }

// Environment returns a caller-owned copy of the sorted complete environment
// actually supplied through exec.Cmd.Env.
func (request ProcessRequest) Environment() []EnvironmentVariable {
	return cloneEnvironmentVariables(request.environment)
}

// WorkingDirectory returns the absolute process working directory.
func (request ProcessRequest) WorkingDirectory() string { return request.workingDirectory }

// BoundLaunchDirectory returns the descriptor and root transferred through the
// strict bound-request constructor. The runner owns closing the descriptor.
func (request ProcessRequest) BoundLaunchDirectory() (*os.File, ValidatedWorkspaceRoot, bool) {
	if !request.hasBoundLaunchDirectory {
		return nil, ValidatedWorkspaceRoot{}, false
	}
	return request.boundLaunchDirectory, request.boundWorkspaceRoot, true
}

// NativeHomeLaunchAuthority returns the optional exact HOME identity required
// by the descriptor-bound trampoline.
func (request ProcessRequest) NativeHomeLaunchAuthority() (NativeHomeLaunchAuthority, bool) {
	if !request.hasNativeHomeLaunchAuthority {
		return NativeHomeLaunchAuthority{}, false
	}
	return request.nativeHomeLaunchAuthority, true
}

// Stdin returns a caller-owned copy of the exact process stdin bytes.
func (request ProcessRequest) Stdin() []byte { return cloneBytes(request.stdin) }

// Timeout returns the exact positive process deadline.
func (request ProcessRequest) Timeout() time.Duration { return request.timeout }

// SpoolStdout reports whether stdout is primary content retained through a
// file-backed spool.
func (request ProcessRequest) SpoolStdout() bool { return request.spoolStdout }

// ProviderPacketBinding returns the optional provider packet binding.
func (request ProcessRequest) ProviderPacketBinding() (ProviderPacketBinding, bool) {
	if !request.hasProviderPacketBinding {
		return ProviderPacketBinding{}, false
	}
	return request.providerPacketBinding, true
}

// PostOutputLifecycle returns the optional bounded strict-output policy.
func (request ProcessRequest) PostOutputLifecycle() (BoundedPostOutputLifecycle, bool) {
	if !request.hasPostOutputLifecycle {
		return BoundedPostOutputLifecycle{}, false
	}
	return request.postOutputLifecycle, true
}

// Valid reports whether request remains a complete canonical direct-execution request.
func (request ProcessRequest) Valid() bool { return validateProcessRequest(request) == nil }

// ProcessTermination is the closed set of neutral child-process termination facts.
type ProcessTermination string

const (
	ProcessTerminationExited               ProcessTermination = "exited"
	ProcessTerminationSignaled             ProcessTermination = "signaled"
	ProcessTerminationStartFailed          ProcessTermination = "start_failed"
	ProcessTerminationStartUnavailable     ProcessTermination = "start_unavailable"
	ProcessTerminationStartConfiguration   ProcessTermination = "start_configuration"
	ProcessTerminationStartSecurity        ProcessTermination = "start_security"
	ProcessTerminationTimedOut             ProcessTermination = "timed_out"
	ProcessTerminationCancelled            ProcessTermination = "cancelled"
	ProcessTerminationStdinIncomplete      ProcessTermination = "stdin_incomplete"
	ProcessTerminationResidualProcessGroup ProcessTermination = "residual_process_group"
)

// Valid reports whether termination is one of the closed process facts.
func (termination ProcessTermination) Valid() bool {
	switch termination {
	case ProcessTerminationExited,
		ProcessTerminationSignaled,
		ProcessTerminationStartFailed,
		ProcessTerminationStartUnavailable,
		ProcessTerminationStartConfiguration,
		ProcessTerminationStartSecurity,
		ProcessTerminationTimedOut,
		ProcessTerminationCancelled,
		ProcessTerminationStdinIncomplete,
		ProcessTerminationResidualProcessGroup:
		return true
	default:
		return false
	}
}

// ProcessSignal is an immutable numeric and symbolic signal fact observed for
// a process that terminated because it received a signal.
type ProcessSignal struct {
	number int
	name   string
}

// NewProcessSignal validates one exact signal fact.
func NewProcessSignal(number int, name string) (ProcessSignal, error) {
	signal := ProcessSignal{number: number, name: name}
	if err := validateProcessSignal(signal); err != nil {
		return ProcessSignal{}, fmt.Errorf("process signal: %w", err)
	}
	return signal, nil
}

// ProcessOutputFraming is the closed output framing policy.
type ProcessOutputFraming string

const (
	ProcessOutputFramingStrictJSON         ProcessOutputFraming = "strict_json"
	ProcessOutputFramingTerminalJSONObject ProcessOutputFraming = "terminal_json_object"
)

func (framing ProcessOutputFraming) Valid() bool {
	return framing == ProcessOutputFramingStrictJSON || framing == ProcessOutputFramingTerminalJSONObject
}

// BoundedPostOutputLifecycle configures opt-in graceful teardown after an exact frame.
type BoundedPostOutputLifecycle struct {
	framing          ProcessOutputFraming
	stabilityGrace   time.Duration
	terminationGrace time.Duration
}

func NewBoundedPostOutputLifecycle(framing ProcessOutputFraming, stabilityGrace, terminationGrace time.Duration) (BoundedPostOutputLifecycle, error) {
	lifecycle := BoundedPostOutputLifecycle{framing: framing, stabilityGrace: stabilityGrace, terminationGrace: terminationGrace}
	if !lifecycle.Valid() {
		return BoundedPostOutputLifecycle{}, fmt.Errorf("bounded post-output lifecycle: invalid framing or grace")
	}
	return lifecycle, nil
}
func (l BoundedPostOutputLifecycle) Framing() ProcessOutputFraming   { return l.framing }
func (l BoundedPostOutputLifecycle) StabilityGrace() time.Duration   { return l.stabilityGrace }
func (l BoundedPostOutputLifecycle) TerminationGrace() time.Duration { return l.terminationGrace }
func (l BoundedPostOutputLifecycle) Valid() bool {
	return l.framing.Valid() && l.stabilityGrace > 0 && l.terminationGrace > 0
}

// ExtractProcessOutputJSONFrame returns the JSON value bound by framing.
// Strict JSON permits only one conventional terminal LF. Terminal-object mode
// additionally permits bounded provider narration on complete preceding lines
// and selects exactly the final top-level JSON object.
func ExtractProcessOutputJSONFrame(framing ProcessOutputFraming, stdout []byte) ([]byte, error) {
	if !framing.Valid() || len(stdout) == 0 {
		return nil, fmt.Errorf("invalid framing or empty output")
	}
	jsonBytes := stdout
	if stdout[len(stdout)-1] == '\n' {
		jsonBytes = stdout[:len(stdout)-1]
	}
	if len(jsonBytes) == 0 || !utf8.Valid(stdout) {
		return nil, fmt.Errorf("invalid JSON frame")
	}
	if framing == ProcessOutputFramingTerminalJSONObject {
		for start := len(jsonBytes) - 1; start >= 0; start-- {
			if jsonBytes[start] != '{' || start > 0 && jsonBytes[start-1] != '\n' {
				continue
			}
			candidate := jsonBytes[start:]
			var object map[string]json.RawMessage
			if err := json.Unmarshal(candidate, &object); err == nil && object != nil {
				return cloneBytes(candidate), nil
			}
		}
		const fenceStart = "```json\n"
		const fenceEnd = "\n```"
		if bytes.HasSuffix(jsonBytes, []byte(fenceEnd)) {
			contentEnd := len(jsonBytes) - len(fenceEnd)
			start := bytes.LastIndex(jsonBytes[:contentEnd], []byte("\n"+fenceStart))
			if start >= 0 {
				start++
			} else if bytes.HasPrefix(jsonBytes, []byte(fenceStart)) {
				start = 0
			}
			if start >= 0 {
				candidate := jsonBytes[start+len(fenceStart) : contentEnd]
				var object map[string]json.RawMessage
				if err := json.Unmarshal(candidate, &object); err == nil && object != nil {
					return cloneBytes(candidate), nil
				}
			}
		}
		return nil, fmt.Errorf("missing terminal JSON object")
	}
	var value json.RawMessage
	if err := json.Unmarshal(jsonBytes, &value); err != nil {
		return nil, fmt.Errorf("invalid JSON frame: %w", err)
	}
	if !bytes.Equal(value, jsonBytes) {
		return nil, fmt.Errorf("JSON frame must contain no leading or trailing bytes")
	}
	return cloneBytes(jsonBytes), nil
}

// ValidateProcessOutputFrame validates one complete stdout frame.
func ValidateProcessOutputFrame(framing ProcessOutputFraming, stdout []byte) error {
	_, err := ExtractProcessOutputJSONFrame(framing, stdout)
	return err
}

type ProcessOutputFrameReceipt struct {
	framing        ProcessOutputFraming
	byteLength     int64
	sha256         string
	stabilityGrace time.Duration
}

func NewProcessOutputFrameReceipt(framing ProcessOutputFraming, stdout []byte, stabilityGrace time.Duration) (ProcessOutputFrameReceipt, error) {
	if err := ValidateProcessOutputFrame(framing, stdout); err != nil || stabilityGrace <= 0 {
		return ProcessOutputFrameReceipt{}, fmt.Errorf("output frame receipt: invalid frame or stability grace")
	}
	sum := sha256.New()
	_, _ = sum.Write([]byte("Mulgae-PROCESS-STDOUT-FRAME/1"))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write(stdout)
	return ProcessOutputFrameReceipt{framing: framing, byteLength: int64(len(stdout)), sha256: hex.EncodeToString(sum.Sum(nil)), stabilityGrace: stabilityGrace}, nil
}
func (r ProcessOutputFrameReceipt) Framing() ProcessOutputFraming { return r.framing }
func (r ProcessOutputFrameReceipt) ByteLength() int64             { return r.byteLength }
func (r ProcessOutputFrameReceipt) SHA256() string                { return r.sha256 }
func (r ProcessOutputFrameReceipt) StabilityGrace() time.Duration { return r.stabilityGrace }
func (r ProcessOutputFrameReceipt) Valid() bool {
	return r.framing.Valid() && r.byteLength > 0 && r.stabilityGrace > 0 && validateRawSHA256(r.sha256) == nil
}
func outputFrameDigest(stdout []byte) string {
	sum := sha256.New()
	_, _ = sum.Write([]byte("Mulgae-PROCESS-STDOUT-FRAME/1"))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write(stdout)
	return hex.EncodeToString(sum.Sum(nil))
}

type ProcessFinalTerminationKind string

const (
	ProcessFinalTerminationExited   ProcessFinalTerminationKind = "exited"
	ProcessFinalTerminationSignaled ProcessFinalTerminationKind = "signaled"
)

type ProcessFinalTermination struct {
	kind        ProcessFinalTerminationKind
	exitCode    int
	hasExitCode bool
	signal      ProcessSignal
	hasSignal   bool
}

func NewExitedProcessFinalTermination(exitCode int) (ProcessFinalTermination, error) {
	f := ProcessFinalTermination{kind: ProcessFinalTerminationExited, exitCode: exitCode, hasExitCode: true}
	if !f.Valid() {
		return ProcessFinalTermination{}, fmt.Errorf("final termination: invalid exit code")
	}
	return f, nil
}
func NewSignaledProcessFinalTermination(signal ProcessSignal) (ProcessFinalTermination, error) {
	f := ProcessFinalTermination{kind: ProcessFinalTerminationSignaled, signal: signal, hasSignal: true}
	if !f.Valid() {
		return ProcessFinalTermination{}, fmt.Errorf("final termination: invalid signal")
	}
	return f, nil
}
func (f ProcessFinalTermination) Kind() ProcessFinalTerminationKind { return f.kind }
func (f ProcessFinalTermination) ExitCode() (int, bool)             { return f.exitCode, f.hasExitCode }
func (f ProcessFinalTermination) Signal() (ProcessSignal, bool)     { return f.signal, f.hasSignal }
func (f ProcessFinalTermination) Valid() bool {
	return (f.kind == ProcessFinalTerminationExited && f.hasExitCode && f.exitCode >= 0 && !f.hasSignal) ||
		(f.kind == ProcessFinalTerminationSignaled && !f.hasExitCode && f.hasSignal && f.signal.Valid())
}

type ProcessGroupSignalRequestReason string

const (
	ProcessGroupSignalRequestPostOutput           ProcessGroupSignalRequestReason = "post_output"
	ProcessGroupSignalRequestPostOutputEscalation ProcessGroupSignalRequestReason = "post_output_escalation"
	ProcessGroupSignalRequestCancellation         ProcessGroupSignalRequestReason = "cancellation"
	ProcessGroupSignalRequestTimeout              ProcessGroupSignalRequestReason = "timeout"
	ProcessGroupSignalRequestStdinIncomplete      ProcessGroupSignalRequestReason = "stdin_incomplete"
	ProcessGroupSignalRequestResidualGroup        ProcessGroupSignalRequestReason = "residual_process_group"
	ProcessGroupSignalRequestInternalTeardown     ProcessGroupSignalRequestReason = "internal_teardown"
)

type ProcessGroupSignalRequestReceipt struct {
	reason         ProcessGroupSignalRequestReason
	signal         ProcessSignal
	packetIdentity ProviderPacketIdentity
	frameSHA256    string
	postOutput     bool
}

func NewAcceptedProcessGroupSignalRequestReceipt(reason ProcessGroupSignalRequestReason, signal ProcessSignal) (ProcessGroupSignalRequestReceipt, error) {
	if !isNonPostOutputProcessGroupSignalRequestReason(reason) {
		return ProcessGroupSignalRequestReceipt{}, fmt.Errorf("signal request receipt: invalid non-post-output request")
	}
	r := ProcessGroupSignalRequestReceipt{reason: reason, signal: signal}
	if !r.Valid() {
		return ProcessGroupSignalRequestReceipt{}, fmt.Errorf("signal request receipt: invalid request")
	}
	return r, nil
}
func NewAcceptedPostOutputProcessGroupSignalRequestReceipt(signal ProcessSignal, packet ProviderPacketIdentity, frame ProcessOutputFrameReceipt) (ProcessGroupSignalRequestReceipt, error) {
	r := ProcessGroupSignalRequestReceipt{reason: ProcessGroupSignalRequestPostOutput, signal: signal, packetIdentity: packet, frameSHA256: frame.SHA256(), postOutput: true}
	if !packet.Valid() || !frame.Valid() || !r.Valid() {
		return ProcessGroupSignalRequestReceipt{}, fmt.Errorf("signal request receipt: invalid post-output request")
	}
	return r, nil
}
func NewAcceptedPostOutputEscalationProcessGroupSignalRequestReceipt(signal ProcessSignal, packet ProviderPacketIdentity, frame ProcessOutputFrameReceipt) (ProcessGroupSignalRequestReceipt, error) {
	r := ProcessGroupSignalRequestReceipt{reason: ProcessGroupSignalRequestPostOutputEscalation, signal: signal, packetIdentity: packet, frameSHA256: frame.SHA256(), postOutput: true}
	if !packet.Valid() || !frame.Valid() || !r.Valid() {
		return ProcessGroupSignalRequestReceipt{}, fmt.Errorf("signal request receipt: invalid post-output escalation")
	}
	return r, nil
}
func isNonPostOutputProcessGroupSignalRequestReason(reason ProcessGroupSignalRequestReason) bool {
	switch reason {
	case ProcessGroupSignalRequestCancellation,
		ProcessGroupSignalRequestTimeout,
		ProcessGroupSignalRequestStdinIncomplete,
		ProcessGroupSignalRequestResidualGroup,
		ProcessGroupSignalRequestInternalTeardown:
		return true
	default:
		return false
	}
}
func (r ProcessGroupSignalRequestReceipt) Reason() ProcessGroupSignalRequestReason { return r.reason }
func (r ProcessGroupSignalRequestReceipt) Signal() ProcessSignal                   { return r.signal }
func (r ProcessGroupSignalRequestReceipt) PacketIdentity() (ProviderPacketIdentity, bool) {
	return r.packetIdentity, r.postOutput
}
func (r ProcessGroupSignalRequestReceipt) FrameSHA256() (string, bool) {
	return r.frameSHA256, r.postOutput
}
func (r ProcessGroupSignalRequestReceipt) Valid() bool {
	if !r.signal.Valid() {
		return false
	}
	if r.postOutput {
		return (r.reason == ProcessGroupSignalRequestPostOutput || r.reason == ProcessGroupSignalRequestPostOutputEscalation) && r.packetIdentity.Valid() && validateRawSHA256(r.frameSHA256) == nil
	}
	return isNonPostOutputProcessGroupSignalRequestReason(r.reason) && !r.packetIdentity.Valid() && r.frameSHA256 == ""
}

type ProcessLifecycleReceipt struct {
	finalTermination   ProcessFinalTermination
	processGroupAbsent bool
	requests           []ProcessGroupSignalRequestReceipt
	outputFrame        ProcessOutputFrameReceipt
	hasOutputFrame     bool
}

func NewProcessLifecycleReceipt(final ProcessFinalTermination, absent bool, requests []ProcessGroupSignalRequestReceipt, frames ...ProcessOutputFrameReceipt) (ProcessLifecycleReceipt, error) {
	r := ProcessLifecycleReceipt{finalTermination: final, processGroupAbsent: absent, requests: append([]ProcessGroupSignalRequestReceipt(nil), requests...)}
	if len(frames) > 1 {
		return ProcessLifecycleReceipt{}, fmt.Errorf("lifecycle receipt: multiple output frames")
	}
	if len(frames) == 1 {
		r.outputFrame, r.hasOutputFrame = frames[0], true
	}
	if !r.Valid() {
		return ProcessLifecycleReceipt{}, fmt.Errorf("lifecycle receipt: invalid evidence")
	}
	return r, nil
}
func (r ProcessLifecycleReceipt) FinalTermination() ProcessFinalTermination {
	return r.finalTermination
}
func (r ProcessLifecycleReceipt) ProcessGroupAbsent() bool { return r.processGroupAbsent }
func (r ProcessLifecycleReceipt) SignalRequests() []ProcessGroupSignalRequestReceipt {
	return append([]ProcessGroupSignalRequestReceipt(nil), r.requests...)
}
func (r ProcessLifecycleReceipt) OutputFrame() (ProcessOutputFrameReceipt, bool) {
	return r.outputFrame, r.hasOutputFrame
}
func (r ProcessLifecycleReceipt) Valid() bool {
	if !r.finalTermination.Valid() || !r.processGroupAbsent || (r.hasOutputFrame && !r.outputFrame.Valid()) {
		return false
	}
	postOutput := 0
	for i, request := range r.requests {
		if !request.Valid() {
			return false
		}
		if request.postOutput {
			postOutput++
			if !r.hasOutputFrame || request.frameSHA256 != r.outputFrame.sha256 || (postOutput == 1 && request.signal.Name() != "SIGTERM") || (postOutput == 2 && (request.signal.Name() != "SIGKILL" || i == 0)) {
				return false
			}
		}
	}
	return postOutput <= 2
}

// Number returns the positive operating-system signal number.
func (signal ProcessSignal) Number() int { return signal.number }

// Name returns the canonical operating-system signal name.
func (signal ProcessSignal) Name() string { return signal.name }

// Valid reports whether signal remains a valid immutable signal fact.
func (signal ProcessSignal) Valid() bool { return validateProcessSignal(signal) == nil }

// StdinWriteReceipt is the immutable record of bytes successfully written to
// one child stdin pipe. SHA256 is the raw lower-case hexadecimal digest of
// "Mulgae-PROVIDER-STDIN/1" || 0x00 || those exact successful bytes.
type StdinWriteReceipt struct {
	intendedByteLength int64
	writtenByteCount   int64
	sha256             string
	complete           bool
}

// NewStdinWriteReceipt validates one stdin write fact. Complete must agree
// exactly with the intended and successfully written byte counts.
func NewStdinWriteReceipt(
	intendedByteLength, writtenByteCount int64,
	sha256 string,
	complete bool,
) (StdinWriteReceipt, error) {
	receipt := StdinWriteReceipt{
		intendedByteLength: intendedByteLength,
		writtenByteCount:   writtenByteCount,
		sha256:             sha256,
		complete:           complete,
	}
	if err := validateStdinWriteReceipt(receipt); err != nil {
		return StdinWriteReceipt{}, fmt.Errorf("stdin write receipt: %w", err)
	}
	return receipt, nil
}

// IntendedByteLength returns the exact requested stdin byte length.
func (receipt StdinWriteReceipt) IntendedByteLength() int64 {
	return receipt.intendedByteLength
}

// WrittenByteCount returns the exact number of bytes accepted by the child
// stdin pipe before it closed or the request completed.
func (receipt StdinWriteReceipt) WrittenByteCount() int64 {
	return receipt.writtenByteCount
}

// SHA256 returns the raw domain-separated digest of exactly the successfully
// written stdin bytes.
func (receipt StdinWriteReceipt) SHA256() string { return receipt.sha256 }

// Complete reports whether every intended stdin byte was successfully written.
func (receipt StdinWriteReceipt) Complete() bool { return receipt.complete }

// Valid reports whether receipt is a coherent immutable stdin write fact.
func (receipt StdinWriteReceipt) Valid() bool {
	return validateStdinWriteReceipt(receipt) == nil
}

// ProviderPacketTransportReceipt is immutable evidence of the channel that
// delivered a complete provider packet. Stdin facts remain in StdinWriteReceipt.
type ProviderPacketTransportReceipt struct {
	channel                 ProviderPacketChannel
	packetIdentity          ProviderPacketIdentity
	promptFileReference     string
	snapshotCWD             string
	preStartIdentity        ProviderPacketIdentity
	postTerminationIdentity ProviderPacketIdentity
}

func NewProviderPacketTransportReceipt(
	channel ProviderPacketChannel, packetIdentity ProviderPacketIdentity,
	promptFileReference, snapshotCWD string,
	preStartIdentity, postTerminationIdentity ProviderPacketIdentity,
) (ProviderPacketTransportReceipt, error) {
	receipt := ProviderPacketTransportReceipt{channel: channel, packetIdentity: packetIdentity, promptFileReference: promptFileReference, snapshotCWD: snapshotCWD, preStartIdentity: preStartIdentity, postTerminationIdentity: postTerminationIdentity}
	if !receipt.Valid() {
		return ProviderPacketTransportReceipt{}, fmt.Errorf("provider packet transport receipt: invalid channel evidence")
	}
	return receipt, nil
}

func (receipt ProviderPacketTransportReceipt) Channel() ProviderPacketChannel { return receipt.channel }
func (receipt ProviderPacketTransportReceipt) PacketIdentity() ProviderPacketIdentity {
	return receipt.packetIdentity
}
func (receipt ProviderPacketTransportReceipt) PromptFileReference() string {
	return receipt.promptFileReference
}
func (receipt ProviderPacketTransportReceipt) SnapshotCWD() string { return receipt.snapshotCWD }
func (receipt ProviderPacketTransportReceipt) PreStartIdentity() ProviderPacketIdentity {
	return receipt.preStartIdentity
}
func (receipt ProviderPacketTransportReceipt) PostTerminationIdentity() ProviderPacketIdentity {
	return receipt.postTerminationIdentity
}
func (receipt ProviderPacketTransportReceipt) Valid() bool {
	if !receipt.channel.Valid() || !receipt.packetIdentity.Valid() {
		return false
	}
	switch receipt.channel {
	case ProviderPacketChannelArgvLiteral, ProviderPacketChannelStdin:
		return receipt.promptFileReference == "" && receipt.snapshotCWD == "" &&
			!receipt.preStartIdentity.Valid() && !receipt.postTerminationIdentity.Valid()
	case ProviderPacketChannelPromptFile:
		return validPromptFileReference(receipt.promptFileReference) &&
			validCanonicalSnapshotCWD(receipt.snapshotCWD) &&
			receipt.preStartIdentity == receipt.packetIdentity &&
			receipt.postTerminationIdentity == receipt.packetIdentity
	default:
		return false
	}
}

// ProcessObservation is the immutable, provider-neutral fact record from one
// direct process attempt. It intentionally contains no repair,
// finding, validation, or outcome authority.
type ProcessObservation struct {
	stdout                    []byte
	stdoutArtifact            ContentArtifact
	hasStdoutArtifact         bool
	stdoutTruncated           bool
	stderr                    []byte
	exitCode                  int
	hasExitCode               bool
	signal                    ProcessSignal
	hasSignal                 bool
	termination               ProcessTermination
	stdinWriteReceipt         StdinWriteReceipt
	packetTransportReceipt    ProviderPacketTransportReceipt
	hasPacketTransportReceipt bool
	startedAt                 time.Time
	endedAt                   time.Time
	lifecycleReceipt          ProcessLifecycleReceipt
	hasLifecycleReceipt       bool
}

// NewProcessObservationWithStdoutArtifact binds a file-backed complete stdout
// artifact to an existing observation whose Stdout bytes are only its bounded
// diagnostic preview.
func NewProcessObservationWithStdoutArtifact(observation ProcessObservation, artifact ContentArtifact, truncated bool) (ProcessObservation, error) {
	if !observation.Valid() || isNilContentArtifact(artifact) || !artifact.Identity().Valid() {
		return ProcessObservation{}, fmt.Errorf("process stdout artifact: invalid observation or artifact")
	}
	identity := artifact.Identity()
	if truncated {
		if identity.ByteLength() <= int64(len(observation.stdout)) {
			return ProcessObservation{}, fmt.Errorf("process stdout artifact: truncated preview is not shorter than content")
		}
		if observation.hasLifecycleReceipt {
			if _, hasFrame := observation.lifecycleReceipt.OutputFrame(); hasFrame {
				return ProcessObservation{}, fmt.Errorf("process stdout artifact: truncated output cannot claim a complete frame")
			}
		}
	} else if identity.ByteLength() != int64(len(observation.stdout)) || identity.SHA256() != sha256Identifier(observation.stdout) {
		return ProcessObservation{}, fmt.Errorf("process stdout artifact: complete bytes do not match artifact")
	}
	observation.stdoutArtifact = artifact
	observation.hasStdoutArtifact = true
	observation.stdoutTruncated = truncated
	return observation, nil
}

// NewProcessObservation validates neutral process facts and retains defensive
// copies of stdout and stderr. An exited process has a nonnegative exit code
// and no signal; a signaled process has one valid signal and no exit code.
func NewProcessObservation(
	stdout, stderr []byte,
	exitCode *int,
	termination ProcessTermination,
	stdinWriteReceipt StdinWriteReceipt,
	startedAt, endedAt time.Time,
	signals ...ProcessSignal,
) (ProcessObservation, error) {
	signal, err := optionalProcessSignal(signals)
	if err != nil {
		return ProcessObservation{}, fmt.Errorf("process observation: %w", err)
	}
	if err := validateProcessObservation(exitCode, signal, termination, stdinWriteReceipt, startedAt, endedAt); err != nil {
		return ProcessObservation{}, fmt.Errorf("process observation: %w", err)
	}

	observation := ProcessObservation{
		stdout:            cloneBytes(stdout),
		stderr:            cloneBytes(stderr),
		termination:       termination,
		stdinWriteReceipt: stdinWriteReceipt,
		startedAt:         startedAt,
		endedAt:           endedAt,
	}
	if exitCode != nil {
		observation.exitCode = *exitCode
		observation.hasExitCode = true
	}
	if signal != nil {
		observation.signal = *signal
		observation.hasSignal = true
	}
	return observation, nil
}

// NewProviderProcessObservation records process facts with truthful packet transport.
func NewProviderProcessObservation(
	stdout, stderr []byte, exitCode *int, termination ProcessTermination,
	stdinWriteReceipt StdinWriteReceipt, transportReceipt ProviderPacketTransportReceipt,
	startedAt, endedAt time.Time, signals ...ProcessSignal,
) (ProcessObservation, error) {
	observation, err := NewProcessObservation(stdout, stderr, exitCode, termination, stdinWriteReceipt, startedAt, endedAt, signals...)
	if err != nil {
		return ProcessObservation{}, err
	}
	if err := validateProviderPacketTransportReceipt(termination, stdinWriteReceipt, transportReceipt); err != nil {
		return ProcessObservation{}, fmt.Errorf("provider process observation: %w", err)
	}
	observation.packetTransportReceipt = transportReceipt
	observation.hasPacketTransportReceipt = true
	return observation, nil
}

// NewStartedProcessObservation records a reaped process with exact final wait
// and full process-group absence evidence.
func NewStartedProcessObservation(
	stdout, stderr []byte, disposition ProcessTermination, stdin StdinWriteReceipt,
	lifecycle ProcessLifecycleReceipt, startedAt, endedAt time.Time,
) (ProcessObservation, error) {
	if !lifecycle.Valid() {
		return ProcessObservation{}, fmt.Errorf("started process observation: invalid lifecycle receipt")
	}
	final := lifecycle.FinalTermination()
	if startedAt.IsZero() || endedAt.IsZero() || startedAt.Location() != time.UTC ||
		endedAt.Location() != time.UTC || endedAt.Before(startedAt) || !disposition.Valid() ||
		!stdin.Valid() {
		return ProcessObservation{}, fmt.Errorf("started process observation: invalid process facts")
	}
	observation := ProcessObservation{
		stdout: cloneBytes(stdout), stderr: cloneBytes(stderr), termination: disposition,
		stdinWriteReceipt: stdin, startedAt: startedAt, endedAt: endedAt,
		lifecycleReceipt: lifecycle, hasLifecycleReceipt: true,
	}
	if code, ok := final.ExitCode(); ok {
		observation.exitCode, observation.hasExitCode = code, true
	} else {
		signal, _ := final.Signal()
		observation.signal, observation.hasSignal = signal, true
	}
	return observation, nil
}

// NewStartedProviderProcessObservation records started provider evidence.
func NewStartedProviderProcessObservation(
	stdout, stderr []byte, disposition ProcessTermination, stdin StdinWriteReceipt,
	transport ProviderPacketTransportReceipt, lifecycle ProcessLifecycleReceipt,
	startedAt, endedAt time.Time,
) (ProcessObservation, error) {
	observation, err := NewStartedProcessObservation(stdout, stderr, disposition, stdin, lifecycle, startedAt, endedAt)
	if err != nil {
		return ProcessObservation{}, err
	}
	if err := validateProviderPacketTransportReceipt(disposition, stdin, transport); err != nil {
		return ProcessObservation{}, fmt.Errorf("started provider process observation: %w", err)
	}
	observation.packetTransportReceipt = transport
	observation.hasPacketTransportReceipt = true
	return observation, nil
}

// Stdout returns a caller-owned copy of captured stdout bytes.
func (observation ProcessObservation) Stdout() []byte { return cloneBytes(observation.stdout) }

// StdoutArtifact returns complete file-backed stdout when report spooling was
// requested.
func (observation ProcessObservation) StdoutArtifact() (ContentArtifact, bool) {
	return observation.stdoutArtifact, observation.hasStdoutArtifact && !isNilContentArtifact(observation.stdoutArtifact)
}

// StdoutTruncated reports whether Stdout is only a bounded diagnostic preview.
func (observation ProcessObservation) StdoutTruncated() bool { return observation.stdoutTruncated }

// Stderr returns a caller-owned copy of captured stderr bytes.
func (observation ProcessObservation) Stderr() []byte { return cloneBytes(observation.stderr) }

// ExitCode returns the process exit code when the process terminated by exit.
func (observation ProcessObservation) ExitCode() (int, bool) {
	return observation.exitCode, observation.hasExitCode
}

// Signal returns the exact operating-system signal fact when the process
// terminated because it received a signal.
func (observation ProcessObservation) Signal() (number int, name string, ok bool) {
	return observation.signal.Number(), observation.signal.Name(), observation.hasSignal
}

// Termination returns the closed neutral termination fact.
func (observation ProcessObservation) Termination() ProcessTermination {
	return observation.termination
}

// StartedAt returns the observed UTC process-start time.
func (observation ProcessObservation) StartedAt() time.Time { return observation.startedAt }

// EndedAt returns the observed UTC process-end time.
func (observation ProcessObservation) EndedAt() time.Time { return observation.endedAt }

// StdinWriteReceipt returns the immutable exact-write fact for child stdin.
func (observation ProcessObservation) StdinWriteReceipt() StdinWriteReceipt {
	return observation.stdinWriteReceipt
}

// ProviderPacketTransportReceipt returns truthful provider packet delivery evidence.
func (observation ProcessObservation) ProviderPacketTransportReceipt() (ProviderPacketTransportReceipt, bool) {
	return observation.packetTransportReceipt, observation.hasPacketTransportReceipt
}

// LifecycleReceipt returns final wait and full group-absence evidence.
func (observation ProcessObservation) LifecycleReceipt() (ProcessLifecycleReceipt, bool) {
	return observation.lifecycleReceipt, observation.hasLifecycleReceipt
}
func (observation ProcessObservation) FinalTermination() (ProcessFinalTermination, bool) {
	if !observation.hasLifecycleReceipt {
		return ProcessFinalTermination{}, false
	}
	return observation.lifecycleReceipt.FinalTermination(), true
}
func (observation ProcessObservation) SignalRequests() []ProcessGroupSignalRequestReceipt {
	if !observation.hasLifecycleReceipt {
		return nil
	}
	return observation.lifecycleReceipt.SignalRequests()
}
func (observation ProcessObservation) ProcessGroupAbsent() bool {
	return observation.hasLifecycleReceipt && observation.lifecycleReceipt.ProcessGroupAbsent()
}

// Succeeded reports either a normal zero exit or an intentional bounded
// post-output termination after an exact stable frame. Both paths require
// complete stdin delivery and terminal process-group absence when lifecycle
// evidence is present.
func (observation ProcessObservation) Succeeded() bool {
	if !observation.stdinWriteReceipt.Valid() || !observation.stdinWriteReceipt.Complete() {
		return false
	}
	if !observation.hasLifecycleReceipt {
		return observation.termination == ProcessTerminationExited &&
			observation.hasExitCode && observation.exitCode == 0
	}
	lifecycle := observation.lifecycleReceipt
	if !lifecycle.Valid() || !lifecycle.ProcessGroupAbsent() {
		return false
	}
	frame, hasFrame := lifecycle.OutputFrame()
	if hasFrame && (int64(len(observation.stdout)) != frame.ByteLength() ||
		outputFrameDigest(observation.stdout) != frame.SHA256() ||
		ValidateProcessOutputFrame(frame.Framing(), observation.stdout) != nil) {
		return false
	}
	final := lifecycle.FinalTermination()
	switch observation.termination {
	case ProcessTerminationExited:
		exitCode, ok := final.ExitCode()
		if !ok || !observation.hasExitCode || observation.exitCode != exitCode {
			return false
		}
		requests := lifecycle.SignalRequests()
		for _, request := range requests {
			if request.Reason() == ProcessGroupSignalRequestPostOutputEscalation {
				return false
			}
		}
		if exitCode == 0 {
			return true
		}
		// A provider may handle the accepted post-output SIGTERM and map that
		// intentional teardown to a non-zero native exit. The exact stable
		// frame predates the signal and remains authoritative; require the
		// single bounded post-output request so an unrelated non-zero exit can
		// never be promoted to success.
		return hasFrame && len(requests) == 1 && requests[0].Reason() == ProcessGroupSignalRequestPostOutput
	case ProcessTerminationSignaled:
		signal, ok := final.Signal()
		if !ok || !hasFrame {
			return false
		}
		matchedFinalSignal := false
		for _, request := range lifecycle.SignalRequests() {
			if request.Reason() != ProcessGroupSignalRequestPostOutput &&
				request.Reason() != ProcessGroupSignalRequestPostOutputEscalation {
				return false
			}
			matchedFinalSignal = matchedFinalSignal || request.Signal() == signal
		}
		return matchedFinalSignal
	default:
		return false
	}
}

// Valid reports whether observation remains a coherent neutral process fact record.
func (observation ProcessObservation) Valid() bool {
	if observation.hasStdoutArtifact != !isNilContentArtifact(observation.stdoutArtifact) {
		return false
	}
	if observation.hasStdoutArtifact {
		identity := observation.stdoutArtifact.Identity()
		if !identity.Valid() {
			return false
		}
		if observation.stdoutTruncated {
			if identity.ByteLength() <= int64(len(observation.stdout)) {
				return false
			}
		} else if identity.ByteLength() != int64(len(observation.stdout)) || identity.SHA256() != sha256Identifier(observation.stdout) {
			return false
		}
	} else if observation.stdoutTruncated {
		return false
	}
	if observation.hasLifecycleReceipt {
		if !observation.lifecycleReceipt.Valid() || !observation.termination.Valid() ||
			!observation.stdinWriteReceipt.Valid() || observation.startedAt.IsZero() ||
			observation.endedAt.IsZero() || observation.startedAt.Location() != time.UTC ||
			observation.endedAt.Location() != time.UTC || observation.endedAt.Before(observation.startedAt) {
			return false
		}
		final := observation.lifecycleReceipt.FinalTermination()
		if code, ok := final.ExitCode(); ok {
			return observation.hasExitCode && observation.exitCode == code && !observation.hasSignal
		}
		signal, _ := final.Signal()
		return observation.hasSignal && observation.signal == signal && !observation.hasExitCode
	}
	var exitCode *int
	if observation.hasExitCode {
		exitCode = &observation.exitCode
	}
	var signal *ProcessSignal
	if observation.hasSignal {
		signal = &observation.signal
	}
	return validateProcessObservation(exitCode, signal, observation.termination, observation.stdinWriteReceipt, observation.startedAt, observation.endedAt) == nil
}

// ProcessRunner executes one direct process request. Implementations must
// reject a nil context and must never introduce shell or TTY behavior.
type ProcessRunner interface {
	Run(context.Context, ProcessRequest) (ProcessObservation, error)
}

// ProcessExecutionError preserves the closed primary cause and any captured
// streams when a runner cannot return a coherent ProcessObservation. Cleanup
// failure is supplemental: it never replaces the initiating cause. The
// wrapped error is retained only for local causal inspection; Error itself is
// a closed safe projection and never includes adapter text.
type ProcessExecutionError struct {
	primaryCause domain.RuntimeDiagnosticCause
	cleanupCause domain.RuntimeDiagnosticCause
	stdout       []byte
	stderr       []byte
	err          error
}

// NewProcessExecutionError constructs a safe typed process failure. Primary
// cause is mandatory. Cleanup cause, when present, must be the dedicated
// process-group cleanup cause.
func NewProcessExecutionError(
	primaryCause domain.RuntimeDiagnosticCause,
	cleanupCause domain.RuntimeDiagnosticCause,
	stdout, stderr []byte,
	err error,
) (*ProcessExecutionError, error) {
	if !primaryCause.Valid() ||
		cleanupCause != "" && cleanupCause != domain.DiagnosticCauseProcessGroupCleanupFailed {
		return nil, fmt.Errorf("process execution error: invalid cause")
	}
	return &ProcessExecutionError{
		primaryCause: primaryCause,
		cleanupCause: cleanupCause,
		stdout:       cloneBytes(stdout),
		stderr:       cloneBytes(stderr),
		err:          err,
	}, nil
}

func (failure *ProcessExecutionError) Error() string {
	if failure == nil || !failure.primaryCause.Valid() {
		return "process execution failed"
	}
	return "process execution failed: " + string(failure.primaryCause)
}

func (failure *ProcessExecutionError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.err
}

func (failure *ProcessExecutionError) PrimaryCause() domain.RuntimeDiagnosticCause {
	if failure == nil {
		return ""
	}
	return failure.primaryCause
}

func (failure *ProcessExecutionError) CleanupCause() (domain.RuntimeDiagnosticCause, bool) {
	if failure == nil || failure.cleanupCause == "" {
		return "", false
	}
	return failure.cleanupCause, true
}

func (failure *ProcessExecutionError) Stdout() []byte {
	if failure == nil {
		return nil
	}
	return cloneBytes(failure.stdout)
}

func (failure *ProcessExecutionError) Stderr() []byte {
	if failure == nil {
		return nil
	}
	return cloneBytes(failure.stderr)
}

func validateEnvironmentVariable(name, value string) error {
	if name == "" {
		return fmt.Errorf("name must be non-empty")
	}
	if !asciiEnvironmentNameStart(name[0]) {
		return fmt.Errorf("name must start with an ASCII letter or underscore")
	}
	for index := 1; index < len(name); index++ {
		if !asciiEnvironmentNamePart(name[index]) {
			return fmt.Errorf("name must contain only ASCII letters, digits, or underscores")
		}
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("value must not contain NUL")
	}
	return nil
}

func asciiEnvironmentNameStart(character byte) bool {
	return character >= 'A' && character <= 'Z' ||
		character >= 'a' && character <= 'z' ||
		character == '_'
}

func asciiEnvironmentNamePart(character byte) bool {
	return asciiEnvironmentNameStart(character) || character >= '0' && character <= '9'
}

func cloneEnvironmentVariables(value []EnvironmentVariable) []EnvironmentVariable {
	copyValue := make([]EnvironmentVariable, len(value))
	copy(copyValue, value)
	return copyValue
}

func validateAbsoluteWorkingDirectory(value string) error {
	if value == "" {
		return fmt.Errorf("must be non-empty")
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("must not contain NUL")
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("must be absolute")
	}
	return nil
}
func validPromptFileReference(reference string) bool {
	if len(reference) <= 1 || reference[0] != '@' || strings.ContainsRune(reference, 0) {
		return false
	}
	path := reference[1:]
	return !filepath.IsAbs(path) && filepath.Clean(path) == path && path != "." &&
		path != ".." && !strings.HasPrefix(path, ".."+string(filepath.Separator))
}

func validCanonicalSnapshotCWD(value string) bool {
	return validateAbsoluteWorkingDirectory(value) == nil && filepath.Clean(value) == value
}

func validateProcessRequest(request ProcessRequest) error {
	if err := validateAnchoredRoot(request.executable); err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	if len(request.argv) == 0 {
		return fmt.Errorf("argv must be non-empty")
	}
	if request.argv[0] != request.executable {
		return fmt.Errorf("argv[0] must exactly equal executable")
	}
	for index, argument := range request.argv {
		if strings.ContainsRune(argument, 0) {
			return fmt.Errorf("argv[%d] must not contain NUL", index)
		}
	}
	if err := validateProcessEnvironment(request.environment, request.workingDirectory); err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	if err := validateAbsoluteWorkingDirectory(request.workingDirectory); err != nil {
		return fmt.Errorf("working directory: %w", err)
	}
	if request.hasBoundLaunchDirectory {
		if request.boundLaunchDirectory == nil || request.boundLaunchDirectory.Fd() == ^uintptr(0) || !request.boundWorkspaceRoot.Valid() || request.boundWorkspaceRoot.Path() != request.workingDirectory {
			return fmt.Errorf("invalid bound launch directory or workspace root")
		}
	} else if request.boundLaunchDirectory != nil || request.boundWorkspaceRoot.Valid() {
		return fmt.Errorf("bound launch directory present without marker")
	}
	if request.hasNativeHomeLaunchAuthority {
		if !request.hasBoundLaunchDirectory || !request.nativeHomeLaunchAuthority.Valid() {
			return fmt.Errorf("invalid native home launch authority")
		}
		hasHome := false
		for _, variable := range request.environment {
			if variable.name == "HOME" {
				hasHome = variable.value == request.nativeHomeLaunchAuthority.Path()
				break
			}
		}
		if !hasHome {
			return fmt.Errorf("native home launch authority does not match HOME")
		}
	} else if request.nativeHomeLaunchAuthority != (NativeHomeLaunchAuthority{}) {
		return fmt.Errorf("native home launch authority present without marker")
	}
	if request.timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if request.hasProviderPacketBinding {
		if err := validateProviderPacketRequestBinding(request, request.providerPacketBinding); err != nil {
			return fmt.Errorf("provider packet binding: %w", err)
		}
	} else if request.providerPacketBinding.Valid() {
		return fmt.Errorf("provider packet binding present without marker")
	}
	if request.hasPostOutputLifecycle {
		if !request.hasProviderPacketBinding || !request.postOutputLifecycle.Valid() {
			return fmt.Errorf("post-output lifecycle requires provider packet binding and valid policy")
		}
		if request.postOutputLifecycle.stabilityGrace > request.timeout-request.postOutputLifecycle.terminationGrace {
			return fmt.Errorf("post-output lifecycle grace exceeds timeout")
		}
	} else if request.postOutputLifecycle.Valid() {
		return fmt.Errorf("post-output lifecycle present without marker")
	}
	return nil
}

func validateCanonicalEnvironment(environment []EnvironmentVariable) error {
	for index, variable := range environment {
		if !variable.Valid() {
			return fmt.Errorf("entry %d is invalid", index)
		}
		if index > 0 && environment[index-1].name >= variable.name {
			return fmt.Errorf("entries must be sorted by unique name")
		}
	}
	return nil
}
func validateProcessEnvironment(environment []EnvironmentVariable, workingDirectory string) error {
	if err := validateCanonicalEnvironment(environment); err != nil {
		return err
	}
	for _, variable := range environment {
		if variable.name == "PWD" {
			if variable.value != workingDirectory {
				return fmt.Errorf("PWD must exactly equal working directory")
			}
			return nil
		}
	}
	return fmt.Errorf("PWD is required")
}

func validateStdinWriteReceipt(receipt StdinWriteReceipt) error {
	if receipt.intendedByteLength < 0 {
		return fmt.Errorf("intended byte length must not be negative")
	}
	if receipt.writtenByteCount < 0 || receipt.writtenByteCount > receipt.intendedByteLength {
		return fmt.Errorf("written byte count must be within intended byte length")
	}
	if err := validateRawSHA256(receipt.sha256); err != nil {
		return fmt.Errorf("invalid SHA-256: %w", err)
	}
	if receipt.complete != (receipt.writtenByteCount == receipt.intendedByteLength) {
		return fmt.Errorf("complete must exactly match written and intended byte counts")
	}
	return nil
}
func validateProviderPacketTransportReceipt(termination ProcessTermination, stdin StdinWriteReceipt, receipt ProviderPacketTransportReceipt) error {
	if !receipt.Valid() {
		return fmt.Errorf("invalid transport receipt")
	}
	if receipt.Channel() == ProviderPacketChannelStdin {
		return nil
	}
	if stdin.IntendedByteLength() != 0 || stdin.WrittenByteCount() != 0 || !stdin.Complete() || stdin.SHA256() != providerPacketDigest(nil) {
		return fmt.Errorf("argv or prompt-file transport requires complete zero-byte stdin receipt")
	}
	switch termination {
	case ProcessTerminationStartFailed, ProcessTerminationStartUnavailable, ProcessTerminationStartConfiguration,
		ProcessTerminationStartSecurity:
		return fmt.Errorf("start failure cannot claim argv or prompt-file delivery")
	}
	return nil
}

func optionalProcessSignal(signals []ProcessSignal) (*ProcessSignal, error) {
	switch len(signals) {
	case 0:
		return nil, nil
	case 1:
		return &signals[0], nil
	default:
		return nil, fmt.Errorf("at most one signal fact is allowed")
	}
}

func validateProcessSignal(signal ProcessSignal) error {
	if signal.number <= 0 {
		return fmt.Errorf("signal number must be positive")
	}
	if len(signal.name) <= len("SIG") || !strings.HasPrefix(signal.name, "SIG") {
		return fmt.Errorf("signal name must use the SIG prefix")
	}
	for index := len("SIG"); index < len(signal.name); index++ {
		character := signal.name[index]
		if character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '+' ||
			character == '-' {
			continue
		}
		return fmt.Errorf("signal name contains invalid character %q", character)
	}
	return nil
}

func validateProcessObservation(
	exitCode *int,
	signal *ProcessSignal,
	termination ProcessTermination,
	stdinWriteReceipt StdinWriteReceipt,
	startedAt, endedAt time.Time,
) error {
	if !termination.Valid() {
		return fmt.Errorf("invalid termination %q", termination)
	}
	if signal != nil && !signal.Valid() {
		return fmt.Errorf("invalid signal")
	}
	if !stdinWriteReceipt.Valid() {
		return fmt.Errorf("invalid stdin write receipt")
	}
	if startedAt.IsZero() || endedAt.IsZero() {
		return fmt.Errorf("start and end times must be non-zero")
	}
	if startedAt.Location() != time.UTC || endedAt.Location() != time.UTC {
		return fmt.Errorf("start and end times must use time.UTC")
	}
	if endedAt.Before(startedAt) {
		return fmt.Errorf("end time must not precede start time")
	}
	switch termination {
	case ProcessTerminationExited:
		if exitCode == nil {
			return fmt.Errorf("exited process must have an exit code")
		}
		if *exitCode < 0 {
			return fmt.Errorf("exit code must not be negative")
		}
		if signal != nil {
			return fmt.Errorf("exited process must not have a signal")
		}
		if !stdinWriteReceipt.Complete() {
			return fmt.Errorf("exited process must have a complete stdin write receipt")
		}
	case ProcessTerminationSignaled:
		if exitCode != nil {
			return fmt.Errorf("signaled process must not have an exit code")
		}
		if signal == nil {
			return fmt.Errorf("signaled process must have a signal")
		}
	default:
		if exitCode != nil {
			return fmt.Errorf("non-exited process must not have an exit code")
		}
		if signal != nil {
			return fmt.Errorf("non-signaled process must not have a signal")
		}
	}
	return nil
}
