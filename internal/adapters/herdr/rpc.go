package herdr

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// SupportedProtocolGeneration is the sole herdr-core JSON-RPC 2.0 protocol
	// generation accepted by Mulgae.
	SupportedProtocolGeneration = 1

	defaultRPCCallTimeout = 30 * time.Second
	maxRPCResponseBytes   = 8 * 1024 * 1024
)

var requiredRPCMethods = []string{
	"hello",
	"server.status",
	"server.stop",
	"terminal.run",
	"terminal.list",
	"terminal.get",
	"terminal.kill",
	"terminal.rm",
	"terminal.read",
	"terminal.send",
	"terminal.wait",
}

// RPCError is a structured JSON-RPC 2.0 error returned by herdr-core.
type RPCError struct {
	Code    int
	Message string
	Kind    string
	Hint    string
}

func (e *RPCError) Error() string {
	if e == nil {
		return "herdr rpc error"
	}
	if e.Kind != "" {
		return fmt.Sprintf("herdr rpc error %d (%s): %s", e.Code, e.Kind, e.Message)
	}
	return fmt.Sprintf("herdr rpc error %d: %s", e.Code, e.Message)
}

// IsRPCErrorKind reports whether err wraps an *RPCError with the given stable
// data.kind identifier (e.g. "not_found", "blocked", "finished", "live").
func IsRPCErrorKind(err error, kind string) bool {
	var rpcErr *RPCError
	return errors.As(err, &rpcErr) && rpcErr.Kind == kind
}

// ProtocolHandshakeError marks an incompatible or malformed hello response.
type ProtocolHandshakeError struct {
	Reason string
}

func (e *ProtocolHandshakeError) Error() string {
	return "herdr protocol handshake failed: " + e.Reason
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcErrorData struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

type rpcErrorPayload struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      json.RawMessage  `json:"id"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *rpcErrorPayload `json:"error,omitempty"`
}

// CoreInfo matches herdr-core's CoreInfo schema.
type CoreInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// HelloParams matches herdr-core's hello request parameters.
type HelloParams struct {
	Generation uint32 `json:"generation"`
	Framed     bool   `json:"framed,omitempty"`
}

// HelloResult matches herdr-core's HelloResult schema.
type HelloResult struct {
	Generation uint32   `json:"generation"`
	Version    string   `json:"version"`
	Core       CoreInfo `json:"core"`
	Framed     bool     `json:"framed"`
	Methods    []string `json:"methods"`
	Features   []string `json:"features"`
}

// HolderInfo matches herdr-core's HolderInfo schema.
type HolderInfo struct {
	PID       uint32 `json:"pid"`
	Instance  string `json:"instance"`
	Current   bool   `json:"current"`
	Terminals uint   `json:"terminals"`
}

// StatusResult matches herdr-core's StatusResult schema.
type StatusResult struct {
	Core     CoreInfo     `json:"core"`
	Version  string       `json:"version"`
	PID      uint32       `json:"pid"`
	UptimeMS uint64       `json:"uptime_ms"`
	Holder   *HolderInfo  `json:"holder"`
	Holders  []HolderInfo `json:"holders"`
	Live     uint         `json:"live"`
	Finished uint         `json:"finished"`
}

// StopResult matches herdr-core's StopResult schema.
type StopResult struct {
	Stopped bool `json:"stopped"`
}

// InitialSize matches herdr-core's InitialSize schema.
type InitialSize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// RunParams matches herdr-core's terminal.run parameters.
type RunParams struct {
	Argv     []string          `json:"argv,omitempty"`
	CWD      string            `json:"cwd,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	NoParent bool              `json:"no_parent,omitempty"`
	NoNotify bool              `json:"no_notify,omitempty"`
	Keep     bool              `json:"keep,omitempty"`
	RM       bool              `json:"rm,omitempty"`
	Size     *InitialSize      `json:"size,omitempty"`
	Wait     bool              `json:"wait,omitempty"`
}

// TerminalStatus matches herdr-core's OSC 7501 Status schema.
type TerminalStatus struct {
	State    string `json:"state"`
	Kind     string `json:"kind,omitempty"`
	Msg      string `json:"msg,omitempty"`
	Title    string `json:"title,omitempty"`
	App      string `json:"app,omitempty"`
	Progress *uint8 `json:"progress,omitempty"`
}

// Terminal matches herdr-core's Terminal and RunResult schemas.
type Terminal struct {
	Address    string            `json:"address"`
	Argv       []string          `json:"argv"`
	CWD        string            `json:"cwd"`
	State      string            `json:"state"`
	Labels     map[string]string `json:"labels"`
	PID        *uint32           `json:"pid,omitempty"`
	ExitCode   *int32            `json:"exit_code,omitempty"`
	Signal     *int32            `json:"signal,omitempty"`
	Reason     *string           `json:"reason,omitempty"`
	Reported   bool              `json:"reported"`
	Status     *TerminalStatus   `json:"status,omitempty"`
	StatusMS   *uint64           `json:"status_ms,omitempty"`
	Turn       uint64            `json:"turn"`
	Cols       uint16            `json:"cols"`
	Rows       uint16            `json:"rows"`
	CreatedMS  uint64            `json:"created_ms"`
	FinishedMS *uint64           `json:"finished_ms,omitempty"`
	Screen     string            `json:"screen"`
}

// ListParams matches herdr-core's terminal.list parameters.
type ListParams struct {
	All    bool              `json:"all,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// ListResult matches herdr-core's ListResult schema.
type ListResult struct {
	Terminals      []Terminal `json:"terminals"`
	HiddenFinished uint       `json:"hidden_finished"`
}

// TerminalRefParams carries the required terminal address for get/kill/rm.
type TerminalRefParams struct {
	Terminal string `json:"terminal"`
}

// RemoveResult matches herdr-core's RemoveResult schema.
type RemoveResult struct {
	Removed string `json:"removed"`
}

// ReadParams matches herdr-core's terminal.read parameters.
type ReadParams struct {
	Terminal string `json:"terminal"`
	Lines    uint   `json:"lines"`
}

// ReadResult matches herdr-core's ReadResult schema.
type ReadResult struct {
	Text     string  `json:"text"`
	Complete bool    `json:"complete"`
	How      string  `json:"how"`
	Why      *string `json:"why,omitempty"`
}

// SendParams matches herdr-core's terminal.send parameters.
type SendParams struct {
	Terminal string   `json:"terminal"`
	Text     string   `json:"text"`
	Caller   string   `json:"caller,omitempty"`
	Force    bool     `json:"force,omitempty"`
	If       string   `json:"if,omitempty"`
	Wait     bool     `json:"wait,omitempty"`
	Timeout  *float64 `json:"timeout,omitempty"`
}

// SendResult matches herdr-core's SendResult schema.
type SendResult struct {
	Turn    uint64      `json:"turn"`
	Started *bool       `json:"started,omitempty"`
	Status  *string     `json:"status,omitempty"`
	Wait    *WaitResult `json:"wait,omitempty"`
}

// WaitParams matches herdr-core's terminal.wait parameters.
type WaitParams struct {
	Terminal string   `json:"terminal,omitempty"`
	Caller   string   `json:"caller,omitempty"`
	Timeout  *float64 `json:"timeout,omitempty"`
}

// WaitResult matches herdr-core's WaitResult schema.
type WaitResult struct {
	Terminal string       `json:"terminal"`
	Ended    bool         `json:"ended"`
	Reason   string       `json:"reason"`
	Status   *string      `json:"status,omitempty"`
	Turn     uint64       `json:"turn"`
	ExitCode *int32       `json:"exit_code,omitempty"`
	Signal   *int32       `json:"signal,omitempty"`
	Children []WaitResult `json:"children"`
}

// RPCClient speaks newline-delimited JSON-RPC 2.0 over a Unix domain socket to
// an isolated herdr-core daemon. Each Call opens a dedicated connection so
// concurrent pane waits never head-of-line block one another and context
// cancellation closes the blocked read immediately.
type RPCClient struct {
	socketPath  string
	callTimeout time.Duration
	nextID      atomic.Uint64
}

// NewRPCClient constructs a pure-Go Unix-socket JSON-RPC 2.0 client bound to
// socketPath.
func NewRPCClient(socketPath string, callTimeout time.Duration) (*RPCClient, error) {
	if socketPath == "" || strings.ContainsRune(socketPath, 0) {
		return nil, fmt.Errorf("herdr rpc: invalid socket path")
	}
	if callTimeout <= 0 {
		callTimeout = defaultRPCCallTimeout
	}
	return &RPCClient{
		socketPath:  socketPath,
		callTimeout: callTimeout,
	}, nil
}

// Call invokes one JSON-RPC 2.0 method and decodes the result payload into out
// (when out != nil).
func (client *RPCClient) Call(ctx context.Context, method string, params any, out any) error {
	if client == nil {
		return fmt.Errorf("herdr rpc: nil client")
	}
	if ctx == nil {
		return fmt.Errorf("herdr rpc: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if method == "" {
		return fmt.Errorf("herdr rpc: empty method")
	}

	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(client.callTimeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "unix", client.socketPath)
	if err != nil {
		if normErr := normalizeRPCIOTimeout(ctx, deadline, err); normErr != nil {
			return normErr
		}
		return fmt.Errorf("herdr rpc %s: dial: %w", method, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("herdr rpc %s: set deadline: %w", method, err)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopCancel()

	id := client.nextID.Add(1)
	wireReq := rpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}
	encoded, err := json.Marshal(wireReq)
	if err != nil {
		return fmt.Errorf("herdr rpc %s: marshal request: %w", method, err)
	}
	encoded = append(encoded, '\n')
	if err := writeAll(conn, encoded); err != nil {
		if normErr := normalizeRPCIOTimeout(ctx, deadline, err); normErr != nil {
			return normErr
		}
		return fmt.Errorf("herdr rpc %s: write request: %w", method, err)
	}

	line, err := readBoundedLine(conn, maxRPCResponseBytes)
	if err != nil {
		if normErr := normalizeRPCIOTimeout(ctx, deadline, err); normErr != nil {
			return normErr
		}
		return fmt.Errorf("herdr rpc %s: read response: %w", method, err)
	}

	var resp rpcResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("herdr rpc %s: decode response: %w", method, err)
	}
	if resp.JSONRPC != "2.0" {
		return fmt.Errorf("herdr rpc %s: unexpected jsonrpc version %q", method, resp.JSONRPC)
	}
	var respID uint64
	if err := json.Unmarshal(resp.ID, &respID); err != nil || respID != id {
		return fmt.Errorf("herdr rpc %s: response id mismatch", method)
	}
	if resp.Error != nil {
		rpcErr := &RPCError{
			Code:    resp.Error.Code,
			Message: resp.Error.Message,
		}
		if len(resp.Error.Data) > 0 {
			var data rpcErrorData
			if json.Unmarshal(resp.Error.Data, &data) == nil {
				rpcErr.Kind = data.Kind
				rpcErr.Hint = data.Hint
			}
		}
		return rpcErr
	}
	if out == nil {
		return nil
	}
	if len(resp.Result) == 0 {
		return fmt.Errorf("herdr rpc %s: empty result", method)
	}
	if err := json.Unmarshal(resp.Result, out); err != nil {
		return fmt.Errorf("herdr rpc %s: decode result: %w", method, err)
	}
	return nil
}

// Hello performs the generation-1 protocol handshake and validates that every
// method required by Mulgae is advertised by the daemon.
func (client *RPCClient) Hello(ctx context.Context) (HelloResult, error) {
	var result HelloResult
	if err := client.Call(ctx, "hello", HelloParams{Generation: SupportedProtocolGeneration}, &result); err != nil {
		return HelloResult{}, err
	}
	if err := validateHelloResult(result); err != nil {
		return HelloResult{}, err
	}
	return result, nil
}

func validateHelloResult(result HelloResult) error {
	if result.Generation != SupportedProtocolGeneration {
		return &ProtocolHandshakeError{
			Reason: fmt.Sprintf("unsupported generation %d (want %d)", result.Generation, SupportedProtocolGeneration),
		}
	}
	if strings.TrimSpace(result.Version) == "" {
		return &ProtocolHandshakeError{Reason: "missing version"}
	}
	present := make(map[string]struct{}, len(result.Methods))
	for _, method := range result.Methods {
		present[method] = struct{}{}
	}
	for _, required := range requiredRPCMethods {
		if _, ok := present[required]; !ok {
			return &ProtocolHandshakeError{Reason: fmt.Sprintf("missing required method %q", required)}
		}
	}
	return nil
}

func (client *RPCClient) ServerStatus(ctx context.Context) (StatusResult, error) {
	var result StatusResult
	if err := client.Call(ctx, "server.status", struct{}{}, &result); err != nil {
		return StatusResult{}, err
	}
	return result, nil
}

func (client *RPCClient) ServerStop(ctx context.Context) (StopResult, error) {
	var result StopResult
	if err := client.Call(ctx, "server.stop", struct{}{}, &result); err != nil {
		return StopResult{}, err
	}
	return result, nil
}

func (client *RPCClient) TerminalRun(ctx context.Context, params RunParams) (Terminal, error) {
	var result Terminal
	if err := client.Call(ctx, "terminal.run", params, &result); err != nil {
		return Terminal{}, err
	}
	return result, nil
}

func (client *RPCClient) TerminalList(ctx context.Context, params ListParams) (ListResult, error) {
	var result ListResult
	if err := client.Call(ctx, "terminal.list", params, &result); err != nil {
		return ListResult{}, err
	}
	return result, nil
}

func (client *RPCClient) TerminalGet(ctx context.Context, terminal string) (Terminal, error) {
	var result Terminal
	if err := client.Call(ctx, "terminal.get", TerminalRefParams{Terminal: terminal}, &result); err != nil {
		return Terminal{}, err
	}
	return result, nil
}

func (client *RPCClient) TerminalKill(ctx context.Context, terminal string) (Terminal, error) {
	var result Terminal
	if err := client.Call(ctx, "terminal.kill", TerminalRefParams{Terminal: terminal}, &result); err != nil {
		return Terminal{}, err
	}
	return result, nil
}

func (client *RPCClient) TerminalRemove(ctx context.Context, terminal string) (RemoveResult, error) {
	var result RemoveResult
	if err := client.Call(ctx, "terminal.rm", TerminalRefParams{Terminal: terminal}, &result); err != nil {
		return RemoveResult{}, err
	}
	return result, nil
}

func (client *RPCClient) TerminalRead(ctx context.Context, params ReadParams) (ReadResult, error) {
	var result ReadResult
	if err := client.Call(ctx, "terminal.read", params, &result); err != nil {
		return ReadResult{}, err
	}
	return result, nil
}

func (client *RPCClient) TerminalSend(ctx context.Context, params SendParams) (SendResult, error) {
	var result SendResult
	if err := client.Call(ctx, "terminal.send", params, &result); err != nil {
		return SendResult{}, err
	}
	return result, nil
}

func (client *RPCClient) TerminalWait(ctx context.Context, params WaitParams) (WaitResult, error) {
	var result WaitResult
	if err := client.Call(ctx, "terminal.wait", params, &result); err != nil {
		return WaitResult{}, err
	}
	return result, nil
}

func normalizeRPCIOTimeout(ctx context.Context, deadline time.Time, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, os.ErrDeadlineExceeded) && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func readBoundedLine(r io.Reader, maxBytes int) ([]byte, error) {
	limited := io.LimitReader(r, int64(maxBytes)+1)
	reader := bufio.NewReaderSize(limited, 16*1024)
	line, err := reader.ReadBytes('\n')
	if len(line) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d-byte limit", maxBytes)
	}
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return line, nil
		}
		return nil, err
	}
	return line, nil
}
