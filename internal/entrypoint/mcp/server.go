package mcpentry

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ProtocolVersion is the newest MCP protocol version accepted by Mulgae.
const ProtocolVersion = "2026-07-28"

const maxMCPFrameBytes = 1 << 20

var (
	errMCPFrameTooLarge  = errors.New("MCP frame exceeds the input limit")
	errMCPFrameTruncated = errors.New("MCP frame is not newline terminated")
)

var supportedProtocolVersions = []string{
	ProtocolVersion,
	"2025-11-25",
	"2025-06-18",
}

// Config fixes process-scoped MCP server identity and project authority.
type Config struct {
	Name             string
	Version          string
	ProjectRoot      string
	Backend          Backend
	NewRequestID     func() (string, error)
	ToolResultSchema json.RawMessage
}

// Serve runs one attached stdio MCP server until input closes or the context is
// cancelled. The reader is closed during shutdown when it implements io.Closer.
func Serve(ctx context.Context, reader io.Reader, writer io.Writer, config Config) error {
	if ctx == nil || reader == nil || writer == nil {
		return errors.New("serve MCP: context and streams are required")
	}
	if config.Name == "" || config.Version == "" || !filepath.IsAbs(config.ProjectRoot) {
		return errors.New("serve MCP: invalid server configuration")
	}
	toolConfigurationPresent := config.Backend != nil || config.NewRequestID != nil || len(config.ToolResultSchema) != 0
	if toolConfigurationPresent && (config.Backend == nil || config.NewRequestID == nil || len(config.ToolResultSchema) == 0) {
		return errors.New("serve MCP: incomplete tool configuration")
	}

	server := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: config.Name, Version: config.Version},
		&mcpsdk.ServerOptions{
			Capabilities: &mcpsdk.ServerCapabilities{},
			Instructions: "Mulgae is an attached, local code-review server bound to one canonical project root. It is advisory and cannot approve merges, releases, waivers, security exceptions, or organizational decisions.",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	)
	server.AddReceivingMiddleware(bindServeContext(ctx), admitSupportedProtocol)
	registerTools(server, config.Backend, config.NewRequestID, config.ToolResultSchema)
	registerResources(server, config.Backend)

	transport := compatibleTransport{Transport: &mcpsdk.IOTransport{
		Reader: newBoundedMCPReader(asReadCloser(reader)),
		Writer: noCloseWriter{Writer: writer},
	}}
	if err := server.Run(ctx, transport); err != nil && !cleanTransportEOF(err) {
		return fmt.Errorf("serve MCP: %w", err)
	}
	return nil
}

func bindServeContext(serveCtx context.Context) mcpsdk.Middleware {
	return func(next mcpsdk.MethodHandler) mcpsdk.MethodHandler {
		return func(requestCtx context.Context, method string, request mcpsdk.Request) (mcpsdk.Result, error) {
			handlerCtx, cancel := context.WithCancelCause(requestCtx)
			stop := context.AfterFunc(serveCtx, func() {
				cancel(context.Cause(serveCtx))
			})
			defer func() {
				stop()
				cancel(nil)
			}()
			return next(handlerCtx, method, request)
		}
	}
}

type boundedMCPReader struct {
	source     io.ReadCloser
	reader     *bufio.Reader
	pending    []byte
	pendingErr error
}

func newBoundedMCPReader(source io.ReadCloser) io.ReadCloser {
	return &boundedMCPReader{
		source: source,
		reader: bufio.NewReaderSize(source, maxMCPFrameBytes+1),
	}
}

func (reader *boundedMCPReader) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if len(reader.pending) == 0 {
		if reader.pendingErr != nil {
			return 0, reader.pendingErr
		}
		frame, err := reader.reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(frame) > maxMCPFrameBytes {
			reader.pendingErr = errMCPFrameTooLarge
			return 0, reader.pendingErr
		}
		if errors.Is(err, io.EOF) {
			if len(frame) == 0 {
				reader.pendingErr = io.EOF
				return 0, reader.pendingErr
			}
			reader.pendingErr = errMCPFrameTruncated
			return 0, reader.pendingErr
		}
		if err != nil {
			reader.pendingErr = err
			return 0, err
		}
		if len(frame) == 0 {
			reader.pendingErr = err
			return 0, err
		}
		reader.pending = frame
		reader.pendingErr = err
	}

	written := copy(destination, reader.pending)
	reader.pending = reader.pending[written:]
	return written, nil
}

func (reader *boundedMCPReader) Close() error {
	return reader.source.Close()
}

func cleanTransportEOF(err error) bool {
	closing := &jsonrpc.Error{Code: -32004, Message: "server is closing"}
	return errors.Is(err, closing) && err.Error() == "server is closing: EOF"
}

type compatibleTransport struct {
	mcpsdk.Transport
}

func (compatibleTransport) SupportsProtocolVersion(version string) bool {
	return supportedProtocolVersion(version)
}

func admitSupportedProtocol(next mcpsdk.MethodHandler) mcpsdk.MethodHandler {
	return func(ctx context.Context, method string, request mcpsdk.Request) (mcpsdk.Result, error) {
		requested, coherent := requestProtocolVersion(method, request)
		if coherent && supportedProtocolVersion(requested) {
			return next(ctx, method, request)
		}
		data, err := json.Marshal(mcpsdk.UnsupportedProtocolVersionData{
			Supported: append([]string(nil), supportedProtocolVersions...),
			Requested: requested,
		})
		if err != nil {
			return nil, err
		}
		return nil, &jsonrpc.Error{
			Code:    mcpsdk.CodeUnsupportedProtocolVersion,
			Message: "unsupported protocol version",
			Data:    data,
		}
	}
}

func requestProtocolVersion(method string, request mcpsdk.Request) (string, bool) {
	if request == nil {
		return "", false
	}
	if method == "initialize" {
		params, ok := request.GetParams().(*mcpsdk.InitializeParams)
		if !ok || params == nil {
			return "", false
		}
		return params.ProtocolVersion, true
	}

	requested := ""
	if versioned, ok := request.(interface{ ProtocolVersion() string }); ok {
		requested = versioned.ProtocolVersion()
	}
	sessionVersion := ""
	if session, ok := request.GetSession().(*mcpsdk.ServerSession); ok && session != nil {
		if initialized := session.InitializeParams(); initialized != nil {
			sessionVersion = initialized.ProtocolVersion
		}
	}
	if sessionVersion != "" {
		if requested != "" && requested != sessionVersion {
			return requested, false
		}
		return sessionVersion, true
	}
	return requested, requested != ""
}

func supportedProtocolVersion(version string) bool {
	for _, supported := range supportedProtocolVersions {
		if version == supported {
			return true
		}
	}
	return false
}

func asReadCloser(reader io.Reader) io.ReadCloser {
	if closer, ok := reader.(io.ReadCloser); ok {
		return closer
	}
	return io.NopCloser(reader)
}

type noCloseWriter struct {
	io.Writer
}

func (noCloseWriter) Close() error { return nil }
