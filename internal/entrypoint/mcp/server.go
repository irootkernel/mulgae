package mcpentry

import (
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

// ProtocolVersion is the only MCP protocol version accepted by Mulgae.
const ProtocolVersion = "2026-07-28"

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
	server.AddReceivingMiddleware(admitLatestProtocol)
	registerTools(server, config.Backend, config.NewRequestID, config.ToolResultSchema)
	registerResources(server, config.Backend)

	transport := latestTransport{Transport: &mcpsdk.IOTransport{
		Reader: asReadCloser(reader),
		Writer: noCloseWriter{Writer: writer},
	}}
	if err := server.Run(ctx, transport); err != nil && !cleanTransportEOF(err) {
		return fmt.Errorf("serve MCP: %w", err)
	}
	return nil
}

func cleanTransportEOF(err error) bool {
	closing := &jsonrpc.Error{Code: -32004, Message: "server is closing"}
	return errors.Is(err, closing) && err.Error() == "server is closing: EOF"
}

type latestTransport struct {
	mcpsdk.Transport
}

func (latestTransport) SupportsProtocolVersion(version string) bool {
	return version == ProtocolVersion
}

func admitLatestProtocol(next mcpsdk.MethodHandler) mcpsdk.MethodHandler {
	return func(ctx context.Context, method string, request mcpsdk.Request) (mcpsdk.Result, error) {
		requested := ""
		if method != "initialize" {
			if params := request.GetParams(); params != nil {
				requested, _ = params.GetMeta()[mcpsdk.MetaKeyProtocolVersion].(string)
			}
			if requested == ProtocolVersion {
				return next(ctx, method, request)
			}
		} else if params, ok := request.GetParams().(*mcpsdk.InitializeParams); ok && params != nil {
			requested = params.ProtocolVersion
		}
		data, err := json.Marshal(mcpsdk.UnsupportedProtocolVersionData{
			Supported: []string{ProtocolVersion},
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
