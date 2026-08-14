package mcpentry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestServeAdvertisesOnlyLatestProtocol(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}` + "\n"
	output := serveRequest(t, request)
	response := decodeResponse(t, output)
	result := response["result"].(map[string]any)
	versions := result["supportedVersions"].([]any)
	if len(versions) != 1 || versions[0] != ProtocolVersion {
		t.Fatalf("supported versions = %#v, want [%q]", versions, ProtocolVersion)
	}
	if _, present := result["capabilities"].(map[string]any)["logging"]; present {
		t.Fatal("latest server unexpectedly advertises deprecated logging capability")
	}
	if strings.Contains(string(output), "level=") {
		t.Fatalf("stdout contains non-protocol logging: %q", output)
	}
}

func TestServeRejectsLegacyInitializeWithSupportedVersion(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}` + "\n"
	response := decodeResponse(t, serveRequest(t, request))
	errorValue := response["error"].(map[string]any)
	if errorValue["code"] != float64(mcpsdk.CodeUnsupportedProtocolVersion) {
		t.Fatalf("error code = %v, want %d; response %#v", errorValue["code"], mcpsdk.CodeUnsupportedProtocolVersion, response)
	}
	data := errorValue["data"].(map[string]any)
	versions := data["supported"].([]any)
	if len(versions) != 1 || versions[0] != ProtocolVersion || data["requested"] != "2025-11-25" {
		t.Fatalf("unsupported version data = %#v", data)
	}
}

func TestServeRejectsOlderPerRequestProtocol(t *testing.T) {
	discover := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}` + "\n"
	older := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}` + "\n"
	responses := serveRequests(t, discover, older)
	response := decodeResponse(t, responses[1])
	errorValue := response["error"].(map[string]any)
	if errorValue["code"] != float64(mcpsdk.CodeUnsupportedProtocolVersion) {
		t.Fatalf("error code = %v, want %d; response %#v", errorValue["code"], mcpsdk.CodeUnsupportedProtocolVersion, response)
	}
	data := errorValue["data"].(map[string]any)
	if data["requested"] != "2025-11-25" {
		t.Fatalf("requested version = %v, want 2025-11-25", data["requested"])
	}
}

func TestServeTreatsEOFAsCleanAndMalformedInputAsFailure(t *testing.T) {
	var output bytes.Buffer
	if err := Serve(context.Background(), strings.NewReader(""), &output, testConfig()); err != nil {
		t.Fatalf("empty input: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("empty input wrote %q", output.String())
	}

	if err := Serve(context.Background(), strings.NewReader("{\n"), &output, testConfig()); err == nil {
		t.Fatal("malformed input was accepted")
	}
}

func TestServeCancellationClosesBlockingInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader, input := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, reader, io.Discard, testConfig())
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for cancelled MCP shutdown")
	}
	_ = input.Close()
}

func testConfig() Config {
	return Config{Name: "mulgae", Version: "test", ProjectRoot: "/work/project"}
}

func serveRequest(t *testing.T, request string) []byte {
	t.Helper()
	return serveRequests(t, request)[0]
}

func serveRequests(t *testing.T, requests ...string) [][]byte {
	t.Helper()
	reader, input := io.Pipe()
	output := make(chan []byte, len(requests))
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), reader, channelWriter{output: output}, testConfig())
	}()
	responses := make([][]byte, 0, len(requests))
	for _, request := range requests {
		if _, err := io.WriteString(input, request); err != nil {
			t.Fatal(err)
		}
		select {
		case raw := <-output:
			responses = append(responses, raw)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for MCP response")
		}
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for MCP shutdown")
	}
	return responses
}

type channelWriter struct {
	output chan<- []byte
}

func (writer channelWriter) Write(value []byte) (int, error) {
	writer.output <- append([]byte(nil), value...)
	return len(value), nil
}

func decodeResponse(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(raw), &response); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	return response
}
