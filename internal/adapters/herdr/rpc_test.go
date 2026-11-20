package herdr

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startFakeRPCSocket(t *testing.T, handler func(req rpcRequest, conn net.Conn)) string {
	t.Helper()
	// Short path to stay safely below Darwin's 104-byte Unix socket sun_path limit.
	dir, err := os.MkdirTemp("", "mhrpc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				scanner := bufio.NewScanner(c)
				scanner.Buffer(make([]byte, 4096), 1024*1024)
				if !scanner.Scan() {
					return
				}
				var req rpcRequest
				if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
					return
				}
				handler(req, c)
			}(conn)
		}
	}()
	return sockPath
}

func writeRPCResult(conn net.Conn, id uint64, result any) {
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
	payload = append(payload, '\n')
	_, _ = conn.Write(payload)
}

func writeRPCError(conn net.Conn, id uint64, code int, message, kind, hint string) {
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
			"data": map[string]any{
				"kind": kind,
				"hint": hint,
			},
		},
	})
	payload = append(payload, '\n')
	_, _ = conn.Write(payload)
}

func TestRPCClientHelloValidationAndErrors(t *testing.T) {
	t.Parallel()

	t.Run("valid generation 1 handshake", func(t *testing.T) {
		sock := startFakeRPCSocket(t, func(req rpcRequest, conn net.Conn) {
			if req.Method != "hello" {
				t.Errorf("unexpected method %q", req.Method)
			}
			writeRPCResult(conn, req.ID, HelloResult{
				Generation: 1,
				Version:    "0.1.20",
				Core:       CoreInfo{ID: "core-1", Name: "host"},
				Methods:    requiredRPCMethods,
			})
		})
		client, err := NewRPCClient(sock, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Hello(context.Background())
		if err != nil {
			t.Fatalf("Hello(): %v", err)
		}
		if res.Generation != 1 || res.Version != "0.1.20" {
			t.Fatalf("Hello() = %+v", res)
		}
	})

	for _, gen := range []uint32{0, 2, 99} {
		t.Run("rejects unsupported generation", func(t *testing.T) {
			sock := startFakeRPCSocket(t, func(req rpcRequest, conn net.Conn) {
				writeRPCResult(conn, req.ID, HelloResult{
					Generation: gen,
					Version:    "0.1.20",
					Methods:    requiredRPCMethods,
				})
			})
			client, err := NewRPCClient(sock, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Hello(context.Background())
			var handshakeErr *ProtocolHandshakeError
			if !errors.As(err, &handshakeErr) {
				t.Fatalf("Hello(gen=%d) err = %v, want *ProtocolHandshakeError", gen, err)
			}
		})
	}

	t.Run("rejects missing required method", func(t *testing.T) {
		partial := make([]string, 0, len(requiredRPCMethods)-1)
		for _, m := range requiredRPCMethods {
			if m != "terminal.wait" {
				partial = append(partial, m)
			}
		}
		sock := startFakeRPCSocket(t, func(req rpcRequest, conn net.Conn) {
			writeRPCResult(conn, req.ID, HelloResult{
				Generation: 1,
				Version:    "0.1.20",
				Methods:    partial,
			})
		})
		client, err := NewRPCClient(sock, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Hello(context.Background())
		var handshakeErr *ProtocolHandshakeError
		if !errors.As(err, &handshakeErr) || !strings.Contains(handshakeErr.Reason, "terminal.wait") {
			t.Fatalf("Hello(missing method) err = %v, want missing terminal.wait handshake error", err)
		}
	})

	t.Run("typed RPC error kind", func(t *testing.T) {
		sock := startFakeRPCSocket(t, func(req rpcRequest, conn net.Conn) {
			writeRPCError(conn, req.ID, -32000, "blocked", "blocked", "needs approval")
		})
		client, err := NewRPCClient(sock, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.TerminalSend(context.Background(), SendParams{Terminal: "t1", Text: "hi"})
		if !IsRPCErrorKind(err, "blocked") {
			t.Fatalf("TerminalSend err = %v, want kind=blocked", err)
		}
	})

	t.Run("response id mismatch rejected", func(t *testing.T) {
		sock := startFakeRPCSocket(t, func(req rpcRequest, conn net.Conn) {
			writeRPCResult(conn, req.ID+99, StopResult{Stopped: true})
		})
		client, err := NewRPCClient(sock, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.ServerStop(context.Background()); err == nil {
			t.Fatal("expected error for mismatched response id")
		}
	})

	t.Run("context cancellation unblocks blocked call immediately", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		sock := startFakeRPCSocket(t, func(req rpcRequest, conn net.Conn) {
			<-release
		})
		client, err := NewRPCClient(sock, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(40 * time.Millisecond)
			cancel()
		}()
		start := time.Now()
		_, err = client.TerminalWait(ctx, WaitParams{Terminal: "t1"})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked call err = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("cancellation took too long: %v", elapsed)
		}
	})

	t.Run("oversized response exceeding maxBytes+1 reports limit error instead of EOF", func(t *testing.T) {
		const limit = 1024
		oversized := strings.Repeat("x", limit+1024) + "\n"
		_, err := readBoundedLine(strings.NewReader(oversized), limit)
		if err == nil || !strings.Contains(err.Error(), "exceeds") || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("readBoundedLine(oversized) err = %v, want response exceeds limit error", err)
		}

		// Also verify end-to-end through RPCClient with a >8 MiB payload.
		sock := startFakeRPCSocket(t, func(_ rpcRequest, conn net.Conn) {
			chunk := make([]byte, 64*1024)
			for i := range chunk {
				chunk[i] = 'a'
			}
			for written := 0; written < maxRPCResponseBytes+1024; written += len(chunk) {
				if _, wErr := conn.Write(chunk); wErr != nil {
					return
				}
			}
			_, _ = conn.Write([]byte{'\n'})
		})
		client, err := NewRPCClient(sock, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.ServerStatus(context.Background())
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("RPCClient oversized response err = %v, want response exceeds limit error", err)
		}
	})
}
