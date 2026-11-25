//go:build darwin && arm64 && vm_qualification

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// vmNativeResponseLoss drops one actual native admission reply. The forwarder
// supplies no controller state or receipts: the released SQLite controller owns
// every response, and the original MCP invocation must recover its saved request.
func vmNativeResponseLoss(t *testing.T, parent context.Context, root, haepari, binary, work string, environment []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	base := filepath.Join(work, "response-loss")
	for _, name := range []string{"project", "providers", "proxy"} {
		if err := os.MkdirAll(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	project, providers := filepath.Join(base, "project"), filepath.Join(base, "providers")
	logPath := filepath.Join(base, "provider.jsonl")
	mustWriteTestFile(t, logPath, nil)
	bundle, node, launcher := fakeZCodeAppPaths(providers)
	buildFakeZCode(t, root, node, launcher, logPath, "success")
	environment = vmZCodeToolsEnvironment(environment, node, launcher)
	initializeReviewGitRepository(t, project)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic", bundle)
	var realHome string
	for _, item := range environment {
		if value, ok := strings.CutPrefix(item, "HAEPARI_HOME="); ok {
			realHome = value
		}
	}
	if !filepath.IsAbs(realHome) {
		t.Fatal("response-loss case omitted the actual isolated controller home")
	}
	proxyHome := filepath.Join(base, "proxy")
	listener, err := net.Listen("unix", filepath.Join(proxyHome, "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(proxyHome, "control.sock"), 0600); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(realHome, "control.sock"))
	}}
	defer transport.CloseIdleConnections()
	forward := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	var mu sync.Mutex
	var acquisitions [][]byte
	var admission json.RawMessage
	errors := make(chan string, 1)
	fail := func(message string) {
		select {
		case errors <- message:
		default:
		}
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 {
			fail("could not read bounded native command")
			http.Error(w, "fault fixture request unavailable", 500)
			return
		}
		isAcquire := r.Method == http.MethodPost && r.URL.Path == "/v1/locks/acquire"
		first := false
		if isAcquire {
			mu.Lock()
			first = len(acquisitions) == 0
			acquisitions = append(acquisitions, append([]byte(nil), body...))
			mu.Unlock()
		}
		request, err := http.NewRequestWithContext(r.Context(), r.Method, "http://haepari"+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			fail(err.Error())
			return
		}
		request.Header = r.Header.Clone()
		reply, err := forward.Do(request)
		if err != nil {
			fail("actual native controller transport failed")
			http.Error(w, "native transport unavailable", 502)
			return
		}
		defer reply.Body.Close()
		data, err := io.ReadAll(reply.Body)
		if err != nil {
			fail("actual native reply unavailable")
			return
		}
		if first {
			var envelope struct {
				OK bool `json:"ok"`
			}
			if json.Unmarshal(data, &envelope) != nil || !envelope.OK {
				fail("first native acquisition was not admitted")
			} else {
				mu.Lock()
				admission = append(json.RawMessage(nil), data...)
				mu.Unlock()
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					fail("could not drop admitted native response")
					return
				}
				_ = connection.Close()
				return
			}
		}
		for name, values := range reply.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(reply.StatusCode)
		_, _ = w.Write(data)
	})}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); _ = server.Serve(listener) }()
	defer func() { _ = server.Close(); <-serverDone }()
	holder := vmHaepari(t, haepari, work, environment, "lock", "acquire", "mulgae-review",
		"--request-key", "response-loss-holder", "--holder", "response-loss-fixture", "--json")["current"].(map[string]any)
	if holder["state"] != "granted" {
		t.Fatal("response-loss fixture holder was not granted")
	}
	released := false
	defer func() {
		if !released {
			vmHaepari(t, haepari, work, environment, "lock", "release", holder["grant_id"].(string), "--json")
		}
	}()
	t.Run("response_loss_reconciliation", func(t *testing.T) {
		client := startCoordinationMCP(t, ctx, binary, project, withHaepariHome(environment, proxyHome))
		started, err := client.tool("start_review", map[string]any{"target": map[string]any{"kind": "head"}, "roles": []string{"logic"}})
		if err != nil || started["outcome"] != "success" {
			t.Fatalf("response-loss start_review: %v / %v", started, err)
		}
		invocation := started["data"].(map[string]any)["invocation_id"].(string)
		vmWaitFor(t, ctx, func() bool {
			select {
			case message := <-errors:
				t.Fatal(message)
			default:
			}
			mu.Lock()
			defer mu.Unlock()
			return len(acquisitions) >= 2 && len(admission) != 0
		}, "same native acquisition after lost admission response")
		mu.Lock()
		requests := append([][]byte(nil), acquisitions...)
		originalAdmission := append(json.RawMessage(nil), admission...)
		mu.Unlock()
		for _, request := range requests[1:] {
			if !bytes.Equal(requests[0], request) {
				t.Fatal("native response loss changed saved acquisition key or payload")
			}
		}
		result, err := client.tool("await_review", map[string]any{"invocation_id": invocation})
		encodedResult, _ := json.Marshal(result)
		if err != nil || result["outcome"] != "error" || !bytes.Contains(encodedResult, []byte("haepari_protection_lost")) {
			t.Fatalf("uncertain admission must reconcile and refuse provider dispatch: %v / %v", result, err)
		}
		var firstReply struct {
			Data struct {
				Current map[string]any `json:"current"`
			} `json:"data"`
		}
		if err := json.Unmarshal(originalAdmission, &firstReply); err != nil || firstReply.Data.Current["state"] != "queued" {
			t.Fatal("lost native reply did not record an actual queued admission")
		}
		queued := firstReply.Data.Current
		locks := vmHaepari(t, haepari, work, environment, "locks", "list", "--lock", "mulgae-review", "--json")
		count := 0
		for _, value := range locks["requests"].([]any) {
			row := value.(map[string]any)
			if row["request_key"] == queued["request_key"] {
				count++
				if row["request_id"] != queued["request_id"] || row["sequence"] != queued["sequence"] || row["state"] != "cancelled" {
					t.Fatal("original invocation did not settle its sole native acquisition")
				}
			}
		}
		if count != 1 || len(fakeZCodeReviewObservations(t, logPath)) != 0 {
			t.Fatal("native response loss duplicated acquisition or provider dispatch")
		}
		vmHaepari(t, haepari, work, environment, "lock", "release", holder["grant_id"].(string), "--json")
		released = true
		vmWriteJSON(t, filepath.Join(work, "response-loss-result.json"), map[string]any{
			"invocation_id": invocation, "actual_dropped_native_reply": originalAdmission,
			"acquisition_call_count": len(requests), "canonical_acquisition": json.RawMessage(requests[0]),
			"original_queue": queued, "native_request_count": count, "provider_dispatch_count": 0,
			"reconciled_terminal_state": "cancelled", "original_invocation_result": result,
			"limits": "One response-loss forwarder around the actual released native controller; no fabricated controller replies.",
		})
	})
}
