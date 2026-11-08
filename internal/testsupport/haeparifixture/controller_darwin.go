//go:build darwin && arm64

// Package haeparifixture provides an isolated advisory-lock controller for
// tests. It exercises the real Unix transport without using a host Installation.
package haeparifixture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type request struct {
	current  map[string]any
	original map[string]any
	payload  []byte
}

type Controller struct {
	Home        string
	mu          sync.Mutex
	requests    []*request
	active      *request
	changed     chan struct{}
	events      []string
	releaseGate chan struct{}
}

func New(t *testing.T) *Controller {
	t.Helper()
	home, err := os.MkdirTemp("/private/tmp", "mh77-")
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(home); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(home, "control.sock")
	if len(socket) > 103 {
		t.Fatal("fixture socket exceeds native bound")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	controller := &Controller{Home: home, changed: make(chan struct{})}
	server := &http.Server{Handler: controller, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close(); <-done })
	return controller
}

func (controller *Controller) Events() []string {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return append([]string(nil), controller.events...)
}

// PauseNextRelease retains the first grant until the test admits disposition.
func (controller *Controller) PauseNextRelease() func() {
	controller.mu.Lock()
	gate := make(chan struct{})
	controller.releaseGate = gate
	controller.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(gate) }) }
}

func (controller *Controller) WaitFor(ctx context.Context, prefix string) error {
	for {
		controller.mu.Lock()
		for _, event := range controller.events {
			if strings.HasPrefix(event, prefix) {
				controller.mu.Unlock()
				return nil
			}
		}
		changed := controller.changed
		controller.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (controller *Controller) event(value string) {
	controller.events = append(controller.events, value)
	close(controller.changed)
	controller.changed = make(chan struct{})
}

func envelope(writer http.ResponseWriter, operation string, data any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"schema": "haepari.envelope/v1", "operation": operation, "ok": true, "data": data})
}
func failure(writer http.ResponseWriter, operation, code string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(writer).Encode(map[string]any{"schema": "haepari.envelope/v1", "operation": operation, "ok": false, "error": map[string]any{"code": code, "message": "isolated fixture refusal", "retry": "none"}})
}
func receipt(req *request, operation string) map[string]any {
	value := map[string]any{"operation": operation, "request_id": req.current["request_id"], "state": req.current["state"], "recorded_at": time.Now().UTC()}
	if grant, ok := req.current["grant_id"]; ok {
		value["grant_id"] = grant
	}
	return value
}
func (controller *Controller) grant(req *request) {
	now := time.Now().UTC()
	req.current["state"], req.current["slot"] = "granted", 0
	req.current["grant_id"], req.current["generation"] = fmt.Sprintf("grant-%d", req.current["sequence"]), req.current["sequence"]
	req.current["granted_at"], req.current["liveness_deadline"], req.current["max_hold_deadline"] = now, now.Add(time.Minute), now.Add(24*time.Hour)
	req.current["liveness_seconds"], req.current["max_hold_seconds"] = 60, 86400
	controller.active = req
	controller.event("granted:" + req.current["request_id"].(string))
}
func (controller *Controller) firstQueued() *request {
	for _, req := range controller.requests {
		if req.current["state"] == "queued" {
			return req
		}
	}
	return nil
}

func (controller *Controller) ServeHTTP(writer http.ResponseWriter, incoming *http.Request) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if incoming.URL.Path == "/v1/hello" {
		envelope(writer, "hello", map[string]any{"protocol": "managed-execution/v1", "protocol_version": 1, "installation_id": "fixture-installation", "capabilities": []string{"managed-execution/v1", "advisory-lock/v1"}})
		return
	}
	if incoming.URL.Path == "/v1/resources/mulgae-review" {
		envelope(writer, "resource.inspect", map[string]any{"resource_id": "mulgae-review", "kind": "lock", "configuration_digest": strings.Repeat("a", 64), "config_revision": 1, "availability_revision": 1, "availability": "available", "capacity": 1})
		return
	}
	if incoming.Method == http.MethodPost && incoming.URL.Path == "/v1/locks/acquire" {
		var payload struct {
			LockID string `json:"lock_id"`
			Key    string `json:"request_key"`
			Holder string `json:"holder"`
		}
		var raw json.RawMessage
		if err := json.NewDecoder(incoming.Body).Decode(&raw); err != nil {
			failure(writer, "lock.acquire", "INVALID_REQUEST")
			return
		}
		if err := json.Unmarshal(raw, &payload); err != nil || payload.LockID != "mulgae-review" {
			failure(writer, "lock.acquire", "INVALID_REQUEST")
			return
		}
		for _, req := range controller.requests {
			if req.current["request_key"] == payload.Key {
				if !bytes.Equal(raw, req.payload) {
					failure(writer, "lock.acquire", "CONFLICT")
					return
				}
				envelope(writer, "lock.acquire", map[string]any{"receipt": req.original, "current": req.current})
				return
			}
		}
		sequence := len(controller.requests) + 1
		req := &request{payload: append([]byte(nil), raw...), current: map[string]any{"installation_id": "fixture-installation", "lock_id": "mulgae-review", "request_id": fmt.Sprintf("request-%d", sequence), "request_key": payload.Key, "holder": payload.Holder, "state": "queued", "sequence": sequence, "slot": -1, "queued_at": time.Now().UTC()}}
		controller.requests = append(controller.requests, req)
		controller.event("acquire:" + req.current["request_id"].(string))
		if controller.active == nil {
			controller.grant(req)
		} else {
			controller.event("queued:" + req.current["request_id"].(string))
		}
		req.original = receipt(req, "acquire")
		envelope(writer, "lock.acquire", map[string]any{"receipt": req.original, "current": req.current})
		return
	}
	parts := strings.Split(strings.Trim(incoming.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "v1" || parts[1] != "locks" {
		http.NotFound(writer, incoming)
		return
	}
	id, action := parts[3], parts[4]
	operation := "lock." + action
	var req *request
	for _, candidate := range controller.requests {
		if parts[2] == "requests" && candidate.current["request_id"] == id || parts[2] == "grants" && candidate.current["grant_id"] == id {
			req = candidate
			break
		}
	}
	if req == nil {
		failure(writer, operation, "NOT_FOUND")
		return
	}
	switch action {
	case "wait":
		controller.event("wait:" + id)
		timeout := time.NewTimer(15 * time.Second)
		defer timeout.Stop()
		for req.current["state"] == "queued" {
			if controller.active == nil && controller.firstQueued() == req {
				controller.grant(req)
				break
			}
			changed := controller.changed
			controller.mu.Unlock()
			select {
			case <-incoming.Context().Done():
				controller.mu.Lock()
				return
			case <-timeout.C:
				controller.mu.Lock()
				failure(writer, operation, "WAIT_TIMEOUT")
				return
			case <-changed:
				controller.mu.Lock()
			}
		}
		kind := "claim"
		if req.current["state"] == "released" {
			kind = "release"
		} else if req.current["state"] == "cancelled" {
			kind = "cancel"
		}
		envelope(writer, operation, map[string]any{"receipt": receipt(req, kind), "current": req.current})
	case "renew":
		if req.current["state"] != "granted" {
			failure(writer, operation, "CONFLICT")
			return
		}
		req.current["liveness_deadline"] = time.Now().UTC().Add(time.Minute)
		controller.event("renew:" + id)
		envelope(writer, operation, map[string]any{"receipt": receipt(req, "renew"), "current": req.current})
	case "release", "cancel":
		if action == "release" && controller.releaseGate != nil {
			gate := controller.releaseGate
			controller.releaseGate = nil
			controller.event("release_pending:" + id)
			controller.mu.Unlock()
			select {
			case <-gate:
			case <-incoming.Context().Done():
				controller.mu.Lock()
				return
			}
			controller.mu.Lock()
		}
		state := req.current["state"]
		if state == "queued" {
			req.current["state"] = "cancelled"
		} else if state == "granted" {
			req.current["state"] = "released"
		}
		req.current["ended_at"] = time.Now().UTC()
		if controller.active == req {
			controller.active = nil
		}
		controller.event(action + ":" + id)
		envelope(writer, operation, map[string]any{"receipt": receipt(req, action), "current": req.current})
	default:
		http.NotFound(writer, incoming)
	}
}
