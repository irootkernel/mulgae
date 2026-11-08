//go:build darwin && arm64

// Package haeparifixture provides an isolated advisory-lock controller for
// tests. It exercises the real Unix transport without using a host Installation.
package haeparifixture

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

type request struct {
	current  map[string]any
	original map[string]any
	payload  []byte
}

type fixtureListCursor struct {
	Kind         string `json:"kind"`
	Installation string `json:"installation"`
	Resource     string `json:"resource"`
	State        string `json:"state,omitempty"`
	Last         int64  `json:"last,omitempty"`
	Upper        int64  `json:"upper,omitempty"`
	LastID       string `json:"last_id,omitempty"`
	UpperID      string `json:"upper_id,omitempty"`
}

type Controller struct {
	Home            string
	mu              sync.Mutex
	requests        []*request
	active          *request
	changed         chan struct{}
	events          []string
	releaseGate     chan struct{}
	livenessSeconds int64
	maxHoldSeconds  int64
	failNextRenew   string
	dropNextAcquire bool

	serverMu   sync.Mutex
	server     *http.Server
	listener   net.Listener
	serverDone chan struct{}
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
	controller := &Controller{Home: home, changed: make(chan struct{})}
	controller.bind(t, false)
	t.Cleanup(func() { controller.Disconnect() })
	return controller
}

func (controller *Controller) bind(t *testing.T, isRestart bool) {
	t.Helper()
	controller.serverMu.Lock()
	defer controller.serverMu.Unlock()
	if controller.server != nil {
		_ = controller.server.Close()
		_ = controller.listener.Close()
		<-controller.serverDone
		controller.server = nil
		controller.listener = nil
		controller.serverDone = nil
	}
	socket := filepath.Join(controller.Home, "control.sock")
	if len(socket) > 103 {
		t.Fatal("fixture socket exceeds native bound")
	}
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	server := &http.Server{Handler: controller, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	controller.server = server
	controller.listener = listener
	controller.serverDone = done
	go func() { defer close(done); _ = server.Serve(listener) }()
	if isRestart {
		controller.mu.Lock()
		controller.event("restart")
		controller.mu.Unlock()
	}
}

// Disconnect stops the Unix socket server while preserving persisted controller state.
func (controller *Controller) Disconnect() {
	controller.serverMu.Lock()
	server := controller.server
	listener := controller.listener
	done := controller.serverDone
	controller.server = nil
	controller.listener = nil
	controller.serverDone = nil
	controller.serverMu.Unlock()
	if server != nil {
		_ = server.Close()
		_ = listener.Close()
		<-done
		_ = os.Remove(filepath.Join(controller.Home, "control.sock"))
		controller.mu.Lock()
		controller.event("disconnect")
		controller.mu.Unlock()
	}
}

// Restart rebinds the Unix socket on the same Home while preserving InstallationID and persisted lock rows.
func (controller *Controller) Restart(t *testing.T) {
	t.Helper()
	controller.bind(t, true)
}

// DropNextAcquireResponse records the next new Acquire on the controller and drops the connection before writing the HTTP response.
func (controller *Controller) DropNextAcquireResponse() {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.dropNextAcquire = true
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

func (controller *Controller) SetLeaseSeconds(livenessSeconds, maxHoldSeconds int64) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.livenessSeconds = livenessSeconds
	controller.maxHoldSeconds = maxHoldSeconds
}

func (controller *Controller) FailNextRenew(code string) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.failNextRenew = code
}

func (controller *Controller) ExpireActiveGrant() {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.active == nil {
		return
	}
	now := time.Now().UTC()
	controller.active.current["state"] = "hold_expired"
	controller.active.current["ended_at"] = now
	controller.event("expired:" + controller.active.current["grant_id"].(string))
	controller.active = nil
}

func (controller *Controller) ActiveGrantJSON() string {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.active == nil {
		return ""
	}
	raw, _ := json.Marshal(map[string]any{
		"installation_id": controller.active.current["installation_id"],
		"lock_id":         controller.active.current["lock_id"],
		"grant_id":        controller.active.current["grant_id"],
		"generation":      controller.active.current["generation"],
	})
	return string(raw)
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
	livenessSec := controller.livenessSeconds
	if livenessSec <= 0 {
		livenessSec = 60
	}
	maxHoldSec := controller.maxHoldSeconds
	if maxHoldSec <= 0 {
		maxHoldSec = 86400
	}
	req.current["state"], req.current["slot"] = "granted", 0
	req.current["grant_id"], req.current["generation"] = fmt.Sprintf("grant-%d", req.current["sequence"]), req.current["sequence"]
	req.current["granted_at"] = now
	req.current["liveness_deadline"] = now.Add(time.Duration(livenessSec) * time.Second)
	req.current["max_hold_deadline"] = now.Add(time.Duration(maxHoldSec) * time.Second)
	req.current["liveness_seconds"], req.current["max_hold_seconds"] = livenessSec, maxHoldSec
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

func (controller *Controller) checkBorrowedHeader(writer http.ResponseWriter, incoming *http.Request, operation string) bool {
	if len(incoming.Header.Values("X-Haepari-Lock-Grant")) == 0 {
		return false
	}
	rawGrant := incoming.Header.Get("X-Haepari-Lock-Grant")
	ref, err := ports.DecodeReviewBorrowedGrantReference(rawGrant)
	if err != nil {
		failure(writer, operation, "INVALID_REQUEST")
		return true
	}
	if ref.InstallationID != "fixture-installation" || ref.LockID != "mulgae-review" {
		failure(writer, operation, "CONFLICT")
		return true
	}
	var target *request
	for _, candidate := range controller.requests {
		if candidate.current["grant_id"] == ref.GrantID {
			target = candidate
			break
		}
	}
	if target == nil {
		failure(writer, operation, "NOT_FOUND")
		return true
	}
	now := time.Now().UTC()
	gen, _ := target.current["generation"].(int)
	gen64 := int64(gen)
	if v, ok := target.current["generation"].(int64); ok {
		gen64 = v
	}
	live, _ := target.current["liveness_deadline"].(time.Time)
	maxHold, _ := target.current["max_hold_deadline"].(time.Time)
	if gen64 != ref.Generation || target.current["state"] != "granted" || !now.Before(live) || !now.Before(maxHold) {
		failure(writer, operation, "LOCK_EXPIRED")
		return true
	}
	failure(writer, operation, "CONFLICT")
	return true
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
	if incoming.Method == http.MethodGet && incoming.URL.Path == "/v1/locks" {
		lockFilter := incoming.URL.Query().Get("lock")
		if lockFilter != "" && !ports.ValidHaepariIdentifier(lockFilter) {
			failure(writer, "locks.list", "INVALID_REQUEST")
			return
		}
		limit := 100
		if rawLimit := incoming.URL.Query().Get("limit"); rawLimit != "" {
			parsed, err := strconv.Atoi(rawLimit)
			if err != nil || parsed < 1 || parsed > 100 {
				failure(writer, "locks.list", "INVALID_REQUEST")
				return
			}
			limit = parsed
		}
		var cursorLast, cursorUpper int64
		if rawCursor := incoming.URL.Query().Get("cursor"); rawCursor != "" {
			decoded, err := base64.RawURLEncoding.DecodeString(rawCursor)
			if err != nil {
				failure(writer, "locks.list", "INVALID_REQUEST")
				return
			}
			var parsed fixtureListCursor
			if err := json.Unmarshal(decoded, &parsed); err != nil || parsed.Kind != "locks" || parsed.Installation != "fixture-installation" || parsed.Resource != "mulgae-review" || parsed.State != "" || parsed.LastID != "" || parsed.UpperID != "" || parsed.Last <= 0 || parsed.Upper < parsed.Last {
				failure(writer, "locks.list", "INVALID_REQUEST")
				return
			}
			cursorLast = parsed.Last
			cursorUpper = parsed.Upper
		}
		matching := make([]map[string]any, 0, len(controller.requests))
		var matchingSeqs []int64
		for _, candidate := range controller.requests {
			if lockFilter != "" && candidate.current["lock_id"] != lockFilter {
				continue
			}
			seqInt, _ := candidate.current["sequence"].(int)
			seq := int64(seqInt)
			if seq <= cursorLast {
				continue
			}
			if cursorUpper > 0 && seq > cursorUpper {
				continue
			}
			matching = append(matching, candidate.current)
			matchingSeqs = append(matchingSeqs, seq)
		}
		more := false
		nextCursor := ""
		if len(matching) > limit {
			more = true
			upper := cursorUpper
			if upper == 0 {
				upper = matchingSeqs[len(matchingSeqs)-1]
			}
			rawCursorBytes, _ := json.Marshal(fixtureListCursor{
				Kind:         "locks",
				Installation: "fixture-installation",
				Resource:     "mulgae-review",
				Last:         matchingSeqs[limit-1],
				Upper:        upper,
			})
			nextCursor = base64.RawURLEncoding.EncodeToString(rawCursorBytes)
			matching = matching[:limit]
		}
		controller.event("list")
		data := map[string]any{
			"installation_id": "fixture-installation",
			"now":             time.Now().UTC(),
			"requests":        matching,
			"more":            more,
		}
		if more {
			data["next_cursor"] = nextCursor
		}
		envelope(writer, "locks.list", data)
		return
	}
	if incoming.Method == http.MethodPost && incoming.URL.Path == "/v1/locks/acquire" {
		if controller.checkBorrowedHeader(writer, incoming, "lock.acquire") {
			return
		}
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
				controller.event("replay:" + req.current["request_id"].(string))
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
		if controller.dropNextAcquire {
			controller.dropNextAcquire = false
			controller.event("dropped_acquire:" + req.current["request_id"].(string))
			if hj, ok := writer.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
		}
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
	if controller.checkBorrowedHeader(writer, incoming, operation) {
		return
	}
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
		switch req.current["state"] {
		case "released":
			kind = "release"
		case "cancelled":
			kind = "cancel"
		case "hold_expired", "queue_expired":
			kind = "expire"
		}
		envelope(writer, operation, map[string]any{"receipt": receipt(req, kind), "current": req.current})
	case "renew":
		if code := controller.failNextRenew; code != "" {
			controller.failNextRenew = ""
			failure(writer, operation, code)
			return
		}
		if req.current["state"] != "granted" {
			code := "LOCK_EXPIRED"
			if req.current["state"] == "queued" {
				code = "CONFLICT"
			}
			failure(writer, operation, code)
			return
		}
		livenessSec, _ := req.current["liveness_seconds"].(int64)
		if livenessSec <= 0 {
			livenessSec = 60
		}
		req.current["liveness_deadline"] = time.Now().UTC().Add(time.Duration(livenessSec) * time.Second)
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
			req.current["ended_at"] = time.Now().UTC()
		} else if state == "granted" {
			req.current["state"] = "released"
			req.current["ended_at"] = time.Now().UTC()
		}
		if controller.active == req {
			controller.active = nil
		}
		kind := action
		switch req.current["state"] {
		case "released":
			kind = "release"
		case "cancelled":
			kind = "cancel"
		case "hold_expired", "queue_expired":
			kind = "expire"
		}
		controller.event(action + ":" + id)
		envelope(writer, operation, map[string]any{"receipt": receipt(req, kind), "current": req.current})
	default:
		http.NotFound(writer, incoming)
	}
}
