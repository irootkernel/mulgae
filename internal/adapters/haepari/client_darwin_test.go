//go:build darwin && arm64

package haepari_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/haepari"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type socketFixture struct {
	home       string
	socketPath string
	listener   net.Listener
	server     *http.Server
}

func TestClientRefusesInheritedGrantBeforeControllerAccess(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	validGrant := `{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":1}`
	fixture := newShortSocketFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("X-Haepari-Lock-Grant"); got != validGrant {
			t.Errorf("X-Haepari-Lock-Grant = %q, want %q", got, validGrant)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/hello":
			_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"hello","ok":true,"data":{"protocol":"managed-execution/v1","protocol_version":1,"installation_id":"inst-01","capabilities":["managed-execution/v1","advisory-lock/v1"]}}`)
		case "/v1/resources/mulgae-review":
			_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"resource.inspect","ok":true,"data":{"resource_id":"mulgae-review","kind":"lock","configuration_digest":"`+strings.Repeat("a", 64)+`","config_revision":1,"availability_revision":1,"availability":"available","capacity":1,"occupancy":1,"advisory_grants":1,"advisory_queued":0,"lease_generation":1}}`)
		case "/v1/locks":
			_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"locks.list","ok":true,"data":{"installation_id":"inst-01","now":"2026-11-08T05:00:10Z","requests":[],"more":false}}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	for _, value := range []string{
		"",
		" \t",
		"{}",
		"null",
		strings.Repeat(" ", ports.HaepariMaxParentContextBytes+1),
		`{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":0}`,
		`{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":null}`,
		`{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":1,"extra":true}`,
		`{"Installation_ID":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":1}`,
	} {
		for _, home := range []string{"", fixture.home} {
			client := haepari.NewClient(haepari.Config{RawHome: home, HasLockGrant: true, RawLockGrant: value})
			_, err := client.Hello(context.Background())
			var coordination *ports.ReviewCoordinationError
			if !errors.As(err, &coordination) || coordination.Reason != ports.ReviewCoordinationReasonParentContextInvalid || coordination.Retry != ports.ReviewCoordinationRetryNever || coordination.Uncertain {
				t.Fatalf("present malformed reference %q: expected zero-effect parent refusal, got %v", value, err)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("malformed inherited grant refusal contacted controller %d times", calls.Load())
	}

	borrowedClient := haepari.NewClient(haepari.Config{RawHome: fixture.home, HasLockGrant: true, RawLockGrant: validGrant})
	for _, op := range []func() error{
		func() error {
			_, err := borrowedClient.Acquire(context.Background(), []byte(`{"lock_id":"mulgae-review","request_key":"mulgae-r_1","holder":"h"}`))
			return err
		},
		func() error { _, err := borrowedClient.Wait(context.Background(), "lreq_01", time.Second); return err },
		func() error { _, err := borrowedClient.Renew(context.Background(), "lgrant_01"); return err },
		func() error { _, err := borrowedClient.Release(context.Background(), "lgrant_01"); return err },
		func() error { _, err := borrowedClient.Cancel(context.Background(), "lreq_01"); return err },
	} {
		err := op()
		var coordination *ports.ReviewCoordinationError
		if !errors.As(err, &coordination) || coordination.Reason != ports.ReviewCoordinationReasonLockStateConflict || coordination.Uncertain {
			t.Fatalf("expected mutating operation refused locally on borrowed client, got %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("mutating operation on borrowed client contacted controller %d times", calls.Load())
	}

	if _, err := borrowedClient.Hello(context.Background()); err != nil {
		t.Fatalf("borrowed Hello: %v", err)
	}
	if _, err := borrowedClient.InspectResource(context.Background(), ports.HaepariReviewResourceID); err != nil {
		t.Fatalf("borrowed InspectResource: %v", err)
	}
	if _, err := borrowedClient.ListLocks(context.Background(), ports.HaepariReviewResourceID, "", 100); err != nil {
		t.Fatalf("borrowed ListLocks: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 read-only borrowed calls, got %d", calls.Load())
	}

	// Valid multiline JSON must remain usable as native header context.
	prettyGrant := strings.ReplaceAll(validGrant, ",", ",\n  ")
	prettyClient := haepari.NewClient(haepari.Config{RawHome: fixture.home, HasLockGrant: true, RawLockGrant: prettyGrant})
	if _, err := prettyClient.Hello(context.Background()); err != nil {
		t.Fatalf("borrowed multiline JSON Hello: %v", err)
	}
	if calls.Load() != 4 {
		t.Fatalf("expected multiline reference to reach read-only controller, got %d calls", calls.Load())
	}

	// Absence remains different from a present empty value.
	if _, err := haepari.NewClient(haepari.Config{}).Hello(context.Background()); !hasReason(err, ports.ReviewCoordinationReasonInstallationNotSelected) {
		t.Fatalf("absent grant changed normal Installation admission: %v", err)
	}
}

func newShortSocketFixture(t *testing.T, handler http.Handler) *socketFixture {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "mh76-")
	if err != nil {
		t.Fatalf("MkdirTemp(/private/tmp): %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(dir): %v", err)
	}
	socketPath := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen(unix, %s): %v", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		t.Fatalf("Chmod(control.sock): %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return &socketFixture{
		home:       dir,
		socketPath: socketPath,
		listener:   ln,
		server:     srv,
	}
}

func assertProtocolHeaders(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("X-Haepari-Protocol"); got != "managed-execution/v1" {
		t.Errorf("X-Haepari-Protocol = %q, want managed-execution/v1", got)
	}
	if got := r.Header.Get("X-Haepari-Protocol-Min"); got != "1" {
		t.Errorf("X-Haepari-Protocol-Min = %q, want 1", got)
	}
	if got := r.Header.Get("X-Haepari-Protocol-Max"); got != "1" {
		t.Errorf("X-Haepari-Protocol-Max = %q, want 1", got)
	}
}

func TestResolveStateRootAndParentContextValidation(t *testing.T) {
	t.Parallel()

	// Unset HAEPARI_HOME must fail with haepari_installation_not_selected.
	if _, err := haepari.ResolveStateRoot(""); !hasReason(err, ports.ReviewCoordinationReasonInstallationNotSelected) {
		t.Fatalf("expected installation_not_selected for empty HAEPARI_HOME, got %v", err)
	}
	if _, err := haepari.ResolveStateRoot("relative/path"); !hasReason(err, ports.ReviewCoordinationReasonControllerUnreachable) {
		t.Fatalf("expected controller_unreachable for relative HAEPARI_HOME, got %v", err)
	}

	fix := newShortSocketFixture(t, http.NewServeMux())
	root, err := haepari.ResolveStateRoot(fix.home)
	if err != nil {
		t.Fatalf("ResolveStateRoot(valid): %v", err)
	}
	if root.SocketPath != fix.socketPath {
		t.Fatalf("SocketPath = %q, want %q", root.SocketPath, fix.socketPath)
	}

	// /tmp prefix symlink normalization must resolve cleanly to /private/tmp.
	tmpSpelling := "/tmp/" + filepath.Base(fix.home)
	if resolved, err := haepari.ResolveStateRoot(tmpSpelling); err != nil || resolved.Home != fix.home {
		t.Fatalf("ResolveStateRoot(%q) = %+v, %v", tmpSpelling, resolved, err)
	}

	// Overlong socket path (>= 104 bytes) must fail closed.
	longDir := filepath.Join(fix.home, strings.Repeat("a", 95))
	if err := os.MkdirAll(longDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := haepari.ResolveStateRoot(longDir); !hasReason(err, ports.ReviewCoordinationReasonControllerUnreachable) {
		t.Fatalf("expected overlong socket path rejected, got %v", err)
	}

	// Group-writable HAEPARI_HOME must be rejected.
	badDir, err := os.MkdirTemp("/private/tmp", "mh76-bad-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(badDir)
	_ = os.Chmod(badDir, 0o770)
	if _, err := haepari.ResolveStateRoot(badDir); !hasReason(err, ports.ReviewCoordinationReasonControllerUnreachable) {
		t.Fatalf("expected 0770 HAEPARI_HOME rejected, got %v", err)
	}

	// ValidateParentContext checks.
	for _, validRaw := range []string{
		"",
		"null",
		"[]",
		`[{"installation_id":"inst-01","job_id":"job-01","lease_generation":1,"nonce":"` + strings.Repeat("a", 64) + `"}]`,
	} {
		if _, err := haepari.ValidateParentContext(validRaw); err != nil {
			t.Fatalf("ValidateParentContext(%q) unexpected error: %v", validRaw, err)
		}
	}

	for _, invalidRaw := range []string{
		"   ",
		"\t\n",
		strings.Repeat(" ", 8193),
		`[{"installation_id":"inst-01","job_id":"job-01","lease_generation":1,"nonce":"not-64-hex"}]`,
		`[{"installation_id":"inst-01","job_id":"job-01","lease_generation":0,"nonce":"` + strings.Repeat("a", 64) + `"}]`,
		`[{"installation_id":"inst-01","job_id":"job-01","lease_generation":1,"nonce":"` + strings.Repeat("a", 64) + `","extra":1}]`,
		`[{"installation_id":"inst-01","job_id":"job-01","lease_generation":1,"nonce":"` + strings.Repeat("a", 64) + `"}] trailing`,
	} {
		if _, err := haepari.ValidateParentContext(invalidRaw); !hasReason(err, ports.ReviewCoordinationReasonParentContextInvalid) {
			t.Fatalf("expected parent_context_invalid for %q, got %v", invalidRaw, err)
		}
	}

	// Nonempty whitespace RawParentContext on Client must fail before dialing or transmitting Acquire.
	var acquireHits int
	wsMux := http.NewServeMux()
	wsMux.HandleFunc("POST /v1/locks/acquire", func(w http.ResponseWriter, r *http.Request) {
		acquireHits++
		w.WriteHeader(http.StatusOK)
	})
	wsFix := newShortSocketFixture(t, wsMux)
	wsClient := haepari.NewClient(haepari.Config{
		RawHome:          wsFix.home,
		RawParentContext: "   \t\n  ",
	})
	_, err = wsClient.Acquire(context.Background(), []byte(`{"lock_id":"mulgae-review","request_key":"mulgae-r_1","holder":"h"}`))
	var coordErr *ports.ReviewCoordinationError
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonParentContextInvalid || coordErr.Uncertain {
		t.Fatalf("expected parent_context_invalid (Uncertain=false) for whitespace RawParentContext, got %+v (%v)", coordErr, err)
	}
	if acquireHits != 0 {
		t.Fatalf("expected zero socket requests for whitespace RawParentContext, got %d", acquireHits)
	}
}

func TestClientHelloAndInspectResourceWireContract(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("b", 64)
	availability := "paused"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hello", func(w http.ResponseWriter, r *http.Request) {
		assertProtocolHeaders(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"hello","ok":true,"data":{"protocol":"managed-execution/v1","protocol_version":1,"installation_id":"local-0123456789abcdef","capabilities":["managed-execution/v1","advisory-lock/v1"]}}`)
	})
	mux.HandleFunc("GET /v1/resources/mulgae-review", func(w http.ResponseWriter, r *http.Request) {
		assertProtocolHeaders(t, r)
		w.Header().Set("Content-Type", "application/json")
		// Frozen Haepari v0.1.0 controller/resources.go emits operation "resource.inspect" and ResourceStatus has no installation_id field on the wire.
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"resource.inspect","ok":true,"data":{"advisory_grants":1,"advisory_queued":2,"resource_id":"mulgae-review","kind":"lock","configuration_digest":"`+digest+`","config_revision":3,"availability_revision":4,"availability":"`+availability+`","reason":"operator maintenance","capacity":1,"occupancy":1,"lease_generation":7}}`)
	})
	mux.HandleFunc("GET /v1/resources/missing-lock", func(w http.ResponseWriter, r *http.Request) {
		assertProtocolHeaders(t, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"resource.inspect","ok":false,"error":{"code":"NOT_FOUND","message":"resource missing-lock is not registered","retry":"none"}}`)
	})

	fix := newShortSocketFixture(t, mux)
	client := haepari.NewClient(haepari.Config{RawHome: fix.home})

	inst, err := client.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if inst.InstallationID != "local-0123456789abcdef" {
		t.Fatalf("unexpected InstallationID %q", inst.InstallationID)
	}

	res, err := client.InspectResource(context.Background(), ports.HaepariReviewResourceID)
	if err != nil {
		t.Fatalf("InspectResource(paused): %v", err)
	}
	if res.InstallationID != "local-0123456789abcdef" || res.Availability != "paused" || res.Capacity != 1 || res.AdvisoryGrants != 1 || res.AdvisoryQueued != 2 {
		t.Fatalf("unexpected resource projection: %+v", res)
	}

	_, err = client.InspectResource(context.Background(), "missing-lock")
	var coordErr *ports.ReviewCoordinationError
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonResourceInvalid || coordErr.NativeCode != "NOT_FOUND" || coordErr.Uncertain {
		t.Fatalf("expected NOT_FOUND under resource.inspect mapped to haepari_resource_invalid (Uncertain=false), got %+v (%v)", coordErr, err)
	}
}

func TestClientAcquireReplayAndTerminalOperationsWireContract(t *testing.T) {
	t.Parallel()

	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	payload, err := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	if err != nil {
		t.Fatal(err)
	}
	parentCtx := `[{"installation_id":"local-0123456789abcdef","job_id":"job-01","lease_generation":2,"nonce":"` + strings.Repeat("c", 64) + `"}]`

	var acquireCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/locks/acquire", func(w http.ResponseWriter, r *http.Request) {
		assertProtocolHeaders(t, r)
		if got := r.Header.Get("X-Haepari-Parent-Context"); got != parentCtx {
			t.Errorf("X-Haepari-Parent-Context = %q, want %q", got, parentCtx)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != string(payload.CanonicalJSON) {
			t.Errorf("acquire body = %s, want exact %s", body, payload.CanonicalJSON)
		}
		acquireCalls++
		w.Header().Set("Content-Type", "application/json")
		if acquireCalls == 1 {
			// Initial acquire is queued (slot -1, unprefixed operation "acquire").
			_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.acquire","ok":true,"data":{"receipt":{"operation":"acquire","request_id":"lreq_01","state":"queued","recorded_at":"2026-11-08T05:00:00Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"`+payload.RequestKey+`","holder":"`+payload.Holder+`","state":"queued","sequence":1,"slot":-1,"queued_at":"2026-11-08T05:00:00Z"}}}`)
			return
		}
		// Second acquire is an exact replay after the request was granted: receipt is STILL the original queued acquire_receipt while current is granted (slot 0)!
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.acquire","ok":true,"data":{"receipt":{"operation":"acquire","request_id":"lreq_01","state":"queued","recorded_at":"2026-11-08T05:00:00Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"`+payload.RequestKey+`","holder":"`+payload.Holder+`","state":"granted","sequence":1,"grant_id":"lgrant_01","generation":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z","granted_at":"2026-11-08T05:00:02Z","liveness_deadline":"2026-11-08T05:02:02Z","max_hold_deadline":"2026-11-08T06:00:02Z","liveness_seconds":120,"max_hold_seconds":3600}}}`)
	})
	mux.HandleFunc("GET /v1/locks/requests/lreq_01/wait", func(w http.ResponseWriter, r *http.Request) {
		assertProtocolHeaders(t, r)
		if got := r.URL.Query().Get("timeout"); got != "25s" {
			t.Errorf("wait timeout query = %q, want 25s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.wait","ok":true,"data":{"receipt":{"operation":"claim","request_id":"lreq_01","grant_id":"lgrant_01","state":"granted","recorded_at":"2026-11-08T05:00:03Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"`+payload.RequestKey+`","holder":"`+payload.Holder+`","state":"granted","sequence":1,"grant_id":"lgrant_01","generation":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z","granted_at":"2026-11-08T05:00:02Z","liveness_deadline":"2026-11-08T05:02:03Z","max_hold_deadline":"2026-11-08T06:00:02Z","liveness_seconds":120,"max_hold_seconds":3600}}}`)
	})
	mux.HandleFunc("POST /v1/locks/grants/lgrant_01/renew", func(w http.ResponseWriter, r *http.Request) {
		assertProtocolHeaders(t, r)
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"force":false}` {
			t.Errorf("renew body = %s, want {\"force\":false}", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.renew","ok":true,"data":{"receipt":{"operation":"renew","request_id":"lreq_01","grant_id":"lgrant_01","state":"granted","recorded_at":"2026-11-08T05:00:10Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"`+payload.RequestKey+`","holder":"`+payload.Holder+`","state":"granted","sequence":1,"grant_id":"lgrant_01","generation":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z","granted_at":"2026-11-08T05:00:02Z","liveness_deadline":"2026-11-08T05:02:10Z","max_hold_deadline":"2026-11-08T06:00:02Z","liveness_seconds":120,"max_hold_seconds":3600}}}`)
	})
	mux.HandleFunc("POST /v1/locks/requests/lreq_01/cancel", func(w http.ResponseWriter, r *http.Request) {
		assertProtocolHeaders(t, r)
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"force":false}` {
			t.Errorf("cancel body = %s, want {\"force\":false}", body)
		}
		// Cancelling a granted request transitions it to "released" and retains slot 0 and grant_id!
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.cancel","ok":true,"data":{"receipt":{"operation":"cancel","request_id":"lreq_01","grant_id":"lgrant_01","state":"released","recorded_at":"2026-11-08T05:00:15Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"`+payload.RequestKey+`","holder":"`+payload.Holder+`","state":"released","sequence":1,"grant_id":"lgrant_01","generation":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z","granted_at":"2026-11-08T05:00:02Z","liveness_deadline":"2026-11-08T05:02:10Z","max_hold_deadline":"2026-11-08T06:00:02Z","liveness_seconds":120,"max_hold_seconds":3600,"ended_at":"2026-11-08T05:00:15Z"}}}`)
	})
	mux.HandleFunc("POST /v1/locks/grants/lgrant_01/release", func(w http.ResponseWriter, r *http.Request) {
		assertProtocolHeaders(t, r)
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"force":false}` {
			t.Errorf("release body = %s, want {\"force\":false}", body)
		}
		// Calling Release on an already-ended request replays the stored end_receipt (which had operation "cancel").
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.release","ok":true,"data":{"receipt":{"operation":"cancel","request_id":"lreq_01","grant_id":"lgrant_01","state":"released","recorded_at":"2026-11-08T05:00:15Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"`+payload.RequestKey+`","holder":"`+payload.Holder+`","state":"released","sequence":1,"grant_id":"lgrant_01","generation":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z","granted_at":"2026-11-08T05:00:02Z","liveness_deadline":"2026-11-08T05:02:10Z","max_hold_deadline":"2026-11-08T06:00:02Z","liveness_seconds":120,"max_hold_seconds":3600,"ended_at":"2026-11-08T05:00:15Z"}}}`)
	})
	mux.HandleFunc("GET /v1/locks", func(w http.ResponseWriter, r *http.Request) {
		assertProtocolHeaders(t, r)
		if r.URL.Query().Get("limit") != "10" || r.URL.Query().Get("lock") != "mulgae-review" {
			t.Errorf("unexpected locks query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"locks.list","ok":true,"data":{"installation_id":"local-0123456789abcdef","now":"2026-11-08T05:00:20Z","requests":[{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"`+payload.RequestKey+`","holder":"  external holder with spaces  ","state":"released","sequence":1,"grant_id":"lgrant_01","generation":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z","granted_at":"2026-11-08T05:00:02Z","liveness_deadline":"2026-11-08T05:02:10Z","max_hold_deadline":"2026-11-08T06:00:02Z","liveness_seconds":120,"max_hold_seconds":3600,"ended_at":"2026-11-08T05:00:15Z"}],"more":false}}`)
	})

	fix := newShortSocketFixture(t, mux)
	client := haepari.NewClient(haepari.Config{
		RawHome:          fix.home,
		RawParentContext: parentCtx,
	})

	first, err := client.Acquire(context.Background(), payload.CanonicalJSON)
	if err != nil {
		t.Fatalf("Acquire(1): %v", err)
	}
	if first.Receipt.Operation != ports.ReviewLockReceiptOperationAcquire || first.Current.State != ports.ReviewLockStateQueued || first.Current.Slot != -1 {
		t.Fatalf("unexpected initial acquire reply: %+v", first)
	}

	second, err := client.Acquire(context.Background(), payload.CanonicalJSON)
	if err != nil {
		t.Fatalf("Acquire(2 replay): %v", err)
	}
	if second.Receipt.State != ports.ReviewLockStateQueued || second.Current.State != ports.ReviewLockStateGranted || second.Current.GrantID != "lgrant_01" {
		t.Fatalf("unexpected replay acquire reply: %+v", second)
	}

	waited, err := client.Wait(context.Background(), "lreq_01", 25*time.Second)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if waited.Receipt.Operation != ports.ReviewLockReceiptOperationClaim || waited.Current.State != ports.ReviewLockStateGranted {
		t.Fatalf("unexpected wait reply: %+v", waited)
	}

	renewed, err := client.Renew(context.Background(), "lgrant_01")
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if renewed.Receipt.Operation != ports.ReviewLockReceiptOperationRenew {
		t.Fatalf("unexpected renew reply: %+v", renewed)
	}

	cancelled, err := client.Cancel(context.Background(), "lreq_01")
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if cancelled.Receipt.Operation != ports.ReviewLockReceiptOperationCancel || cancelled.Current.State != ports.ReviewLockStateReleased || cancelled.Current.Slot != 0 {
		t.Fatalf("unexpected cancel-on-granted reply: %+v", cancelled)
	}

	released, err := client.Release(context.Background(), "lgrant_01")
	if err != nil {
		t.Fatalf("Release(terminal replay): %v", err)
	}
	if released.Receipt.Operation != ports.ReviewLockReceiptOperationCancel || released.Current.State != ports.ReviewLockStateReleased {
		t.Fatalf("unexpected terminal replay release reply: %+v", released)
	}

	list, err := client.ListLocks(context.Background(), ports.HaepariReviewResourceID, "", 10)
	if err != nil {
		t.Fatalf("ListLocks: %v", err)
	}
	if len(list.Requests) != 1 || list.Requests[0].Holder != "  external holder with spaces  " {
		t.Fatalf("unexpected list requests: %+v", list.Requests)
	}
}

func TestClientNativeIssueAndTransportUncertaintyMapping(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/locks/requests/lreq_01/wait", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.wait","ok":false,"error":{"code":"WAIT_TIMEOUT","message":"The wait timeout elapsed before the lock state settled.","retry":"retry_same_key"}}`)
	})
	mux.HandleFunc("GET /v1/locks/requests/lreq_storage/wait", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.wait","ok":false,"error":{"code":"STORAGE_UNAVAILABLE","message":"sqlite failed during ClaimLock","retry":"reconcile"}}`)
	})
	mux.HandleFunc("POST /v1/locks/acquire", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.acquire","ok":false,"error":{"code":"STORAGE_UNAVAILABLE","message":"sqlite failed at /private/var/db/secret.sqlite","retry":"reconcile"}}`)
	})

	fix := newShortSocketFixture(t, mux)
	client := haepari.NewClient(haepari.Config{RawHome: fix.home})

	// Known WAIT_TIMEOUT must remain Uncertain=false.
	_, err := client.Wait(context.Background(), "lreq_01", 5*time.Second)
	var coordErr *ports.ReviewCoordinationError
	if !errors.As(err, &coordErr) || coordErr.NativeCode != "WAIT_TIMEOUT" || coordErr.NativeRetry != ports.ReviewLockNativeRetrySameKey || coordErr.Retry != ports.ReviewCoordinationRetrySameKey || coordErr.Uncertain {
		t.Fatalf("unexpected WAIT_TIMEOUT mapping: %+v (err=%v)", coordErr, err)
	}

	// Pre-transmission Wait refusals must remain Uncertain=false.
	_, err = client.Wait(context.Background(), "invalid id", 5*time.Second)
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonAcquireInvalid || coordErr.Uncertain {
		t.Fatalf("expected pre-transmission invalid request_id Wait refusal Uncertain=false, got %+v (%v)", coordErr, err)
	}
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.Wait(cancelledCtx, "lreq_01", 5*time.Second)
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonContextCancelled || coordErr.Uncertain {
		t.Fatalf("expected pre-transmission cancelled Wait refusal Uncertain=false, got %+v (%v)", coordErr, err)
	}

	// STORAGE_UNAVAILABLE on Wait (which can execute ClaimLock) must set Uncertain=true.
	_, err = client.Wait(context.Background(), "lreq_storage", 5*time.Second)
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonControllerUnreachable || !coordErr.Uncertain || coordErr.NativeCode != "STORAGE_UNAVAILABLE" || coordErr.NativeRetry != ports.ReviewLockNativeRetryReconcile || coordErr.Retry != ports.ReviewCoordinationRetryReconcile {
		t.Fatalf("expected STORAGE_UNAVAILABLE on Wait to preserve Uncertain=true, got %+v (%v)", coordErr, err)
	}

	_, err = client.Acquire(context.Background(), []byte(`{"lock_id":"mulgae-review","request_key":"mulgae-r_1","holder":"h"}`))
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonAcquireUncertain || !coordErr.Uncertain || coordErr.NativeCode != "STORAGE_UNAVAILABLE" || coordErr.NativeRetry != ports.ReviewLockNativeRetryReconcile {
		t.Fatalf("unexpected STORAGE_UNAVAILABLE mapping: %+v (err=%v)", coordErr, err)
	}
	if strings.Contains(coordErr.Message, "/private/var") {
		t.Fatalf("expected native message path redacted, got %q", coordErr.Message)
	}

	// Mid-flight EOF during Acquire or Wait (lost post-claim response) must preserve Uncertain=true.
	dropMux := http.NewServeMux()
	dropMux.HandleFunc("POST /v1/locks/acquire", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not support Hijacker")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	})
	dropMux.HandleFunc("GET /v1/locks/requests/lreq_01/wait", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not support Hijacker")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	})
	dropFix := newShortSocketFixture(t, dropMux)
	dropClient := haepari.NewClient(haepari.Config{RawHome: dropFix.home})
	_, err = dropClient.Acquire(context.Background(), []byte(`{"lock_id":"mulgae-review","request_key":"mulgae-r_1","holder":"h"}`))
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonAcquireUncertain || !coordErr.Uncertain {
		t.Fatalf("expected mid-flight acquire drop to map to haepari_acquire_uncertain (Uncertain=true), got %+v (%v)", coordErr, err)
	}
	_, err = dropClient.Wait(context.Background(), "lreq_01", 5*time.Second)
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonControllerUnreachable || !coordErr.Uncertain || coordErr.Retry != ports.ReviewCoordinationRetryInspectFirst {
		t.Fatalf("expected lost post-claim Wait response to preserve Uncertain=true, got %+v (%v)", coordErr, err)
	}
}

func TestClientPostTransmissionValidationPreservesUncertaintyAndTargetIDBinding(t *testing.T) {
	t.Parallel()

	var acquireStep, waitStep int
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"hello","ok":true,"data":{"protocol":"managed-execution/v1","protocol_version":1,"installation_id":"local-0123456789abcdef","capabilities":["managed-execution/v1","advisory-lock/v1"]}}`)
	})
	mux.HandleFunc("POST /v1/locks/acquire", func(w http.ResponseWriter, r *http.Request) {
		acquireStep++
		w.Header().Set("Content-Type", "application/json")
		switch acquireStep {
		case 1:
			// Malformed Current state/slot (queued with slot 0) after acquire transmission.
			_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.acquire","ok":true,"data":{"receipt":{"operation":"acquire","request_id":"lreq_01","state":"queued","recorded_at":"2026-11-08T05:00:00Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"mulgae-r_1","holder":"h","state":"queued","sequence":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z"}}}`)
		case 2:
			// Valid structure, but installation_id mismatches selected installation after acquire transmission.
			_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.acquire","ok":true,"data":{"receipt":{"operation":"acquire","request_id":"lreq_01","state":"queued","recorded_at":"2026-11-08T05:00:00Z"},"current":{"installation_id":"foreign-installation","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"mulgae-r_1","holder":"h","state":"queued","sequence":1,"slot":-1,"queued_at":"2026-11-08T05:00:00Z"}}}`)
		default:
			// Malformed error envelope (ok:false carrying data) after acquire transmission.
			_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.acquire","ok":false,"data":{"unexpected":true},"error":{"code":"CONFLICT","message":"conflict","retry":"none"}}`)
		}
	})
	mux.HandleFunc("GET /v1/locks/requests/lreq_expected/wait", func(w http.ResponseWriter, r *http.Request) {
		waitStep++
		w.Header().Set("Content-Type", "application/json")
		if waitStep == 1 {
			// Internally consistent receipt+current for the WRONG request_id ("lreq_other").
			_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.wait","ok":true,"data":{"receipt":{"operation":"claim","request_id":"lreq_other","state":"queued","recorded_at":"2026-11-08T05:00:00Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_other","request_key":"mulgae-r_1","holder":"h","state":"queued","sequence":1,"slot":-1,"queued_at":"2026-11-08T05:00:00Z"}}}`)
			return
		}
		// Malformed post-claim Wait reply (granted without grant_id) after Wait transmission.
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.wait","ok":true,"data":{"receipt":{"operation":"claim","request_id":"lreq_expected","state":"granted","recorded_at":"2026-11-08T05:00:00Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_expected","request_key":"mulgae-r_1","holder":"h","state":"granted","sequence":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z"}}}`)
	})
	mux.HandleFunc("POST /v1/locks/requests/lreq_expected/cancel", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.cancel","ok":true,"data":{"receipt":{"operation":"cancel","request_id":"lreq_other","state":"cancelled","recorded_at":"2026-11-08T05:00:10Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_other","request_key":"mulgae-r_1","holder":"h","state":"cancelled","sequence":1,"slot":-1,"queued_at":"2026-11-08T05:00:00Z","ended_at":"2026-11-08T05:00:10Z"}}}`)
	})
	mux.HandleFunc("POST /v1/locks/grants/lgrant_expected/renew", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Internally consistent receipt+current for the WRONG grant_id ("lgrant_other").
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.renew","ok":true,"data":{"receipt":{"operation":"renew","request_id":"lreq_01","grant_id":"lgrant_other","state":"granted","recorded_at":"2026-11-08T05:00:10Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"mulgae-r_1","holder":"h","state":"granted","sequence":1,"grant_id":"lgrant_other","generation":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z","granted_at":"2026-11-08T05:00:02Z","liveness_deadline":"2026-11-08T05:02:10Z","max_hold_deadline":"2026-11-08T06:00:02Z","liveness_seconds":120,"max_hold_seconds":3600}}}`)
	})
	mux.HandleFunc("POST /v1/locks/grants/lgrant_expected/release", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema":"haepari.envelope/v1","operation":"lock.release","ok":true,"data":{"receipt":{"operation":"release","request_id":"lreq_01","grant_id":"lgrant_other","state":"released","recorded_at":"2026-11-08T05:00:15Z"},"current":{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","request_id":"lreq_01","request_key":"mulgae-r_1","holder":"h","state":"released","sequence":1,"grant_id":"lgrant_other","generation":1,"slot":0,"queued_at":"2026-11-08T05:00:00Z","granted_at":"2026-11-08T05:00:02Z","liveness_deadline":"2026-11-08T05:02:10Z","max_hold_deadline":"2026-11-08T06:00:02Z","liveness_seconds":120,"max_hold_seconds":3600,"ended_at":"2026-11-08T05:00:15Z"}}}`)
	})

	fix := newShortSocketFixture(t, mux)
	client := haepari.NewClient(haepari.Config{RawHome: fix.home})
	if _, err := client.Hello(context.Background()); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	var coordErr *ports.ReviewCoordinationError
	_, err := client.Acquire(context.Background(), []byte(`{"lock_id":"mulgae-review","request_key":"mulgae-r_1","holder":"h"}`))
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonProtocolIncompatible || !coordErr.Uncertain {
		t.Fatalf("expected malformed post-transmission acquire reply to preserve Uncertain=true, got %+v (%v)", coordErr, err)
	}

	_, err = client.Acquire(context.Background(), []byte(`{"lock_id":"mulgae-review","request_key":"mulgae-r_1","holder":"h"}`))
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonInstallationMismatch || !coordErr.Uncertain {
		t.Fatalf("expected mismatched-installation acquire reply to preserve Uncertain=true, got %+v (%v)", coordErr, err)
	}

	_, err = client.Acquire(context.Background(), []byte(`{"lock_id":"mulgae-review","request_key":"mulgae-r_1","holder":"h"}`))
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonProtocolIncompatible || !coordErr.Uncertain {
		t.Fatalf("expected malformed error envelope on acquire to preserve Uncertain=true, got %+v (%v)", coordErr, err)
	}

	_, err = client.Wait(context.Background(), "lreq_expected", 5*time.Second)
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonProtocolIncompatible || !coordErr.Uncertain {
		t.Fatalf("expected Wait to reject mismatched request_id with Uncertain=true, got %+v (%v)", coordErr, err)
	}
	_, err = client.Wait(context.Background(), "lreq_expected", 5*time.Second)
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonProtocolIncompatible || !coordErr.Uncertain {
		t.Fatalf("expected Wait to reject malformed post-claim reply with Uncertain=true, got %+v (%v)", coordErr, err)
	}

	_, err = client.Cancel(context.Background(), "lreq_expected")
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonProtocolIncompatible || !coordErr.Uncertain {
		t.Fatalf("expected Cancel to reject mismatched request_id with Uncertain=true, got %+v (%v)", coordErr, err)
	}

	_, err = client.Renew(context.Background(), "lgrant_expected")
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonProtocolIncompatible || !coordErr.Uncertain {
		t.Fatalf("expected Renew to reject mismatched grant_id with Uncertain=true, got %+v (%v)", coordErr, err)
	}

	_, err = client.Release(context.Background(), "lgrant_expected")
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonProtocolIncompatible || !coordErr.Uncertain {
		t.Fatalf("expected Release to reject mismatched grant_id with Uncertain=true, got %+v (%v)", coordErr, err)
	}
}

func hasReason(err error, want ports.ReviewCoordinationReason) bool {
	var coordErr *ports.ReviewCoordinationError
	return errors.As(err, &coordErr) && coordErr.Reason == want
}
