//go:build darwin && arm64

package haepari

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/strictjson"
)

const (
	haepariEnvelopeSchema = "haepari.envelope/v1"
	maxWaitTimeout        = 24 * time.Hour
)

type Config struct {
	RawHome          string
	RawParentContext string
	RawLockGrant     string
	HasLockGrant     bool
}

type Client struct {
	rawHome          string
	rawParentContext string
	hasLockGrant     bool
	httpClient       *http.Client

	mu             sync.Mutex
	installationID string
}

var _ ports.ReviewLockTransport = (*Client)(nil)

func NewClient(cfg Config) *Client {
	return &Client{
		rawHome:          cfg.RawHome,
		rawParentContext: cfg.RawParentContext,
		hasLockGrant:     cfg.HasLockGrant || cfg.RawLockGrant != "",
	}
}

type wireEnvelope struct {
	Schema    string          `json:"schema"`
	Operation string          `json:"operation"`
	OK        bool            `json:"ok"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     *wireIssue      `json:"error,omitempty"`
}

type wireHandshake struct {
	Protocol        string   `json:"protocol"`
	ProtocolVersion int      `json:"protocol_version"`
	InstallationID  string   `json:"installation_id"`
	Capabilities    []string `json:"capabilities"`
}

type wireResourceStatus struct {
	AdvisoryGrants       int             `json:"advisory_grants,omitempty"`
	AdvisoryQueued       int             `json:"advisory_queued,omitempty"`
	Mutation             json.RawMessage `json:"mutation,omitempty"`
	ResourceID           string          `json:"resource_id"`
	Kind                 string          `json:"kind"`
	ConfigurationDigest  string          `json:"configuration_digest"`
	ConfigRevision       int64           `json:"config_revision"`
	AvailabilityRevision int64           `json:"availability_revision"`
	Availability         string          `json:"availability"`
	Reason               string          `json:"reason,omitempty"`
	Capacity             int             `json:"capacity"`
	Occupancy            int             `json:"occupancy"`
	LeaseGeneration      int64           `json:"lease_generation"`
	IdleSince            *time.Time      `json:"idle_since,omitempty"`
}

type wireLockReceipt struct {
	Operation  string    `json:"operation"`
	RequestID  string    `json:"request_id"`
	GrantID    string    `json:"grant_id,omitempty"`
	State      string    `json:"state"`
	RecordedAt time.Time `json:"recorded_at"`
	Force      bool      `json:"force,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

type wireLockRequest struct {
	InstallationID   string     `json:"installation_id"`
	LockID           string     `json:"lock_id"`
	RequestID        string     `json:"request_id"`
	RequestKey       string     `json:"request_key"`
	Holder           string     `json:"holder"`
	State            string     `json:"state"`
	Sequence         int64      `json:"sequence"`
	GrantID          string     `json:"grant_id,omitempty"`
	Generation       int64      `json:"generation,omitempty"`
	Slot             int        `json:"slot"`
	QueuedAt         time.Time  `json:"queued_at"`
	QueueDeadline    *time.Time `json:"queue_deadline,omitempty"`
	GrantedAt        *time.Time `json:"granted_at,omitempty"`
	LivenessDeadline *time.Time `json:"liveness_deadline,omitempty"`
	MaxHoldDeadline  *time.Time `json:"max_hold_deadline,omitempty"`
	LivenessSeconds  int64      `json:"liveness_seconds,omitempty"`
	MaxHoldSeconds   int64      `json:"max_hold_seconds,omitempty"`
	EndedAt          *time.Time `json:"ended_at,omitempty"`
	Reason           string     `json:"reason,omitempty"`
	Forced           bool       `json:"forced,omitempty"`
}

type wireLockReply struct {
	Receipt wireLockReceipt `json:"receipt"`
	Current wireLockRequest `json:"current"`
}

type wireLockList struct {
	InstallationID string            `json:"installation_id"`
	Now            time.Time         `json:"now"`
	Requests       []wireLockRequest `json:"requests"`
	More           bool              `json:"more"`
	NextCursor     string            `json:"next_cursor,omitempty"`
}

type wireLockActionRequest struct {
	Force bool `json:"force"`
}

func (c *Client) Hello(ctx context.Context) (ports.ReviewLockInstallation, error) {
	var raw wireHandshake
	if err := c.doJSON(ctx, ports.ReviewLockOperationHello, http.MethodGet, "/v1/hello", nil, &raw); err != nil {
		return ports.ReviewLockInstallation{}, err
	}
	inst := ports.ReviewLockInstallation{
		Protocol:        raw.Protocol,
		ProtocolVersion: raw.ProtocolVersion,
		InstallationID:  raw.InstallationID,
		Capabilities:    append([]string(nil), raw.Capabilities...),
	}
	if err := inst.Validate(); err != nil {
		reason := ports.ReviewCoordinationReasonProtocolIncompatible
		if strings.Contains(err.Error(), "missing capability") {
			reason = ports.ReviewCoordinationReasonCapabilityUnsupported
		}
		return ports.ReviewLockInstallation{}, &ports.ReviewCoordinationError{
			Reason:    reason,
			Operation: ports.ReviewLockOperationHello,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   err.Error(),
			Cause:     err,
		}
	}
	c.mu.Lock()
	if c.installationID != "" && c.installationID != inst.InstallationID {
		c.mu.Unlock()
		return ports.ReviewLockInstallation{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonInstallationMismatch,
			Operation: ports.ReviewLockOperationHello,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "controller installation_id changed across calls",
		}
	}
	c.installationID = inst.InstallationID
	c.mu.Unlock()
	return inst, nil
}

func (c *Client) InspectResource(ctx context.Context, resourceID string) (ports.ReviewLockResource, error) {
	if !ports.ValidHaepariIdentifier(resourceID) {
		return ports.ReviewLockResource{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonResourceInvalid,
			Operation: ports.ReviewLockOperationInspectResource,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid resource_id",
		}
	}
	boundInstallation, err := c.ensureInstallationID(ctx)
	if err != nil {
		return ports.ReviewLockResource{}, err
	}
	var raw wireResourceStatus
	if err := c.doJSON(ctx, ports.ReviewLockOperationInspectResource, http.MethodGet, "/v1/resources/"+url.PathEscape(resourceID), nil, &raw); err != nil {
		return ports.ReviewLockResource{}, err
	}
	var idleSince *time.Time
	if raw.IdleSince != nil {
		t := raw.IdleSince.UTC()
		idleSince = &t
	}
	res := ports.ReviewLockResource{
		InstallationID:       boundInstallation,
		ResourceID:           raw.ResourceID,
		Kind:                 raw.Kind,
		ConfigurationDigest:  raw.ConfigurationDigest,
		ConfigRevision:       raw.ConfigRevision,
		AvailabilityRevision: raw.AvailabilityRevision,
		Availability:         raw.Availability,
		Reason:               raw.Reason,
		Capacity:             raw.Capacity,
		Occupancy:            raw.Occupancy,
		AdvisoryGrants:       raw.AdvisoryGrants,
		AdvisoryQueued:       raw.AdvisoryQueued,
		LeaseGeneration:      raw.LeaseGeneration,
		IdleSince:            idleSince,
	}
	if err := res.Validate(boundInstallation); err != nil {
		return ports.ReviewLockResource{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonResourceInvalid,
			Operation: ports.ReviewLockOperationInspectResource,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   err.Error(),
			Cause:     err,
		}
	}
	return res, nil
}

func (c *Client) Acquire(ctx context.Context, canonicalPayload []byte) (ports.ReviewLockReply, error) {
	if len(canonicalPayload) == 0 {
		return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "empty acquire payload",
		}
	}
	var raw wireLockReply
	if err := c.doJSON(ctx, ports.ReviewLockOperationAcquire, http.MethodPost, "/v1/locks/acquire", canonicalPayload, &raw); err != nil {
		return ports.ReviewLockReply{}, err
	}
	return c.validateAndMapReply(ports.ReviewLockOperationAcquire, "", raw)
}

func (c *Client) Wait(ctx context.Context, requestID string, timeout time.Duration) (ports.ReviewLockReply, error) {
	if !ports.ValidHaepariIdentifier(requestID) {
		return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationWait,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid request_id",
		}
	}
	if timeout < 0 || timeout > maxWaitTimeout {
		return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationWait,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "wait timeout out of range (0, 24h]",
		}
	}
	path := "/v1/locks/requests/" + url.PathEscape(requestID) + "/wait"
	if timeout > 0 {
		path += "?timeout=" + url.QueryEscape(timeout.String())
	}
	var raw wireLockReply
	if err := c.doJSON(ctx, ports.ReviewLockOperationWait, http.MethodGet, path, nil, &raw); err != nil {
		return ports.ReviewLockReply{}, err
	}
	return c.validateAndMapReply(ports.ReviewLockOperationWait, requestID, raw)
}

func (c *Client) Renew(ctx context.Context, grantID string) (ports.ReviewLockReply, error) {
	if !ports.ValidHaepariIdentifier(grantID) {
		return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationRenew,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid grant_id",
		}
	}
	body, _ := json.Marshal(wireLockActionRequest{Force: false})
	var raw wireLockReply
	if err := c.doJSON(ctx, ports.ReviewLockOperationRenew, http.MethodPost, "/v1/locks/grants/"+url.PathEscape(grantID)+"/renew", body, &raw); err != nil {
		return ports.ReviewLockReply{}, err
	}
	return c.validateAndMapReply(ports.ReviewLockOperationRenew, grantID, raw)
}

func (c *Client) Release(ctx context.Context, grantID string) (ports.ReviewLockReply, error) {
	if !ports.ValidHaepariIdentifier(grantID) {
		return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationRelease,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid grant_id",
		}
	}
	body, _ := json.Marshal(wireLockActionRequest{Force: false})
	var raw wireLockReply
	if err := c.doJSON(ctx, ports.ReviewLockOperationRelease, http.MethodPost, "/v1/locks/grants/"+url.PathEscape(grantID)+"/release", body, &raw); err != nil {
		return ports.ReviewLockReply{}, err
	}
	return c.validateAndMapReply(ports.ReviewLockOperationRelease, grantID, raw)
}

func (c *Client) Cancel(ctx context.Context, requestID string) (ports.ReviewLockReply, error) {
	if !ports.ValidHaepariIdentifier(requestID) {
		return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationCancel,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid request_id",
		}
	}
	body, _ := json.Marshal(wireLockActionRequest{Force: false})
	var raw wireLockReply
	if err := c.doJSON(ctx, ports.ReviewLockOperationCancel, http.MethodPost, "/v1/locks/requests/"+url.PathEscape(requestID)+"/cancel", body, &raw); err != nil {
		return ports.ReviewLockReply{}, err
	}
	return c.validateAndMapReply(ports.ReviewLockOperationCancel, requestID, raw)
}

func (c *Client) ListLocks(ctx context.Context, lockID string, cursor string, limit int) (ports.ReviewLockList, error) {
	if lockID != "" && !ports.ValidHaepariIdentifier(lockID) {
		return ports.ReviewLockList{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid lock_id filter",
		}
	}
	if limit < 1 || limit > 100 {
		return ports.ReviewLockList{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "locks.list limit must be in [1, 100]",
		}
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	if lockID != "" {
		query.Set("lock", lockID)
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	var raw wireLockList
	if err := c.doJSON(ctx, ports.ReviewLockOperationList, http.MethodGet, "/v1/locks?"+query.Encode(), nil, &raw); err != nil {
		return ports.ReviewLockList{}, err
	}
	requests := make([]ports.ReviewLockRequest, 0, len(raw.Requests))
	for _, r := range raw.Requests {
		requests = append(requests, mapWireLockRequest(r))
	}
	list := ports.ReviewLockList{
		InstallationID: raw.InstallationID,
		Now:            raw.Now.UTC(),
		Requests:       requests,
		More:           raw.More,
		NextCursor:     raw.NextCursor,
	}
	c.mu.Lock()
	expectedInst := c.installationID
	c.mu.Unlock()
	if err := list.Validate(expectedInst); err != nil {
		reason := ports.ReviewCoordinationReasonProtocolIncompatible
		if expectedInst != "" && list.InstallationID != expectedInst && ports.ValidHaepariIdentifier(list.InstallationID) {
			reason = ports.ReviewCoordinationReasonInstallationMismatch
		}
		return ports.ReviewLockList{}, &ports.ReviewCoordinationError{
			Reason:    reason,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   err.Error(),
			Cause:     err,
		}
	}
	return list, nil
}

func (c *Client) ensureInstallationID(ctx context.Context) (string, error) {
	c.mu.Lock()
	id := c.installationID
	c.mu.Unlock()
	if id != "" {
		return id, nil
	}
	inst, err := c.Hello(ctx)
	if err != nil {
		return "", err
	}
	return inst.InstallationID, nil
}

func (c *Client) validateAndMapReply(op ports.ReviewLockOperation, expectedTargetID string, raw wireLockReply) (ports.ReviewLockReply, error) {
	uncertain := isMutatingLockOp(op)
	reply := ports.ReviewLockReply{
		Receipt: ports.ReviewLockReceipt{
			Operation:  ports.ReviewLockReceiptOperation(raw.Receipt.Operation),
			RequestID:  raw.Receipt.RequestID,
			GrantID:    raw.Receipt.GrantID,
			State:      ports.ReviewLockState(raw.Receipt.State),
			RecordedAt: raw.Receipt.RecordedAt.UTC(),
			Force:      raw.Receipt.Force,
			Reason:     raw.Receipt.Reason,
		},
		Current: mapWireLockRequest(raw.Current),
	}
	if err := reply.Validate(op); err != nil {
		return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: uncertain,
			Message:   err.Error(),
			Cause:     err,
		}
	}
	switch op {
	case ports.ReviewLockOperationWait, ports.ReviewLockOperationCancel:
		if expectedTargetID != "" && reply.Current.RequestID != expectedTargetID {
			return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
				Operation: op,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: uncertain,
				Message:   fmt.Sprintf("lock reply request_id %q does not match requested %q", reply.Current.RequestID, expectedTargetID),
			}
		}
	case ports.ReviewLockOperationRenew, ports.ReviewLockOperationRelease:
		if expectedTargetID != "" && reply.Current.GrantID != expectedTargetID {
			return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
				Operation: op,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: uncertain,
				Message:   fmt.Sprintf("lock reply grant_id %q does not match requested %q", reply.Current.GrantID, expectedTargetID),
			}
		}
	}
	c.mu.Lock()
	expectedInst := c.installationID
	if expectedInst == "" {
		c.installationID = reply.Current.InstallationID
	}
	c.mu.Unlock()
	if expectedInst != "" && reply.Current.InstallationID != expectedInst {
		return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonInstallationMismatch,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: uncertain,
			Message:   "lock reply installation_id does not match selected installation",
		}
	}
	return reply, nil
}

func mapWireLockRequest(raw wireLockRequest) ports.ReviewLockRequest {
	return ports.ReviewLockRequest{
		InstallationID:   raw.InstallationID,
		LockID:           raw.LockID,
		RequestID:        raw.RequestID,
		RequestKey:       raw.RequestKey,
		Holder:           raw.Holder,
		State:            ports.ReviewLockState(raw.State),
		Sequence:         raw.Sequence,
		GrantID:          raw.GrantID,
		Generation:       raw.Generation,
		Slot:             raw.Slot,
		QueuedAt:         raw.QueuedAt.UTC(),
		QueueDeadline:    utcTimePtr(raw.QueueDeadline),
		GrantedAt:        utcTimePtr(raw.GrantedAt),
		LivenessDeadline: utcTimePtr(raw.LivenessDeadline),
		MaxHoldDeadline:  utcTimePtr(raw.MaxHoldDeadline),
		LivenessSeconds:  raw.LivenessSeconds,
		MaxHoldSeconds:   raw.MaxHoldSeconds,
		EndedAt:          utcTimePtr(raw.EndedAt),
		Reason:           raw.Reason,
		Forced:           raw.Forced,
	}
}

func utcTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	u := value.UTC()
	return &u
}

func (c *Client) doJSON(
	ctx context.Context,
	op ports.ReviewLockOperation,
	method string,
	path string,
	body []byte,
	destination any,
) error {
	if ctx == nil {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "nil context",
		}
	}
	if err := ctx.Err(); err != nil {
		return mapTransportError(op, false, err)
	}
	if c.hasLockGrant {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonParentContextInvalid,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "inherited review grant borrowing is not available",
		}
	}
	parentHeaderValue, err := ValidateParentContext(c.rawParentContext)
	if err != nil {
		return err
	}
	stateRoot, err := ResolveStateRoot(c.rawHome)
	if err != nil {
		return err
	}

	var writeStarted bool
	var mu sync.Mutex
	markWriteStarted := func() {
		mu.Lock()
		writeStarted = true
		mu.Unlock()
	}
	didWriteStart := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return writeStarted
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			conn, dialErr := d.DialContext(dialCtx, "unix", stateRoot.SocketPath)
			if dialErr != nil {
				return nil, dialErr
			}
			return &writeTrackingConn{Conn: conn, onWrite: markWriteStarted}, nil
		},
	}
	defer transport.CloseIdleConnections()

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://haepari"+path, bodyReader)
	if err != nil {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "failed to construct controller HTTP request",
			Cause:     err,
		}
	}
	req.Header.Set(protocolHeader, ports.HaepariProtocolID)
	req.Header.Set(protocolMinHeader, "1")
	req.Header.Set(protocolMaxHeader, "1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if parentHeaderValue != "" {
		req.Header.Set(parentContextHeader, parentHeaderValue)
	}

	httpClient := &http.Client{Transport: transport}
	resp, err := httpClient.Do(req)
	if err != nil {
		return mapTransportError(op, didWriteStart(), err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, HaepariMaxControlEnvelopeBytes+1))
	if err != nil {
		return mapTransportError(op, true, err)
	}
	mutating := isMutatingLockOp(op)
	if len(rawResp) > HaepariMaxControlEnvelopeBytes {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: mutating,
			Message:   fmt.Sprintf("controller response exceeds %d byte bound", HaepariMaxControlEnvelopeBytes),
		}
	}

	var env wireEnvelope
	if err := strictjson.DecodeObject(rawResp, &env); err != nil {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: mutating,
			Message:   "malformed controller envelope JSON",
			Cause:     err,
		}
	}
	if env.Schema != haepariEnvelopeSchema {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: mutating,
			Message:   fmt.Sprintf("unexpected envelope schema %q", env.Schema),
		}
	}
	if !env.OK {
		if len(env.Data) != 0 {
			return &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
				Operation: op,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: mutating,
				Message:   "error envelope must not carry data payload",
			}
		}
		if env.Operation != string(op) && env.Operation != "handshake" {
			return &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
				Operation: op,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: mutating,
				Message:   fmt.Sprintf("unexpected error envelope operation %q for %q", env.Operation, op),
			}
		}
		return mapNativeIssue(op, env.Error)
	}

	if env.Operation != string(op) {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: mutating,
			Message:   fmt.Sprintf("unexpected envelope operation %q for %q", env.Operation, op),
		}
	}
	if env.Error != nil || len(bytes.TrimSpace(env.Data)) == 0 || string(bytes.TrimSpace(env.Data)) == "null" {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: mutating,
			Message:   "success envelope missing data or carrying error",
		}
	}
	if destination != nil {
		if err := strictjson.DecodeObject(env.Data, destination); err != nil {
			return &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
				Operation: op,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: mutating,
				Message:   "malformed envelope data payload",
				Cause:     err,
			}
		}
	}
	return nil
}

type writeTrackingConn struct {
	net.Conn
	onWrite func()
}

func (c *writeTrackingConn) Write(b []byte) (int, error) {
	if c.onWrite != nil && len(b) > 0 {
		c.onWrite()
	}
	return c.Conn.Write(b)
}
