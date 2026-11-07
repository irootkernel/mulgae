package ports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
)

const (
	HaepariReviewResourceID                   = "mulgae-review"
	HaepariProtocolID                         = "managed-execution/v1"
	HaepariProtocolVersion                    = 1
	HaepariCapabilityManagedExecutionV1       = "managed-execution/v1"
	HaepariCapabilityAdvisoryLockV1           = "advisory-lock/v1"
	HaepariMaxQueueSeconds              int64 = 9223372036
	HaepariMaxHolderBytes                     = 512
)

type ReviewLockState string

const (
	ReviewLockStateQueued       ReviewLockState = "queued"
	ReviewLockStateGranted      ReviewLockState = "granted"
	ReviewLockStateReleased     ReviewLockState = "released"
	ReviewLockStateCancelled    ReviewLockState = "cancelled"
	ReviewLockStateQueueExpired ReviewLockState = "queue_expired"
	ReviewLockStateHoldExpired  ReviewLockState = "hold_expired"
)

func (state ReviewLockState) Valid() bool {
	switch state {
	case ReviewLockStateQueued,
		ReviewLockStateGranted,
		ReviewLockStateReleased,
		ReviewLockStateCancelled,
		ReviewLockStateQueueExpired,
		ReviewLockStateHoldExpired:
		return true
	default:
		return false
	}
}

func (state ReviewLockState) IsTerminal() bool {
	switch state {
	case ReviewLockStateReleased,
		ReviewLockStateCancelled,
		ReviewLockStateQueueExpired,
		ReviewLockStateHoldExpired:
		return true
	default:
		return false
	}
}

func (state ReviewLockState) WasGranted() bool {
	switch state {
	case ReviewLockStateGranted,
		ReviewLockStateReleased,
		ReviewLockStateHoldExpired:
		return true
	default:
		return false
	}
}

type ReviewLockOperation string

const (
	ReviewLockOperationHello           ReviewLockOperation = "hello"
	ReviewLockOperationInspectResource ReviewLockOperation = "resource.inspect"
	ReviewLockOperationAcquire         ReviewLockOperation = "lock.acquire"
	ReviewLockOperationWait            ReviewLockOperation = "lock.wait"
	ReviewLockOperationRenew           ReviewLockOperation = "lock.renew"
	ReviewLockOperationRelease         ReviewLockOperation = "lock.release"
	ReviewLockOperationCancel          ReviewLockOperation = "lock.cancel"
	ReviewLockOperationList            ReviewLockOperation = "locks.list"
)

func (op ReviewLockOperation) Valid() bool {
	switch op {
	case ReviewLockOperationHello,
		ReviewLockOperationInspectResource,
		ReviewLockOperationAcquire,
		ReviewLockOperationWait,
		ReviewLockOperationRenew,
		ReviewLockOperationRelease,
		ReviewLockOperationCancel,
		ReviewLockOperationList:
		return true
	default:
		return false
	}
}

type ReviewLockReceiptOperation string

const (
	ReviewLockReceiptOperationAcquire ReviewLockReceiptOperation = "acquire"
	ReviewLockReceiptOperationClaim   ReviewLockReceiptOperation = "claim"
	ReviewLockReceiptOperationRenew   ReviewLockReceiptOperation = "renew"
	ReviewLockReceiptOperationRelease ReviewLockReceiptOperation = "release"
	ReviewLockReceiptOperationCancel  ReviewLockReceiptOperation = "cancel"
	ReviewLockReceiptOperationExpire  ReviewLockReceiptOperation = "expire"
)

func (op ReviewLockReceiptOperation) Valid() bool {
	switch op {
	case ReviewLockReceiptOperationAcquire,
		ReviewLockReceiptOperationClaim,
		ReviewLockReceiptOperationRenew,
		ReviewLockReceiptOperationRelease,
		ReviewLockReceiptOperationCancel,
		ReviewLockReceiptOperationExpire:
		return true
	default:
		return false
	}
}

// ValidHaepariIdentifier matches Haepari's frozen identifier grammar:
// ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$.
func ValidHaepariIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	if !isASCIIAlphaNum(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		ch := value[i]
		if !isASCIIAlphaNum(ch) && ch != '.' && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}

func isASCIIAlphaNum(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
}

func ValidHaepariDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func ValidMulgaeSHA256Digest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && ValidHaepariDigest(strings.TrimPrefix(value, "sha256:"))
}

// ValidHaepariHolder matches Haepari AcquireLock's native holder check:
// strings.TrimSpace(holder) != "" && len(holder) <= 512.
func ValidHaepariHolder(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= HaepariMaxHolderBytes
}

type ReviewLockInstallation struct {
	Protocol        string
	ProtocolVersion int
	InstallationID  string
	Capabilities    []string
}

func (inst ReviewLockInstallation) Validate() error {
	if inst.Protocol != HaepariProtocolID {
		return fmt.Errorf("haepari installation: unexpected protocol %q", inst.Protocol)
	}
	if inst.ProtocolVersion != HaepariProtocolVersion {
		return fmt.Errorf("haepari installation: unexpected protocol_version %d", inst.ProtocolVersion)
	}
	if !ValidHaepariIdentifier(inst.InstallationID) {
		return fmt.Errorf("haepari installation: invalid installation_id %q", inst.InstallationID)
	}
	if !slices.Contains(inst.Capabilities, HaepariCapabilityManagedExecutionV1) {
		return fmt.Errorf("haepari installation: missing capability %q", HaepariCapabilityManagedExecutionV1)
	}
	if !slices.Contains(inst.Capabilities, HaepariCapabilityAdvisoryLockV1) {
		return fmt.Errorf("haepari installation: missing capability %q", HaepariCapabilityAdvisoryLockV1)
	}
	return nil
}

type ReviewLockResource struct {
	InstallationID       string
	ResourceID           string
	Kind                 string
	ConfigurationDigest  string
	ConfigRevision       int64
	AvailabilityRevision int64
	Availability         string
	Reason               string
	Capacity             int
	Occupancy            int
	AdvisoryGrants       int
	AdvisoryQueued       int
	LeaseGeneration      int64
	IdleSince            *time.Time
}

func (res ReviewLockResource) Validate(expectedInstallationID string) error {
	if !ValidHaepariIdentifier(res.InstallationID) {
		return fmt.Errorf("haepari resource: invalid bound installation_id %q", res.InstallationID)
	}
	if expectedInstallationID != "" && res.InstallationID != expectedInstallationID {
		return fmt.Errorf("haepari resource: installation_id %q does not match expected %q", res.InstallationID, expectedInstallationID)
	}
	if res.ResourceID != HaepariReviewResourceID {
		return fmt.Errorf("haepari resource: unexpected resource_id %q", res.ResourceID)
	}
	if res.Kind != "lock" {
		return fmt.Errorf("haepari resource: unexpected kind %q", res.Kind)
	}
	if res.Capacity != 1 {
		return fmt.Errorf("haepari resource: unexpected capacity %d", res.Capacity)
	}
	if !ValidHaepariDigest(res.ConfigurationDigest) {
		return fmt.Errorf("haepari resource: invalid configuration_digest")
	}
	if res.ConfigRevision <= 0 {
		return fmt.Errorf("haepari resource: invalid config_revision %d", res.ConfigRevision)
	}
	if res.AvailabilityRevision < 0 {
		return fmt.Errorf("haepari resource: negative availability_revision %d", res.AvailabilityRevision)
	}
	if res.Availability != "available" && res.Availability != "paused" {
		return fmt.Errorf("haepari resource: unexpected availability %q", res.Availability)
	}
	if res.Occupancy < 0 || res.AdvisoryGrants < 0 || res.AdvisoryQueued < 0 || res.LeaseGeneration < 0 {
		return fmt.Errorf("haepari resource: negative resource counters")
	}
	return nil
}

type ReviewLockRequestPayload struct {
	LockID              string
	RequestKey          string
	Holder              string
	QueueSeconds        *int64
	CanonicalJSON       []byte
	PayloadSHA256       string
	NativePayloadDigest string
}

func NewReviewLockRequestPayload(sessionID domain.SessionID, runID domain.RunID, queueSeconds *int64) (ReviewLockRequestPayload, error) {
	if !validSessionID(sessionID) {
		return ReviewLockRequestPayload{}, fmt.Errorf("review lock payload: invalid session ID")
	}
	if !validRunID(runID) {
		return ReviewLockRequestPayload{}, fmt.Errorf("review lock payload: invalid run ID")
	}
	requestKey := "mulgae-" + runID.String()
	holder := "mulgae:" + sessionID.String() + ":" + runID.String()
	var queueCopy *int64
	if queueSeconds != nil {
		if *queueSeconds < 1 || *queueSeconds > HaepariMaxQueueSeconds {
			return ReviewLockRequestPayload{}, fmt.Errorf("review lock payload: queue_seconds %d out of range [1, %d]", *queueSeconds, HaepariMaxQueueSeconds)
		}
		v := *queueSeconds
		queueCopy = &v
	}
	wire := artifactwire.HaepariLockPayloadWire{
		LockID:       HaepariReviewResourceID,
		RequestKey:   requestKey,
		Holder:       holder,
		QueueSeconds: queueCopy,
	}
	canonical, err := json.Marshal(wire)
	if err != nil {
		return ReviewLockRequestPayload{}, fmt.Errorf("review lock payload: marshal canonical JSON: %w", err)
	}
	sum := sha256.Sum256(canonical)
	nativeHex := hex.EncodeToString(sum[:])
	payload := ReviewLockRequestPayload{
		LockID:              HaepariReviewResourceID,
		RequestKey:          requestKey,
		Holder:              holder,
		QueueSeconds:        queueCopy,
		CanonicalJSON:       canonical,
		PayloadSHA256:       "sha256:" + nativeHex,
		NativePayloadDigest: nativeHex,
	}
	if err := payload.ValidateForIdentity(sessionID, runID); err != nil {
		return ReviewLockRequestPayload{}, err
	}
	return payload, nil
}

func (payload ReviewLockRequestPayload) ValidateForIdentity(sessionID domain.SessionID, runID domain.RunID) error {
	if !validSessionID(sessionID) || !validRunID(runID) {
		return fmt.Errorf("review lock payload: invalid session or run identity")
	}
	if payload.LockID != HaepariReviewResourceID {
		return fmt.Errorf("review lock payload: unexpected lock_id %q", payload.LockID)
	}
	wantKey := "mulgae-" + runID.String()
	if payload.RequestKey != wantKey || !ValidHaepariIdentifier(payload.RequestKey) {
		return fmt.Errorf("review lock payload: request_key %q does not match %q", payload.RequestKey, wantKey)
	}
	wantHolder := "mulgae:" + sessionID.String() + ":" + runID.String()
	if payload.Holder != wantHolder || !ValidHaepariHolder(payload.Holder) {
		return fmt.Errorf("review lock payload: holder %q does not match %q", payload.Holder, wantHolder)
	}
	if payload.QueueSeconds != nil && (*payload.QueueSeconds < 1 || *payload.QueueSeconds > HaepariMaxQueueSeconds) {
		return fmt.Errorf("review lock payload: invalid queue_seconds %d", *payload.QueueSeconds)
	}
	expectedWire := artifactwire.HaepariLockPayloadWire{
		LockID:       payload.LockID,
		RequestKey:   payload.RequestKey,
		Holder:       payload.Holder,
		QueueSeconds: payload.QueueSeconds,
	}
	expectedBytes, err := json.Marshal(expectedWire)
	if err != nil {
		return fmt.Errorf("review lock payload: marshal verification JSON: %w", err)
	}
	if !bytes.Equal(payload.CanonicalJSON, expectedBytes) {
		return fmt.Errorf("review lock payload: canonical JSON bytes do not match payload fields")
	}
	sum := sha256.Sum256(payload.CanonicalJSON)
	nativeHex := hex.EncodeToString(sum[:])
	if payload.NativePayloadDigest != "" && payload.NativePayloadDigest != nativeHex {
		return fmt.Errorf("review lock payload: native digest mismatch")
	}
	if payload.PayloadSHA256 != "sha256:"+nativeHex {
		return fmt.Errorf("review lock payload: payload_sha256 mismatch")
	}
	return nil
}

type ReviewLockReceipt struct {
	Operation  ReviewLockReceiptOperation
	RequestID  string
	GrantID    string
	State      ReviewLockState
	RecordedAt time.Time
	Force      bool
	Reason     string
}

func (receipt ReviewLockReceipt) Validate() error {
	if !receipt.Operation.Valid() {
		return fmt.Errorf("review lock receipt: invalid operation %q", receipt.Operation)
	}
	if !ValidHaepariIdentifier(receipt.RequestID) {
		return fmt.Errorf("review lock receipt: invalid request_id %q", receipt.RequestID)
	}
	if !receipt.State.Valid() {
		return fmt.Errorf("review lock receipt: invalid state %q", receipt.State)
	}
	if receipt.RecordedAt.IsZero() {
		return fmt.Errorf("review lock receipt: missing recorded_at")
	}
	if len(receipt.Reason) > HaepariMaxHolderBytes {
		return fmt.Errorf("review lock receipt: reason exceeds %d bytes", HaepariMaxHolderBytes)
	}
	if receipt.Force && strings.TrimSpace(receipt.Reason) == "" {
		return fmt.Errorf("review lock receipt: forced receipt requires reason")
	}
	if receipt.State.WasGranted() {
		if !ValidHaepariIdentifier(receipt.GrantID) {
			return fmt.Errorf("review lock receipt: state %q requires valid grant_id", receipt.State)
		}
	} else if receipt.GrantID != "" {
		return fmt.Errorf("review lock receipt: state %q must not carry grant_id %q", receipt.State, receipt.GrantID)
	}

	switch receipt.Operation {
	case ReviewLockReceiptOperationAcquire, ReviewLockReceiptOperationClaim, ReviewLockReceiptOperationRenew:
		if receipt.State != ReviewLockStateQueued && receipt.State != ReviewLockStateGranted {
			return fmt.Errorf("review lock receipt: operation %q incompatible with state %q", receipt.Operation, receipt.State)
		}
	case ReviewLockReceiptOperationRelease, ReviewLockReceiptOperationCancel:
		if receipt.State != ReviewLockStateReleased && receipt.State != ReviewLockStateCancelled {
			return fmt.Errorf("review lock receipt: operation %q incompatible with state %q", receipt.Operation, receipt.State)
		}
	case ReviewLockReceiptOperationExpire:
		if receipt.State != ReviewLockStateQueueExpired && receipt.State != ReviewLockStateHoldExpired {
			return fmt.Errorf("review lock receipt: operation %q incompatible with state %q", receipt.Operation, receipt.State)
		}
	}
	return nil
}

type ReviewLockRequest struct {
	InstallationID   string
	LockID           string
	RequestID        string
	RequestKey       string
	Holder           string
	State            ReviewLockState
	Sequence         int64
	GrantID          string
	Generation       int64
	Slot             int
	QueuedAt         time.Time
	QueueDeadline    *time.Time
	GrantedAt        *time.Time
	LivenessDeadline *time.Time
	MaxHoldDeadline  *time.Time
	LivenessSeconds  int64
	MaxHoldSeconds   int64
	EndedAt          *time.Time
	Reason           string
	Forced           bool
}

func (req ReviewLockRequest) Validate() error {
	if !ValidHaepariIdentifier(req.InstallationID) {
		return fmt.Errorf("review lock request: invalid installation_id %q", req.InstallationID)
	}
	if req.LockID != HaepariReviewResourceID {
		return fmt.Errorf("review lock request: unexpected lock_id %q", req.LockID)
	}
	if !ValidHaepariIdentifier(req.RequestID) {
		return fmt.Errorf("review lock request: invalid request_id %q", req.RequestID)
	}
	if !ValidHaepariIdentifier(req.RequestKey) {
		return fmt.Errorf("review lock request: invalid request_key %q", req.RequestKey)
	}
	if !ValidHaepariHolder(req.Holder) {
		return fmt.Errorf("review lock request: invalid holder")
	}
	if len(req.Reason) > HaepariMaxHolderBytes {
		return fmt.Errorf("review lock request: reason exceeds %d bytes", HaepariMaxHolderBytes)
	}
	if !req.State.Valid() {
		return fmt.Errorf("review lock request: invalid state %q", req.State)
	}
	if req.Sequence <= 0 {
		return fmt.Errorf("review lock request: invalid sequence %d", req.Sequence)
	}
	if req.QueuedAt.IsZero() {
		return fmt.Errorf("review lock request: missing queued_at")
	}
	if req.QueueDeadline != nil && req.QueueDeadline.IsZero() {
		return fmt.Errorf("review lock request: zero queue_deadline")
	}

	switch req.State {
	case ReviewLockStateQueued:
		if req.Slot != -1 {
			return fmt.Errorf("review lock request: queued state requires slot -1, got %d", req.Slot)
		}
		if req.GrantID != "" || req.Generation != 0 {
			return fmt.Errorf("review lock request: queued state must not carry grant_id or generation")
		}
		if req.GrantedAt != nil || req.LivenessDeadline != nil || req.MaxHoldDeadline != nil || req.EndedAt != nil {
			return fmt.Errorf("review lock request: queued state must not carry grant or end timestamps")
		}
	case ReviewLockStateGranted:
		if err := req.validateGrantMetadata(); err != nil {
			return err
		}
		if req.EndedAt != nil {
			return fmt.Errorf("review lock request: granted state must not carry ended_at")
		}
	case ReviewLockStateReleased, ReviewLockStateHoldExpired:
		if err := req.validateGrantMetadata(); err != nil {
			return err
		}
		if req.EndedAt == nil || req.EndedAt.IsZero() {
			return fmt.Errorf("review lock request: terminal state %q requires ended_at", req.State)
		}
	case ReviewLockStateCancelled, ReviewLockStateQueueExpired:
		if req.Slot != -1 {
			return fmt.Errorf("review lock request: state %q requires slot -1, got %d", req.State, req.Slot)
		}
		if req.GrantID != "" || req.Generation != 0 || req.GrantedAt != nil {
			return fmt.Errorf("review lock request: state %q must not carry grant metadata", req.State)
		}
		if req.EndedAt == nil || req.EndedAt.IsZero() {
			return fmt.Errorf("review lock request: terminal state %q requires ended_at", req.State)
		}
	}
	return nil
}

func (req ReviewLockRequest) validateGrantMetadata() error {
	if req.Slot != 0 {
		return fmt.Errorf("review lock request: state %q requires slot 0, got %d", req.State, req.Slot)
	}
	if !ValidHaepariIdentifier(req.GrantID) {
		return fmt.Errorf("review lock request: state %q requires valid grant_id", req.State)
	}
	if req.Generation < 1 {
		return fmt.Errorf("review lock request: state %q requires generation >= 1, got %d", req.State, req.Generation)
	}
	if req.GrantedAt == nil || req.GrantedAt.IsZero() {
		return fmt.Errorf("review lock request: state %q requires granted_at", req.State)
	}
	if req.LivenessDeadline == nil || req.LivenessDeadline.IsZero() {
		return fmt.Errorf("review lock request: state %q requires liveness_deadline", req.State)
	}
	if req.MaxHoldDeadline == nil || req.MaxHoldDeadline.IsZero() {
		return fmt.Errorf("review lock request: state %q requires max_hold_deadline", req.State)
	}
	if req.LivenessSeconds <= 0 || req.MaxHoldSeconds <= 0 {
		return fmt.Errorf("review lock request: state %q requires positive liveness_seconds and max_hold_seconds", req.State)
	}
	return nil
}

type ReviewLockReply struct {
	Receipt ReviewLockReceipt
	Current ReviewLockRequest
}

// Validate checks each component and the native transition relationship between
// Receipt and Current. On AcquireLock replay, Receipt is the stored original
// acquire_receipt while Current is the live or terminal request; on terminal
// Release/Cancel/Wait replay, Receipt is the stored end_receipt whose operation
// records whichever terminal transition ended the request.
func (reply ReviewLockReply) Validate(envelopeOp ReviewLockOperation) error {
	if err := reply.Receipt.Validate(); err != nil {
		return err
	}
	if err := reply.Current.Validate(); err != nil {
		return err
	}
	if reply.Receipt.RequestID != reply.Current.RequestID {
		return fmt.Errorf("review lock reply: receipt request_id %q does not match current %q", reply.Receipt.RequestID, reply.Current.RequestID)
	}

	switch envelopeOp {
	case "":
	case ReviewLockOperationAcquire:
		if reply.Receipt.Operation != ReviewLockReceiptOperationAcquire {
			return fmt.Errorf("review lock reply: lock.acquire requires receipt operation %q, got %q", ReviewLockReceiptOperationAcquire, reply.Receipt.Operation)
		}
	case ReviewLockOperationWait:
		switch reply.Receipt.Operation {
		case ReviewLockReceiptOperationClaim,
			ReviewLockReceiptOperationRelease,
			ReviewLockReceiptOperationCancel,
			ReviewLockReceiptOperationExpire:
		default:
			return fmt.Errorf("review lock reply: lock.wait incompatible with receipt operation %q", reply.Receipt.Operation)
		}
	case ReviewLockOperationRenew:
		if reply.Receipt.Operation != ReviewLockReceiptOperationRenew {
			return fmt.Errorf("review lock reply: lock.renew requires receipt operation %q, got %q", ReviewLockReceiptOperationRenew, reply.Receipt.Operation)
		}
	case ReviewLockOperationRelease, ReviewLockOperationCancel:
		switch reply.Receipt.Operation {
		case ReviewLockReceiptOperationRelease,
			ReviewLockReceiptOperationCancel,
			ReviewLockReceiptOperationExpire:
		default:
			return fmt.Errorf("review lock reply: %s incompatible with receipt operation %q", envelopeOp, reply.Receipt.Operation)
		}
	default:
		return fmt.Errorf("review lock reply: unsupported envelope operation %q", envelopeOp)
	}

	if reply.Receipt.Operation == ReviewLockReceiptOperationAcquire {
		if reply.Receipt.State == ReviewLockStateGranted {
			if !reply.Current.State.WasGranted() {
				return fmt.Errorf("review lock reply: granted acquire receipt incompatible with current state %q", reply.Current.State)
			}
			if reply.Current.GrantID != reply.Receipt.GrantID {
				return fmt.Errorf("review lock reply: granted acquire receipt grant_id %q does not match current %q", reply.Receipt.GrantID, reply.Current.GrantID)
			}
		}
		return nil
	}

	if reply.Receipt.State != reply.Current.State {
		return fmt.Errorf("review lock reply: receipt state %q does not match current %q for operation %q", reply.Receipt.State, reply.Current.State, reply.Receipt.Operation)
	}
	if reply.Receipt.GrantID != reply.Current.GrantID {
		return fmt.Errorf("review lock reply: receipt grant_id %q does not match current %q for operation %q", reply.Receipt.GrantID, reply.Current.GrantID, reply.Receipt.Operation)
	}
	return nil
}

type ReviewLockList struct {
	InstallationID string
	Now            time.Time
	Requests       []ReviewLockRequest
	More           bool
	NextCursor     string
}

func (list ReviewLockList) Validate(expectedInstallationID string) error {
	if !ValidHaepariIdentifier(list.InstallationID) {
		return fmt.Errorf("review lock list: invalid installation_id %q", list.InstallationID)
	}
	if expectedInstallationID != "" && list.InstallationID != expectedInstallationID {
		return fmt.Errorf("review lock list: installation_id %q does not match expected %q", list.InstallationID, expectedInstallationID)
	}
	if list.Now.IsZero() {
		return fmt.Errorf("review lock list: missing now timestamp")
	}
	if list.More && list.NextCursor == "" {
		return fmt.Errorf("review lock list: more=true requires next_cursor")
	}
	if !list.More && list.NextCursor != "" {
		return fmt.Errorf("review lock list: more=false must not set next_cursor")
	}
	for i, req := range list.Requests {
		if err := req.Validate(); err != nil {
			return fmt.Errorf("review lock list: request[%d]: %w", i, err)
		}
		if req.InstallationID != list.InstallationID {
			return fmt.Errorf("review lock list: request[%d] installation_id %q does not match list %q", i, req.InstallationID, list.InstallationID)
		}
	}
	return nil
}

type ReviewLockGrantReference struct {
	SessionID        domain.SessionID
	RunID            domain.RunID
	InstallationID   string
	ResourceID       string
	RequestKey       string
	Holder           string
	RequestID        string
	GrantID          string
	Generation       int64
	Slot             int
	GrantedAt        time.Time
	LivenessDeadline time.Time
	MaxHoldDeadline  time.Time
	LivenessSeconds  int64
	MaxHoldSeconds   int64
}

func (ref ReviewLockGrantReference) Validate() error {
	if !validSessionID(ref.SessionID) || !validRunID(ref.RunID) {
		return fmt.Errorf("review lock grant reference: invalid session or run identity")
	}
	if !ValidHaepariIdentifier(ref.InstallationID) {
		return fmt.Errorf("review lock grant reference: invalid installation_id %q", ref.InstallationID)
	}
	if ref.ResourceID != HaepariReviewResourceID {
		return fmt.Errorf("review lock grant reference: unexpected resource_id %q", ref.ResourceID)
	}
	if ref.RequestKey != "mulgae-"+ref.RunID.String() {
		return fmt.Errorf("review lock grant reference: unexpected request_key %q", ref.RequestKey)
	}
	if ref.Holder != "mulgae:"+ref.SessionID.String()+":"+ref.RunID.String() {
		return fmt.Errorf("review lock grant reference: unexpected holder %q", ref.Holder)
	}
	if !ValidHaepariIdentifier(ref.RequestID) || !ValidHaepariIdentifier(ref.GrantID) {
		return fmt.Errorf("review lock grant reference: invalid request_id or grant_id")
	}
	if ref.Generation < 1 || ref.Slot != 0 {
		return fmt.Errorf("review lock grant reference: invalid generation %d or slot %d", ref.Generation, ref.Slot)
	}
	if ref.GrantedAt.IsZero() || ref.LivenessDeadline.IsZero() || ref.MaxHoldDeadline.IsZero() {
		return fmt.Errorf("review lock grant reference: missing grant timestamps")
	}
	if ref.LivenessSeconds <= 0 || ref.MaxHoldSeconds <= 0 {
		return fmt.Errorf("review lock grant reference: non-positive lease durations")
	}
	return nil
}

type ReviewLockRecord struct {
	SchemaVersion   string
	SessionID       domain.SessionID
	RunID           domain.RunID
	InstallationID  string
	ResourceID      string
	Payload         ReviewLockRequestPayload
	PersistedAt     time.Time
	UpdatedAt       time.Time
	ObservedReceipt *ReviewLockReceipt
	ObservedRequest *ReviewLockRequest
}

func (record ReviewLockRecord) Validate() error {
	if record.SchemaVersion != artifactwire.HaepariLockIntentSchemaV1 {
		return fmt.Errorf("review lock record: unexpected schema_version %q", record.SchemaVersion)
	}
	if !validSessionID(record.SessionID) || !validRunID(record.RunID) {
		return fmt.Errorf("review lock record: invalid session or run identity")
	}
	if !ValidHaepariIdentifier(record.InstallationID) {
		return fmt.Errorf("review lock record: invalid installation_id %q", record.InstallationID)
	}
	if record.ResourceID != HaepariReviewResourceID {
		return fmt.Errorf("review lock record: unexpected resource_id %q", record.ResourceID)
	}
	if err := record.Payload.ValidateForIdentity(record.SessionID, record.RunID); err != nil {
		return fmt.Errorf("review lock record: %w", err)
	}
	if record.PersistedAt.IsZero() || record.UpdatedAt.IsZero() || record.UpdatedAt.Before(record.PersistedAt) {
		return fmt.Errorf("review lock record: invalid persisted_at or updated_at timestamps")
	}
	if (record.ObservedReceipt == nil) != (record.ObservedRequest == nil) {
		return fmt.Errorf("review lock record: observed_receipt and observed_request must be present together")
	}
	if record.ObservedReceipt != nil {
		reply := ReviewLockReply{
			Receipt: *record.ObservedReceipt,
			Current: *record.ObservedRequest,
		}
		if err := reply.Validate(""); err != nil {
			return fmt.Errorf("review lock record: invalid observation: %w", err)
		}
		if record.ObservedRequest.InstallationID != record.InstallationID {
			return fmt.Errorf("review lock record: observed installation_id %q does not match %q", record.ObservedRequest.InstallationID, record.InstallationID)
		}
		if record.ObservedRequest.LockID != record.ResourceID {
			return fmt.Errorf("review lock record: observed lock_id %q does not match %q", record.ObservedRequest.LockID, record.ResourceID)
		}
		if record.ObservedRequest.RequestKey != record.Payload.RequestKey {
			return fmt.Errorf("review lock record: observed request_key %q does not match %q", record.ObservedRequest.RequestKey, record.Payload.RequestKey)
		}
		if record.ObservedRequest.Holder != record.Payload.Holder {
			return fmt.Errorf("review lock record: observed holder %q does not match %q", record.ObservedRequest.Holder, record.Payload.Holder)
		}
	}
	return nil
}

func (record ReviewLockRecord) GrantReference() (ReviewLockGrantReference, bool) {
	if record.ObservedRequest == nil || record.ObservedRequest.State != ReviewLockStateGranted {
		return ReviewLockGrantReference{}, false
	}
	req := record.ObservedRequest
	if req.GrantedAt == nil || req.LivenessDeadline == nil || req.MaxHoldDeadline == nil {
		return ReviewLockGrantReference{}, false
	}
	ref := ReviewLockGrantReference{
		SessionID:        record.SessionID,
		RunID:            record.RunID,
		InstallationID:   record.InstallationID,
		ResourceID:       record.ResourceID,
		RequestKey:       record.Payload.RequestKey,
		Holder:           record.Payload.Holder,
		RequestID:        req.RequestID,
		GrantID:          req.GrantID,
		Generation:       req.Generation,
		Slot:             req.Slot,
		GrantedAt:        *req.GrantedAt,
		LivenessDeadline: *req.LivenessDeadline,
		MaxHoldDeadline:  *req.MaxHoldDeadline,
		LivenessSeconds:  req.LivenessSeconds,
		MaxHoldSeconds:   req.MaxHoldSeconds,
	}
	if err := ref.Validate(); err != nil {
		return ReviewLockGrantReference{}, false
	}
	return ref, true
}

type ReviewCoordinationReason string

const (
	ReviewCoordinationReasonInstallationNotSelected  ReviewCoordinationReason = "haepari_installation_not_selected"
	ReviewCoordinationReasonParentContextInvalid     ReviewCoordinationReason = "haepari_parent_context_invalid"
	ReviewCoordinationReasonControllerUnreachable    ReviewCoordinationReason = "haepari_controller_unreachable"
	ReviewCoordinationReasonProtocolIncompatible     ReviewCoordinationReason = "haepari_protocol_incompatible"
	ReviewCoordinationReasonInstallationMismatch     ReviewCoordinationReason = "haepari_installation_mismatch"
	ReviewCoordinationReasonCapabilityUnsupported    ReviewCoordinationReason = "haepari_capability_unsupported"
	ReviewCoordinationReasonResourceInvalid          ReviewCoordinationReason = "haepari_resource_invalid"
	ReviewCoordinationReasonPersistenceRefused       ReviewCoordinationReason = "haepari_persistence_refused"
	ReviewCoordinationReasonObservationPersistFailed ReviewCoordinationReason = "haepari_observation_persist_failed"
	ReviewCoordinationReasonAcquireConflict          ReviewCoordinationReason = "haepari_acquire_conflict"
	ReviewCoordinationReasonAcquireInvalid           ReviewCoordinationReason = "haepari_acquire_invalid"
	ReviewCoordinationReasonAcquireOverloaded        ReviewCoordinationReason = "haepari_acquire_overloaded"
	ReviewCoordinationReasonAcquireUncertain         ReviewCoordinationReason = "haepari_acquire_uncertain"
	ReviewCoordinationReasonQueueExpired             ReviewCoordinationReason = "haepari_queue_expired"
	ReviewCoordinationReasonHoldExpired              ReviewCoordinationReason = "haepari_hold_expired"
	ReviewCoordinationReasonLockCancelled            ReviewCoordinationReason = "haepari_lock_cancelled"
	ReviewCoordinationReasonLockReleased             ReviewCoordinationReason = "haepari_lock_released"
	ReviewCoordinationReasonLockStateConflict        ReviewCoordinationReason = "haepari_lock_state_conflict"
	ReviewCoordinationReasonLockNotFound             ReviewCoordinationReason = "haepari_lock_not_found"
	ReviewCoordinationReasonContextCancelled         ReviewCoordinationReason = "haepari_context_cancelled"
)

type ReviewLockNativeRetry string

const (
	ReviewLockNativeRetryNone      ReviewLockNativeRetry = "none"
	ReviewLockNativeRetrySameKey   ReviewLockNativeRetry = "retry_same_key"
	ReviewLockNativeRetryReconcile ReviewLockNativeRetry = "reconcile"
)

func (retry ReviewLockNativeRetry) Valid() bool {
	switch retry {
	case ReviewLockNativeRetryNone, ReviewLockNativeRetrySameKey, ReviewLockNativeRetryReconcile:
		return true
	default:
		return false
	}
}

type ReviewCoordinationRetryHint string

const (
	ReviewCoordinationRetryNever         ReviewCoordinationRetryHint = "never"
	ReviewCoordinationRetryNone          ReviewCoordinationRetryHint = "none"
	ReviewCoordinationRetrySameKey       ReviewCoordinationRetryHint = "retry_same_key"
	ReviewCoordinationRetryReconcile     ReviewCoordinationRetryHint = "reconcile"
	ReviewCoordinationRetryAfterBackoff  ReviewCoordinationRetryHint = "after_backoff"
	ReviewCoordinationRetryWhenAvailable ReviewCoordinationRetryHint = "when_available"
	ReviewCoordinationRetryInspectFirst  ReviewCoordinationRetryHint = "inspect_first"
)

type ReviewCoordinationError struct {
	Reason      ReviewCoordinationReason
	Operation   ReviewLockOperation
	NativeCode  string
	NativeRetry ReviewLockNativeRetry
	Retry       ReviewCoordinationRetryHint
	Uncertain   bool
	Message     string
	KnownRecord *ReviewLockRecord
	KnownReply  *ReviewLockReply
	Cause       error
}

func (err *ReviewCoordinationError) Error() string {
	if err == nil {
		return ""
	}
	base := fmt.Sprintf("review coordination (%s)", err.Reason)
	if err.Operation != "" {
		base += fmt.Sprintf(" [%s]", err.Operation)
	}
	if err.NativeCode != "" {
		base += fmt.Sprintf(" code=%s", err.NativeCode)
	}
	if err.NativeRetry != "" {
		base += fmt.Sprintf(" native_retry=%s", err.NativeRetry)
	}
	if err.Message != "" {
		base += ": " + err.Message
	}
	return base
}

func (err *ReviewCoordinationError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

type ReviewCoordinationIntentStore interface {
	LoadIntent(ctx context.Context, root AnchoredRoot, sessionID domain.SessionID, runID domain.RunID) (ReviewLockRecord, bool, error)
	PersistIntent(ctx context.Context, root AnchoredRoot, record ReviewLockRecord) (ReviewLockRecord, error)
	UpdateObservation(ctx context.Context, root AnchoredRoot, sessionID domain.SessionID, runID domain.RunID, reply ReviewLockReply, updatedAt time.Time) (ReviewLockRecord, error)
}

type ReviewLockTransport interface {
	Hello(ctx context.Context) (ReviewLockInstallation, error)
	InspectResource(ctx context.Context, resourceID string) (ReviewLockResource, error)
	Acquire(ctx context.Context, canonicalPayload []byte) (ReviewLockReply, error)
	Wait(ctx context.Context, requestID string, timeout time.Duration) (ReviewLockReply, error)
	Renew(ctx context.Context, grantID string) (ReviewLockReply, error)
	Release(ctx context.Context, grantID string) (ReviewLockReply, error)
	Cancel(ctx context.Context, requestID string) (ReviewLockReply, error)
	ListLocks(ctx context.Context, lockID string, cursor string, limit int) (ReviewLockList, error)
}
