package artifactwire

const (
	HaepariLockIntentSchemaV1 = "mulgae-haepari-lock-intent.v1"
	HaepariLockIntentSchemaV2 = "mulgae-haepari-lock-intent.v2"
)

type HaepariLockPayloadWire struct {
	LockID       string `json:"lock_id"`
	RequestKey   string `json:"request_key"`
	Holder       string `json:"holder"`
	QueueSeconds *int64 `json:"queue_seconds,omitempty"`
}

type HaepariLockReceiptWire struct {
	Operation  string `json:"operation"`
	RequestID  string `json:"request_id"`
	GrantID    string `json:"grant_id,omitempty"`
	State      string `json:"state"`
	RecordedAt string `json:"recorded_at"`
	Force      bool   `json:"force,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type HaepariLockRequestWire struct {
	InstallationID   string  `json:"installation_id"`
	LockID           string  `json:"lock_id"`
	RequestID        string  `json:"request_id"`
	RequestKey       string  `json:"request_key"`
	Holder           string  `json:"holder"`
	State            string  `json:"state"`
	Sequence         int64   `json:"sequence"`
	GrantID          string  `json:"grant_id,omitempty"`
	Generation       int64   `json:"generation,omitempty"`
	Slot             int     `json:"slot"`
	QueuedAt         string  `json:"queued_at"`
	QueueDeadline    *string `json:"queue_deadline,omitempty"`
	GrantedAt        *string `json:"granted_at,omitempty"`
	LivenessDeadline *string `json:"liveness_deadline,omitempty"`
	MaxHoldDeadline  *string `json:"max_hold_deadline,omitempty"`
	LivenessSeconds  int64   `json:"liveness_seconds,omitempty"`
	MaxHoldSeconds   int64   `json:"max_hold_seconds,omitempty"`
	EndedAt          *string `json:"ended_at,omitempty"`
	Reason           string  `json:"reason,omitempty"`
	Forced           bool    `json:"forced,omitempty"`
}

type HaepariLockIntentWire struct {
	SchemaVersion   string                  `json:"schema_version"`
	SessionID       string                  `json:"session_id"`
	RunID           string                  `json:"run_id"`
	InstallationID  string                  `json:"installation_id"`
	ResourceID      string                  `json:"resource_id"`
	Payload         HaepariLockPayloadWire  `json:"payload"`
	PayloadJSON     string                  `json:"payload_json"`
	PayloadSHA256   string                  `json:"payload_sha256"`
	PersistedAt     string                  `json:"persisted_at"`
	UpdatedAt       string                  `json:"updated_at"`
	ObservedReceipt *HaepariLockReceiptWire `json:"observed_receipt,omitempty"`
	ObservedRequest *HaepariLockRequestWire `json:"observed_request,omitempty"`
}

type HaepariLockIntentWireV2 struct {
	HaepariLockIntentWire
	LocalDrainState string `json:"local_drain_state"`
}
