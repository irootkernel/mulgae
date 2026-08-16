// Package heartbeat owns the explicitly authorized live provider diagnostic.
package heartbeat

import (
	"fmt"
	"time"
)

const SchemaVersion = "mulgae-provider-heartbeat-result.v1"

type Request struct {
	ProviderID        string
	CredentialProfile string
}

type Result struct {
	SchemaVersion          string    `json:"schema_version"`
	CheckedAt              time.Time `json:"checked_at"`
	ProviderID             string    `json:"provider_id"`
	CredentialProfile      string    `json:"credential_profile"`
	Attempted              bool      `json:"attempted"`
	Status                 string    `json:"status"`
	ReasonCode             string    `json:"reason_code"`
	AuthenticationMayOccur bool      `json:"authentication_may_occur"`
	NetworkMayOccur        bool      `json:"network_may_occur"`
	CostMayOccur           bool      `json:"cost_may_occur"`
	RemoteLoggingMayOccur  bool      `json:"remote_logging_may_occur"`
}

func (result Result) Validate() error {
	if result.SchemaVersion != SchemaVersion || result.CheckedAt.IsZero() || result.ProviderID == "" || result.ReasonCode == "" {
		return fmt.Errorf("heartbeat result: invalid identity")
	}
	switch result.Status {
	case "succeeded", "provider_failure", "timeout", "authentication_failure", "malformed_response":
		if !result.Attempted {
			return fmt.Errorf("heartbeat result: attempted status without attempt")
		}
	case "execution_failure":
		// Local preparation may fail before the provider process is launched.
		// Attempted remains the authoritative live-request signal.
	case "not_authorized":
		if result.Attempted || result.ReasonCode != "live_authorization_required" {
			return fmt.Errorf("heartbeat result: invalid authorization rejection")
		}
	default:
		return fmt.Errorf("heartbeat result: invalid status")
	}
	if !result.AuthenticationMayOccur || !result.NetworkMayOccur || !result.CostMayOccur || !result.RemoteLoggingMayOccur {
		return fmt.Errorf("heartbeat result: incomplete effects disclosure")
	}
	return nil
}
