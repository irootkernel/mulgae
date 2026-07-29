// Package jsonschema adapts immutable contract-catalog JSON assets to the
// JSON Schema validator without exposing the JSON Schema library to domain code.
package jsonschema

import "github.com/irootkernel/mulgae/internal/ports"

// MaxInputBytes is the maximum size of one JSON instance accepted by Validate.
// The finite 8 MiB limit bounds decoding and schema-validation memory use.
const MaxInputBytes = 8 << 20

const (
	providerContractEvidenceV2ID = "https://mulgae.local/schemas/mulgae-provider-contract-evidence.v2.schema.json"
	platformContractEvidenceV2ID = "https://mulgae.local/schemas/mulgae-platform-contract-evidence.v2.schema.json"
)

// ReadinessAuthority reports whether schemaID is an authoritative readiness
// contract. Only the provider and platform v2 evidence schemas are authority;
// v1 evidence remains validation-compatible but is never authoritative.
func ReadinessAuthority(schemaID ports.AssetID) bool {
	switch schemaID.String() {
	case providerContractEvidenceV2ID, platformContractEvidenceV2ID:
		return true
	default:
		return false
	}
}
