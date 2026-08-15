// Package jsonschema adapts immutable contract-catalog JSON assets to the
// JSON Schema validator without exposing the JSON Schema library to domain code.
package jsonschema

import "github.com/irootkernel/mulgae/internal/ports"

// MaxInputBytes is the maximum size of one JSON instance accepted by Validate.
// The finite 8 MiB limit bounds decoding and schema-validation memory use.
const MaxInputBytes = 8 << 20

const (
	providerContractEvidenceID = "https://mulgae.local/schemas/mulgae-provider-contract-evidence.v2.schema.json"
	platformContractEvidenceID = "https://mulgae.local/schemas/mulgae-platform-contract-evidence.v1.schema.json"
)

// ReadinessAuthority reports whether schemaID is an authoritative readiness
// contract. Only the provider and platform v1 evidence schemas are authority.
func ReadinessAuthority(schemaID ports.AssetID) bool {
	switch schemaID.String() {
	case providerContractEvidenceID, platformContractEvidenceID:
		return true
	default:
		return false
	}
}
