package query

import "fmt"

// VerifiedReadCapabilities is a closed version advertisement. An empty field
// means unavailable; a consumer must not infer support from a binary version.
type VerifiedReadCapabilities struct {
	ProjectBinding    string `json:"project_binding"`
	ExecutionGuard    string `json:"execution_guard"`
	CaptureIdentity   string `json:"capture_identity"`
	Inspection        string `json:"inspection"`
	FindingPages      string `json:"finding_pages"`
	FindingDetails    string `json:"finding_details"`
	ReportContent     string `json:"report_content"`
	IndexedEvidence   string `json:"indexed_evidence"`
	CompositeEvidence string `json:"composite_evidence"`
}

func (capabilities VerifiedReadCapabilities) Validate() error {
	for _, version := range []string{capabilities.ProjectBinding, capabilities.ExecutionGuard, capabilities.CaptureIdentity, capabilities.Inspection, capabilities.FindingPages, capabilities.FindingDetails, capabilities.ReportContent, capabilities.IndexedEvidence, capabilities.CompositeEvidence} {
		if version != "" && version != "v1" {
			return fmt.Errorf("contract_unsupported")
		}
	}
	return nil
}

// ImplementedReadCapabilities advertises only wired native read contracts.
func ImplementedReadCapabilities() VerifiedReadCapabilities {
	return VerifiedReadCapabilities{ProjectBinding: "v1", ExecutionGuard: "v1", CaptureIdentity: "v1", Inspection: "v1", FindingPages: "v1", FindingDetails: "v1", ReportContent: "v1", IndexedEvidence: "v1"}
}
