package publication

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// D retains a dynamic encoder; F retains consumer behavior while X retires
// only historical creation. These classifications authorize no M1 removal.
// Every key is explicit, so a new, missing or unclassified golden key fails.
var retainedRuntimeGoldenOwners = map[string]string{
	"built-support-v1": "D:TestRetainedRuntimeWireBytes",
	"built-support-v2": "D:TestRetainedRuntimeWireBytes",
	"built-support-v3": "D:TestRetainedRuntimeWireBytes",
	"identity":         "D:TestRetainedRuntimeWireBytes",
	"prompt-null":      "D:TestRetainedRuntimeWireBytes",
	"prompt-present":   "D:TestRetainedRuntimeWireBytes",
	"runtime/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/prompts/a_019f596a-d048-79e7-b2b7-59822f012273/001-initial.manifest.json": "X/F:TestHistoricalCorpusAttempts+TestRuntimeTargetReconstructsFrozenArchive",
	"runtime/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/prompts/a_019f596a-d048-79e7-b2b7-59822f012273/001-initial.stdin":         "X/F:TestHistoricalCorpusAttempts+TestRuntimeTargetReconstructsFrozenArchive",
	"runtime/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/prompts/a_019f596a-d0ac-7c12-8b68-0bd73e911b2e/001-initial.manifest.json": "X/F:TestHistoricalCorpusAttempts+TestRuntimeTargetReconstructsFrozenArchive",
	"runtime/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/prompts/a_019f596a-d0ac-7c12-8b68-0bd73e911b2e/001-initial.stdin":         "X/F:TestHistoricalCorpusAttempts+TestRuntimeTargetReconstructsFrozenArchive",
	"runtime/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/target/target-manifest.json":                                              "X/F:TestHistoricalCorpusAttempts+TestRuntimeTargetReconstructsFrozenArchive",
	"runtime/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/target/target.bytes":                                                      "X/F:TestHistoricalCorpusAttempts+TestRuntimeTargetReconstructsFrozenArchive",
	"selected-prompt": "D:TestRetainedRuntimeWireBytes",
	"support-empty":   "D:TestRetainedRuntimeWireBytes",
	"support-null":    "D:TestRetainedRuntimeWireBytes",
	"target-absent":   "D:TestRetainedRuntimeWireBytes",
	"target-present":  "D:TestRetainedRuntimeWireBytes",
}
var retainedPublicationGoldenOwners = map[string]string{
	"captured-empty/epoch":    "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-empty/final":    "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-empty/journal":  "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-empty/lineage":  "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-empty/manifest": "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-empty/status":   "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-empty/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/role-reports/logic.md":    "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-empty/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/role-reports/security.md": "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-empty/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/support/index.json":       "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/epoch":    "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/final":    "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/journal":  "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/lineage":  "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/manifest": "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/status":   "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/excerpts/F001.json":       "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/excerpts/F001_1.md":       "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/role-reports/logic.md":    "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/role-reports/security.md": "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"captured-findings/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/support/index.json":       "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/epoch":    "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/final":    "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/journal":  "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/lineage":  "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/manifest": "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/status":   "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/role-reports/logic.md":       "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/support/index.json":          "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/target/target-manifest.json": "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composite/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/target/target.bytes":         "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"composition/false": "D:TestRetainedPublicationDTOBytes",
	"composition/true":  "D:TestRetainedPublicationDTOBytes",
	"corruption/[\"missing_final\",\"candidate_mismatch\"]": "D:TestRetainedPublicationDTOBytes",
	"corruption/[]":        "D:TestRetainedPublicationDTOBytes",
	"corruption/null":      "D:TestRetainedPublicationDTOBytes",
	"custom-finding/false": "D:TestRetainedPublicationDTOBytes",
	"custom-finding/true":  "D:TestRetainedPublicationDTOBytes",
	"custom-role/false":    "D:TestRetainedPublicationDTOBytes",
	"custom-role/true":     "D:TestRetainedPublicationDTOBytes",
	"followup/epoch":       "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/final":       "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/journal":     "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/lineage":     "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/manifest":    "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/status":      "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/attempts/a_019f596a-d048-79e7-b2b7-59822f012273/candidate.initial.json":             "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/attempts/a_019f596a-d048-79e7-b2b7-59822f012273/invocations/001-initial/stdout.raw": "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/attempts/a_019f596a-d048-79e7-b2b7-59822f012273/status.json":                        "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/excerpts/F001.json":                                                                 "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/excerpts/F001_1.md":                                                                 "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/prompts/a_019f596a-d048-79e7-b2b7-59822f012273/001-initial.manifest.json":           "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/prompts/a_019f596a-d048-79e7-b2b7-59822f012273/001-initial.stdin":                   "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/role-reports/logic.md":                                                              "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/support/index.json":                                                                 "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/target/target-manifest.json":                                                        "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"followup/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/target/target.bytes":                                                                "X/F:TestHistoricalCorpusRead+TestCompositeRecoveryReencodesFrozenCanonicalManifest+TestIntegrationHistoricalCorpusConsumers",
	"journal/collecting":           "D:TestRetainedPublicationDTOBytes",
	"journal/completed":            "D:TestRetainedPublicationDTOBytes",
	"journal/content_validated":    "D:TestRetainedPublicationDTOBytes",
	"journal/final_file_installed": "D:TestRetainedPublicationDTOBytes",
	"journal/final_staged":         "D:TestRetainedPublicationDTOBytes",
	"journal/manifest_committed":   "D:TestRetainedPublicationDTOBytes",
	"live-empty/epoch":             "D:TestRetainedLiveGoldenBytes",
	"live-empty/final":             "D:TestRetainedLiveGoldenBytes",
	"live-empty/journal":           "D:TestRetainedLiveGoldenBytes",
	"live-empty/lineage":           "D:TestRetainedLiveGoldenBytes",
	"live-empty/manifest":          "D:TestRetainedLiveGoldenBytes",
	"live-empty/status":            "D:TestRetainedLiveGoldenBytes",
	"live-empty/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/source/source.json": "D:TestRetainedLiveGoldenBytes",
	"live-empty/support/s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/support/index.json": "D:TestRetainedLiveGoldenBytes",
	"live-findings/epoch":    "D:TestRetainedLiveGoldenBytes",
	"live-findings/final":    "D:TestRetainedLiveGoldenBytes",
	"live-findings/journal":  "D:TestRetainedLiveGoldenBytes",
	"live-findings/lineage":  "D:TestRetainedLiveGoldenBytes",
	"live-findings/manifest": "D:TestRetainedLiveGoldenBytes",
	"live-findings/status":   "D:TestRetainedLiveGoldenBytes",
	"live-findings/support/s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/evidence/images/sha256-843ac23b1736b4487ec81cf7c07ddd9bb46ae5b7818c2c3843d99d62fa75f3c9.png": "D:TestRetainedLiveGoldenBytes",
	"live-findings/support/s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/excerpts/F001.json":                                                                          "D:TestRetainedLiveGoldenBytes",
	"live-findings/support/s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/excerpts/F001_1.md":                                                                          "D:TestRetainedLiveGoldenBytes",
	"live-findings/support/s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/role-reports/logic.md":                                                                       "D:TestRetainedLiveGoldenBytes",
	"live-findings/support/s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/role-reports/security.md":                                                                    "D:TestRetainedLiveGoldenBytes",
	"live-findings/support/s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/source/source.json":                                                                          "D:TestRetainedLiveGoldenBytes",
	"live-findings/support/s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/support/index.json":                                                                          "D:TestRetainedLiveGoldenBytes",
	"status/collecting/P0":             "D:TestRetainedPublicationDTOBytes",
	"status/collecting/P1":             "D:TestRetainedPublicationDTOBytes",
	"status/collecting/P2":             "D:TestRetainedPublicationDTOBytes",
	"status/collecting/none":           "D:TestRetainedPublicationDTOBytes",
	"status/completed/P0":              "D:TestRetainedPublicationDTOBytes",
	"status/completed/P1":              "D:TestRetainedPublicationDTOBytes",
	"status/completed/P2":              "D:TestRetainedPublicationDTOBytes",
	"status/completed/none":            "D:TestRetainedPublicationDTOBytes",
	"status/content_validated/P0":      "D:TestRetainedPublicationDTOBytes",
	"status/content_validated/P1":      "D:TestRetainedPublicationDTOBytes",
	"status/content_validated/P2":      "D:TestRetainedPublicationDTOBytes",
	"status/content_validated/none":    "D:TestRetainedPublicationDTOBytes",
	"status/final_file_installed/P0":   "D:TestRetainedPublicationDTOBytes",
	"status/final_file_installed/P1":   "D:TestRetainedPublicationDTOBytes",
	"status/final_file_installed/P2":   "D:TestRetainedPublicationDTOBytes",
	"status/final_file_installed/none": "D:TestRetainedPublicationDTOBytes",
	"status/final_staged/P0":           "D:TestRetainedPublicationDTOBytes",
	"status/final_staged/P1":           "D:TestRetainedPublicationDTOBytes",
	"status/final_staged/P2":           "D:TestRetainedPublicationDTOBytes",
	"status/final_staged/none":         "D:TestRetainedPublicationDTOBytes",
	"status/manifest_committed/P0":     "D:TestRetainedPublicationDTOBytes",
	"status/manifest_committed/P1":     "D:TestRetainedPublicationDTOBytes",
	"status/manifest_committed/P2":     "D:TestRetainedPublicationDTOBytes",
	"status/manifest_committed/none":   "D:TestRetainedPublicationDTOBytes",
}

func retainedGoldenMap(t *testing.T, file string, owners map[string]string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]string
	if err := json.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	if len(values) != len(owners) {
		t.Fatalf("golden inventory changed: %s members=%d owners=%d", file, len(values), len(owners))
	}
	for key := range values {
		if owners[key] == "" {
			t.Fatalf("unclassified golden %s/%s", file, key)
		}
	}
	for key := range owners {
		if _, ok := values[key]; !ok {
			t.Fatalf("missing golden %s/%s", file, key)
		}
	}
	return values
}

func TestRetainedGoldenInventory(t *testing.T) {
	retainedGoldenMap(t, "m1-runtime-wire.json", retainedRuntimeGoldenOwners)
	retainedGoldenMap(t, "m2-publication-wire.json", retainedPublicationGoldenOwners)
}

func TestRetainedRuntimeWireBytes(t *testing.T) {
	expected := retainedGoldenMap(t, "m1-runtime-wire.json", retainedRuntimeGoldenOwners)
	actual := retainedRuntimeWireOutputs(t)
	count := 0
	for key, owner := range retainedRuntimeGoldenOwners {
		if owner != "D:TestRetainedRuntimeWireBytes" {
			continue
		}
		count++
		got, ok := actual[key]
		if !ok || got != expected[key] {
			t.Fatalf("retained runtime DTO bytes changed: %s got=%q want=%q", key, got, expected[key])
		}
	}
	if count != len(actual) {
		t.Fatal("unclassified retained runtime output")
	}
}

func TestRetainedPublicationDTOBytes(t *testing.T) {
	expected := retainedGoldenMap(t, "m2-publication-wire.json", retainedPublicationGoldenOwners)
	actual := retainedPublicationWireOutputs(t)
	count := 0
	for key, owner := range retainedPublicationGoldenOwners {
		if owner != "D:TestRetainedPublicationDTOBytes" {
			continue
		}
		count++
		got, ok := actual[key]
		if !ok || got != expected[key] {
			t.Fatalf("retained publication DTO bytes changed: %s got=%q want=%q", key, got, expected[key])
		}
	}
	if count != len(actual) {
		t.Fatal("unclassified retained publication DTO output")
	}
}
