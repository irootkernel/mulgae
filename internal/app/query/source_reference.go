package query

import "strings"

func (lineage CommittedLineage) SourceRecoveryManifestSHA256() (string, bool) {
	if lineage.sourceRecoveryManifestSHA256 == nil {
		return "", false
	}
	return *lineage.sourceRecoveryManifestSHA256, true
}
func sourceLineageVersion(version string, hash *string) string {
	if hash != nil {
		return strings.TrimSuffix(version, ".v1") + ".v2"
	}
	return version
}
