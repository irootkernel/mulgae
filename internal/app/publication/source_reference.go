package publication

import (
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
)

// NewRecoveryRerunPublicationContext binds a child to a sealed recovery source
// without inventing a review identity for the failed source run.
func NewRecoveryRerunPublicationContext(parent domain.RunID, source domain.SourceReference, attempt domain.AttemptID, mode ReplayMode) (RunPublicationContext, error) {
	if !source.Valid() || source.Kind() != "failed_run_recovery" {
		return RunPublicationContext{}, fmt.Errorf("recovery rerun source is invalid")
	}
	run, hash := source.RunID(), source.RecoveryManifestSHA256()
	context := RunPublicationContext{lineage: preparedLineage{runType: domain.RunTypeRerun, parentRunID: &parent, sourceRunID: &run, sourceRecoveryManifestSHA256: &hash, sourceAttemptID: &attempt, replayMode: &mode}}
	if err := context.validate(); err != nil {
		return RunPublicationContext{}, err
	}
	return context, nil
}
func lineageVersion(version string, hash *string) string {
	if hash != nil {
		return strings.TrimSuffix(version, ".v1") + ".v2"
	}
	return version
}
func lineageSchema(uri string, hash *string) string {
	if hash != nil {
		return strings.Replace(uri, ".v1.schema.json", ".v2.schema.json", 1)
	}
	return uri
}
func recoverySourceKind(hash *string) string {
	if hash != nil {
		return "failed_run_recovery"
	}
	return ""
}
