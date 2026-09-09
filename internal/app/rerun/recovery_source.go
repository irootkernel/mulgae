package rerun

import (
	"fmt"
	"sort"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
)

func SourceFromRecovery(snapshot recovery.Snapshot, attemptID domain.AttemptID) (SourceAttempt, error) {
	document := snapshot.Document()
	reference, err := snapshot.Reference()
	if err != nil {
		return SourceAttempt{}, err
	}
	session, err := domain.ParseSessionID(document.SessionID)
	if err != nil {
		return SourceAttempt{}, err
	}
	target, err := document.Target.Identity()
	if err != nil {
		return SourceAttempt{}, err
	}
	for _, attempt := range document.Attempts {
		if attempt.AttemptID != attemptID.String() {
			continue
		}
		if attempt.State == domain.AttemptSucceeded {
			return SourceAttempt{}, fmt.Errorf("recovery rerun cannot replace an accepted role")
		}
		input := attempt.InitialPrompt
		stdin := snapshot.Blob(input.Stdin)
		source := SourceAttempt{SessionID: session, RunID: reference.RunID(), RecoveryManifestSHA256: reference.RecoveryManifestSHA256(), AttemptID: attemptID, ProviderInstance: attempt.ProviderInstance, Target: Target{Identity: target, Bytes: snapshot.Blob(document.Target.Bytes), SHA256: target.SHA256(), CapturedArchive: snapshot.Blob(document.Target.CapturedArchive)}, Prompt: PromptManifest{URI: document.SessionID + "/" + document.RunID + "/recovery/manifest.json", SHA256: strings.TrimPrefix(reference.RecoveryManifestSHA256(), "sha256:"), ComposedStdin: stdin, ComposedStdinSHA256: strings.TrimPrefix(input.Stdin.SHA256, "sha256:"), CompleteStdinSHA256: prompt.CompleteStdinSHA256(stdin), SourceInvocationID: input.SourceInvocationID, ExecutionInvocationID: input.ExecutionInvocationID, TemplateID: input.TemplateID, TemplateVersion: input.TemplateVersion, TemplateSHA256: strings.TrimPrefix(input.TemplateSHA256, "sha256:"), AdapterProfile: input.AdapterProfile, Scope: input.Scope, Role: string(attempt.Role)}}
		for name, value := range input.AdapterParameters {
			source.Prompt.Parameters = append(source.Prompt.Parameters, Parameter{Name: name, Value: value})
		}
		sort.Slice(source.Prompt.Parameters, func(i, j int) bool { return source.Prompt.Parameters[i].Name < source.Prompt.Parameters[j].Name })
		source.ImmutableSHA256 = SourceAttemptSHA256(source)
		return source, nil
	}
	return SourceAttempt{}, fmt.Errorf("recovery rerun attempt is absent")
}
