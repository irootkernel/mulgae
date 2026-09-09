package recovery

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func validateMetadata(ctx context.Context, document Document, sealed bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if document.SchemaVersion != SchemaVersion || document.RunState != domain.RunFailed && document.RunState != domain.RunCancelled {
		return fmt.Errorf("recovery: invalid schema or terminal state")
	}
	if _, err := domain.ParseSessionID(document.SessionID); err != nil {
		return err
	}
	if _, err := domain.ParseRunID(document.RunID); err != nil {
		return err
	}
	if !document.Threshold.Valid() || !validDigest(document.SnapshotManifestSHA256) {
		return fmt.Errorf("recovery: invalid policy or snapshot")
	}
	if sealed && (!strings.HasPrefix(document.WorkspaceTerminalReceipt, "workspace-terminal:v1:") || !validDigest(strings.TrimPrefix(document.WorkspaceTerminalReceipt, "workspace-terminal:v1:"))) {
		return fmt.Errorf("recovery: missing cleanup receipt")
	}
	switch document.RunType {
	case domain.RunTypeReview:
		if document.Source != nil {
			return fmt.Errorf("recovery: root has child lineage")
		}
	case domain.RunTypeRerun:
		if document.Source == nil {
			return fmt.Errorf("recovery: child has no source")
		}
		if _, err := document.Source.Reference(); err != nil {
			return err
		}
		if document.Source.RunID == document.RunID {
			return fmt.Errorf("recovery: source cycle")
		}
		if _, err := domain.ParseAttemptID(document.Source.AttemptID); err != nil {
			return err
		}
		if document.Source.ReplayMode != "exact" && document.Source.ReplayMode != "recompose" {
			return fmt.Errorf("recovery: invalid replay mode")
		}
	default:
		return fmt.Errorf("recovery: unsupported run type")
	}
	if len(document.Roles) == 0 || len(document.Roles) > len(domain.FixedRoleOrder()) || len(document.Attempts) != len(document.Roles) {
		return fmt.Errorf("recovery: incomplete role inputs")
	}
	if document.RunType == domain.RunTypeRerun && len(document.Roles) != 1 {
		return fmt.Errorf("recovery: rerun must contain one role")
	}
	if len(document.Findings) > 1000 {
		return fmt.Errorf("recovery: too many structured findings")
	}
	if _, err := document.Target.Identity(); err != nil {
		return err
	}
	if document.Target.Bytes.SHA256 != document.Target.SHA256 {
		return fmt.Errorf("recovery: target digest mismatch")
	}
	lengths := make(map[string]int64)
	checkReference := func(blob Blob) error {
		if !validDigest(blob.SHA256) || blob.ByteLength < 0 {
			return fmt.Errorf("recovery: invalid blob reference")
		}
		if length, ok := lengths[blob.SHA256]; ok && length != blob.ByteLength {
			return fmt.Errorf("recovery: inconsistent blob lengths")
		}
		lengths[blob.SHA256] = blob.ByteLength
		return nil
	}
	if err := checkReference(document.Target.Bytes); err != nil {
		return err
	}
	if err := checkReference(document.Target.CapturedArchive); err != nil {
		return err
	}
	attempts := make(map[string]Attempt, len(document.Attempts))
	roles := make(map[domain.Role]Role, len(document.Roles))
	failed := false
	for index, role := range document.Roles {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !role.Role.Valid() || index > 0 && roleOrder(document.Roles[index-1].Role) >= roleOrder(role.Role) {
			return fmt.Errorf("recovery: non-canonical roles")
		}
		if role.Role == domain.RoleLogic && !role.Required {
			return fmt.Errorf("recovery: logic policy is not required")
		}
		attempt := document.Attempts[index]
		if attempt.Role != role.Role || attempt.AttemptID != role.AttemptID || attempt.ProviderInstance != role.ProviderInstance || !safeText(attempt.ProviderInstance, 128) {
			return fmt.Errorf("recovery: attempt-role binding mismatch")
		}
		if _, err := domain.ParseAttemptID(attempt.AttemptID); err != nil {
			return err
		}
		if _, exists := attempts[attempt.AttemptID]; exists {
			return fmt.Errorf("recovery: duplicate attempt")
		}
		attempts[attempt.AttemptID] = attempt
		roles[role.Role] = role
		if err := checkReference(attempt.InitialPrompt.Stdin); err != nil {
			return err
		}
		if err := validatePromptMetadata(attempt.InitialPrompt); err != nil {
			return err
		}
		switch role.Outcome {
		case "completed", "degraded":
			if attempt.State != domain.AttemptSucceeded || attempt.FailureClass != "" || attempt.ReasonCode != "" || role.Report == nil {
				return fmt.Errorf("recovery: invalid successful role")
			}
			if role.ReportsOnly && len(role.FindingIDs) != 0 {
				return fmt.Errorf("recovery: reports-only role cannot retain structured findings")
			}
			if err := checkReference(*role.Report); err != nil {
				return err
			}
		case "failed":
			failed = true
			if !recoverableClass(attempt.FailureClass) || !safeText(attempt.ReasonCode, 128) || role.Report != nil || role.ReportsOnly || len(role.FindingIDs) != 0 {
				return fmt.Errorf("recovery: unsafe or inconsistent failed role")
			}
			switch attempt.State {
			case domain.AttemptFailed, domain.AttemptTimedOut, domain.AttemptCancelled, domain.AttemptBlocked:
			default:
				return fmt.Errorf("recovery: failed attempt is not terminal")
			}
		default:
			return fmt.Errorf("recovery: invalid role outcome")
		}
	}
	if !failed {
		return fmt.Errorf("recovery: no failed role")
	}
	idsByRole := make(map[domain.Role][]string)
	for index, finding := range document.Findings {
		if err := ctx.Err(); err != nil {
			return err
		}
		role, ok := roles[finding.Role]
		if !ok || role.Outcome == "failed" || finding.ProviderInstance != role.ProviderInstance || finding.ID != fmt.Sprintf("F%03d", index+1) || !validDigest(finding.Fingerprint) {
			return fmt.Errorf("recovery: finding identity mismatch")
		}
		if !finding.Severity.Valid() || !finding.Confidence.Valid() || !finding.Lifecycle.Valid() || !safeText(finding.Title, 240) || !safeText(finding.Description, 8000) || !safeText(finding.Recommendation, 8000) || len(finding.Evidence) == 0 || len(finding.Evidence) > 20 {
			return fmt.Errorf("recovery: invalid finding content")
		}
		idsByRole[finding.Role] = append(idsByRole[finding.Role], finding.ID)
	}
	for _, role := range document.Roles {
		if len(role.FindingIDs) != len(idsByRole[role.Role]) {
			return fmt.Errorf("recovery: role finding inventory mismatch")
		}
		for i, id := range role.FindingIDs {
			if id != idsByRole[role.Role][i] {
				return fmt.Errorf("recovery: role finding order mismatch")
			}
		}
	}
	return nil
}

func validate(ctx context.Context, document Document, blobs map[string][]byte, sealed bool) error {
	if err := validateMetadata(ctx, document, sealed); err != nil {
		return err
	}
	references := document.Blobs()
	if len(blobs) != len(references) {
		return fmt.Errorf("recovery: unexpected or missing content")
	}
	// Metadata has already checked repeated hashes for divergent lengths.
	check := func(blob Blob) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, ok := blobs[blob.SHA256]
		if !ok || !validDigest(blob.SHA256) || blob.ByteLength < 0 || int64(len(content)) != blob.ByteLength || Digest(content) != blob.SHA256 {
			return fmt.Errorf("recovery: blob integrity mismatch")
		}
		return nil
	}
	for _, blob := range references {
		if err := check(blob); err != nil {
			return err
		}
	}
	target, err := document.Target.Identity()
	if err != nil {
		return err
	}
	archive, err := ports.UnmarshalCapturedReviewMaterial(blobs[document.Target.CapturedArchive.SHA256])
	if err != nil {
		return fmt.Errorf("recovery: captured archive: %w", err)
	}
	if archive.Target().Identity() != target || !bytes.Equal(archive.Target().Bytes(), blobs[document.Target.Bytes.SHA256]) {
		return fmt.Errorf("recovery: archived target mismatch")
	}
	for index, role := range document.Roles {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempt := document.Attempts[index]
		if err := validatePrompt(document, attempt, blobs[attempt.InitialPrompt.Stdin.SHA256]); err != nil {
			return err
		}
		if role.Report != nil {
			report := blobs[role.Report.SHA256]
			if len(bytes.TrimSpace(report)) == 0 || !utf8.Valid(report) || bytes.ContainsRune(report, 0) {
				return fmt.Errorf("recovery: invalid report")
			}
		}
	}
	verifier, err := evidence.NewVerifier(archiveReader{archive: archive, target: document.Target.SHA256})
	if err != nil {
		return err
	}
	for _, finding := range document.Findings {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, item := range finding.Evidence {
			if err := ctx.Err(); err != nil {
				return err
			}
			if item.TargetSHA256 != document.Target.SHA256 {
				return fmt.Errorf("recovery: evidence target mismatch")
			}
			claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{TargetSHA256: item.TargetSHA256, Side: item.Side, Path: item.Path, LineStart: item.LineStart, LineEnd: item.LineEnd, Quote: item.Quote})
			if err != nil {
				return err
			}
			receipt, err := verifier.VerifyCurrent(ctx, claim)
			if err != nil {
				return fmt.Errorf("recovery: evidence verification failed: %w", err)
			}
			if receipt.Status() != evidence.ReceiptVerified || receipt.ExcerptSHA256() != item.ExcerptSHA256 {
				return fmt.Errorf("recovery: evidence receipt mismatch")
			}
			if item.Visual != nil {
				visual := item.Visual
				if visual.X < 0 || visual.Y < 0 || visual.Width <= 0 || visual.Height <= 0 || !validDigest(visual.SHA256) {
					return fmt.Errorf("recovery: invalid visual reference")
				}
				workspace, err := archive.ProviderWorkspace()
				if err != nil {
					return err
				}
				matched := false
				for _, file := range workspace.Files() {
					if file.Path().String() == visual.Path && file.SHA256() == visual.SHA256 && (file.MediaType() == "image/png" || file.MediaType() == "image/jpeg" || file.MediaType() == "image/webp") {
						matched = true
					}
				}
				if !matched {
					return fmt.Errorf("recovery: visual evidence not captured")
				}
			}
		}
	}
	return ctx.Err()
}

func validatePromptMetadata(input Prompt) error {
	if !safeText(input.TemplateID, 128) || !safeText(input.TemplateVersion, 128) || !safeText(input.AdapterProfile, 128) || len(input.AdapterParameters) > 64 {
		return fmt.Errorf("recovery: invalid prompt metadata")
	}
	if _, err := prompt.ParseExecutionInvocationID(input.ExecutionInvocationID); err != nil {
		return err
	}
	for key, value := range input.AdapterParameters {
		if !safeText(key, 128) || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return fmt.Errorf("recovery: invalid adapter parameter")
		}
	}
	return nil
}

func validatePrompt(document Document, attempt Attempt, stdin []byte) error {
	input := attempt.InitialPrompt
	boundary := bytes.Index(stdin, []byte("\nMulgae-FRAMES/1\n"))
	if boundary <= 0 {
		return fmt.Errorf("recovery: prompt boundary absent")
	}
	template, err := prompt.NewTrustedTemplate(input.TemplateID, input.TemplateVersion, stdin[:boundary])
	if err != nil {
		return err
	}
	if "sha256:"+template.SHA256() != input.TemplateSHA256 {
		return fmt.Errorf("recovery: template digest mismatch")
	}
	if manifest, ok := input.AdapterParameters[prompt.TrustedLayerManifestAdapterParameter]; ok {
		if _, err := prompt.RestoreTrustedLayerManifest(template, manifest); err != nil {
			return err
		}
	}
	parsed, err := prompt.ParseStdin(template, stdin)
	if err != nil {
		return err
	}
	scope := parsed.Scope()
	if scope.String() != input.Scope || scope.SessionID().String() != document.SessionID || scope.SourceInvocationID().String() != input.SourceInvocationID {
		return fmt.Errorf("recovery: prompt scope mismatch")
	}
	if document.Source == nil || document.Source.ReplayMode != "exact" {
		if scope.RunID().String() != document.RunID || scope.AttemptID().String() != attempt.AttemptID {
			return fmt.Errorf("recovery: initial scope mismatch")
		}
	}
	return nil
}
func recoverableClass(class domain.FailureClass) bool {
	if !class.Valid() {
		return false
	}
	switch class {
	case domain.FailureSecurityPolicy, domain.FailureConfiguration, domain.FailureArtifact:
		return false
	default:
		return true
	}
}
func roleOrder(role domain.Role) int {
	for index, value := range domain.FixedRoleOrder() {
		if value == role {
			return index
		}
	}
	return -1
}

type archiveReader struct {
	archive ports.CapturedReviewMaterial
	target  string
}

func (reader archiveReader) ReadImmutableTarget(ctx context.Context, target string, side evidence.Side, path ports.SafeRelativePath) (evidence.ImmutableTargetAvailability, []byte, error) {
	if err := ctx.Err(); err != nil {
		return evidence.ImmutableTargetUnavailable, nil, err
	}
	if target != reader.target {
		return evidence.ImmutableTargetStale, nil, nil
	}
	files, ok := reader.archive.Evidence().Files(ports.CapturedEvidenceSide(side))
	if !ok {
		return evidence.ImmutableTargetUnavailable, nil, nil
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return evidence.ImmutableTargetUnavailable, nil, err
		}
		if file.Path() == path && file.IsText() {
			return evidence.ImmutableTargetAvailable, file.Bytes(), nil
		}
	}
	return evidence.ImmutableTargetUnavailable, nil, nil
}
