package export

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

var (
	ErrMalformedProjection = errors.New("malformed verified export projection")
	ErrSecretDetected      = errors.New("secret detected in export projection")

	sha256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idPatterns    = map[string]*regexp.Regexp{
		"session": regexp.MustCompile(`^s_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`),
		"run":     regexp.MustCompile(`^r_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`),
		"review":  regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`),
		"export":  regexp.MustCompile(`^x_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`),
	}
	canonicalPathPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)
	findingIDPattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,63}$`)
	absolutePathPattern  = regexp.MustCompile(`(?m)(^|[\s("'])/(?:[^\s"')]+)`)
	secretPattern        = regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?key|secret|token|password|authorization|cookie|x-api-key|client_secret)\s*[:=]\s*[^\s,;]+|\bbearer\s+[a-z0-9._~+/-]+=*|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
)

func validateProjection(source VerifiedSourceProjection, options BuildOptions) error {
	if !idPatterns["session"].MatchString(source.SessionID) || !idPatterns["run"].MatchString(source.RunID) || !idPatterns["review"].MatchString(source.ReviewID) {
		return fmt.Errorf("%w: source identity", ErrMalformedProjection)
	}
	if !idPatterns["export"].MatchString(options.ExportID) || options.CreatedAt.IsZero() {
		return fmt.Errorf("%w: export identity", ErrMalformedProjection)
	}
	if err := validateArtifact(source.RunManifest); err != nil {
		return err
	}
	if err := validateArtifact(source.ReviewArtifact); err != nil {
		return err
	}
	if source.Review.SchemaVersion == "" || source.Run.SchemaVersion == "" || len(source.SchemaVersions) == 0 {
		return fmt.Errorf("%w: schema versions", ErrMalformedProjection)
	}
	if err := validateSourceIdentity(source.SourceIdentity); err != nil {
		return err
	}
	if source.SourceIdentity.SessionID != source.SessionID || source.SourceIdentity.RunID != source.RunID || source.SourceIdentity.ReviewID != source.ReviewID {
		return fmt.Errorf("%w: source identity does not bind selected source", ErrMalformedProjection)
	}
	if err := validateCurrentIdentity(source.CurrentIdentity); err != nil {
		return err
	}
	findings := make(map[string]struct{}, len(source.Findings))
	for _, finding := range source.Findings {
		if !findingIDPattern.MatchString(finding.ID) || !sha256Pattern.MatchString(finding.Fingerprint) {
			return fmt.Errorf("%w: finding", ErrMalformedProjection)
		}
		if _, exists := findings[finding.ID]; exists {
			return fmt.Errorf("%w: duplicate finding", ErrMalformedProjection)
		}
		findings[finding.ID] = struct{}{}
	}
	sourceFindingBound := source.SourceIdentity.FindingID == ""
	for _, item := range source.Evidence {
		if !findingIDPattern.MatchString(item.FindingID) || !idPatterns["session"].MatchString(item.SourceSessionID) || !idPatterns["run"].MatchString(item.SourceRunID) || !idPatterns["review"].MatchString(item.SourceReviewID) || !findingIDPattern.MatchString(item.SourceFindingID) || !sha256Pattern.MatchString(item.SourceTargetSHA256) || !sha256Pattern.MatchString(item.SourceExcerptSHA256) || !sha256Pattern.MatchString(item.TargetSHA256) || !canonicalPathPattern.MatchString(item.Path) || item.LineStart < 1 || item.LineEnd < item.LineStart || !validSide(item.Side) || !validVerification(item.Verification) {
			return fmt.Errorf("%w: evidence", ErrMalformedProjection)
		}
		if _, exists := findings[item.FindingID]; !exists {
			return fmt.Errorf("%w: evidence references unknown finding", ErrMalformedProjection)
		}
		if item.SourceSessionID == source.SourceIdentity.SessionID && item.SourceRunID == source.SourceIdentity.RunID && item.SourceReviewID == source.SourceIdentity.ReviewID && item.SourceFindingID == source.SourceIdentity.FindingID && item.SourceTargetSHA256 == source.SourceIdentity.SourceTargetSHA256 && item.SourceExcerptSHA256 == source.SourceIdentity.SourceExcerptSHA256 {
			sourceFindingBound = true
		}
	}
	if !sourceFindingBound {
		return fmt.Errorf("%w: source identity does not bind exported evidence", ErrMalformedProjection)
	}
	if source.SourceIdentity.FindingID == "" && len(source.Findings) != 0 {
		return fmt.Errorf("%w: findings require source finding identity", ErrMalformedProjection)
	}
	return nil
}

func validateArtifact(ref ImmutableArtifactRef) error {
	if !canonicalPathPattern.MatchString(ref.ArtifactPath) || !sha256Pattern.MatchString(ref.SHA256) {
		return fmt.Errorf("%w: immutable artifact reference", ErrMalformedProjection)
	}
	return nil
}

func validateSourceIdentity(identity SourceIdentity) error {
	if !idPatterns["session"].MatchString(identity.SessionID) || !idPatterns["run"].MatchString(identity.RunID) || !idPatterns["review"].MatchString(identity.ReviewID) || !sha256Pattern.MatchString(identity.SourceTargetSHA256) {
		return fmt.Errorf("%w: source identity", ErrMalformedProjection)
	}
	findingPresent := identity.FindingID != ""
	excerptPresent := identity.SourceExcerptSHA256 != ""
	if findingPresent != excerptPresent {
		return fmt.Errorf("%w: source finding and excerpt identity must be present together", ErrMalformedProjection)
	}
	if findingPresent && !findingIDPattern.MatchString(identity.FindingID) {
		return fmt.Errorf("%w: source identity", ErrMalformedProjection)
	}
	if excerptPresent && !sha256Pattern.MatchString(identity.SourceExcerptSHA256) {
		return fmt.Errorf("%w: source identity", ErrMalformedProjection)
	}
	return nil
}

func validateCurrentIdentity(identity CurrentIdentity) error {
	if !sha256Pattern.MatchString(identity.TargetSHA256) {
		return fmt.Errorf("%w: current identity", ErrMalformedProjection)
	}
	detailsPresent := identity.Path != "" || identity.Side != "" || identity.LineStart != 0 || identity.LineEnd != 0 || identity.Verification != ""
	if !detailsPresent {
		return nil
	}
	if !canonicalPathPattern.MatchString(identity.Path) || identity.LineStart < 1 || identity.LineEnd < identity.LineStart || !validSide(identity.Side) || !validVerification(identity.Verification) {
		return fmt.Errorf("%w: current identity", ErrMalformedProjection)
	}
	return nil
}

func validSide(value string) bool { return value == "base" || value == "head" || value == "worktree" }
func validVerification(value string) bool {
	switch value {
	case "claimed", "verified", "stale", "invalid", "unverifiable":
		return true
	}
	return false
}

func redactText(value string) (string, error) {
	if secretPattern.MatchString(value) {
		return "", secretDetectedFailure()
	}
	return absolutePathPattern.ReplaceAllStringFunc(value, func(match string) string {
		prefix := ""
		if strings.HasPrefix(match, " ") || strings.HasPrefix(match, "(") || strings.HasPrefix(match, "\"") || strings.HasPrefix(match, "'") {
			prefix = match[:1]
		}
		return prefix + "[redacted-path]"
	}), nil
}

func secretDetectedFailure() error {
	failure, err := domain.NewFailure("export.redact", domain.FailureSecurityPolicy, "secret_detected", ErrSecretDetected)
	if err != nil {
		panic(err)
	}
	return failure
}
