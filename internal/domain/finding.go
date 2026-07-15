package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityBlocker  Severity = "blocker"
)

func (severity Severity) Valid() bool { return severity.Rank() >= 0 }

func (severity Severity) Rank() int {
	switch severity {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	case SeverityBlocker:
		return 5
	default:
		return -1
	}
}

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

func (confidence Confidence) Valid() bool {
	return oneOf(string(confidence), string(ConfidenceLow), string(ConfidenceMedium), string(ConfidenceHigh))
}

type FindingInput struct {
	Severity                 Severity
	Path                     string
	LineStart                int
	Role                     Role
	ProviderInstance         string
	Title                    string
	Description              string
	Recommendation           string
	Confidence               Confidence
	Lifecycle                FindingLifecycle
	EvidenceState            EvidenceState
	NormalizedRuleCategory   string
	NormalizedEvidenceRegion string
}

// Finding is an immutable, system-normalized finding. Its final ID is assigned
// only by OrderAndAssignFindings after validation and deterministic ordering.
type Finding struct {
	id                       string
	fingerprint              string
	severity                 Severity
	path                     string
	lineStart                int
	role                     Role
	providerInstance         string
	title                    string
	description              string
	recommendation           string
	confidence               Confidence
	lifecycle                FindingLifecycle
	evidenceState            EvidenceState
	normalizedRuleCategory   string
	normalizedEvidenceRegion string
}

func NewFinding(input FindingInput) (Finding, error) {
	if !input.Severity.Valid() {
		return Finding{}, fmt.Errorf("finding: invalid severity %q", input.Severity)
	}
	normalizedPath, err := normalizeFindingPath(input.Path)
	if err != nil {
		return Finding{}, err
	}
	if input.LineStart < 1 {
		return Finding{}, fmt.Errorf("finding: line start must be positive")
	}
	if !input.Role.Valid() {
		return Finding{}, fmt.Errorf("finding: invalid role %q", input.Role)
	}
	if strings.TrimSpace(input.ProviderInstance) == "" || strings.TrimSpace(input.Title) == "" || strings.TrimSpace(input.Description) == "" || strings.TrimSpace(input.Recommendation) == "" {
		return Finding{}, fmt.Errorf("finding: provider, title, description, and recommendation are required")
	}
	if !input.Confidence.Valid() || !input.Lifecycle.Valid() || !input.EvidenceState.Valid() {
		return Finding{}, fmt.Errorf("finding: invalid confidence, lifecycle, or evidence state")
	}
	rule := normalizeFingerprintText(input.NormalizedRuleCategory)
	region := normalizeFingerprintText(input.NormalizedEvidenceRegion)
	if rule == "" || region == "" {
		return Finding{}, fmt.Errorf("finding: normalized rule/category and evidence region are required")
	}
	return Finding{
		fingerprint: fingerprint(rule, normalizedPath, region), severity: input.Severity,
		path: normalizedPath, lineStart: input.LineStart, role: input.Role,
		providerInstance: strings.TrimSpace(input.ProviderInstance), title: strings.TrimSpace(input.Title),
		description: input.Description, recommendation: input.Recommendation,
		confidence: input.Confidence, lifecycle: input.Lifecycle, evidenceState: input.EvidenceState,
		normalizedRuleCategory: rule, normalizedEvidenceRegion: region,
	}, nil
}
func (finding Finding) Validate() error {
	if !finding.severity.Valid() {
		return fmt.Errorf("finding: invalid severity %q", finding.severity)
	}
	normalizedPath, err := normalizeFindingPath(finding.path)
	if err != nil || normalizedPath != finding.path {
		return fmt.Errorf("finding: invalid normalized path")
	}
	if finding.lineStart < 1 || !finding.role.Valid() {
		return fmt.Errorf("finding: invalid line or role")
	}
	if strings.TrimSpace(finding.providerInstance) == "" ||
		strings.TrimSpace(finding.title) == "" ||
		strings.TrimSpace(finding.description) == "" ||
		strings.TrimSpace(finding.recommendation) == "" {
		return fmt.Errorf("finding: required content is empty")
	}
	if !finding.confidence.Valid() || !finding.lifecycle.Valid() || !finding.evidenceState.Valid() {
		return fmt.Errorf("finding: invalid confidence, lifecycle, or evidence state")
	}
	if finding.normalizedRuleCategory == "" ||
		finding.normalizedRuleCategory != normalizeFingerprintText(finding.normalizedRuleCategory) ||
		finding.normalizedEvidenceRegion == "" ||
		finding.normalizedEvidenceRegion != normalizeFingerprintText(finding.normalizedEvidenceRegion) {
		return fmt.Errorf("finding: fingerprint inputs are not normalized")
	}
	expectedFingerprint := fingerprint(finding.normalizedRuleCategory, finding.path, finding.normalizedEvidenceRegion)
	if finding.fingerprint != expectedFingerprint {
		return fmt.Errorf("finding: fingerprint does not match normalized content")
	}
	return nil
}

func (finding Finding) WithEvidenceState(state EvidenceState) (Finding, error) {
	if err := finding.Validate(); err != nil {
		return Finding{}, fmt.Errorf("finding: cannot update evidence state: %w", err)
	}
	if !state.Valid() {
		return Finding{}, fmt.Errorf("finding: invalid evidence state %q", state)
	}
	finding.evidenceState = state
	return finding, nil
}

func OrderAndAssignFindings(input []Finding) ([]Finding, error) {
	findings := append([]Finding(nil), input...)
	for index := range findings {
		if err := findings[index].Validate(); err != nil {
			return nil, fmt.Errorf("finding %d: %w", index, err)
		}
		findings[index].id = ""
	}
	sort.Slice(findings, func(left, right int) bool {
		a, b := findings[left], findings[right]
		if a.severity.Rank() != b.severity.Rank() {
			return a.severity.Rank() > b.severity.Rank()
		}
		if a.path != b.path {
			return a.path < b.path
		}
		if a.lineStart != b.lineStart {
			return a.lineStart < b.lineStart
		}
		if a.role != b.role {
			return a.role < b.role
		}
		if a.providerInstance != b.providerInstance {
			return a.providerInstance < b.providerInstance
		}
		if a.title != b.title {
			return a.title < b.title
		}
		if a.fingerprint != b.fingerprint {
			return a.fingerprint < b.fingerprint
		}
		if a.normalizedRuleCategory != b.normalizedRuleCategory {
			return a.normalizedRuleCategory < b.normalizedRuleCategory
		}
		if a.normalizedEvidenceRegion != b.normalizedEvidenceRegion {
			return a.normalizedEvidenceRegion < b.normalizedEvidenceRegion
		}
		if a.confidence != b.confidence {
			return a.confidence < b.confidence
		}
		if a.lifecycle != b.lifecycle {
			return a.lifecycle < b.lifecycle
		}
		if a.evidenceState != b.evidenceState {
			return a.evidenceState < b.evidenceState
		}
		if a.description != b.description {
			return a.description < b.description
		}
		return a.recommendation < b.recommendation
	})
	for index := range findings {
		findings[index].id = fmt.Sprintf("F%03d", index+1)
	}
	return findings, nil
}

func normalizeFindingPath(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\\\x00\r\n") || strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("finding: path must be a safe relative slash path")
	}
	normalized := path.Clean(value)
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") || strings.Contains(value, "//") || strings.HasSuffix(value, "/") {
		return "", fmt.Errorf("finding: path is noncanonical or escapes the target")
	}
	if normalized != value {
		return "", fmt.Errorf("finding: path must already be normalized")
	}
	return normalized, nil
}

func normalizeFingerprintText(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func fingerprint(rule, normalizedPath, region string) string {
	hash := sha256.New()
	for _, value := range []string{rule, normalizedPath, region} {
		length := uint64(len(value))
		for shift := 56; shift >= 0; shift -= 8 {
			hash.Write([]byte{byte(length >> shift)})
		}
		hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (finding Finding) ID() string                       { return finding.id }
func (finding Finding) Fingerprint() string              { return finding.fingerprint }
func (finding Finding) Severity() Severity               { return finding.severity }
func (finding Finding) Path() string                     { return finding.path }
func (finding Finding) LineStart() int                   { return finding.lineStart }
func (finding Finding) Role() Role                       { return finding.role }
func (finding Finding) ProviderInstance() string         { return finding.providerInstance }
func (finding Finding) Title() string                    { return finding.title }
func (finding Finding) Description() string              { return finding.description }
func (finding Finding) Recommendation() string           { return finding.recommendation }
func (finding Finding) Confidence() Confidence           { return finding.confidence }
func (finding Finding) Lifecycle() FindingLifecycle      { return finding.lifecycle }
func (finding Finding) EvidenceState() EvidenceState     { return finding.evidenceState }
func (finding Finding) NormalizedRuleCategory() string   { return finding.normalizedRuleCategory }
func (finding Finding) NormalizedEvidenceRegion() string { return finding.normalizedEvidenceRegion }
