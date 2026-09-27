package reviewrun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// NewProjectBinding hashes private local identity. Only its returned digest may
// cross a public boundary; callers observe canonical paths through descriptors.
func NewProjectBinding(root, gitDirectory, commonDirectory ports.AnchoredRoot, rootIdentity, gitIdentity, commonIdentity ports.ProjectDirectoryIdentity) (domain.ProjectBinding, error) {
	if !root.Valid() || !gitDirectory.Valid() || !commonDirectory.Valid() || !utf8.ValidString(root.String()) || !utf8.ValidString(gitDirectory.String()) || !utf8.ValidString(commonDirectory.String()) {
		return domain.ProjectBinding{}, fmt.Errorf("project binding: invalid anchors")
	}
	for _, identity := range []ports.ProjectDirectoryIdentity{rootIdentity, gitIdentity, commonIdentity} {
		if identity.Device == 0 || identity.Inode == 0 || identity.BirthSeconds < 0 || identity.BirthNanoseconds < 0 || identity.BirthNanoseconds >= 1_000_000_000 {
			return domain.ProjectBinding{}, fmt.Errorf("project binding: invalid descriptor identity")
		}
	}
	data, err := json.Marshal(struct {
		Root            string                         `json:"root"`
		GitDirectory    string                         `json:"git_directory"`
		CommonDirectory string                         `json:"common_directory"`
		RootIdentity    ports.ProjectDirectoryIdentity `json:"root_identity"`
		GitIdentity     ports.ProjectDirectoryIdentity `json:"git_identity"`
		CommonIdentity  ports.ProjectDirectoryIdentity `json:"common_identity"`
	}{root.String(), gitDirectory.String(), commonDirectory.String(), rootIdentity, gitIdentity, commonIdentity})
	if err != nil {
		return domain.ProjectBinding{}, err
	}
	return domain.ParseProjectBinding(identitySHA256(append([]byte("mulgae-project-binding.v1\x00"), data...)))
}

// RequestIdentityInput contains only admitted request facts. Component hashes
// are over canonical, credential-free inputs, never temporary paths or run IDs.
type RequestIdentityInput struct {
	ObjectivePresent      bool
	Objective             []byte
	RolesExplicit         bool
	Roles                 []domain.Role
	TargetSelectionSHA256 string
	PolicySHA256          string
	RoutesSHA256          string
	AssetsSHA256          string
	BudgetSHA256          string
	WorkflowSHA256        string
}

type RequestComponents struct {
	TargetSelection string `json:"target_selection"`
	Objective       string `json:"objective"`
	Roles           string `json:"roles"`
	Policy          string `json:"policy"`
	Routes          string `json:"routes"`
	Assets          string `json:"assets"`
	Budget          string `json:"budget"`
	Workflow        string `json:"workflow"`
}

type RequestReceipt struct {
	SchemaVersion   string            `json:"schema_version"`
	ProjectBinding  string            `json:"project_binding"`
	CaptureIdentity string            `json:"capture_identity"`
	Components      RequestComponents `json:"components"`
	RequestDigest   string            `json:"request_digest"`
}

const RequestReceiptVersion = "mulgae-request-receipt.v1"

// DecodeRequestReceipt requires a complete canonical receipt, including its
// computed digest. Identity also supports construction before that field is set.
func DecodeRequestReceipt(data []byte) (RequestReceipt, error) {
	var receipt RequestReceipt
	if err := json.Unmarshal(data, &receipt); err != nil || receipt.RequestDigest == "" {
		return RequestReceipt{}, fmt.Errorf("request receipt: incomplete JSON")
	}
	if _, err := receipt.Identity(); err != nil {
		return RequestReceipt{}, err
	}
	canonical, err := json.Marshal(receipt)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, data) != nil || !bytes.Equal(canonical, compact.Bytes()) {
		return RequestReceipt{}, fmt.Errorf("request receipt: noncanonical encoding")
	}
	return receipt, nil
}

// RequestComponentDigest frames a canonical component without exposing its
// content. The closed names are the fields of RequestComponents.
func RequestComponentDigest(component string, canonical []byte) (string, error) {
	if !slices.Contains([]string{"target_selection", "objective", "roles", "policy", "routes", "assets", "budget", "workflow"}, component) {
		return "", fmt.Errorf("request component: unsupported name")
	}
	return identitySHA256(append([]byte(RequestReceiptVersion+"/"+component+"\x00"), canonical...)), nil
}

func NewRequestReceipt(binding domain.ProjectBinding, capture domain.CaptureIdentity, input RequestIdentityInput) (RequestReceipt, error) {
	if !binding.Valid() || !capture.Valid() || (!input.ObjectivePresent && len(input.Objective) != 0) || !utf8.Valid(input.Objective) || strings.ContainsRune(string(input.Objective), 0) || len(input.Roles) == 0 || len(input.Roles) > 7 {
		return RequestReceipt{}, fmt.Errorf("request receipt: invalid input")
	}
	roles := append([]domain.Role(nil), input.Roles...)
	slices.Sort(roles)
	for i, role := range roles {
		if !role.Valid() || (i > 0 && roles[i-1] == role) {
			return RequestReceipt{}, fmt.Errorf("request receipt: invalid roles")
		}
	}
	objective, err := json.Marshal(struct {
		Present bool   `json:"present"`
		Text    string `json:"text"`
	}{input.ObjectivePresent, string(input.Objective)})
	if err != nil {
		return RequestReceipt{}, err
	}
	roleBytes, err := json.Marshal(struct {
		Explicit bool          `json:"explicit"`
		Roles    []domain.Role `json:"roles"`
	}{input.RolesExplicit, roles})
	if err != nil {
		return RequestReceipt{}, err
	}
	objectiveDigest, err := RequestComponentDigest("objective", objective)
	if err != nil {
		return RequestReceipt{}, err
	}
	roleDigest, err := RequestComponentDigest("roles", roleBytes)
	if err != nil {
		return RequestReceipt{}, err
	}
	receipt := RequestReceipt{SchemaVersion: RequestReceiptVersion, ProjectBinding: binding.String(), CaptureIdentity: capture.String(), Components: RequestComponents{input.TargetSelectionSHA256, objectiveDigest, roleDigest, input.PolicySHA256, input.RoutesSHA256, input.AssetsSHA256, input.BudgetSHA256, input.WorkflowSHA256}}
	identity, err := receipt.Identity()
	if err != nil {
		return RequestReceipt{}, err
	}
	receipt.RequestDigest = identity.String()
	return receipt, nil
}

func (receipt RequestReceipt) Identity() (domain.RequestIdentity, error) {
	c := receipt.Components
	if receipt.SchemaVersion != RequestReceiptVersion {
		return domain.RequestIdentity{}, fmt.Errorf("request receipt: unsupported version")
	}
	for _, digest := range []string{receipt.ProjectBinding, receipt.CaptureIdentity, c.TargetSelection, c.Objective, c.Roles, c.Policy, c.Routes, c.Assets, c.Budget, c.Workflow} {
		if !identityDigestValid(digest) {
			return domain.RequestIdentity{}, fmt.Errorf("request receipt: incomplete components")
		}
	}
	// The digest field is excluded from its own preimage, not encoded as empty.
	data, err := json.Marshal(struct {
		SchemaVersion   string            `json:"schema_version"`
		ProjectBinding  string            `json:"project_binding"`
		CaptureIdentity string            `json:"capture_identity"`
		Components      RequestComponents `json:"components"`
	}{receipt.SchemaVersion, receipt.ProjectBinding, receipt.CaptureIdentity, receipt.Components})
	if err != nil {
		return domain.RequestIdentity{}, err
	}
	identity, err := domain.ParseRequestIdentity(identitySHA256(append([]byte(RequestReceiptVersion+"\x00"), data...)))
	if err != nil {
		return domain.RequestIdentity{}, err
	}
	if receipt.RequestDigest != "" && receipt.RequestDigest != identity.String() {
		return domain.RequestIdentity{}, fmt.Errorf("request receipt: digest mismatch")
	}
	return identity, nil
}

type GuardError string

func (err GuardError) Error() string { return string(err) }

const (
	ErrGuardIncomplete        GuardError = "guard_incomplete"
	ErrGuardInvalid           GuardError = "guard_invalid"
	ErrProjectBindingMismatch GuardError = "project_binding_mismatch"
	ErrRequestDigestMismatch  GuardError = "request_digest_mismatch"
	ErrContractUnsupported    GuardError = "contract_unsupported"
)

// ExecutionGuard is either absent or complete. CheckProject belongs before
// capture; CheckRequest belongs after planning but before provider construction.
type ExecutionGuard struct {
	project domain.ProjectBinding
	request domain.RequestIdentity
	guarded bool
}

func NewExecutionGuard(project, request string) (ExecutionGuard, error) {
	if project == "" && request == "" {
		return ExecutionGuard{}, nil
	}
	if project == "" || request == "" {
		return ExecutionGuard{}, ErrGuardIncomplete
	}
	binding, err := domain.ParseProjectBinding(project)
	if err != nil {
		return ExecutionGuard{}, ErrGuardInvalid
	}
	digest, err := domain.ParseRequestIdentity(request)
	if err != nil {
		return ExecutionGuard{}, ErrGuardInvalid
	}
	return ExecutionGuard{binding, digest, true}, nil
}
func (guard ExecutionGuard) Guarded() bool { return guard.guarded }
func (guard ExecutionGuard) CheckProject(observed domain.ProjectBinding, supported bool) error {
	if !guard.guarded {
		return nil
	}
	if !supported {
		return ErrContractUnsupported
	}
	if !observed.Valid() || observed != guard.project {
		return ErrProjectBindingMismatch
	}
	return nil
}
func (guard ExecutionGuard) CheckRequest(observed domain.RequestIdentity) error {
	if guard.guarded && (!observed.Valid() || observed != guard.request) {
		return ErrRequestDigestMismatch
	}
	return nil
}
