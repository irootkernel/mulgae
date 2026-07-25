package ports

import (
	"context"
	"errors"
	"fmt"
)

type ConfigLocalityReason string

const (
	ConfigLocalityTargetPrivateConfigForbidden    ConfigLocalityReason = "target_private_config_forbidden"
	ConfigLocalityTargetPrivateNamespaceForbidden ConfigLocalityReason = "target_private_namespace_forbidden"
)

func (reason ConfigLocalityReason) Valid() bool {
	return reason == ConfigLocalityTargetPrivateConfigForbidden || reason == ConfigLocalityTargetPrivateNamespaceForbidden
}

type ConfigLocalityViolation struct {
	reason ConfigLocalityReason
	cause  error
}

func NewConfigLocalityViolation(reason ConfigLocalityReason, cause error) error {
	if !reason.Valid() {
		return fmt.Errorf("config locality violation: invalid reason")
	}
	return &ConfigLocalityViolation{reason: reason, cause: cause}
}

func (violation *ConfigLocalityViolation) Error() string {
	if violation == nil {
		return "config locality violation"
	}
	return "config locality violation: " + string(violation.reason)
}

func (violation *ConfigLocalityViolation) Unwrap() error {
	if violation == nil {
		return nil
	}
	return violation.cause
}

func (violation *ConfigLocalityViolation) Reason() ConfigLocalityReason {
	if violation == nil {
		return ""
	}
	return violation.reason
}

func ConfigLocalityReasonFromError(err error) (ConfigLocalityReason, bool) {
	var violation *ConfigLocalityViolation
	if !errors.As(err, &violation) || violation == nil || !violation.reason.Valid() {
		return "", false
	}
	return violation.reason, true
}

type ConfigFileProof struct {
	present       bool
	rootDevice    uint64
	rootInode     uint64
	rootUID       uint32
	rootMode      uint32
	privateDevice uint64
	privateInode  uint64
	privateUID    uint32
	privateMode   uint32
	configDevice  uint64
	configInode   uint64
	configUID     uint32
	configMode    uint32
	configLinks   uint64
	configSize    int64
	configSHA256  string
}

func NewConfigFileProof(present bool, rootDevice, rootInode uint64, rootUID, rootMode uint32, privateDevice, privateInode uint64, privateUID, privateMode uint32, configDevice, configInode uint64, configUID, configMode uint32, configLinks uint64, configSize int64, configSHA256 string) (ConfigFileProof, error) {
	rootModeAllowed := rootMode == 0o700 || rootMode == 0o750 || rootMode == 0o755
	if rootDevice == 0 || rootInode == 0 || !rootModeAllowed {
		return ConfigFileProof{}, fmt.Errorf("config file proof: missing root identity")
	}
	privatePresent := privateDevice != 0 || privateInode != 0 || privateUID != 0 || privateMode != 0
	if privatePresent && (privateDevice == 0 || privateInode == 0 || privateUID != rootUID || privateMode != 0o700) {
		return ConfigFileProof{}, fmt.Errorf("config file proof: incomplete private directory identity")
	}
	if present && (!privatePresent || configDevice == 0 || configInode == 0 || configUID != rootUID || configMode != 0o600 || configLinks != 1 || configSize < 1 || configSHA256 == "") {
		return ConfigFileProof{}, fmt.Errorf("config file proof: incomplete config identity")
	}
	if !present && (configDevice != 0 || configInode != 0 || configUID != 0 || configMode != 0 || configLinks != 0 || configSize != 0 || configSHA256 != "") {
		return ConfigFileProof{}, fmt.Errorf("config file proof: contradictory absence")
	}
	return ConfigFileProof{present: present, rootDevice: rootDevice, rootInode: rootInode, rootUID: rootUID, rootMode: rootMode, privateDevice: privateDevice, privateInode: privateInode, privateUID: privateUID, privateMode: privateMode, configDevice: configDevice, configInode: configInode, configUID: configUID, configMode: configMode, configLinks: configLinks, configSize: configSize, configSHA256: configSHA256}, nil
}
func (proof ConfigFileProof) Present() bool { return proof.present }
func (proof ConfigFileProof) RootIdentity() (uint64, uint64, uint32, uint32) {
	return proof.rootDevice, proof.rootInode, proof.rootUID, proof.rootMode
}
func (proof ConfigFileProof) PrivateDirectoryIdentity() (uint64, uint64, uint32, uint32) {
	return proof.privateDevice, proof.privateInode, proof.privateUID, proof.privateMode
}
func (proof ConfigFileProof) ConfigIdentity() (uint64, uint64, uint32, uint32, uint64, int64, string) {
	return proof.configDevice, proof.configInode, proof.configUID, proof.configMode, proof.configLinks, proof.configSize, proof.configSHA256
}
func (proof ConfigFileProof) Equal(other ConfigFileProof) bool { return proof == other }

type ParsedTargetProof struct {
	SHA256          string
	Parsed          bool
	PrivatePathFree bool
}

type ConfigLocalityRequest struct {
	root       AnchoredRoot
	config     ConfigFileProof
	applicable []GitObjectID
	target     []byte
}

func NewConfigLocalityRequest(root AnchoredRoot, config ConfigFileProof, applicable []GitObjectID, target []byte) (ConfigLocalityRequest, error) {
	if !root.Valid() {
		return ConfigLocalityRequest{}, fmt.Errorf("config locality request: invalid root")
	}
	for _, oid := range applicable {
		if !oid.Valid() {
			return ConfigLocalityRequest{}, fmt.Errorf("config locality request: invalid commit")
		}
	}
	return ConfigLocalityRequest{root: root, config: config, applicable: append([]GitObjectID(nil), applicable...), target: append([]byte(nil), target...)}, nil
}
func (request ConfigLocalityRequest) Root() AnchoredRoot      { return request.root }
func (request ConfigLocalityRequest) Config() ConfigFileProof { return request.config }
func (request ConfigLocalityRequest) ApplicableCommits() []GitObjectID {
	return append([]GitObjectID(nil), request.applicable...)
}
func (request ConfigLocalityRequest) TargetBytes() []byte {
	return append([]byte(nil), request.target...)
}

type ConfigLocalityContext struct {
	kind            string
	repositoryID    string
	rootDevice      uint64
	rootInode       uint64
	rootUID         uint32
	rootMode        uint32
	headCommit      string
	headTree        string
	indexSHA256     string
	indexEntryCount int
	hasUnmerged     bool
	applicable      []string
	config          ConfigFileProof
	target          ParsedTargetProof
}

func NewConfigLocalityContext(repositoryID string, rootDevice, rootInode uint64, rootUID, rootMode uint32, headCommit, headTree, indexSHA256 string, indexEntryCount int, hasUnmerged bool, applicable []string, config ConfigFileProof, target ParsedTargetProof) (ConfigLocalityContext, error) {
	if repositoryID == "" || rootDevice == 0 || rootInode == 0 || headCommit == "" || headTree == "" || indexSHA256 == "" || indexEntryCount < 0 || target.SHA256 == "" {
		return ConfigLocalityContext{}, fmt.Errorf("config locality context: incomplete")
	}
	if hasUnmerged || !target.PrivatePathFree {
		return ConfigLocalityContext{}, fmt.Errorf("config locality context: unsafe")
	}
	return ConfigLocalityContext{kind: "git", repositoryID: repositoryID, rootDevice: rootDevice, rootInode: rootInode, rootUID: rootUID, rootMode: rootMode, headCommit: headCommit, headTree: headTree, indexSHA256: indexSHA256, indexEntryCount: indexEntryCount, hasUnmerged: hasUnmerged, applicable: append([]string(nil), applicable...), config: config, target: target}, nil
}

func NewFilesystemConfigLocalityContext(config ConfigFileProof, target ParsedTargetProof) (ConfigLocalityContext, error) {
	rootDevice, rootInode, rootUID, rootMode := config.RootIdentity()
	if rootDevice == 0 || rootInode == 0 || target.SHA256 == "" || !target.PrivatePathFree {
		return ConfigLocalityContext{}, fmt.Errorf("filesystem config locality context: incomplete or unsafe")
	}
	return ConfigLocalityContext{
		kind: "filesystem", repositoryID: fmt.Sprintf("filesystem:%d:%d", rootDevice, rootInode),
		rootDevice: rootDevice, rootInode: rootInode, rootUID: rootUID, rootMode: rootMode,
		indexSHA256: "sha256:filesystem", config: config, target: target,
	}, nil
}

func (context ConfigLocalityContext) Kind() string         { return context.kind }
func (context ConfigLocalityContext) RepositoryID() string { return context.repositoryID }
func (context ConfigLocalityContext) Checkout() (string, string) {
	return context.headCommit, context.headTree
}
func (context ConfigLocalityContext) Index() (string, int, bool) {
	return context.indexSHA256, context.indexEntryCount, context.hasUnmerged
}
func (context ConfigLocalityContext) ApplicableCommitOIDs() []string {
	return append([]string(nil), context.applicable...)
}
func (context ConfigLocalityContext) Config() ConfigFileProof   { return context.config }
func (context ConfigLocalityContext) Target() ParsedTargetProof { return context.target }
func (context ConfigLocalityContext) Equal(other ConfigLocalityContext) bool {
	if context.kind != other.kind || context.repositoryID != other.repositoryID || context.rootDevice != other.rootDevice || context.rootInode != other.rootInode || context.rootUID != other.rootUID || context.rootMode != other.rootMode || context.headCommit != other.headCommit || context.headTree != other.headTree || context.indexSHA256 != other.indexSHA256 || context.indexEntryCount != other.indexEntryCount || context.hasUnmerged != other.hasUnmerged || context.config != other.config || context.target != other.target || len(context.applicable) != len(other.applicable) {
		return false
	}
	for index := range context.applicable {
		if context.applicable[index] != other.applicable[index] {
			return false
		}
	}
	return true
}
func (context ConfigLocalityContext) SameRepositoryEnvironment(other ConfigLocalityContext) bool {
	if context.kind != other.kind || context.repositoryID != other.repositoryID || context.rootDevice != other.rootDevice || context.rootInode != other.rootInode || context.rootUID != other.rootUID || context.rootMode != other.rootMode || context.headCommit != other.headCommit || context.headTree != other.headTree || context.indexSHA256 != other.indexSHA256 || context.indexEntryCount != other.indexEntryCount || context.hasUnmerged != other.hasUnmerged || context.target != other.target || len(context.applicable) != len(other.applicable) {
		return false
	}
	for index := range context.applicable {
		if context.applicable[index] != other.applicable[index] {
			return false
		}
	}
	return true
}

type ConfigLocalityAttestor interface {
	Attest(context.Context, ConfigLocalityRequest) (ConfigLocalityContext, error)
	Revalidate(context.Context, ConfigLocalityRequest, ConfigLocalityContext) error
}
