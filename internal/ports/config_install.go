package ports

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

type ConfigDestinationState string

const (
	ConfigDestinationPresent     ConfigDestinationState = "present"
	ConfigDestinationAbsent      ConfigDestinationState = "absent"
	ConfigDestinationNotObserved ConfigDestinationState = "not_observed"
)

type ConfigInstallStage string

const (
	ConfigInstallStagePrivateDirRace     ConfigInstallStage = "private_dir_race"
	ConfigInstallStageRootSync           ConfigInstallStage = "root_sync"
	ConfigInstallStageRootReattestation  ConfigInstallStage = "root_reattestation"
	ConfigInstallStagePreparedIdentity   ConfigInstallStage = "prepared_identity"
	ConfigInstallStagePreinstall         ConfigInstallStage = "preinstall"
	ConfigInstallStageCollision          ConfigInstallStage = "collision"
	ConfigInstallStageDirectorySync      ConfigInstallStage = "directory_sync"
	ConfigInstallStageFinalReattestation ConfigInstallStage = "final_reattestation"
	ConfigInstallStageBundlePartial      ConfigInstallStage = "bundle_partial"
)

type ConfigDirectoryIdentity struct {
	rootDevice, rootInode       uint64
	rootUID, rootMode           uint32
	privateDevice, privateInode uint64
	privateUID, privateMode     uint32
}

func NewConfigDirectoryIdentity(rootDevice, rootInode uint64, rootUID, rootMode uint32, privateDevice, privateInode uint64, privateUID, privateMode uint32) (ConfigDirectoryIdentity, error) {
	rootModeAllowed := rootMode == 0o700 || rootMode == 0o750 || rootMode == 0o755
	if rootDevice == 0 || rootInode == 0 || !rootModeAllowed || privateDevice == 0 || privateInode == 0 || privateUID != rootUID || privateMode != 0o700 {
		return ConfigDirectoryIdentity{}, fmt.Errorf("config directory identity: invalid")
	}
	return ConfigDirectoryIdentity{rootDevice: rootDevice, rootInode: rootInode, rootUID: rootUID, rootMode: rootMode, privateDevice: privateDevice, privateInode: privateInode, privateUID: privateUID, privateMode: privateMode}, nil
}
func (identity ConfigDirectoryIdentity) Valid() bool {
	_, err := NewConfigDirectoryIdentity(identity.rootDevice, identity.rootInode, identity.rootUID, identity.rootMode, identity.privateDevice, identity.privateInode, identity.privateUID, identity.privateMode)
	return err == nil
}
func (identity ConfigDirectoryIdentity) Equal(other ConfigDirectoryIdentity) bool {
	return identity == other
}
func (identity ConfigDirectoryIdentity) Root() (uint64, uint64, uint32, uint32) {
	return identity.rootDevice, identity.rootInode, identity.rootUID, identity.rootMode
}
func (identity ConfigDirectoryIdentity) PrivateDirectory() (uint64, uint64, uint32, uint32) {
	return identity.privateDevice, identity.privateInode, identity.privateUID, identity.privateMode
}

type ConfigDirectoryReceipt struct {
	created  bool
	identity ConfigDirectoryIdentity
}

func (receipt ConfigDirectoryReceipt) CreatedByInvocation() bool { return receipt.created }
func NewVerifiedConfigDirectoryReceipt(created bool, identity ConfigDirectoryIdentity) (ConfigDirectoryReceipt, error) {
	if !identity.Valid() {
		return ConfigDirectoryReceipt{}, fmt.Errorf("config directory receipt: invalid identity")
	}
	return ConfigDirectoryReceipt{created: created, identity: identity}, nil
}
func (receipt ConfigDirectoryReceipt) Identity() (ConfigDirectoryIdentity, bool) {
	return receipt.identity, receipt.identity.Valid()
}

type ConfigFileIdentity struct {
	device, inode uint64
	uid, mode     uint32
	links         uint64
	byteLength    int64
	sha256        string
}

func NewConfigFileIdentity(device, inode uint64, uid, mode uint32, links uint64, byteLength int64, sha256 string) (ConfigFileIdentity, error) {
	digest, digestErr := hex.DecodeString(strings.TrimPrefix(sha256, "sha256:"))
	if device == 0 || inode == 0 || mode != 0o600 || links != 1 || byteLength < 1 || !strings.HasPrefix(sha256, "sha256:") || len(digest) != 32 || digestErr != nil {
		return ConfigFileIdentity{}, fmt.Errorf("config file identity: invalid")
	}
	return ConfigFileIdentity{device: device, inode: inode, uid: uid, mode: mode, links: links, byteLength: byteLength, sha256: sha256}, nil
}
func (identity ConfigFileIdentity) Valid() bool {
	_, err := NewConfigFileIdentity(identity.device, identity.inode, identity.uid, identity.mode, identity.links, identity.byteLength, identity.sha256)
	return err == nil
}
func (identity ConfigFileIdentity) Equal(other ConfigFileIdentity) bool { return identity == other }
func (identity ConfigFileIdentity) Descriptor() (uint64, uint64, uint32, uint32, uint64) {
	return identity.device, identity.inode, identity.uid, identity.mode, identity.links
}
func (identity ConfigFileIdentity) ByteLength() int64 { return identity.byteLength }
func (identity ConfigFileIdentity) SHA256() string    { return identity.sha256 }

type ConfigInstallReceipt struct {
	installed  bool
	sha256     string
	byteLength int64
	directory  ConfigDirectoryIdentity
	config     ConfigFileIdentity
}

func NewVerifiedConfigInstallReceipt(directory ConfigDirectoryIdentity, config ConfigFileIdentity) (ConfigInstallReceipt, error) {
	if !directory.Valid() || !config.Valid() {
		return ConfigInstallReceipt{}, fmt.Errorf("config install receipt: invalid identity")
	}
	_, _, privateUID, _ := directory.PrivateDirectory()
	_, _, configUID, _, _ := config.Descriptor()
	if privateUID != configUID {
		return ConfigInstallReceipt{}, fmt.Errorf("config install receipt: ownership mismatch")
	}
	return ConfigInstallReceipt{installed: true, sha256: config.SHA256(), byteLength: config.ByteLength(), directory: directory, config: config}, nil
}
func (receipt ConfigInstallReceipt) Installed() bool   { return receipt.installed }
func (receipt ConfigInstallReceipt) SHA256() string    { return receipt.sha256 }
func (receipt ConfigInstallReceipt) ByteLength() int64 { return receipt.byteLength }
func (receipt ConfigInstallReceipt) DirectoryIdentity() (ConfigDirectoryIdentity, bool) {
	return receipt.directory, receipt.directory.Valid()
}
func (receipt ConfigInstallReceipt) ConfigIdentity() (ConfigFileIdentity, bool) {
	return receipt.config, receipt.config.Valid()
}

type ConfigInstallError struct {
	stage       ConfigInstallStage
	destination ConfigDestinationState
	cause       error
}

func NewConfigInstallError(stage ConfigInstallStage, destination ConfigDestinationState, cause error) *ConfigInstallError {
	return &ConfigInstallError{stage: stage, destination: destination, cause: cause}
}
func (err *ConfigInstallError) Error() string {
	if err == nil {
		return "config install failed"
	}
	return fmt.Sprintf("config install failed at %s: %v", err.stage, err.cause)
}
func (err *ConfigInstallError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}
func (err *ConfigInstallError) Stage() ConfigInstallStage {
	if err == nil {
		return ""
	}
	return err.stage
}
func (err *ConfigInstallError) DestinationState() ConfigDestinationState {
	if err == nil {
		return ConfigDestinationNotObserved
	}
	return err.destination
}

type ConfigInstaller interface {
	PrepareConfigDirectory(context.Context, AnchoredRoot) (ConfigDirectoryReceipt, error)
	InstallConfig(context.Context, AnchoredRoot, ConfigDirectoryReceipt, []byte) (ConfigInstallReceipt, error)
}

// ConfigSource is a descriptor-bound view of the sole project-local config.
type ConfigSource interface {
	Present() bool
	Read() ([]byte, ConfigFileIdentity, error)
	Proof() (ConfigFileProof, error)
	DirectoryIdentity() (ConfigDirectoryIdentity, error)
	Revalidate() error
}

// ConfigSourceFactory opens a config source without giving application code
// filesystem construction authority.
type ConfigSourceFactory interface {
	OpenConfigSource(AnchoredRoot, bool) (ConfigSource, error)
}

// SplitConfigSource exposes the separately admitted Config v3 authorities.
type SplitConfigSource interface {
	ConfigSource
	ProjectPresent() bool
	ProjectBytes() []byte
	LocalBytes() []byte
}

// SplitConfigInstaller installs or refreshes Config v3 without allowing the
// machine-local operation to rewrite shared project policy.
type SplitConfigInstaller interface {
	ConfigInstaller
	InstallConfigBundle(context.Context, AnchoredRoot, ConfigDirectoryReceipt, []byte, []byte) (ConfigInstallReceipt, error)
	InstallLocalConfig(context.Context, AnchoredRoot, ConfigDirectoryReceipt, []byte) (ConfigInstallReceipt, error)
	RefreshLocalConfig(context.Context, AnchoredRoot, ConfigDirectoryReceipt, []byte) (ConfigInstallReceipt, error)
}
