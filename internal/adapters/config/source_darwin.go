//go:build darwin

package config

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

type LocalConfigObservation struct {
	present       bool
	rootDevice    uint64
	rootInode     uint64
	rootUID       uint32
	rootMode      uint32
	mulgaeDevice  uint64
	mulgaeInode   uint64
	mulgaeUID     uint32
	mulgaeMode    uint32
	configDevice  uint64
	configInode   uint64
	configUID     uint32
	configMode    uint32
	configLinks   uint64
	size          int64
	digest        [sha256.Size]byte
	projectDevice uint64
	projectInode  uint64
	projectUID    uint32
	projectMode   uint32
	projectLinks  uint64
	projectSize   int64
	projectDigest [sha256.Size]byte
}

func (observation LocalConfigObservation) Present() bool { return observation.present }
func (observation LocalConfigObservation) SHA256() string {
	if !observation.present {
		return ""
	}
	return fmt.Sprintf("sha256:%x", observation.digest)
}
func (observation LocalConfigObservation) RootIdentity() (uint64, uint64, uint32, uint32) {
	return observation.rootDevice, observation.rootInode, observation.rootUID, observation.rootMode
}
func (observation LocalConfigObservation) PrivateDirectoryIdentity() (uint64, uint64) {
	return observation.mulgaeDevice, observation.mulgaeInode
}
func (observation LocalConfigObservation) ConfigIdentity() (uint64, uint64, uint32, uint32, uint64, int64) {
	return observation.configDevice, observation.configInode, observation.configUID, observation.configMode, observation.configLinks, observation.size
}
func (observation LocalConfigObservation) Proof() (ports.ConfigFileProof, error) {
	return ports.NewConfigFileProof(observation.present, observation.rootDevice, observation.rootInode, observation.rootUID, observation.rootMode, observation.mulgaeDevice, observation.mulgaeInode, observation.mulgaeUID, observation.mulgaeMode, observation.configDevice, observation.configInode, observation.configUID, observation.configMode, observation.configLinks, observation.size, observation.SHA256())
}
func (observation LocalConfigObservation) DirectoryIdentity() (ports.ConfigDirectoryIdentity, error) {
	return ports.NewConfigDirectoryIdentity(observation.rootDevice, observation.rootInode, observation.rootUID, observation.rootMode, observation.mulgaeDevice, observation.mulgaeInode, observation.mulgaeUID, observation.mulgaeMode)
}
func (observation LocalConfigObservation) InstalledConfigIdentity() (ports.ConfigFileIdentity, error) {
	if !observation.present {
		return ports.ConfigFileIdentity{}, fmt.Errorf("local config: config identity absent")
	}
	return ports.NewConfigFileIdentity(observation.configDevice, observation.configInode, observation.configUID, observation.configMode, observation.configLinks, observation.size, observation.SHA256())
}

type LocalConfigSource struct {
	root        ports.AnchoredRoot
	project     []byte
	local       []byte
	observation LocalConfigObservation
}

// NewLocalConfigSource opens only the Config v2 project/local pair beneath
// <root>/.mulgae. It never consults HOME, XDG, embedded defaults, or legacy
// filenames.
func NewLocalConfigSource(root ports.AnchoredRoot, allowAbsent bool) (*LocalConfigSource, error) {
	if !root.Valid() {
		return nil, fmt.Errorf("local config: invalid project root")
	}
	project, local, observation, err := readLocalConfig(root, allowAbsent)
	if err != nil {
		return nil, err
	}
	return &LocalConfigSource{root: root, project: project, local: local, observation: observation}, nil
}

func (source *LocalConfigSource) Present() bool { return source != nil && source.observation.present }
func (source *LocalConfigSource) ProjectPresent() bool {
	return source != nil && len(source.project) != 0
}
func (source *LocalConfigSource) ProjectBytes() []byte {
	if source == nil {
		return nil
	}
	return append([]byte(nil), source.project...)
}
func (source *LocalConfigSource) LocalBytes() []byte {
	if source == nil {
		return nil
	}
	return append([]byte(nil), source.local...)
}
func (source *LocalConfigSource) Observation() LocalConfigObservation {
	if source == nil {
		return LocalConfigObservation{}
	}
	return source.observation
}
func (source *LocalConfigSource) Read() ([]byte, ports.ConfigFileIdentity, error) {
	if source == nil || !source.observation.present {
		return nil, ports.ConfigFileIdentity{}, fmt.Errorf("local config: absent")
	}
	if err := source.Revalidate(); err != nil {
		return nil, ports.ConfigFileIdentity{}, err
	}
	identity, err := source.observation.InstalledConfigIdentity()
	if err != nil {
		return nil, ports.ConfigFileIdentity{}, err
	}
	decoded, err := DecodeSplit(source.project, source.local)
	if err != nil {
		return nil, ports.ConfigFileIdentity{}, err
	}
	contents, err := EncodeCanonical(decoded)
	if err != nil {
		return nil, ports.ConfigFileIdentity{}, err
	}
	return contents, identity, nil
}
func (source *LocalConfigSource) Proof() (ports.ConfigFileProof, error) {
	return source.Observation().Proof()
}
func (source *LocalConfigSource) DirectoryIdentity() (ports.ConfigDirectoryIdentity, error) {
	return source.Observation().DirectoryIdentity()
}
func (source *LocalConfigSource) Revalidate() error {
	if source == nil || !source.root.Valid() {
		return fmt.Errorf("local config: invalid source")
	}
	project, local, observation, err := readLocalConfig(source.root, true)
	if err != nil {
		return err
	}
	if observation != source.observation || !equalBytes(project, source.project) || !equalBytes(local, source.local) {
		return fmt.Errorf("local config: source drifted")
	}
	return nil
}

type SourceFactory struct{}

func (SourceFactory) OpenConfigSource(root ports.AnchoredRoot, allowAbsent bool) (ports.ConfigSource, error) {
	return NewLocalConfigSource(root, allowAbsent)
}

func readLocalConfig(root ports.AnchoredRoot, allowAbsent bool) ([]byte, []byte, LocalConfigObservation, error) {
	rootFD, err := unix.Open(root.String(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, LocalConfigObservation{}, fmt.Errorf("local config: open project root: %w", err)
	}
	defer unix.Close(rootFD)
	rootStat, err := statFD(rootFD)
	if err != nil {
		return nil, nil, LocalConfigObservation{}, err
	}
	rootMode := uint32(rootStat.Mode & 0o7777)
	if rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Uid != uint32(os.Geteuid()) || rootMode != 0o700 && rootMode != 0o750 && rootMode != 0o755 {
		return nil, nil, LocalConfigObservation{}, fmt.Errorf("local config: unsafe project root")
	}
	observation := LocalConfigObservation{rootDevice: uint64(rootStat.Dev), rootInode: uint64(rootStat.Ino), rootUID: rootStat.Uid, rootMode: rootMode}
	mulgaeFD, err := unix.Openat(rootFD, ".mulgae", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if allowAbsent && err == unix.ENOENT {
			return nil, nil, observation, nil
		}
		return nil, nil, LocalConfigObservation{}, fmt.Errorf("local config: open private directory: %w", err)
	}
	defer unix.Close(mulgaeFD)
	mulgaeStat, err := statFD(mulgaeFD)
	if err != nil {
		return nil, nil, LocalConfigObservation{}, err
	}
	privateMode := uint32(mulgaeStat.Mode & 0o7777)
	if mulgaeStat.Mode&unix.S_IFMT != unix.S_IFDIR || mulgaeStat.Uid != uint32(os.Geteuid()) || privateMode != 0o700 && privateMode != 0o755 {
		return nil, nil, LocalConfigObservation{}, fmt.Errorf("local config: unsafe private directory")
	}
	observation.mulgaeDevice, observation.mulgaeInode = uint64(mulgaeStat.Dev), uint64(mulgaeStat.Ino)
	observation.mulgaeUID, observation.mulgaeMode = mulgaeStat.Uid, uint32(mulgaeStat.Mode&0o7777)
	project, projectStat, err := readConfigFile(mulgaeFD, "config.yaml", false)
	if err != nil {
		if allowAbsent && err == unix.ENOENT && privateMode == 0o700 {
			return nil, nil, observation, nil
		}
		return nil, nil, LocalConfigObservation{}, fmt.Errorf("local config: project config: %w", err)
	}
	observation.projectDevice, observation.projectInode = uint64(projectStat.Dev), uint64(projectStat.Ino)
	observation.projectUID, observation.projectMode, observation.projectLinks, observation.projectSize = projectStat.Uid, uint32(projectStat.Mode&0o7777), uint64(projectStat.Nlink), projectStat.Size
	observation.projectDigest = sha256.Sum256(project)
	local, localStat, err := readConfigFile(mulgaeFD, "local.yaml", true)
	if err != nil {
		if allowAbsent && err == unix.ENOENT {
			return project, nil, observation, nil
		}
		return nil, nil, LocalConfigObservation{}, fmt.Errorf("local config: machine config: %w", err)
	}
	if privateMode != 0o700 {
		return nil, nil, LocalConfigObservation{}, fmt.Errorf("local config: private directory must be mode 0700 when local config exists")
	}
	digest := sha256.Sum256(local)
	observation.present = true
	observation.configDevice, observation.configInode = uint64(localStat.Dev), uint64(localStat.Ino)
	observation.configUID, observation.configMode, observation.configLinks, observation.size = localStat.Uid, uint32(localStat.Mode&0o7777), uint64(localStat.Nlink), localStat.Size
	observation.digest = digest
	return project, local, observation, nil
}

func readConfigFile(directoryFD int, name string, private bool) ([]byte, unix.Stat_t, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	defer unix.Close(fd)
	stat, err := statFD(fd)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	mode := uint32(stat.Mode & 0o7777)
	modeAllowed := mode == 0o600
	if !private {
		modeAllowed = mode == 0o600 || mode == 0o644
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || !modeAllowed || stat.Nlink != 1 || stat.Size < 1 || stat.Size > MaximumConfigBytes {
		return nil, unix.Stat_t{}, fmt.Errorf("unsafe %s", name)
	}
	readFD, err := unix.Dup(fd)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	file := os.NewFile(uintptr(readFD), name)
	data := make([]byte, stat.Size)
	_, readErr := io.ReadFull(file, data)
	closeErr := file.Close()
	if readErr != nil {
		return nil, unix.Stat_t{}, readErr
	}
	if closeErr != nil {
		return nil, unix.Stat_t{}, closeErr
	}
	return data, stat, nil
}

func statFD(fd int) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return stat, fmt.Errorf("local config: stat descriptor: %w", err)
	}
	return stat, nil
}
func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
