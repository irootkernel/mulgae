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
	present      bool
	rootDevice   uint64
	rootInode    uint64
	rootUID      uint32
	rootMode     uint32
	mulgaeDevice uint64
	mulgaeInode  uint64
	mulgaeUID    uint32
	mulgaeMode   uint32
	configDevice uint64
	configInode  uint64
	configUID    uint32
	configMode   uint32
	configLinks  uint64
	size         int64
	digest       [sha256.Size]byte
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
	contents    []byte
	observation LocalConfigObservation
}

// NewLocalConfigSource opens only <root>/.mulgae/config.yaml. It never consults
// HOME, XDG, embedded defaults, legacy filenames, or Git-controlled content.
func NewLocalConfigSource(root ports.AnchoredRoot, allowAbsent bool) (*LocalConfigSource, error) {
	if !root.Valid() {
		return nil, fmt.Errorf("local config: invalid project root")
	}
	contents, observation, err := readLocalConfig(root, allowAbsent)
	if err != nil {
		return nil, err
	}
	return &LocalConfigSource{root: root, contents: contents, observation: observation}, nil
}

func (source *LocalConfigSource) Present() bool { return source != nil && source.observation.present }
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
	return append([]byte(nil), source.contents...), identity, nil
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
	contents, observation, err := readLocalConfig(source.root, true)
	if err != nil {
		return err
	}
	if observation != source.observation || !equalBytes(contents, source.contents) {
		return fmt.Errorf("local config: source drifted")
	}
	return nil
}

type SourceFactory struct{}

func (SourceFactory) OpenConfigSource(root ports.AnchoredRoot, allowAbsent bool) (ports.ConfigSource, error) {
	return NewLocalConfigSource(root, allowAbsent)
}

func readLocalConfig(root ports.AnchoredRoot, allowAbsent bool) ([]byte, LocalConfigObservation, error) {
	rootFD, err := unix.Open(root.String(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, LocalConfigObservation{}, fmt.Errorf("local config: open project root: %w", err)
	}
	defer unix.Close(rootFD)
	rootStat, err := statFD(rootFD)
	if err != nil {
		return nil, LocalConfigObservation{}, err
	}
	rootMode := uint32(rootStat.Mode & 0o7777)
	if rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Uid != uint32(os.Geteuid()) || rootMode != 0o700 && rootMode != 0o750 && rootMode != 0o755 {
		return nil, LocalConfigObservation{}, fmt.Errorf("local config: unsafe project root")
	}
	observation := LocalConfigObservation{rootDevice: uint64(rootStat.Dev), rootInode: uint64(rootStat.Ino), rootUID: rootStat.Uid, rootMode: rootMode}
	mulgaeFD, err := unix.Openat(rootFD, ".mulgae", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if allowAbsent && err == unix.ENOENT {
			return nil, observation, nil
		}
		return nil, LocalConfigObservation{}, fmt.Errorf("local config: open private directory: %w", err)
	}
	defer unix.Close(mulgaeFD)
	mulgaeStat, err := statFD(mulgaeFD)
	if err != nil {
		return nil, LocalConfigObservation{}, err
	}
	if mulgaeStat.Mode&unix.S_IFMT != unix.S_IFDIR || mulgaeStat.Uid != uint32(os.Geteuid()) || mulgaeStat.Mode&0o7777 != 0o700 {
		return nil, LocalConfigObservation{}, fmt.Errorf("local config: unsafe private directory")
	}
	observation.mulgaeDevice, observation.mulgaeInode = uint64(mulgaeStat.Dev), uint64(mulgaeStat.Ino)
	observation.mulgaeUID, observation.mulgaeMode = mulgaeStat.Uid, uint32(mulgaeStat.Mode&0o7777)
	configFD, err := unix.Openat(mulgaeFD, "config.yaml", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if allowAbsent && err == unix.ENOENT {
			return nil, observation, nil
		}
		return nil, LocalConfigObservation{}, fmt.Errorf("local config: open config: %w", err)
	}
	defer unix.Close(configFD)
	configStat, err := statFD(configFD)
	if err != nil {
		return nil, LocalConfigObservation{}, err
	}
	if configStat.Mode&unix.S_IFMT != unix.S_IFREG || configStat.Uid != uint32(os.Geteuid()) || configStat.Mode&0o7777 != 0o600 || configStat.Nlink != 1 || configStat.Size < 1 || configStat.Size > MaximumConfigBytes {
		return nil, LocalConfigObservation{}, fmt.Errorf("local config: unsafe config file")
	}
	contents := make([]byte, configStat.Size)
	readFD, err := unix.Dup(configFD)
	if err != nil {
		return nil, LocalConfigObservation{}, fmt.Errorf("local config: duplicate config descriptor: %w", err)
	}
	file := os.NewFile(uintptr(readFD), "config.yaml")
	_, readErr := io.ReadFull(file, contents)
	closeErr := file.Close()
	if readErr != nil {
		return nil, LocalConfigObservation{}, fmt.Errorf("local config: read config: %w", readErr)
	}
	if closeErr != nil {
		return nil, LocalConfigObservation{}, fmt.Errorf("local config: close config reader: %w", closeErr)
	}
	digest := sha256.Sum256(contents)
	observation.present = true
	observation.configDevice, observation.configInode = uint64(configStat.Dev), uint64(configStat.Ino)
	observation.configUID, observation.configMode, observation.configLinks, observation.size = configStat.Uid, uint32(configStat.Mode&0o7777), uint64(configStat.Nlink), configStat.Size
	observation.digest = digest
	return contents, observation, nil
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
