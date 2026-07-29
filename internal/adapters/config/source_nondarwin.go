//go:build !darwin

package config

import (
	"fmt"
	"github.com/irootkernel/mulgae/internal/ports"
)

type LocalConfigObservation struct{}

func (LocalConfigObservation) Present() bool                                  { return false }
func (LocalConfigObservation) SHA256() string                                 { return "" }
func (LocalConfigObservation) RootIdentity() (uint64, uint64, uint32, uint32) { return 0, 0, 0, 0 }
func (LocalConfigObservation) PrivateDirectoryIdentity() (uint64, uint64)     { return 0, 0 }
func (LocalConfigObservation) ConfigIdentity() (uint64, uint64, uint32, uint32, uint64, int64) {
	return 0, 0, 0, 0, 0, 0
}
func (LocalConfigObservation) Proof() (ports.ConfigFileProof, error) {
	return ports.ConfigFileProof{}, fmt.Errorf("local config: unsupported platform")
}

type LocalConfigSource struct{}

func NewLocalConfigSource(ports.AnchoredRoot, bool) (*LocalConfigSource, error) {
	return nil, fmt.Errorf("local config: unsupported platform")
}
func (*LocalConfigSource) Present() bool                       { return false }
func (*LocalConfigSource) Observation() LocalConfigObservation { return LocalConfigObservation{} }
func (*LocalConfigSource) Read() ([]byte, ports.ConfigFileIdentity, error) {
	return nil, ports.ConfigFileIdentity{}, fmt.Errorf("local config: unsupported platform")
}
func (*LocalConfigSource) Proof() (ports.ConfigFileProof, error) {
	return ports.ConfigFileProof{}, fmt.Errorf("local config: unsupported platform")
}
func (*LocalConfigSource) DirectoryIdentity() (ports.ConfigDirectoryIdentity, error) {
	return ports.ConfigDirectoryIdentity{}, fmt.Errorf("local config: unsupported platform")
}
func (*LocalConfigSource) Revalidate() error { return fmt.Errorf("local config: unsupported platform") }

type SourceFactory struct{}

func (SourceFactory) OpenConfigSource(root ports.AnchoredRoot, allowAbsent bool) (ports.ConfigSource, error) {
	return NewLocalConfigSource(root, allowAbsent)
}
