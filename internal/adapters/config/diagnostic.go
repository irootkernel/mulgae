package config

import appconfig "github.com/irootkernel/mulgae/internal/app/config"

type ReasonCode = appconfig.ReasonCode
type AdmissionError = appconfig.AdmissionError

const (
	ReasonYAMLInvalid             = appconfig.ReasonYAMLInvalid
	ReasonSizeInvalid             = appconfig.ReasonSizeInvalid
	ReasonProviderTimeoutInvalid  = appconfig.ReasonProviderTimeoutInvalid
	ReasonProviderIdentityInvalid = appconfig.ReasonProviderIdentityInvalid
	ReasonRoleMappingInvalid      = appconfig.ReasonRoleMappingInvalid
	ReasonCredentialKeyDetected   = appconfig.ReasonCredentialKeyDetected
	ReasonCredentialValueDetected = appconfig.ReasonCredentialValueDetected
)

func AsAdmissionError(err error) (*AdmissionError, bool) { return appconfig.AsAdmissionError(err) }
func reject(reason ReasonCode) error                     { return appconfig.NewAdmissionError(reason) }

// YAMLCodec implements the application-owned configuration codec port.
type YAMLCodec struct{}

func (YAMLCodec) Decode(data []byte) (Config, error)            { return Decode(data) }
func (YAMLCodec) EncodeCanonical(config Config) ([]byte, error) { return EncodeCanonical(config) }
func (YAMLCodec) DecodeSplit(project, local []byte) (Config, error) {
	return DecodeSplit(project, local)
}
func (YAMLCodec) EncodeSplit(config Config) ([]byte, []byte, error) { return EncodeSplit(config) }
func (YAMLCodec) ProjectProviderIDs(project []byte) ([]string, error) {
	return ProjectProviderIDs(project)
}
func (YAMLCodec) MergeProjectConfig(project []byte, local Config) (Config, error) {
	return MergeProjectConfig(project, local)
}
