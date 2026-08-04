package config

import appconfig "github.com/irootkernel/mulgae/internal/app/config"

type ReasonCode = appconfig.ReasonCode
type AdmissionError = appconfig.AdmissionError

const (
	ReasonYAMLInvalid             = appconfig.ReasonYAMLInvalid
	ReasonSizeInvalid             = appconfig.ReasonSizeInvalid
	ReasonProviderTimeoutInvalid  = appconfig.ReasonProviderTimeoutInvalid
	ReasonCredentialKeyDetected   = appconfig.ReasonCredentialKeyDetected
	ReasonCredentialValueDetected = appconfig.ReasonCredentialValueDetected
)

func AsAdmissionError(err error) (*AdmissionError, bool) { return appconfig.AsAdmissionError(err) }
func reject(reason ReasonCode) error                     { return appconfig.NewAdmissionError(reason) }

// YAMLCodec implements the application-owned configuration codec port.
type YAMLCodec struct{}

func (YAMLCodec) Decode(data []byte) (Config, error)            { return Decode(data) }
func (YAMLCodec) EncodeCanonical(config Config) ([]byte, error) { return EncodeCanonical(config) }
