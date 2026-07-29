package init

import appconfig "github.com/irootkernel/mulgae/internal/app/config"

func RenderConfigYAML(codec appconfig.Codec, config appconfig.Config) ([]byte, error) {
	return codec.EncodeCanonical(config)
}
