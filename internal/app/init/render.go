package init

import appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"

func RenderConfigYAML(codec appconfig.Codec, config appconfig.Config) ([]byte, error) {
	return codec.EncodeCanonical(config)
}
