package config

import "testing"

func TestProviderTimeoutProvenanceDistinguishesConfiguredAndDefaulted(t *testing.T) {
	config := Config{Providers: ProvidersConfig{
		Kimi:  &KimiProviderConfig{Timeout: ProviderTimeoutText(DefaultProviderTimeout)},
		ZCode: &ZCodeProviderConfig{Timeout: "30m"},
	}}
	rows := provenanceRows(config)
	want := map[string]struct {
		source      string
		disposition string
	}{
		"providers.kimi.timeout":  {source: "default", disposition: "defaulted"},
		"providers.zcode.timeout": {source: "project", disposition: "configured"},
	}
	for _, row := range rows {
		expected, ok := want[row.Field]
		if !ok {
			continue
		}
		if row.Source != expected.source || row.Disposition != expected.disposition || row.ValueClass != "policy" {
			t.Fatalf("%s provenance = %#v", row.Field, row)
		}
		delete(want, row.Field)
	}
	if len(want) != 0 {
		t.Fatalf("missing provider timeout provenance: %#v", want)
	}
}
