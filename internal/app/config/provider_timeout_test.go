package config

import "testing"

func TestProviderTimeoutProvenanceDistinguishesConfiguredAndDefaulted(t *testing.T) {
	config := Config{Providers: ProvidersConfig{
		ZCode: &ZCodeProviderConfig{Timeout: "30m"},
		Grok:  &GrokProviderConfig{Timeout: ProviderTimeoutText(DefaultProviderTimeout)},
	}}
	rows := provenanceRows(config)
	want := map[string]struct {
		source      string
		disposition string
	}{
		"providers.zcode.timeout": {source: "project", disposition: "configured"},
		"providers.grok.timeout":  {source: "default", disposition: "defaulted"},
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

func TestExtractionProvenanceDistinguishesConfiguredAndDefaulted(t *testing.T) {
	for _, test := range []struct {
		name        string
		extraction  ExtractionConfig
		source      string
		disposition string
	}{
		{name: "omitted", source: "default", disposition: "defaulted"},
		{name: "explicit false", extraction: ExtractionConfig{EnabledExplicit: true}, source: "project", disposition: "configured"},
		{name: "explicit true", extraction: ExtractionConfig{Enabled: true, EnabledExplicit: true}, source: "project", disposition: "configured"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows := provenanceRows(Config{Validation: ValidationConfig{Extraction: test.extraction}})
			for _, row := range rows {
				if row.Field != "validation.extraction.enabled" {
					continue
				}
				if row.Source != test.source || row.Disposition != test.disposition || row.ValueClass != "policy" {
					t.Fatalf("extraction provenance = %#v", row)
				}
				return
			}
			t.Fatal("extraction provenance is missing")
		})
	}
}
