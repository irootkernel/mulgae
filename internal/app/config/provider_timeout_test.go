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

func TestZCodeProviderDefaultProvenance(t *testing.T) {
	rows := provenanceRows(Config{Providers: ProvidersConfig{ZCode: &ZCodeProviderConfig{}}})
	want := map[string]bool{"providers.zcode.model": false, "providers.zcode.reasoning_effort": false}
	for _, row := range rows {
		if _, ok := want[row.Field]; !ok {
			continue
		}
		if row.Source != "provider" || row.Disposition != "defaulted" || row.ValueClass != "policy" {
			t.Fatalf("%s provenance = %#v", row.Field, row)
		}
		want[row.Field] = true
	}
	for field, found := range want {
		if !found {
			t.Fatalf("missing ZCode provider default provenance for %s", field)
		}
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

func TestAbsentProviderMachineFieldsRemainAbsent(t *testing.T) {
	rows := provenanceRows(Config{})
	want := map[string]bool{
		"providers.zcode.app_bundle": false,
		"providers.grok.executable":  false,
	}
	for _, row := range rows {
		if _, ok := want[row.Field]; !ok {
			continue
		}
		if row.Source != "local" || row.Disposition != "absent" || row.ValueClass != "machine" {
			t.Fatalf("%s provenance = %#v", row.Field, row)
		}
		want[row.Field] = true
	}
	for field, found := range want {
		if !found {
			t.Fatalf("missing provider machine provenance for %s", field)
		}
	}
}

func TestCursorProvenanceCoversPresenceAndTimeoutOwnership(t *testing.T) {
	for _, test := range []struct {
		name   string
		config Config
		want   map[string]ProvenanceRow
	}{
		{
			name: "absent",
			want: map[string]ProvenanceRow{
				"providers.cursor.configured": {Field: "providers.cursor.configured", Source: "project", Disposition: "absent", ValueClass: "policy"},
				"providers.cursor.executable": {Field: "providers.cursor.executable", Source: "local", Disposition: "absent", ValueClass: "machine"},
				"providers.cursor.timeout":    {Field: "providers.cursor.timeout", Source: "project", Disposition: "absent", ValueClass: "policy"},
			},
		},
		{
			name: "present default timeout",
			config: Config{Providers: ProvidersConfig{Cursor: &CursorProviderConfig{
				Executable: "/opt/cursor/bin/cursor-agent",
				Timeout:    ProviderTimeoutText(DefaultProviderTimeout),
			}}},
			want: map[string]ProvenanceRow{
				"providers.cursor.configured": {Field: "providers.cursor.configured", Source: "project", Disposition: "configured", ValueClass: "policy"},
				"providers.cursor.executable": {Field: "providers.cursor.executable", Source: "local", Disposition: "configured", ValueClass: "machine"},
				"providers.cursor.timeout":    {Field: "providers.cursor.timeout", Source: "default", Disposition: "defaulted", ValueClass: "policy"},
			},
		},
		{
			name: "present custom timeout",
			config: Config{Providers: ProvidersConfig{Cursor: &CursorProviderConfig{
				Executable: "/opt/cursor/bin/cursor-agent",
				Timeout:    "25m",
			}}},
			want: map[string]ProvenanceRow{
				"providers.cursor.configured": {Field: "providers.cursor.configured", Source: "project", Disposition: "configured", ValueClass: "policy"},
				"providers.cursor.executable": {Field: "providers.cursor.executable", Source: "local", Disposition: "configured", ValueClass: "machine"},
				"providers.cursor.timeout":    {Field: "providers.cursor.timeout", Source: "project", Disposition: "configured", ValueClass: "policy"},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows := provenanceRows(test.config)
			found := map[string]ProvenanceRow{}
			for _, row := range rows {
				if _, ok := test.want[row.Field]; ok {
					found[row.Field] = row
				}
			}
			for field, want := range test.want {
				got, ok := found[field]
				if !ok || got != want {
					t.Fatalf("%s provenance = %#v, want %#v", field, got, want)
				}
			}
		})
	}
}

// TestAgyProvenanceCoversPresenceSettingsAndTimeoutOwnership mirrors the
// provider-agnostic provenance contract for the AGY block: the executable is
// machine-local, omitted model and effort read as provider defaults, and only
// the timeout carries an implicit Mulgae default.
func TestAgyProvenanceCoversPresenceSettingsAndTimeoutOwnership(t *testing.T) {
	for _, test := range []struct {
		name   string
		config Config
		want   map[string]ProvenanceRow
	}{
		{
			name: "absent",
			want: map[string]ProvenanceRow{
				"providers.agy.configured":       {Field: "providers.agy.configured", Source: "project", Disposition: "absent", ValueClass: "policy"},
				"providers.agy.executable":       {Field: "providers.agy.executable", Source: "local", Disposition: "absent", ValueClass: "machine"},
				"providers.agy.model":            {Field: "providers.agy.model", Source: "project", Disposition: "absent", ValueClass: "policy"},
				"providers.agy.reasoning_effort": {Field: "providers.agy.reasoning_effort", Source: "project", Disposition: "absent", ValueClass: "policy"},
				"providers.agy.timeout":          {Field: "providers.agy.timeout", Source: "project", Disposition: "absent", ValueClass: "policy"},
			},
		},
		{
			name: "present omitted settings",
			config: Config{Providers: ProvidersConfig{Agy: &AgyProviderConfig{
				Executable: "/opt/agy/bin/agy",
				Timeout:    ProviderTimeoutText(DefaultProviderTimeout),
			}}},
			want: map[string]ProvenanceRow{
				"providers.agy.configured":       {Field: "providers.agy.configured", Source: "project", Disposition: "configured", ValueClass: "policy"},
				"providers.agy.executable":       {Field: "providers.agy.executable", Source: "local", Disposition: "configured", ValueClass: "machine"},
				"providers.agy.model":            {Field: "providers.agy.model", Source: "provider", Disposition: "defaulted", ValueClass: "policy"},
				"providers.agy.reasoning_effort": {Field: "providers.agy.reasoning_effort", Source: "provider", Disposition: "defaulted", ValueClass: "policy"},
				"providers.agy.timeout":          {Field: "providers.agy.timeout", Source: "default", Disposition: "defaulted", ValueClass: "policy"},
			},
		},
		{
			name: "present explicit settings",
			config: Config{Providers: ProvidersConfig{Agy: &AgyProviderConfig{
				Executable:      "/opt/agy/bin/agy",
				Model:           "gemini-3-pro",
				ReasoningEffort: "high",
				Timeout:         "40m",
			}}},
			want: map[string]ProvenanceRow{
				"providers.agy.configured":       {Field: "providers.agy.configured", Source: "project", Disposition: "configured", ValueClass: "policy"},
				"providers.agy.executable":       {Field: "providers.agy.executable", Source: "local", Disposition: "configured", ValueClass: "machine"},
				"providers.agy.model":            {Field: "providers.agy.model", Source: "project", Disposition: "configured", ValueClass: "policy"},
				"providers.agy.reasoning_effort": {Field: "providers.agy.reasoning_effort", Source: "project", Disposition: "configured", ValueClass: "policy"},
				"providers.agy.timeout":          {Field: "providers.agy.timeout", Source: "project", Disposition: "configured", ValueClass: "policy"},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows := provenanceRows(test.config)
			found := map[string]ProvenanceRow{}
			for _, row := range rows {
				if _, ok := test.want[row.Field]; ok {
					found[row.Field] = row
				}
			}
			for field, want := range test.want {
				got, ok := found[field]
				if !ok || got != want {
					t.Fatalf("%s provenance = %#v, want %#v", field, got, want)
				}
			}
		})
	}
}
