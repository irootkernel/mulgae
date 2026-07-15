package config

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func TestRedactOmitsRuntimeAndProviderSecrets(t *testing.T) {
	optional := true
	global := testGlobalConfig()
	global.Runtime.Home = "/Users/alice/TopSecret"
	global.Runtime.Path.Prepend = []string{"/Users/alice/private/bin"}
	global.Runtime.Path.Append = []string{"/opt/private/bin"}
	global.Runtime.EnvAllowlist = []string{"HOME", "API_TOKEN"}
	global.Providers = adapterconfig.ProvidersConfig{
		"codex-optional": {
			Driver:         "codex",
			Status:         "unverified",
			Optional:       &optional,
			Bin:            "/Users/alice/private/codex",
			Args:           []string{"--token", "super-password", "--command=never-persist"},
			ConcurrencyKey: "codex-optional",
		},
		"kimi-main": {
			Driver:         "kimi",
			Status:         "unverified",
			Bin:            "/Users/alice/private/kimi",
			Args:           []string{"--api-token", "TopSecret"},
			ConcurrencyKey: "kimi-main",
		},
	}

	resolved, err := ResolveConfiguration(global, nil)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}
	view := Redact(resolved)
	serialized, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("json.Marshal(Redact()) error = %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{
		"home", "/users", "private", "path", "args", "token", "password", "secret", "command",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("redacted JSON contains forbidden %q: %s", forbidden, serialized)
		}
	}

	if got, want := view.Providers, []RedactedProvider{
		{ID: "codex-optional", Driver: "codex", Status: "unverified", Optional: true, ConcurrencyKey: "codex-optional"},
		{ID: "kimi-main", Driver: "kimi", Status: "unverified", Optional: false, ConcurrencyKey: "kimi-main"},
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("redacted providers = %#v, want %#v", got, want)
	}
	if got, want := view.Policy.RequiredRoles, []domain.Role{domain.RoleLogic, domain.RoleSecurity}; !reflect.DeepEqual(got, want) {
		t.Errorf("redacted required roles = %v, want %v", got, want)
	}
	if got, want := provenanceSources(view.Provenance, "providers.kimi-main.status"), []FieldSource{SourceGlobal}; !reflect.DeepEqual(got, want) {
		t.Errorf("provider provenance = %v, want %v", got, want)
	}
}

func TestRedactIsDeterministicAndDetached(t *testing.T) {
	global := testGlobalConfig()
	global.Providers = adapterconfig.ProvidersConfig{
		"zcode-main": {Driver: "zcode", Status: "unverified", ConcurrencyKey: "zcode-main"},
		"agy-main":   {Driver: "agy", Status: "unverified", ConcurrencyKey: "agy-main"},
	}
	resolved, err := ResolveConfiguration(global, nil)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}

	first, err := json.Marshal(Redact(resolved))
	if err != nil {
		t.Fatalf("first json.Marshal() error = %v", err)
	}
	secondView := Redact(resolved)
	second, err := json.Marshal(secondView)
	if err != nil {
		t.Fatalf("second json.Marshal() error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("Redact() is not deterministic:\nfirst:  %s\nsecond: %s", first, second)
	}

	secondView.Providers[0].ID = "mutated"
	secondView.Policy.RequiredRoles[0] = domain.RoleTesting
	third := Redact(resolved)
	if got, want := third.Providers[0].ID, "agy-main"; got != want {
		t.Errorf("mutating redacted view changed provider ID to %q, want %q", got, want)
	}
	if got, want := third.Policy.RequiredRoles[0], domain.RoleLogic; got != want {
		t.Errorf("mutating redacted view changed required role to %q, want %q", got, want)
	}
}
func TestRedactProvenanceIsExhaustiveAndValueSafe(t *testing.T) {
	global := testGlobalConfig()
	global.Providers = adapterconfig.ProvidersConfig{
		"kimi-main":  {Driver: "kimi", Status: "unverified", ConcurrencyKey: "kimi-main"},
		"zcode-main": {Driver: "zcode", Status: "unverified", ConcurrencyKey: "zcode-main"},
	}

	resolved, err := ResolveConfiguration(global, nil)
	if err != nil {
		t.Fatalf("ResolveConfiguration() error = %v", err)
	}
	view := Redact(resolved)

	// Every produced provenance field must be explicitly safe or explicitly
	// omitted here; additions cannot silently disappear from Redact.
	safe := map[string][]FieldSource{
		"policy.required_roles":                {SourceBuiltin, SourceGlobal},
		"policy.workspace_access":              {SourceBuiltin, SourceGlobal},
		"policy.request_changes_on":            {SourceBuiltin, SourceGlobal},
		"policy.require_verified_for":          {SourceBuiltin, SourceGlobal},
		"policy.role_max_invocations":          {SourceBuiltin, SourceGlobal},
		"policy.run_max_invocations":           {SourceBuiltin, SourceGlobal},
		"policy.run_total_output_cap_bytes":    {SourceBuiltin, SourceGlobal},
		"policy.ci_fail_on_severity":           {SourceBuiltin, SourceGlobal},
		"policy.degraded_review_fails":         {SourceBuiltin, SourceGlobal},
		"providers.kimi-main.id":               {SourceGlobal},
		"providers.kimi-main.driver":           {SourceGlobal},
		"providers.kimi-main.status":           {SourceGlobal},
		"providers.kimi-main.optional":         {SourceGlobal},
		"providers.kimi-main.concurrency_key":  {SourceGlobal},
		"providers.zcode-main.id":              {SourceGlobal},
		"providers.zcode-main.driver":          {SourceGlobal},
		"providers.zcode-main.status":          {SourceGlobal},
		"providers.zcode-main.optional":        {SourceGlobal},
		"providers.zcode-main.concurrency_key": {SourceGlobal},
	}
	for _, role := range domain.FixedRoleOrder() {
		safe["policy.roles."+string(role)+".enabled"] = []FieldSource{SourceBuiltin, SourceGlobal}
		safe["policy.roles."+string(role)+".required"] = []FieldSource{SourceBuiltin, SourceGlobal}
	}
	omitted := map[string]struct{}{}

	redacted := make(map[string][]FieldSource, len(view.Provenance))
	for _, entry := range view.Provenance {
		expected, isSafe := safe[entry.Field]
		if !isSafe {
			t.Errorf("unexpected redacted provenance field %q", entry.Field)
			continue
		}
		if _, duplicate := redacted[entry.Field]; duplicate {
			t.Errorf("duplicate redacted provenance field %q", entry.Field)
			continue
		}
		redacted[entry.Field] = entry.Sources
		if !reflect.DeepEqual(entry.Sources, expected) {
			t.Errorf("provenance for %q = %v, want %v", entry.Field, entry.Sources, expected)
		}
		for _, forbidden := range []string{"bin", "args", "guide", "root", "path"} {
			if strings.Contains(entry.Field, forbidden) {
				t.Errorf("unsafe provenance field %q contains %q", entry.Field, forbidden)
			}
		}
	}
	for field, expected := range safe {
		got, exists := redacted[field]
		if !exists {
			t.Errorf("redacted provenance is missing safe field %q", field)
			continue
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("provenance for %q = %v, want %v", field, got, expected)
		}
	}
	for _, entry := range resolved.Provenance().Entries() {
		if _, isSafe := safe[entry.Field]; isSafe {
			continue
		}
		if _, isOmitted := omitted[entry.Field]; isOmitted {
			if _, exists := redacted[entry.Field]; exists {
				t.Errorf("explicitly omitted provenance field %q was redacted", entry.Field)
			}
			continue
		}
		t.Errorf("produced provenance field %q is neither explicitly safe nor explicitly omitted", entry.Field)
	}
}

func provenanceSources(entries []RedactedProvenance, field string) []FieldSource {
	for _, entry := range entries {
		if entry.Field == field {
			return entry.Sources
		}
	}
	return nil
}
