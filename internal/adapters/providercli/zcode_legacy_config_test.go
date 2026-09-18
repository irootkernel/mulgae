package providercli

import (
	"errors"
	"strings"
	"testing"
)

func TestMaterializeZCodePersonalProviderConfig(t *testing.T) {
	source := `{
  "model": {"main":"zai/GLM-5.2"},
  "provider": {
    "zai": {
      "kind":"anthropic",
      "name":"Z.ai",
      "headers":{"shared":"base","base":"value"},
      "options":{"apiKey":"private-key","baseURL":"https://api.z.ai/api/anthropic","headers":{"shared":"override"}},
      "models": {
        "removed":{"deleted":true},
        "alias":{"id":"GLM-5.2","limit":{"context":1000000}},
        "duplicate":{"id":"GLM-5.2","contextWindow":5}
      }
    },
    "account:managed":{"kind":"anthropic"},
    "foreign":{"kind":"openai","source":"plugin"}
  }
}`
	encoded, err := materializeZCodePersonalProviderConfig([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"zai","providerName":"Z.ai","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"private-key"},"api":{"type":"anthropic-messages","baseUrl":"https://api.z.ai/api/anthropic","headers":{"base":"value","shared":"override"}},"personalModelIds":["GLM-5.2"],"modelOrder":["GLM-5.2"]}}]},"modelConfigRules":{"providerModelRules":[{"modelId":"GLM-5.2","config":{"properties":{"contextWindow":1000000}},"providerId":"zai"}],"manualProviderModelRules":[]},"defaultModelSelection":{"providerId":"zai","modelId":"GLM-5.2"}}}`
	if string(encoded) != want {
		t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, want)
	}
}

func TestMaterializeZCodePersonalProviderConfigRejectsUnsupportedInput(t *testing.T) {
	for _, source := range []string{
		`not-json`,
		`{"model":"zai/model","provider":{"zai":{"kind":"anthropic","options":{"apiKeyRequired":false}}}}`,
		`{"model":"zai/model","provider":{"zai":"invalid"}}`,
		`{"model":"builtin:zai/model","provider":{"zai-api":{"kind":"openai","options":{"apiKey":"custom"}},"builtin:zai":{"options":{"apiKey":"builtin"}}}}`,
		`{"model":"account:managed/model","provider":{"account:managed":{"kind":"anthropic","options":{"apiKey":"secret"}}}}`,
		`{"model":"account:managed/model","provider":{}}`,
		`{"model":"builtin:zapi/model","provider":{"other":{"kind":"openai","options":{"apiKey":"secret"},"models":{"model":{}}}}}`,
		`{"model":"builtin:future/model","provider":{"builtin:future":{"options":{"apiKey":"secret"}}}}`,
		`{"model":"builtin:future/model","provider":{}}`,
		`{"model":"builtin:zai/model","provider":{"zai-api":{"kind":"openai","options":{"apiKey":"custom"},"models":{"model":{}}}}}`,
		`{"model":"foreign/model","provider":{"foreign":{"kind":"openai","source":"plugin","options":{"apiKey":"secret"}}}}`,
		`{"model":"zai/model","provider":{"zai":{"kind":"anthropic","options":{"apiKey":"   "}}}}`,
		`{"model":"zai/deleted","provider":{"zai":{"kind":"anthropic","options":{"apiKey":"secret"},"models":{"deleted":{"deleted":true}}}}`,
		`{"model":"invalid","provider":{}}`,
	} {
		if _, err := materializeZCodePersonalProviderConfig([]byte(source)); err == nil {
			t.Fatalf("unsupported config accepted: %s", source)
		}
	}
}

func TestMaterializeZCodePersonalProviderConfigAddsSelectedModelMissingFromOptionalCatalog(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "model":"zai/GLM-5.3",
  "provider":{
    "zai":{"kind":"anthropic","options":{"apiKey":"secret"},"models":{"GLM-5.2":{}}}
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"zai","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"secret"},"api":{"type":"anthropic-messages"},"personalModelIds":["GLM-5.2","GLM-5.3"],"modelOrder":["GLM-5.2","GLM-5.3"]}}]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]},"defaultModelSelection":{"providerId":"zai","modelId":"GLM-5.3"}}}`
	if string(encoded) != want {
		t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, want)
	}
}

func TestMaterializeZCodePersonalProviderConfigTreatsNullAndEmptySelectionsAsUnset(t *testing.T) {
	for _, test := range []struct {
		source string
		want   string
	}{
		{`{"provider":null}`, `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]}}}`},
		{`{"model":"","provider":{}}`, `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]}}}`},
		{`{"provider":{"unused":{"kind":"openai","options":{"apiKey":"secret"},"models":null}}}`, `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"unused","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"secret"},"api":{"type":"openai-responses"}}}]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]}}}`},
	} {
		encoded, err := materializeZCodePersonalProviderConfig([]byte(test.source))
		if err != nil {
			t.Fatalf("unset legacy value rejected: %s: %v", test.source, err)
		}
		if string(encoded) != test.want {
			t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, test.want)
		}
	}
}

func TestMaterializeZCodePersonalProviderConfigSkipsBlankUnselectedKey(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "model":"good/model",
  "provider":{
    "blank":{"kind":"openai","options":{"apiKey":"   "}},
    "good":{"kind":"openai","options":{"apiKey":"  secret  "},"models":{"model":{}}}
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"good","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"secret"},"api":{"type":"openai-responses"},"personalModelIds":["model"],"modelOrder":["model"]}}]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]},"defaultModelSelection":{"providerId":"good","modelId":"model"}}}`
	if string(encoded) != want {
		t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, want)
	}
}

func TestMaterializeZCodePersonalProviderConfigPreservesOrderCaseAndBuiltinCredentials(t *testing.T) {
	source := `{
  "model":"builtin:zai/GLM-5",
  "provider":{
    "Zulu":{"kind":"openai","options":{"apiKey":"zulu"},"models":{"second":{},"first":{"id":"First"}}},
    "builtin:zai":{"options":{"apiKey":"  zai-secret  "}},
    "builtin:bigmodel":{"options":{"apiKey":"bigmodel-secret"}},
    "alpha":{"kind":"openai","options":{"apiKey":"alpha"}}
  }
}`
	encoded, err := materializeZCodePersonalProviderConfig([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"Zulu","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"zulu"},"api":{"type":"openai-responses"},"personalModelIds":["second","First"],"modelOrder":["second","First"]}},{"providerId":"zai-api","templateId":"zai-api","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"zai-secret"}}},{"providerId":"bigmodel-api","templateId":"bigmodel-api","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"bigmodel-secret"}}},{"providerId":"alpha","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"alpha"},"api":{"type":"openai-responses"}}}]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]},"defaultModelSelection":{"providerId":"zai-api","modelId":"GLM-5"}}}`
	if string(encoded) != want {
		t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, want)
	}
}

func TestMaterializeZCodePersonalProviderConfigUsesECMAScriptPropertyOrder(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "provider":{
    "10":{"kind":"openai","options":{"apiKey":"ten"}},
    "01":{"kind":"openai","options":{"apiKey":"zero-one"}},
    "4294967295":{"kind":"openai","options":{"apiKey":"max"}},
    "2":{"kind":"openai","options":{"apiKey":"two"}},
    "4294967294":{"kind":"openai","options":{"apiKey":"max-index"}},
    "plain":{"kind":"openai","options":{"apiKey":"plain"}}
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	wantOrder := []string{`"providerId":"2"`, `"providerId":"10"`, `"providerId":"4294967294"`, `"providerId":"01"`, `"providerId":"4294967295"`, `"providerId":"plain"`}
	previous := -1
	for _, fragment := range wantOrder {
		position := strings.Index(text, fragment)
		if position <= previous {
			t.Fatalf("ECMAScript property order mismatch for %q in %s", fragment, encoded)
		}
		previous = position
	}
}

func TestMaterializeZCodePersonalProviderConfigUsesECMAScriptOrderForTrimmedCollisions(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "provider":{
    " 2 ":{"kind":"openai","options":{"apiKey":"string-key"}},
    "2":{"kind":"openai","options":{"apiKey":"array-index"}}
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(encoded), `"providerId":"2"`) != 1 || !strings.Contains(string(encoded), `"apiKey":"string-key"`) {
		t.Fatalf("ordinary string key did not win after array-index enumeration: %s", encoded)
	}
}

func TestMaterializeZCodePersonalProviderConfigRejectsUnsupportedSelectedKinds(t *testing.T) {
	for _, source := range []string{
		`{"model":"selected/model","provider":{"selected":{"options":{"apiKey":"secret"}}}}`,
		`{"model":"selected/model","provider":{"selected":{"kind":"future-kind","options":{"apiKey":"secret"}}}}`,
		`{"model":"selected/model","provider":{"selected":{"kind":"openai","npm":"package","options":{"apiKey":"secret"}}}}`,
	} {
		_, err := materializeZCodePersonalProviderConfig([]byte(source))
		if !errors.Is(err, errZCodeLegacySelectedUnsupported) {
			t.Fatalf("unsupported selected provider error = %v, want %v", err, errZCodeLegacySelectedUnsupported)
		}
	}
}

func TestMaterializeZCodePersonalProviderConfigUsesExactLegacyKeys(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "Model":"wrong/model",
  "model":{"Main":"wrong/model","main":"good/model"},
  "Provider":{"wrong":{"kind":"openai","options":{"apiKey":"wrong"}}},
  "provider":{"good":{"Kind":"anthropic","kind":"openai-compatible","options":{"APIKey":"wrong","apiKey":"secret","BaseURL":"wrong","baseURL":"https://example.test","headers":{"X-Test":"yes"}},"models":{"alias":{"ID":"wrong","id":"model","Deleted":true,"deleted":false,"ContextWindow":1,"contextWindow":2,"limit":{"Context":3,"context":4}}}}}
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"good","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"secret"},"api":{"type":"openai-chat-completions","baseUrl":"https://example.test","headers":{"X-Test":"yes"}},"personalModelIds":["model"],"modelOrder":["model"]}}]},"modelConfigRules":{"providerModelRules":[{"modelId":"model","config":{"properties":{"contextWindow":2}},"providerId":"good"}],"manualProviderModelRules":[]},"defaultModelSelection":{"providerId":"good","modelId":"model"}}}`
	if string(encoded) != want {
		t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, want)
	}
}

func TestZCodeLegacyModelStatePrefersAnyLiveAlias(t *testing.T) {
	for _, source := range []string{
		`{"model":"good/model","provider":{"good":{"kind":"openai","options":{"apiKey":"secret"},"models":{"deleted":{"id":"model","deleted":true},"live":{"id":"model"}}}}}`,
		`{"model":"good/model","provider":{"good":{"kind":"openai","options":{"apiKey":"secret"},"models":{"live":{"id":"model"},"deleted":{"id":"model","deleted":true}}}}}`,
	} {
		if _, err := materializeZCodePersonalProviderConfig([]byte(source)); err != nil {
			t.Fatalf("live alias rejected: %v", err)
		}
	}
}

func TestMaterializeZCodePersonalProviderConfigUsesLastExactDuplicateKey(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "model":"wrong/old","model":"good/model",
  "provider":{"good":{"kind":"anthropic","kind":"openai","options":{"apiKey":"old","apiKey":"secret"},"models":{"model":{}}}}
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"good","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"secret"},"api":{"type":"openai-responses"},"personalModelIds":["model"],"modelOrder":["model"]}}]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]},"defaultModelSelection":{"providerId":"good","modelId":"model"}}}`
	if string(encoded) != want {
		t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, want)
	}
}

func TestMaterializeZCodePersonalProviderConfigSkipsInvalidUnselectedProvider(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "model":"good/model",
  "provider":{
    "broken":{"kind":"anthropic","options":{"apiKeyRequired":false}},
    "malformed":"not-an-object",
    "good":{"kind":"anthropic","options":{"apiKey":"secret"},"models":{"model":{}}}
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"good","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"secret"},"api":{"type":"anthropic-messages"},"personalModelIds":["model"],"modelOrder":["model"]}}]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]},"defaultModelSelection":{"providerId":"good","modelId":"model"}}}`
	if string(encoded) != want {
		t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, want)
	}
}

func TestMaterializeZCodePersonalProviderConfigIgnoresCollisionFromSkippedProvider(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "model":"builtin:zai/GLM-5",
  "provider":{
    "zai-api":{"kind":"openai","source":"plugin","options":{"apiKey":"plugin-secret"}},
    "builtin:zai":{"options":{"apiKey":"builtin-secret"}}
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"zai-api","templateId":"zai-api","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"builtin-secret"}}}]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]},"defaultModelSelection":{"providerId":"zai-api","modelId":"GLM-5"}}}`
	if string(encoded) != want {
		t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, want)
	}
}

func TestMaterializeZCodePersonalProviderConfigUsesLastUnselectedEmittedID(t *testing.T) {
	for _, test := range []struct {
		source  string
		wantKey string
	}{
		{`{"provider":{"zai":{"kind":"openai","options":{"apiKey":"first"}}," zai ":{"kind":"openai","options":{"apiKey":"second"}}}}`, `"apiKey":"second"`},
		{`{"provider":{"builtin:zai":{"options":{"apiKey":"builtin"}},"zai-api":{"kind":"openai","options":{"apiKey":"custom"}}}}`, `"apiKey":"custom"`},
	} {
		encoded, err := materializeZCodePersonalProviderConfig([]byte(test.source))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(encoded), `"providerId":`) != 1 || !strings.Contains(string(encoded), test.wantKey) {
			t.Fatalf("last emitted provider did not win: %s", encoded)
		}
	}
}

func TestMaterializeZCodePersonalProviderConfigRejectsSelectedEmittedIDAmbiguity(t *testing.T) {
	for _, source := range []string{
		`{"model":"zai/model","provider":{"zai":{"kind":"openai","options":{"apiKey":"first"}}," zai ":{"kind":"openai","options":{"apiKey":"second"}}}}`,
		`{"model":"builtin:zai/model","provider":{"builtin:zai":{"options":{"apiKey":"builtin"}},"zai-api":{"kind":"openai","options":{"apiKey":"custom"}}}}`,
	} {
		_, err := materializeZCodePersonalProviderConfig([]byte(source))
		if !errors.Is(err, errZCodeLegacyProviderAmbiguous) {
			t.Fatalf("ambiguity error = %v, want %v", err, errZCodeLegacyProviderAmbiguous)
		}
	}
}

func TestMaterializeZCodePersonalProviderConfigMatchesLegacySourceSemantics(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "provider":{
    "absent":{"kind":"openai","options":{"apiKey":"absent"}},
    "custom":{"kind":"openai","source":"custom","options":{"apiKey":"custom"}},
    "null":{"kind":"openai","source":null,"options":{"apiKey":"null"}},
    "empty":{"kind":"openai","source":"","options":{"apiKey":"empty"}},
    "plugin":{"kind":"openai","source":"plugin","options":{"apiKey":"plugin"}}
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, present := range []string{`"providerId":"absent"`, `"providerId":"custom"`} {
		if !strings.Contains(text, present) {
			t.Fatalf("custom provider missing from projection: %s", encoded)
		}
	}
	for _, absent := range []string{`"providerId":"null"`, `"providerId":"empty"`, `"providerId":"plugin"`} {
		if strings.Contains(text, absent) {
			t.Fatalf("non-custom provider imported: %s", encoded)
		}
	}
	for _, source := range []string{
		`{"model":"p/model","provider":{"p":{"kind":"openai","source":null,"options":{"apiKey":"secret"}}}}`,
		`{"model":"p/model","provider":{"p":{"kind":"openai","source":"","options":{"apiKey":"secret"}}}}`,
	} {
		if _, err := materializeZCodePersonalProviderConfig([]byte(source)); !errors.Is(err, errZCodeLegacySelectedUnsupported) {
			t.Fatalf("selected non-custom source error = %v", err)
		}
	}
}

func TestMaterializeZCodePersonalProviderConfigMatchesLegacyModelValueSemantics(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{
  "provider":{"p":{"kind":"openai","options":{"apiKey":"secret"},"models":{
    "scientific":{"contextWindow":1e6},
    "decimal":{"limit":{"context":128000.0}},
    "fractional":{"contextWindow":1000.5},
    "string-deleted":{"deleted":"true"}
  }}}
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"p","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"secret"},"api":{"type":"openai-responses"},"personalModelIds":["scientific","decimal","fractional","string-deleted"],"modelOrder":["scientific","decimal","fractional","string-deleted"]}}]},"modelConfigRules":{"providerModelRules":[{"modelId":"scientific","config":{"properties":{"contextWindow":1000000}},"providerId":"p"},{"modelId":"decimal","config":{"properties":{"contextWindow":128000}},"providerId":"p"}],"manualProviderModelRules":[]}}}`
	if string(encoded) != want {
		t.Fatalf("materialized config bytes = %s\nwant = %s", encoded, want)
	}
}

func TestMaterializeZCodePersonalProviderConfigRejectsTrailingJSON(t *testing.T) {
	for _, source := range []string{`{"provider":{}}}`, `{"provider":{}} []`} {
		if _, err := materializeZCodePersonalProviderConfig([]byte(source)); err == nil {
			t.Fatalf("trailing JSON accepted: %s", source)
		}
	}
}

func TestMaterializeZCodePersonalProviderConfigAllowsLiteOnlyDefault(t *testing.T) {
	encoded, err := materializeZCodePersonalProviderConfig([]byte(`{"model":{"lite":"zai/lite"},"provider":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[]},"modelConfigRules":{"providerModelRules":[],"manualProviderModelRules":[]}}}`
	if string(encoded) != want {
		t.Fatalf("lite-only config = %s, want %s", encoded, want)
	}
}
