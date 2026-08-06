package review

import (
	"bytes"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestClassifyAssistantContentFreeFormStructuredLikeAndStructured(t *testing.T) {
	class, candidate := classifyAssistantContent([]byte("  # prose review\n\nLooks fine.\n  "))
	if class != assistantContentFreeForm || candidate != nil {
		t.Fatalf("prose class=%v candidate=%q", class, candidate)
	}
	class, candidate = classifyAssistantContent([]byte("```json\n{\"findings\":[]}\n```\n```json\n{\"findings\":[]}\n```"))
	if class != assistantContentFreeForm || candidate != nil {
		t.Fatalf("multi-fence class=%v candidate=%q", class, candidate)
	}
	class, candidate = classifyAssistantContent([]byte("{\"findings\":[]}\ntrailing"))
	if class != assistantContentFreeForm || candidate != nil {
		t.Fatalf("trailing JSON class=%v candidate=%q", class, candidate)
	}
	class, candidate = classifyAssistantContent([]byte("Narration\n\n```json\n{\"findings\":[]}\n```\n"))
	if class != assistantContentStructured || string(candidate) != `{"findings":[]}` {
		t.Fatalf("unique fence structured class=%v candidate=%q", class, candidate)
	}
	class, candidate = classifyAssistantContent([]byte("```json\n{\"findings\":\n```"))
	if class != assistantContentStructuredLike || string(candidate) != `{"findings":` {
		t.Fatalf("malformed fence structured-like class=%v candidate=%q", class, candidate)
	}
	class, candidate = classifyAssistantContent([]byte("{\"findings\":"))
	if class != assistantContentStructuredLike || string(candidate) != `{"findings":` {
		t.Fatalf("malformed object structured-like class=%v candidate=%q", class, candidate)
	}
	whole := []byte(`{"findings":[],"summary":"ok"}`)
	class, candidate = classifyAssistantContent(whole)
	if class != assistantContentStructured || !bytes.Equal(candidate, whole) {
		t.Fatalf("whole object structured class=%v candidate=%q", class, candidate)
	}
}

func TestDecodeExactJSONObjectRequiresEOF(t *testing.T) {
	if _, ok := decodeExactJSONObject([]byte(`{"a":1}{"b":2}`)); ok {
		t.Fatal("trailing second object was trusted")
	}
	if _, ok := decodeExactJSONObject([]byte("{\"a\":1}\n{\"b\":2}\n")); ok {
		t.Fatal("trailing second object after newline was trusted")
	}
	got, ok := decodeExactJSONObject([]byte("  {\"a\":1}  "))
	if !ok || string(got) != `{"a":1}` {
		t.Fatalf("exact object = %q ok=%t", got, ok)
	}
}

func TestBindStructuredPrimaryReportPreservesExactAssistantContent(t *testing.T) {
	mixed := []byte("Narration before fence.\n\n```json\n{\"findings\":[]}\n```\n")
	validated := validation.ValidatedReview{}
	got, err := bindStructuredPrimaryReport(domain.RoleLogic, validated, mixed)
	if err != nil || !bytes.Equal(got, mixed) {
		t.Fatalf("mixed primary report = %q err=%v", got, err)
	}
	pure := []byte("{\"findings\":[],\"summary\":\"pure\"}\n")
	got, err = bindStructuredPrimaryReport(domain.RoleLogic, validated, pure)
	if err != nil || !bytes.Equal(got, pure) {
		t.Fatalf("pure structured primary report = %q err=%v", got, err)
	}
}
