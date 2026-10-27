package reviewrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type requirementsCountingSource struct {
	ports.LiveSourceReader
	raw   []byte
	reads int
}

func (source *requirementsCountingSource) ReadRequirementsInput(context.Context, ports.SafeRelativePath) ([]byte, error) {
	source.reads++
	return source.raw, nil
}

func TestRequirementsAdmissionReadsOnceAndRetainsExactUnboundedInput(t *testing.T) {
	raw := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"R","text":"` + strings.Repeat("prose ", 1500000) + `","acceptance_criteria":["Preserve behavior."],"owner_role":"logic"}]}` + "\n")
	if len(raw) <= 8<<20 {
		t.Fatal("fixture does not cross the structured-envelope ceiling")
	}
	source := &requirementsCountingSource{raw: raw}
	want := append([]byte(nil), raw...)
	input, err := AdmitRequirementsInput(context.Background(), source, "requirements.json", []domain.Role{domain.RoleLogic})
	if err != nil || source.reads != 1 || !bytes.Equal(input.Bytes(), want) || input.SHA256() != fmt.Sprintf("sha256:%x", sha256.Sum256(want)) {
		t.Fatalf("exact admission: reads=%d error=%v", source.reads, err)
	}
	source.raw[0] = 'x'
	copyOfInput := input.Bytes()
	copyOfInput[0] = 'y'
	if !bytes.Equal(input.Bytes(), want) || source.reads != 1 {
		t.Fatal("later use reopened input or lost admitted bytes")
	}
}

func TestRequirementsAdmissionRejectsInvalidInputBeforeFurtherUse(t *testing.T) {
	const valid = `{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"R","text":"private-marker","acceptance_criteria":["Preserve behavior."],"owner_role":"logic"}]}`
	for _, raw := range []string{
		`{}`, valid + `{}`, strings.Replace(valid, `"id":"R"`, `"id":"R","id":"S"`, 1),
		strings.Replace(valid, `"logic"`, `"security"`, 1), strings.Replace(valid, `private-marker`, `\ud800`, 1),
		strings.Replace(valid, `private-marker`, "\xff", 1), strings.Replace(valid, `private-marker`, `bad\u0000text`, 1),
	} {
		source := &requirementsCountingSource{raw: []byte(raw)}
		_, err := AdmitRequirementsInput(context.Background(), source, "requirements.json", []domain.Role{domain.RoleLogic})
		if err == nil || source.reads != 1 || strings.Contains(err.Error(), "private-marker") {
			t.Fatalf("invalid input was admitted or exposed: reads=%d error=%v", source.reads, err)
		}
	}
	for _, path := range []string{"", "../requirements.json", "/requirements.json", "a//b"} {
		source := &requirementsCountingSource{raw: []byte(valid)}
		if _, err := AdmitRequirementsInput(context.Background(), source, path, []domain.Role{domain.RoleLogic}); err == nil || source.reads != 0 {
			t.Fatal("unsafe path reached the file reader")
		}
	}
}
