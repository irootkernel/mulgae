package init

import (
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestRenderProjectYAMLIsDeterministicAndStrict(t *testing.T) {
	contextPath, err := ports.NewSafeRelativePath(".kar/context.md")
	if err != nil {
		t.Fatal(err)
	}

	first, err := RenderProjectYAML("project-alpha", &contextPath)
	if err != nil {
		t.Fatalf("RenderProjectYAML() error = %v", err)
	}
	second, err := RenderProjectYAML("project-alpha", &contextPath)
	if err != nil {
		t.Fatalf("RenderProjectYAML() second error = %v", err)
	}
	want := "version: 1\ntrusted_base: true\nproject:\n  name: \"project-alpha\"\n  root: \".\"\n  context: \".kar/context.md\"\n"
	if got := string(first); got != want {
		t.Fatalf("rendered YAML = %q, want %q", got, want)
	}
	if got := string(second); got != want {
		t.Fatalf("second rendered YAML = %q, want %q", got, want)
	}
	for _, forbidden := range []string{
		"providers:", "bin:", "args:", "command:", "shell:", "env:", "environment:", "my-project",
	} {
		if strings.Contains(string(first), forbidden) {
			t.Fatalf("rendered YAML contains forbidden content %q: %q", forbidden, first)
		}
	}
}

func TestRenderProjectYAMLOmitsOptionalContext(t *testing.T) {
	document, err := RenderProjectYAML("project", nil)
	if err != nil {
		t.Fatalf("RenderProjectYAML() error = %v", err)
	}
	want := "version: 1\ntrusted_base: true\nproject:\n  name: \"project\"\n  root: \".\"\n"
	if got := string(document); got != want {
		t.Fatalf("rendered YAML = %q, want %q", got, want)
	}
	if strings.Contains(string(document), "context:") {
		t.Fatalf("rendered YAML unexpectedly contains context: %q", document)
	}
}

func TestRenderProjectYAMLQuotesContextAsAScalar(t *testing.T) {
	contextPath, err := ports.NewSafeRelativePath(`notes/quoted" context: [not-a-map].md`)
	if err != nil {
		t.Fatal(err)
	}

	document, err := RenderProjectYAML("project", &contextPath)
	if err != nil {
		t.Fatalf("RenderProjectYAML() error = %v", err)
	}
	want := "version: 1\ntrusted_base: true\nproject:\n  name: \"project\"\n  root: \".\"\n  context: \"notes/quoted\\\" context: [not-a-map].md\"\n"
	if got := string(document); got != want {
		t.Fatalf("rendered YAML = %q, want %q", got, want)
	}
}

func TestRenderProjectYAMLRejectsInvalidInputs(t *testing.T) {
	invalidContext := ports.SafeRelativePath{}
	for _, test := range []struct {
		name        string
		projectName string
		contextPath *ports.SafeRelativePath
	}{
		{name: "empty project name"},
		{name: "uppercase project name", projectName: "Project"},
		{name: "project name with YAML syntax", projectName: "project: value"},
		{name: "invalid context", projectName: "project", contextPath: &invalidContext},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := RenderProjectYAML(test.projectName, test.contextPath); err == nil {
				t.Fatal("RenderProjectYAML() succeeded")
			}
		})
	}
}
