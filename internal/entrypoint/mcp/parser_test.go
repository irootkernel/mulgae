package mcpentry

import (
	"errors"
	"testing"
)

func TestParseAcceptsDefaultAndExplicitProjectRoot(t *testing.T) {
	command, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if root, present := command.ProjectRoot(); present || root != "" {
		t.Fatalf("default project root = %q, %t; want empty, false", root, present)
	}

	command, err = Parse([]string{"--project-root", "/work/project"})
	if err != nil {
		t.Fatal(err)
	}
	if root, present := command.ProjectRoot(); !present || root != "/work/project" {
		t.Fatalf("explicit project root = %q, %t; want /work/project, true", root, present)
	}
}

func TestParseRejectsInvalidGrammar(t *testing.T) {
	for _, arguments := range [][]string{
		{"--project-root"},
		{"--project-root", "relative"},
		{"--unknown", "/work/project"},
		{"--project-root", "/work/project", "extra"},
	} {
		if _, err := Parse(arguments); !errors.Is(err, ErrUsage) {
			t.Errorf("Parse(%q) error = %v, want ErrUsage", arguments, err)
		}
	}
}
