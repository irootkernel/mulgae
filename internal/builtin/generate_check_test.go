package builtin

import (
	"os/exec"
	"testing"
)

func TestAssetGenerator(t *testing.T) {
	// The generator is a build-ignored main package; explicit files keep its
	// regression tests in the standard unit gate without importing runtime code.
	command := exec.CommandContext(t.Context(), "go", "test", "-race", "-count=1", "generate.go", "generate_regression_test.go")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("asset generator regression tests: %v\n%s", err, output)
	}
}
