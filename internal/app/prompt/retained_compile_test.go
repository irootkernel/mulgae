package prompt

import (
	"bytes"
	"testing"
)

func TestCompileTwiceKeepsFreshNonReplayIdentities(t *testing.T) {
	compiler := newTestCompiler(t, []int{5, 8}, []int{6, 9})
	input := testCompileInput(t)
	initial, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	recomposed, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}

	if recomposed.ExactReplay() {
		t.Fatal("Compile() marked a recomposition as replay")
	}
	if recomposed.Scope().SourceInvocationID() == initial.Scope().SourceInvocationID() {
		t.Fatal("recomposition reused source invocation identity")
	}
	if recomposed.Scope().ExecutionInvocationID() == initial.Scope().ExecutionInvocationID() {
		t.Fatal("recomposition reused execution invocation identity")
	}
	if bytes.Equal(recomposed.Stdin(), initial.Stdin()) || recomposed.WireIdentity() == initial.WireIdentity() {
		t.Fatal("recomposition retained exact replay wire identity")
	}
	if recomposed.Sections()[1].ID() == initial.Sections()[1].ID() {
		t.Fatal("recomposition reused section identity")
	}
}
