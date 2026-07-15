package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Layer identifies the configuration layer that produced a diagnostic.
type Layer string

const (
	LayerGlobal  Layer = "global"
	LayerProject Layer = "project"
)

// Diagnostic identifies a configuration violation at its YAML source location.
type Diagnostic struct {
	Layer   Layer
	Source  string
	Path    string
	Line    int
	Column  int
	Code    string
	Message string
}

// DiagnosticError is returned when untrusted configuration is rejected.
type DiagnosticError struct {
	diagnostics []Diagnostic
}

func (e *DiagnosticError) Error() string {
	if e == nil || len(e.diagnostics) == 0 {
		return "configuration rejected"
	}

	parts := make([]string, 0, len(e.diagnostics))
	for _, diagnostic := range e.diagnostics {
		parts = append(parts, fmt.Sprintf("%s %s %s:%d:%d [%s] %s", diagnostic.Layer, diagnostic.Source, diagnostic.Path, diagnostic.Line, diagnostic.Column, diagnostic.Code, diagnostic.Message))
	}
	return "configuration rejected: " + strings.Join(parts, "; ")
}

// Diagnostics returns a copy of the diagnostics in stable source-location order.
func (e *DiagnosticError) Diagnostics() []Diagnostic {
	if e == nil {
		return nil
	}
	return append([]Diagnostic(nil), e.diagnostics...)
}

// AsDiagnosticError returns the typed diagnostic error, including when it is wrapped.
func AsDiagnosticError(err error) (*DiagnosticError, bool) {
	var diagnosticError *DiagnosticError
	if !errors.As(err, &diagnosticError) {
		return nil, false
	}
	return diagnosticError, true
}

func newDiagnosticError(diagnostics []Diagnostic) error {
	if len(diagnostics) == 0 {
		return nil
	}
	ordered := append([]Diagnostic(nil), diagnostics...)
	sort.SliceStable(ordered, func(left, right int) bool {
		if ordered[left].Line != ordered[right].Line {
			return ordered[left].Line < ordered[right].Line
		}
		if ordered[left].Column != ordered[right].Column {
			return ordered[left].Column < ordered[right].Column
		}
		if ordered[left].Path != ordered[right].Path {
			return ordered[left].Path < ordered[right].Path
		}
		return ordered[left].Code < ordered[right].Code
	})
	return &DiagnosticError{diagnostics: ordered}
}
