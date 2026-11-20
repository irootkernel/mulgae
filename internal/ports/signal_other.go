//go:build !unix

package ports

import "fmt"

// SignalNameFromNumber maps a positive signal number to a canonical SIG-prefixed
// name on non-Unix platforms.
func SignalNameFromNumber(number int) string {
	if number <= 0 {
		return ""
	}
	return fmt.Sprintf("SIG%d", number)
}

// NewProcessSignalFromNumber builds a validated ProcessSignal from a positive
// signal number.
func NewProcessSignalFromNumber(number int) (ProcessSignal, error) {
	return NewProcessSignal(number, SignalNameFromNumber(number))
}
