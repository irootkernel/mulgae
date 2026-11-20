//go:build unix

package ports

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SignalNameFromNumber maps a positive POSIX signal number to its canonical
// symbolic name via unix.SignalName, falling back to SIG<number> only when the
// platform table defines no symbolic name.
func SignalNameFromNumber(number int) string {
	if number <= 0 {
		return ""
	}
	if name := unix.SignalName(unix.Signal(number)); name != "" {
		return name
	}
	return fmt.Sprintf("SIG%d", number)
}

// NewProcessSignalFromNumber builds a validated ProcessSignal from a positive
// operating-system signal number using the platform's canonical signal name.
func NewProcessSignalFromNumber(number int) (ProcessSignal, error) {
	return NewProcessSignal(number, SignalNameFromNumber(number))
}
