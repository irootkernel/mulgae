package ports

import "context"

// RequirementsInputReader reads one invocation-local file under an admitted
// project lease. It grants no selected-source side or evidence authority.
type RequirementsInputReader interface {
	ReadRequirementsInput(context.Context, SafeRelativePath) ([]byte, error)
}
