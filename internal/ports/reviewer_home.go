package ports

import "os"

// ReviewerHome owns the shared neutral directory and one safely read guide.
// Guidance is explicitly composed by the application, not added by a provider.
type ReviewerHome interface {
	Root() AnchoredRoot
	Guide() []byte
	Revalidate() error
	DuplicateLaunchDirectory() (*os.File, error)
	Close() error
}
