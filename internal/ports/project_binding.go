package ports

import "context"

// ProjectBindingLease keeps the worktree and its Git directories anchored by
// descriptors. Revalidate must reject replacement or relocation of any anchor.
// Observing a binding never reads configuration or credentials, creates files,
// discovers providers, or grants authority to retarget a running server.
type ProjectBindingLease interface {
	Observation() ProjectBindingObservation
	Revalidate(context.Context) error
	Close() error
}

type ProjectBindingObserver interface {
	ObserveProjectBinding(context.Context, AnchoredRoot) (ProjectBindingLease, error)
}

// ProjectDirectoryIdentity contains private descriptor observations. Birth time
// participates in replacement detection, including reuse of an inode number.
type ProjectDirectoryIdentity struct {
	Device           uint64 `json:"device"`
	Inode            uint64 `json:"inode"`
	BirthSeconds     int64  `json:"birth_seconds"`
	BirthNanoseconds int64  `json:"birth_nanoseconds"`
}

// ProjectBindingObservation is private input to application identity policy.
// Adapters supply descriptor facts; they do not select the hash encoding.
type ProjectBindingObservation struct {
	Root, GitDirectory, CommonDirectory       AnchoredRoot
	RootIdentity, GitIdentity, CommonIdentity ProjectDirectoryIdentity
}
