package childrun

import (
	"fmt"
	"sync"
)

// PublicationEpochSource issues process-local, strictly increasing publication
// epochs to child workflows that share one artifact store.
type PublicationEpochSource struct {
	mu   sync.Mutex
	last uint64
}

// NewPublicationEpochSource starts after the supplied last committed epoch.
func NewPublicationEpochSource(lastCommitted uint64) *PublicationEpochSource {
	return &PublicationEpochSource{last: lastCommitted}
}

// Next returns the next positive epoch exactly once.
func (source *PublicationEpochSource) Next() (uint64, error) {
	if source == nil {
		return 0, fmt.Errorf("publication epoch source is required")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.last == ^uint64(0) {
		return 0, fmt.Errorf("publication epoch space is exhausted")
	}
	source.last++
	return source.last, nil
}
