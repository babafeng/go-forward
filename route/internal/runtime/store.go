package runtime

import (
	"sync/atomic"

	"go-forward/route/internal/router"
	"go-forward/route/internal/transport"
)

// Snapshot represents an immutable view of runtime dependencies used by proxy handlers.
type Snapshot struct {
	Router  *router.Engine
	Dialers *transport.Manager
}

// Store maintains the latest runtime snapshot, supporting lock-free loads for fast path handlers.
type Store struct {
	state atomic.Pointer[Snapshot]
}

// NewStore constructs a store with the initial snapshot.
func NewStore(initial *Snapshot) *Store {
	s := &Store{}
	s.state.Store(initial)
	return s
}

// Load retrieves the current snapshot.
func (s *Store) Load() *Snapshot {
	return s.state.Load()
}

// Update replaces the snapshot with a new one.
func (s *Store) Update(snapshot *Snapshot) {
	s.state.Store(snapshot)
}
