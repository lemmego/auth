package handoff

import (
	"context"
	"sync"
	"time"
)

// MemoryStore records redemptions in this process only.
//
// For tests, and for a single-process development run. It is NOT a
// production store, and the reason is worth stating plainly rather than
// leaving as an implied "obviously": with two web processes behind a load
// balancer, each has its own map, so one token can be redeemed once per
// process. The single-use guarantee would be silently weakened by the one
// change that looks like pure capacity — adding a second instance — and
// nothing would fail.
//
// A real deployment uses a store whose uniqueness the database enforces.
type MemoryStore struct {
	mu   sync.Mutex
	used map[string]time.Time
	now  func() time.Time
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{used: map[string]time.Time{}, now: time.Now}
}

var _ Store = (*MemoryStore)(nil)

// Consume records a redemption and reports whether this caller is first.
func (m *MemoryStore) Consume(_ context.Context, id string, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Prune first, so the map's size is bounded by the number of tokens
	// minted in one TTL rather than by the lifetime of the process. The
	// entries are useless once expired: a token past its expiry is refused
	// before it ever reaches a store.
	now := m.now()
	for key, expiry := range m.used {
		if !now.Before(expiry) {
			delete(m.used, key)
		}
	}

	if _, seen := m.used[id]; seen {
		return false, nil
	}
	m.used[id] = expiresAt
	return true, nil
}
