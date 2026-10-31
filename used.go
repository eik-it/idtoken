package idtoken

import (
	"context"
	"sync"
	"time"
)

// MemoryUsedTokens is an in-process UsedTokenStore. It is correct only for an
// App that runs as ONE process: with several instances, a token could be
// accepted once by each. Use the App's database for anything else.
type MemoryUsedTokens struct {
	mu   sync.Mutex
	seen map[string]time.Time
	// Now is the clock used to forget expired entries. Default: time.Now.
	Now func() time.Time
}

func (m *MemoryUsedTokens) MarkUsed(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	if m.seen == nil {
		m.seen = map[string]time.Time{}
	}
	for id, until := range m.seen {
		if !now.Before(until) {
			delete(m.seen, id)
		}
	}
	if _, ok := m.seen[jti]; ok {
		return false, nil
	}
	m.seen[jti] = expiresAt
	return true, nil
}
