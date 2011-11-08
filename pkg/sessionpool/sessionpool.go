// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// Package sessionpool implements a reuse pool for session IDs.
package sessionpool

import (
	"math"
	"sync"
)

// A SessionPool is a pool for session IDs.
// IDs are re-used in MRU order, for ease of implementation in Go.
type SessionPool struct {
	mutex  sync.Mutex
	used   map[uint32]bool
	unused []uint32
	cur    uint32
}

// Create a new SessionPool container.
func New() (pool *SessionPool) {
	pool = new(SessionPool)
	return
}

// Enable use-tracking for the SessionPool.
//
// When enabled, the SessionPool stores all session IDs
// returned by Get() internally. When an ID is reclaimed,
// the SessionPool checks whether the ID being reclaimed
// is in its list of used IDs. If this is not the case,
// the program will panic.
func (pool *SessionPool) EnableUseTracking() {
	if len(pool.unused) != 0 || pool.cur != 0 {
		panic("Attempt to enable use tracking on an existing SessionPool.")
	}
	pool.used = make(map[uint32]bool)
}

// Get a new session ID from the SessionPool.
// Must be reclaimed using Reclaim() when done using it.
func (pool *SessionPool) Get() (id uint32) {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()

	// If use tracking is enabled, mark our returned session id as used.
	if pool.used != nil {
		defer func() {
			pool.used[id] = true
		}()
	}

	// First, look in the unused stack.
	length := len(pool.unused)
	if length > 0 {
		id = pool.unused[length-1]
		pool.unused = pool.unused[:length-1]
		return
	}

	// Check for depletion. If cur is MaxUint32,
	// there aren't any session IDs left, since the
	// increment below would overflow us back to 0.
	if pool.cur == math.MaxUint32 {
		panic("SessionPool depleted")
	}

	// Increment the next session id and return it.
	// Note: By incrementing and *then* returning, we skip 0.
	// This is deliberate, as 0 is an invalid session ID in Mumble.
	pool.cur += 1
	id = pool.cur
	return
}

// Reclaim a session ID so it can be reused.
func (pool *SessionPool) Reclaim(id uint32) {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()

	// Check whether this ID is marked as being in use.
	if pool.used != nil {
		_, inUse := pool.used[id]
		if !inUse {
			panic("Attempt to reclaim invalid session ID")
		}
		delete(pool.used, id)
	}

	pool.unused = append(pool.unused, id)
}
