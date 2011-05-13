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
// IDs are reclaimed in MRU order, for ease of implementation in Go.
type SessionPool struct {
	mutex  sync.Mutex
	used   map[uint32]bool
	unused []uint32
	next   uint32
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
// panic.
func (pool *SessionPool) EnableUseTracking() {
	if len(pool.unused) != 0 || pool.next != 0 {
		panic("Attempt to enable use tracking on an existing SessionPool.")
	}
	pool.used = make(map[uint32]bool)
}

// Get a new session ID from the SessionPool.
// Must be reclaimed using Reclaim() when done.
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

	// Check for session pool depletion. Note that this depletion
	// check makes MaxUint32 an invalid next value, and thus limits
	// the session pool to 2**32-2 distinct sessions.
	if pool.next == math.MaxUint32 {
		panic("SessionPool depleted")
	}

	// Return the current 'next' value and increment it
	// for next time we're here.
	id = pool.next
	pool.next += 1
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
		pool.used[id] = false, false
	}

	pool.unused = append(pool.unused, id)
}
