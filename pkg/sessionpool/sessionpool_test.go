package sessionpool

import (
	"math"
	"testing"
)

func TestReclaim(t *testing.T) {
	pool := New()
	id := pool.Get()
	if id != 1 {
		t.Errorf("Got %v, expected 1 (first time)", id)
	}

	pool.Reclaim(1)

	id = pool.Get()
	if id != 1 {
		t.Errorf("Got %v, expected 1 (second time)", id)
	}

	id = pool.Get()
	if id != 2 {
		t.Errorf("Got %v, expected 2", id)
	}
}

func TestDepletion(t *testing.T) {
	defer func() {
		r := recover()
		if r != "SessionPool depleted" {
			t.Errorf("Expected depletion panic")
		}
	}()
	pool := New()
	pool.cur = math.MaxUint32
	pool.Get()
}

func TestUseTracking(t *testing.T) {
	defer func() {
		r := recover()
		if r != "Attempt to reclaim invalid session ID" {
			t.Errorf("Expected reclamation panic")
		}
	}()

	pool := New()
	pool.EnableUseTracking()
	pool.Reclaim(42)
}
