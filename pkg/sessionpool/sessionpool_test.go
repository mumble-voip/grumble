package sessionpool

import (
	"math"
	"testing"
)

func TestReclaim(t *testing.T) {
	pool := New(2)
	id, err := pool.Get()
	if err != nil {
		t.Errorf("Expected no error: %v", err)
	}
	if id != 1 {
		t.Errorf("Got %v, expected 1 (first time)", id)
	}

	pool.Reclaim(1)

	id, err = pool.Get()
	if err != nil {
		t.Errorf("Expected no error: %v", err)
	}
	if id != 1 {
		t.Errorf("Got %v, expected 1 (second time)", id)
	}

	id, err = pool.Get()
	if err != nil {
		t.Errorf("Expected no error: %v", err)
	}
	if id != 2 {
		t.Errorf("Got %v, expected 2", id)
	}
}

func TestDepletion(t *testing.T) {
	pool := New(0)
	pool.cur = math.MaxUint32
	_, err := pool.Get()
	if err == nil {
		t.Errorf("Expected depletion error")
	}
}

func TestUseTracking(t *testing.T) {
	defer func() {
		r := recover()
		if r != "Attempt to reclaim invalid session ID" {
			t.Errorf("Expected reclamation panic")
		}
	}()

	pool := New(0)
	pool.EnableUseTracking()
	pool.Reclaim(42)
}
