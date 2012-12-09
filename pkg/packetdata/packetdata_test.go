package packetdata

import (
	"crypto/rand"
	"math"
	"testing"
)

func TestSelfUint8(t *testing.T) {
	buf := make([]byte, 500)
	pds := New(buf)

	for i := uint8(0); i < 0xff; i++ {
		pds.PutUint8(i)
		if !pds.IsValid() {
			t.Errorf("Invalid PDS")
			return
		}
	}

	pds2 := New(pds.Buf)
	for i := uint8(0); i < 0xff; i++ {
		val := pds2.GetUint8()
		if val != i {
			t.Errorf("Mismatch (read: %v, expected: %v)", val, i)
			return
		}
	}
}

func TestSelfUint64(t *testing.T) {
	buf := make([]byte, 500)
	pds := New(buf)

	for i := uint64(1 << 54); i < (uint64(1<<54) + 10); i++ {
		pds.PutUint64(i)
		if !pds.IsValid() {
			t.Errorf("Invalid PDS")
			return
		}
	}

	pds2 := New(buf)
	for i := uint64(1 << 54); i < (uint64(1<<54) + 10); i++ {
		val := pds2.GetUint64()
		if !pds.IsValid() {
			t.Errorf("Invalid PDS")
		}
		if val != i {
			t.Errorf("Mismatch (read: %v, expected: %v)", val, i)
			return
		}
	}
}

func TestSelfMumbleVoicePacket(t *testing.T) {
	buf := make([]byte, 500)
	pds := New(buf)
	data := make([]byte, 54)

	rand.Read(data)

	pds.PutUint32(1)
	pds.PutBytes(data)

	pds2 := New(buf)
	if pds2.GetUint32() != 1 {
		t.Errorf("Session mismatch")
	}

	outbuf := make([]byte, 54)
	pds2.CopyBytes(outbuf)

	if !pds.IsValid() {
		t.Errorf("Invalid PDS")
		return
	}

	for i := 0; i < 54; i++ {
		if outbuf[i] != data[i] {
			t.Errorf("Voice data mismatch (got %v, expected %v)", outbuf[i], data[i])
			return
		}
	}
}

func TestSelfFloat64(t *testing.T) {
	buf := make([]byte, 500)
	pds := New(buf)
	pds2 := New(buf)

	pds.PutFloat64(math.Pi)
	pi := pds2.GetFloat64()

	if !pds.IsValid() || !pds2.IsValid() {
		t.Errorf("Invalid PDS")
		return
	}

	if pi != float64(math.Pi) {
		t.Errorf("Unexpected result. Got %v, expected %v", pi, float64(math.Pi))
		return
	}
}

func TestSelfFloat32(t *testing.T) {
	buf := make([]byte, 500)
	pds := New(buf)
	pds2 := New(buf)

	pds.PutFloat32(math.E)
	e := pds2.GetFloat32()

	if !pds.IsValid() || !pds2.IsValid() {
		t.Errorf("Invalid PDS")
	}

	if e != float32(math.E) {
		t.Errorf("Unexpected result. Got %v, expected %v", e, float32(math.E))
	}
}

func TestSelfBytes(t *testing.T) {
	msg := [15]byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}
	buf := make([]byte, 500)
	pds := New(buf)
	pds2 := New(buf)

	pds.PutBytes(msg[0:])
	out := make([]byte, 15)
	pds2.CopyBytes(out)

	if !pds.IsValid() || !pds.IsValid() {
		t.Errorf("Invalid PDS")
		return
	}

	for i := 0; i < 15; i++ {
		if msg[i] != out[i] {
			t.Errorf("Mismatch at index %v. Got %v, expected %v", i, out[i], msg[i])
			return
		}
	}
}
