package ban

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestMaskNonPowerOf8(t *testing.T) {
	mask := []byte{0xff, 0x1f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b := Ban{}
	b.Mask = 13
	if !bytes.Equal(b.IPMask(), mask) {
		t.Errorf("Mask mismatch: %v, %v", mask, []byte(b.IPMask()))
	}
}

func TestMaksPowerOf2(t *testing.T) {
	mask := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}
	b := Ban{}
	b.Mask = 64
	if !bytes.Equal(b.IPMask(), mask) {
		t.Errorf("Mask mismatch: %v, %v", mask, []byte(b.IPMask()))
	}
}

func TestMatchV4(t *testing.T) {
	b := Ban{}
	b.IP = net.ParseIP("192.168.1.1")
	b.Mask = 24 + 96 // ipv4 /24
	if len(b.IP) == 0 {
		t.Errorf("Invalid IP")
	}

	clientIp := net.ParseIP("192.168.1.50")
	if len(clientIp) == 0 {
		t.Errorf("Invalid IP")
	}

	if b.Match(clientIp) != true {
		t.Errorf("IPv4: unexpected match")
	}
}

func TestMismatchV4(t *testing.T) {
	b := Ban{}
	b.IP = net.ParseIP("192.168.1.1")
	b.Mask = 24 + 96 // ipv4 /24
	if len(b.IP) == 0 {
		t.Errorf("Invalid IP")
	}

	clientIp := net.ParseIP("192.168.2.1")
	if len(clientIp) == 0 {
		t.Errorf("Invalid IP")
	}

	if b.Match(clientIp) == true {
		t.Errorf("IPv4: unexpected mismatch")
	}
}

func TestMatchV6(t *testing.T) {
	b := Ban{}
	b.IP = net.ParseIP("2a00:1450:400b:c00::63")
	b.Mask = 64
	if len(b.IP) == 0 {
		t.Errorf("Invalid IP")
	}

	clientIp := net.ParseIP("2a00:1450:400b:c00::54")
	if len(clientIp) == 0 {
		t.Errorf("Invalid IP")
	}

	if b.Match(clientIp) != true {
		t.Errorf("IPv6: unexpected match")
	}
}

func TestMismatchV6(t *testing.T) {
	b := Ban{}
	b.IP = net.ParseIP("2a00:1450:400b:c00::63")
	b.Mask = 64

	if len(b.IP) == 0 {
		t.Errorf("Invalid IP")
	}

	clientIp := net.ParseIP("2a00:1450:400b:deaf:42f0:cafe:babe:54")
	if len(clientIp) == 0 {
		t.Errorf("Invalid IP")
	}

	if b.Match(clientIp) == true {
		t.Errorf("IPv6: unexpected mismatch")
	}
}

func TestISODate(t *testing.T) {
	sometime := "2011-05-14T13:48:00"
	b := Ban{}
	b.SetISOStartDate(sometime)
	if sometime != b.ISOStartDate() {
		t.Errorf("UNIX timestamp mismatch: %v %v", b.ISOStartDate(), sometime)
	}
}

func TestInfiniteExpiry(t *testing.T) {
	b := Ban{}
	b.Start = time.Now().Add(-10 * time.Second).Unix()
	b.Duration = 0

	if b.IsExpired() {
		t.Errorf("∞ should not expire")
	}
}

func TestExpired(t *testing.T) {
	b := Ban{}
	b.Start = time.Now().Add(-10 * time.Second).Unix()
	b.Duration = 9

	if !b.IsExpired() {
		t.Errorf("Should have expired 1 second ago")
	}
}

func TestNotExpired(t *testing.T) {
	b := Ban{}
	b.Start = time.Now().Unix()
	b.Duration = 60 * 60 * 24

	if b.IsExpired() {
		t.Errorf("Should expire in 24 hours")
	}
}
