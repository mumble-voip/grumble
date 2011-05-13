// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package serverconf

import (
	"testing"
)

func TestIntValue(t *testing.T) {
	cfg := New(nil)
	cfg.Set("Test", "13")
	if cfg.IntValue("Test") != 13 {
		t.Errorf("Expected 13")
	}
}

func TestFloatAsInt(t *testing.T) {
	cfg := New(nil)
	cfg.Set("Test", "13.4")
	if cfg.IntValue("Test") != 0 {
		t.Errorf("Expected 0")
	}
}

func TestDefaultValue(t *testing.T) {
	cfg := New(nil)
	if cfg.IntValue("MaxBandwidth") != 72000 {
		t.Errorf("Expected 72000")
	}
}

func TestBoolValue(t *testing.T) {
	cfg := New(nil)
	cfg.Set("DoStuffOnStartup", "true")
	if cfg.BoolValue("DoStuffOnStartup") != true {
		t.Errorf("Expected true")
	}
}
