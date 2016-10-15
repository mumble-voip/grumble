// Copyright (c) 2010-2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package cryptstate

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func TestOCB2AES128Encrypt(t *testing.T) {
	msg := [15]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	key := [aes.BlockSize]byte{
		0x96, 0x8b, 0x1b, 0x0c, 0x53, 0x1e, 0x1f, 0x80, 0xa6, 0x1d, 0xcb, 0x27, 0x94, 0x09, 0x6f, 0x32,
	}
	eiv := [aes.BlockSize]byte{
		0x1e, 0x2a, 0x9b, 0xd0, 0x2d, 0xa6, 0x8e, 0x46, 0x26, 0x85, 0x83, 0xe9, 0x14, 0x2a, 0xff, 0x2a,
	}
	div := [aes.BlockSize]byte{
		0x73, 0x99, 0x9d, 0xa2, 0x03, 0x70, 0x00, 0x96, 0xef, 0x55, 0x06, 0x7a, 0x8b, 0xbe, 0x00, 0x07,
	}
	expected := [19]byte{
		0x1f, 0xfc, 0xdd, 0xb4, 0x68, 0x13, 0x68, 0xb7, 0x92, 0x67, 0xca, 0x2d, 0xba, 0xb7, 0x0d, 0x44, 0xdf, 0x32, 0xd4,
	}
	expected_eiv := [aes.BlockSize]byte{
		0x1f, 0x2a, 0x9b, 0xd0, 0x2d, 0xa6, 0x8e, 0x46, 0x26, 0x85, 0x83, 0xe9, 0x14, 0x2a, 0xff, 0x2a,
	}

	cs := CryptState{}
	out := make([]byte, 19)
	cs.SetKey("OCB2-AES128", key[:], eiv[:], div[:])
	cs.Encrypt(out, msg[:])

	if !bytes.Equal(out[:], expected[:]) {
		t.Errorf("Mismatch in output")
	}

	if !bytes.Equal(cs.EncryptIV[:], expected_eiv[:]) {
		t.Errorf("EIV mismatch")
	}
}

func TestOCB2AES128Decrypt(t *testing.T) {
	key := [aes.BlockSize]byte{
		0x96, 0x8b, 0x1b, 0x0c, 0x53, 0x1e, 0x1f, 0x80, 0xa6, 0x1d, 0xcb, 0x27, 0x94, 0x09, 0x6f, 0x32,
	}
	eiv := [aes.BlockSize]byte{
		0x1e, 0x2a, 0x9b, 0xd0, 0x2d, 0xa6, 0x8e, 0x46, 0x26, 0x85, 0x83, 0xe9, 0x14, 0x2a, 0xff, 0x2a,
	}
	div := [aes.BlockSize]byte{
		0x73, 0x99, 0x9d, 0xa2, 0x03, 0x70, 0x00, 0x96, 0xef, 0x55, 0x06, 0x7a, 0x8b, 0xbe, 0x00, 0x07,
	}
	crypted := [19]byte{
		0x1f, 0xfc, 0xdd, 0xb4, 0x68, 0x13, 0x68, 0xb7, 0x92, 0x67, 0xca, 0x2d, 0xba, 0xb7, 0x0d, 0x44, 0xdf, 0x32, 0xd4,
	}
	expected := [15]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	post_div := [aes.BlockSize]byte{
		0x1f, 0x2a, 0x9b, 0xd0, 0x2d, 0xa6, 0x8e, 0x46, 0x26, 0x85, 0x83, 0xe9, 0x14, 0x2a, 0xff, 0x2a,
	}

	cs := CryptState{}
	out := make([]byte, 15)
	cs.SetKey("OCB2-AES128", key[:], div[:], eiv[:])
	err := cs.Decrypt(out, crypted[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, expected[:]) {
		t.Errorf("Mismatch in output")
	}

	if !bytes.Equal(cs.DecryptIV, post_div[:]) {
		t.Errorf("Mismatch in DIV")
	}
}

// Test that our wrapped NaCl secretbox cipher
// works. The test data for this test was lifted
// from the secretbox_test.go file.
func TestXSalsa20Poly1305Encrypt(t *testing.T) {
	cs := CryptState{}

	var key [32]byte
	var eiv [24]byte
	var div [24]byte
	var message [64]byte

	for i := range key[:] {
		key[i] = 1
	}

	// Since we pre-increment our EIV,
	// this look a bit off compared to
	// the secretbox_test.go test case.
	for i := range eiv[:] {
		eiv[i] = 2
		div[i] = 2
	}
	eiv[0] = 1
	div[0] = 1

	for i := range message[:] {
		message[i] = 3
	}

	cs.SetKey("XSalsa20-Poly1305", key[:], div[:], eiv[:])
	dst := make([]byte, len(message)+cs.Overhead())
	cs.Encrypt(dst, message[:])

	expected, _ := hex.DecodeString("8442bc313f4626f1359e3b50122b6ce6fe66ddfe7d39d14e637eb4fd5b45beadab55198df6ab5368439792a23c87db70acb6156dc5ef957ac04f6276cf6093b84be77ff0849cc33e34b7254d5a8f65ad")
	if !bytes.Equal(dst[1:], expected) {
		t.Fatalf("mismatch! got\n%x\n, expected\n%x", dst, expected)
	}
}

// Test that we can reverse the result of the Encrypt test.
func TestXSalsa20Poly1305Decrypt(t *testing.T) {
	cs := CryptState{}

	var key [32]byte
	var eiv [24]byte
	var div [24]byte
	var expected [64]byte

	for i := range key[:] {
		key[i] = 1
	}

	// Since we pre-increment our EIV,
	// this look a bit off compared to
	// the secretbox_test.go test case.
	for i := range eiv[:] {
		eiv[i] = 2
		div[i] = 2
	}
	eiv[0] = 1
	div[0] = 1

	for i := range expected[:] {
		expected[i] = 3
	}

	message, _ := hex.DecodeString("028442bc313f4626f1359e3b50122b6ce6fe66ddfe7d39d14e637eb4fd5b45beadab55198df6ab5368439792a23c87db70acb6156dc5ef957ac04f6276cf6093b84be77ff0849cc33e34b7254d5a8f65ad")
	cs.SetKey("XSalsa20-Poly1305", key[:], eiv[:], div[:])
	dst := make([]byte, len(message)-cs.Overhead())
	err := cs.Decrypt(dst, message[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(dst, expected[:]) {
		t.Fatalf("mismatch! got\n%x\n, expected\n%x", dst, expected)
	}
}
