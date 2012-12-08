// Copyright (c) 2010-2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package ocb2

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func MustDecodeHex(s string) []byte {
	buf, err := hex.DecodeString(s)
	if err != nil {
		panic("MustDecodeHex: " + err.Error())
	}
	return buf
}

type ocbVector struct {
	Name       string
	Key        string
	Nonce      string
	Header     string
	PlainText  string
	CipherText string
	Tag        string
}

func (v ocbVector) KeyBytes() []byte {
	return MustDecodeHex(v.Key)
}

func (v ocbVector) NonceBytes() []byte {
	return MustDecodeHex(v.Nonce)
}

func (v ocbVector) PlainTextBytes() []byte {
	return MustDecodeHex(v.PlainText)
}

func (v ocbVector) CipherTextBytes() []byte {
	return MustDecodeHex(v.CipherText)
}

func (v ocbVector) TagBytes() []byte {
	return MustDecodeHex(v.Tag)
}

// ocb128Vectors are the test vectors for OCB-AES128 from
// http://www.cs.ucdavis.edu/~rogaway/papers/draft-krovetz-ocb-00.txt
//
// Note: currently, the vectors with headers are not included in this list
// as this implementation does not implement header authentication.
var ocb128Vectors = []ocbVector{
	{
		Name:       "OCB2-AES-128-001",
		Key:        "000102030405060708090A0B0C0D0E0F",
		Nonce:      "000102030405060708090A0B0C0D0E0F",
		PlainText:  "",
		CipherText: "",
		Tag:        "BF3108130773AD5EC70EC69E7875A7B0",
	},
	{
		Name:       "OCB2-AES-128-002",
		Key:        "000102030405060708090A0B0C0D0E0F",
		Nonce:      "000102030405060708090A0B0C0D0E0F",
		PlainText:  "0001020304050607",
		CipherText: "C636B3A868F429BB",
		Tag:        "A45F5FDEA5C088D1D7C8BE37CABC8C5C",
	},
	{
		Name:       "OCB2-AES-128-003",
		Key:        "000102030405060708090A0B0C0D0E0F",
		Nonce:      "000102030405060708090A0B0C0D0E0F",
		PlainText:  "000102030405060708090A0B0C0D0E0F",
		CipherText: "52E48F5D19FE2D9869F0C4A4B3D2BE57",
		Tag:        "F7EE49AE7AA5B5E6645DB6B3966136F9",
	},
	{
		Name:       "OCB2-AES-128-003",
		Key:        "000102030405060708090A0B0C0D0E0F",
		Nonce:      "000102030405060708090A0B0C0D0E0F",
		PlainText:  "000102030405060708090A0B0C0D0E0F1011121314151617",
		CipherText: "F75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB",
		Tag:        "A1A50F822819D6E0A216784AC24AC84C",
	},
	{
		Name:       "OCB2-AES-128-004",
		Key:        "000102030405060708090A0B0C0D0E0F",
		Nonce:      "000102030405060708090A0B0C0D0E0F",
		PlainText:  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		CipherText: "F75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27",
		Tag:        "09CA6C73F0B5C6C5FD587122D75F2AA3",
	},
	{
		Name:       "OCB2-AES-128-005",
		Key:        "000102030405060708090A0B0C0D0E0F",
		Nonce:      "000102030405060708090A0B0C0D0E0F",
		PlainText:  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
		CipherText: "F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C",
		Tag:        "9DB0CDF880F73E3E10D4EB3217766688",
	},
}

func TestTimes2(t *testing.T) {
	msg := [aes.BlockSize]byte{
		0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	}
	expected := [aes.BlockSize]byte{
		0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7b,
	}

	times2(msg[0:])
	if !bytes.Equal(msg[0:], expected[0:]) {
		t.Fatalf("times2 produces invalid output: %v, expected: %v", msg, expected)
	}
}

func TestTimes3(t *testing.T) {
	msg := [aes.BlockSize]byte{
		0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	}
	expected := [aes.BlockSize]byte{
		0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85,
	}

	times3(msg[0:])
	if !bytes.Equal(msg[0:], expected[0:]) {
		t.Errorf("times3 produces invalid output: %v, expected: %v", msg, expected)
	}
}

func TestZeros(t *testing.T) {
	var msg [aes.BlockSize]byte
	zeros(msg[0:])
	for i := 0; i < len(msg); i++ {
		if msg[i] != 0 {
			t.Fatalf("zeros does not zero slice.")
		}
	}
}

func TestXor(t *testing.T) {
	msg := [aes.BlockSize]byte{
		0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	}
	var out [aes.BlockSize]byte
	xor(out[0:], msg[0:], msg[0:])
	for i := 0; i < len(out); i++ {
		if out[i] != 0 {
			t.Fatalf("XOR broken")
		}
	}
}

func TestEncryptOCBAES128Vectors(t *testing.T) {
	for _, vector := range ocb128Vectors {
		cipher, err := aes.NewCipher(vector.KeyBytes())
		if err != nil {
			t.Fatalf("%v", err)
		}

		plainText := vector.PlainTextBytes()
		cipherText := make([]byte, len(plainText))
		tag := make([]byte, TagSize)
		Encrypt(cipher, cipherText, plainText, vector.NonceBytes(), tag)

		expectedCipherText := vector.CipherTextBytes()
		if !bytes.Equal(cipherText, expectedCipherText) {
			t.Fatalf("expected CipherText %#v, got %#v", expectedCipherText, cipherText)
		}

		expectedTag := vector.TagBytes()
		if !bytes.Equal(tag, expectedTag) {
			t.Fatalf("expected tag %#v, got %#v", expectedTag, tag)
		}
	}
}

func TestDecryptOCBAES128Vectors(t *testing.T) {
	for _, vector := range ocb128Vectors {
		cipher, err := aes.NewCipher(vector.KeyBytes())
		if err != nil {
			t.Fatalf("%v", err)
		}

		cipherText := vector.CipherTextBytes()
		plainText := make([]byte, len(cipherText))
		if Decrypt(cipher, plainText, cipherText, vector.NonceBytes(), vector.TagBytes()) == false {
			t.Fatalf("expected decrypt success; got failure. tag mismatch?")
		}

		expectedPlainText := vector.PlainTextBytes()
		if !bytes.Equal(plainText, expectedPlainText) {
			t.Fatalf("expected PlainText %#v, got %#v", expectedPlainText, plainText)
		}
	}
}
