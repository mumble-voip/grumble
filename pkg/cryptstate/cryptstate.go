// Copyright (c) 2010-2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package cryptstate

import (
	"crypto/rand"
	"errors"
	"io"
	"time"
)

const decryptHistorySize = 0x100

type CryptoMode interface {
	NonceSize() int
	KeySize() int
	Overhead() int

	SetKey([]byte)
	Encrypt(dst []byte, src []byte, nonce []byte)
	Decrypt(dst []byte, src []byte, nonce []byte) bool
}

type CryptState struct {
	Key       []byte
	EncryptIV []byte
	DecryptIV []byte

	LastGoodTime int64

	Good         uint32
	Late         uint32
	Lost         uint32
	Resync       uint32
	RemoteGood   uint32
	RemoteLate   uint32
	RemoteLost   uint32
	RemoteResync uint32

	decryptHistory [decryptHistorySize]byte
	mode           CryptoMode
}

// SupportedModes returns the list of supported CryptoModes.
func SupportedModes() []string {
	return []string{
		"OCB2-AES128",
		"XSalsa20-Poly1305",
	}
}

// createMode creates the CryptoMode with the given mode name.
func createMode(mode string) (CryptoMode, error) {
	switch mode {
	case "OCB2-AES128":
		return &ocb2Mode{}, nil
	case "XSalsa20-Poly1305":
		return &secretBoxMode{}, nil
	}
	return nil, errors.New("cryptstate: no such CryptoMode")
}

func (cs *CryptState) GenerateKey(mode string) error {
	cm, err := createMode(mode)
	if err != nil {
		return err
	}

	key := make([]byte, cm.KeySize())
	_, err = io.ReadFull(rand.Reader, key)
	if err != nil {
		return err
	}

	cm.SetKey(key)
	cs.mode = cm
	cs.Key = key

	cs.EncryptIV = make([]byte, cm.NonceSize())
	_, err = io.ReadFull(rand.Reader, cs.EncryptIV)
	if err != nil {
		return err
	}

	cs.DecryptIV = make([]byte, cm.NonceSize())
	_, err = io.ReadFull(rand.Reader, cs.DecryptIV)
	if err != nil {
		return err
	}

	return nil
}

func (cs *CryptState) SetKey(mode string, key []byte, eiv []byte, div []byte) error {
	cm, err := createMode(mode)
	if err != nil {
		return err
	}

	cm.SetKey(key)
	cs.mode = cm
	cs.Key = key

	cs.EncryptIV = eiv
	cs.DecryptIV = div

	return nil
}

// Overhead returns the length, in bytes, that a ciphertext
// is longer than a plaintext.
func (cs *CryptState) Overhead() int {
	return 1 + cs.mode.Overhead()
}

func (cs *CryptState) Decrypt(dst, src []byte) error {
	if len(src) < cs.Overhead() {
		return errors.New("cryptstate: crypted length too short to decrypt")
	}

	plain_len := len(src) - cs.Overhead()
	if len(dst) < plain_len {
		return errors.New("cryptstate: not enough space in dst for plain text")
	}

	ivbyte := src[0]
	restore := false
	lost := 0
	late := 0

	saveiv := make([]byte, len(cs.DecryptIV))
	copy(saveiv, cs.DecryptIV)

	if byte(cs.DecryptIV[0]+1) == ivbyte {
		// In order as expected
		if ivbyte > cs.DecryptIV[0] {
			cs.DecryptIV[0] = ivbyte
		} else if ivbyte < cs.DecryptIV[0] {
			cs.DecryptIV[0] = ivbyte
			for i := 1; i < len(cs.DecryptIV); i++ {
				cs.DecryptIV[i] += 1
				if cs.DecryptIV[i] > 0 {
					break
				}
			}
		} else {
			return errors.New("cryptstate: invalid ivbyte")
		}
	} else {
		// Out of order or repeat
		var diff int
		diff = int(ivbyte - cs.DecryptIV[0])
		if diff > 128 {
			diff = diff - 256
		} else if diff < -128 {
			diff = diff + 256
		}

		if ivbyte < cs.DecryptIV[0] && diff > -30 && diff < 0 {
			// Late packet, but no wraparound
			late = 1
			lost = -1
			cs.DecryptIV[0] = ivbyte
			restore = true
		} else if ivbyte > cs.DecryptIV[0] && diff > -30 && diff < 0 {
			// Last was 0x02, here comes 0xff from last round
			late = 1
			lost = -1
			cs.DecryptIV[0] = ivbyte
			for i := 1; i < len(cs.DecryptIV); i++ {
				cs.DecryptIV[i] -= 1
				if cs.DecryptIV[i] > 0 {
					break
				}
			}
			restore = true
		} else if ivbyte > cs.DecryptIV[0] && diff > 0 {
			// Lost a few packets, but beyond that we're good.
			lost = int(ivbyte - cs.DecryptIV[0] - 1)
			cs.DecryptIV[0] = ivbyte
		} else if ivbyte < cs.DecryptIV[0] && diff > 0 {
			// Lost a few packets, and wrapped around
			lost = int(256 - int(cs.DecryptIV[0]) + int(ivbyte) - 1)
			cs.DecryptIV[0] = ivbyte
			for i := 1; i < len(cs.DecryptIV); i++ {
				cs.DecryptIV[i] += 1
				if cs.DecryptIV[i] > 0 {
					break
				}
			}
		} else {
			return errors.New("cryptstate: no matching ivbyte")
		}

		if cs.decryptHistory[cs.DecryptIV[0]] == cs.DecryptIV[1] {
			cs.DecryptIV = saveiv
		}
	}

	ok := cs.mode.Decrypt(dst, src[1:], cs.DecryptIV)
	if !ok {
		cs.DecryptIV = saveiv
		return errors.New("cryptstate: tag mismatch")
	}

	cs.decryptHistory[cs.DecryptIV[0]] = cs.DecryptIV[1]

	if restore {
		cs.DecryptIV = saveiv
	}

	cs.Good += 1
	if late > 0 {
		cs.Late += uint32(late)
	} else {
		cs.Late -= uint32(-late)
	}
	if lost > 0 {
		cs.Lost = uint32(lost)
	} else {
		cs.Lost = uint32(-lost)
	}

	cs.LastGoodTime = time.Now().Unix()

	return nil
}

func (cs *CryptState) Encrypt(dst, src []byte) {
	// First, increase our IV
	for i := range cs.EncryptIV {
		cs.EncryptIV[i] += 1
		if cs.EncryptIV[i] > 0 {
			break
		}
	}

	dst[0] = cs.EncryptIV[0]
	cs.mode.Encrypt(dst[1:], src, cs.EncryptIV)
}
