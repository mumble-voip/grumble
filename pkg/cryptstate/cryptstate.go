// Grumble - an implementation of Murmur in Go
// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package cryptstate

import (
	"crypto/aes"
	"crypto/rand"
	"os"
	"time"
)

const DecryptHistorySize = 0x100

type CryptState struct {
	RawKey         [aes.BlockSize]byte
	EncryptIV      [aes.BlockSize]byte
	DecryptIV      [aes.BlockSize]byte
	decryptHistory [DecryptHistorySize]byte

	LastGoodTime   int64

	Good           uint32
	Late           uint32
	Lost           uint32
	Resync         uint32
	RemoteGood     uint32
	RemoteLate     uint32
	RemoteLost     uint32
	RemoteResync   uint32

	cipher *aes.Cipher
}

func New() (cs *CryptState, err os.Error) {
	cs = new(CryptState)

	return
}

func (cs *CryptState) GenerateKey() (err os.Error) {
	rand.Read(cs.RawKey[0:])
	rand.Read(cs.EncryptIV[0:])
	rand.Read(cs.DecryptIV[0:])

	cs.cipher, err = aes.NewCipher(cs.RawKey[0:])
	if err != nil {
		return
	}

	return
}

func (cs *CryptState) SetKey(key []byte, eiv []byte, div []byte) (err os.Error) {
	if copy(cs.RawKey[0:], key[0:]) != aes.BlockSize {
		err = os.NewError("Unable to copy key")
		return
	}

	if copy(cs.EncryptIV[0:], eiv[0:]) != aes.BlockSize {
		err = os.NewError("Unable to copy EIV")
		return
	}

	if copy(cs.DecryptIV[0:], div[0:]) != aes.BlockSize {
		err = os.NewError("Unable to copy DIV")
		return
	}

	cs.cipher, err = aes.NewCipher(cs.RawKey[0:])
	if err != nil {
		return
	}

	return
}

func (cs *CryptState) Decrypt(dst, src []byte) (err os.Error) {
	if len(src) < 4 {
		err = os.NewError("Crypted length too short to decrypt")
		return
	}

	plain_len := len(src) - 4
	if len(dst) != plain_len {
		err = os.NewError("plain_len and src len mismatch")
		return
	}

	var saveiv [aes.BlockSize]byte
	var tag [aes.BlockSize]byte
	var ivbyte byte
	var restore bool
	lost := 0
	late := 0

	ivbyte = src[0]
	restore = false

	if copy(saveiv[0:], cs.DecryptIV[0:]) != aes.BlockSize {
		err = os.NewError("Copy failed")
		return
	}

	if byte(cs.DecryptIV[0]+1) == ivbyte {
		// In order as expected
		if ivbyte > cs.DecryptIV[0] {
			cs.DecryptIV[0] = ivbyte
		} else if ivbyte < cs.DecryptIV[0] {
			cs.DecryptIV[0] = ivbyte
			for i := 1; i < aes.BlockSize; i++ {
				cs.DecryptIV[i] += 1
				if cs.DecryptIV[i] > 0 {
					break
				}
			}
		} else {
			err = os.NewError("invalid ivbyte")
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
			for i := 1; i < aes.BlockSize; i++ {
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
			for i := 1; i < aes.BlockSize; i++ {
				cs.DecryptIV[i] += 1
				if cs.DecryptIV[i] > 0 {
					break
				}
			}
		} else {
			err = os.NewError("No matching ivbyte")
			return
		}

		if cs.decryptHistory[cs.DecryptIV[0]] == cs.DecryptIV[0] {
			if copy(cs.DecryptIV[0:], saveiv[0:]) != aes.BlockSize {
				err = os.NewError("Failed to copy aes.BlockSize bytes")
				return
			}
		}
	}

	cs.OCBDecrypt(dst[0:], src[4:], cs.DecryptIV[0:], tag[0:])

	for i := 0; i < 3; i++ {
		if tag[i] != src[i+1] {
			if copy(cs.DecryptIV[0:], saveiv[0:]) != aes.BlockSize {
				err = os.NewError("Error while trying to recover from error")
				return
			}
			err = os.NewError("tag mismatch")
			return
		}
	}

	cs.decryptHistory[cs.DecryptIV[0]] = cs.DecryptIV[0]

	if restore {
		if copy(cs.DecryptIV[0:], saveiv[0:]) != aes.BlockSize {
			err = os.NewError("Error while trying to recover IV")
			return
		}
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

	cs.LastGoodTime = time.Seconds()

	return
}

func (cs *CryptState) Encrypt(dst, src []byte) {
	var tag [aes.BlockSize]byte

	// First, increase our IV
	for i := range cs.EncryptIV {
		cs.EncryptIV[i] += 1
		if cs.EncryptIV[i] > 0 {
			break
		}
	}

	cs.OCBEncrypt(dst[4:], src, cs.EncryptIV[0:], tag[0:])

	dst[0] = cs.EncryptIV[0]
	dst[1] = tag[0]
	dst[2] = tag[1]
	dst[3] = tag[2]

	return
}

func zeros(block []byte) {
	for i := range block {
		block[i] = 0
	}
}

func xor(dst []byte, a []byte, b []byte) {
	for i := 0; i < aes.BlockSize; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func times2(block []byte) {
	carry := (block[0] >> 7) & 0x1
	for i := 0; i < aes.BlockSize-1; i++ {
		block[i] = (block[i] << 1) | ((block[i+1] >> 7) & 0x1)
	}
	block[aes.BlockSize-1] = (block[aes.BlockSize-1] << 1) ^ (carry * 135)
}

func times3(block []byte) {
	carry := (block[0] >> 7) & 0x1
	for i := 0; i < aes.BlockSize-1; i++ {
		block[i] ^= (block[i] << 1) | ((block[i+1] >> 7) & 0x1)
	}
	block[aes.BlockSize-1] ^= ((block[aes.BlockSize-1] << 1) ^ (carry * 135))
}

func (cs *CryptState) OCBEncrypt(dst []byte, src []byte, nonce []byte, tag []byte) (err os.Error) {
	var delta [aes.BlockSize]byte
	var checksum [aes.BlockSize]byte
	var tmp [aes.BlockSize]byte
	var pad [aes.BlockSize]byte
	off := 0

	cs.cipher.Encrypt(delta[0:], cs.EncryptIV[0:])
	zeros(checksum[0:])

	remain := len(src)
	for remain > aes.BlockSize {
		times2(delta[0:])
		xor(tmp[0:], delta[0:], src[off:off+aes.BlockSize])
		cs.cipher.Encrypt(tmp[0:], tmp[0:])
		xor(dst[off:off+aes.BlockSize], delta[0:], tmp[0:])
		xor(checksum[0:], checksum[0:], src[off:off+aes.BlockSize])
		remain -= aes.BlockSize
		off += aes.BlockSize
	}

	times2(delta[0:])
	zeros(tmp[0:])
	num := remain * 8
	tmp[aes.BlockSize-2] = uint8((uint32(num) >> 8) & 0xff)
	tmp[aes.BlockSize-1] = uint8(num & 0xff)
	xor(tmp[0:], tmp[0:], delta[0:])
	cs.cipher.Encrypt(pad[0:], tmp[0:])
	copied := copy(tmp[0:], src[off:])
	if copied != remain {
		err = os.NewError("Copy failed")
		return
	}
	if copy(tmp[copied:], pad[copied:]) != (aes.BlockSize - remain) {
		err = os.NewError("Copy failed")
		return
	}
	xor(checksum[0:], checksum[0:], tmp[0:])
	xor(tmp[0:], pad[0:], tmp[0:])
	if copy(dst[off:], tmp[0:]) != remain {
		err = os.NewError("Copy failed")
		return
	}

	times3(delta[0:])
	xor(tmp[0:], delta[0:], checksum[0:])
	cs.cipher.Encrypt(tag[0:], tmp[0:])

	return
}

func (cs *CryptState) OCBDecrypt(plain []byte, encrypted []byte, nonce []byte, tag []byte) (err os.Error) {
	var checksum [aes.BlockSize]byte
	var delta [aes.BlockSize]byte
	var tmp [aes.BlockSize]byte
	var pad [aes.BlockSize]byte
	off := 0

	cs.cipher.Encrypt(delta[0:], nonce[0:])
	zeros(checksum[0:])

	remain := len(encrypted)
	for remain > aes.BlockSize {
		times2(delta[0:])
		xor(tmp[0:], delta[0:], encrypted[off:off+aes.BlockSize])
		cs.cipher.Decrypt(tmp[0:], tmp[0:])
		xor(plain[off:off+aes.BlockSize], delta[0:], tmp[0:])
		xor(checksum[0:], checksum[0:], plain[off:off+aes.BlockSize])
		off += aes.BlockSize
		remain -= aes.BlockSize
	}

	times2(delta[0:])
	zeros(tmp[0:])
	num := remain * 8
	tmp[aes.BlockSize-2] = uint8((uint32(num) >> 8) & 0xff)
	tmp[aes.BlockSize-1] = uint8(num & 0xff)
	xor(tmp[0:], tmp[0:], delta[0:])
	cs.cipher.Encrypt(pad[0:], tmp[0:])
	zeros(tmp[0:])
	copied := copy(tmp[0:remain], encrypted[off:off+remain])
	if copied != remain {
		err = os.NewError("Copy failed")
		return
	}
	xor(tmp[0:], tmp[0:], pad[0:])
	xor(checksum[0:], checksum[0:], tmp[0:])
	copied = copy(plain[off:off+remain], tmp[0:remain])
	if copied != remain {
		err = os.NewError("Copy failed")
		return
	}

	times3(delta[0:])
	xor(tmp[0:], delta[0:], checksum[0:])
	cs.cipher.Encrypt(tag[0:], tmp[0:])

	return
}
