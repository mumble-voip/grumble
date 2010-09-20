// Grumble - an implementation of Murmur in Go
// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package cryptstate

import (
	"crypto/aes"
	"crypto/rand"
	"os"
)

const AESBlockSize        = 16
const DecryptHistorySize  = 0x100

type CryptState struct {
	RawKey [AESBlockSize]byte
	EncryptIV [AESBlockSize]byte
	DecryptIV [AESBlockSize]byte
	decryptHistory [DecryptHistorySize]byte

	Good int
	Late int
	Lost int
	Resync int

	RemoteGood int
	RemoteLate int
	RemoteLost int
	RemoteResync int

	cipher *aes.Cipher
}

func New() (cs *CryptState, err os.Error) {
	cs = new(CryptState)

	for i := 0; i < DecryptHistorySize; i++ {
		cs.decryptHistory[i] = 0
	}

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

func (cs *CryptState) SetKey(key []byte, eiv []byte, div[]byte) (err os.Error) {
	if copy(cs.RawKey[0:], key[0:]) != AESBlockSize {
		err = os.NewError("Unable to copy key")
		return
	}

	if copy(cs.EncryptIV[0:], eiv[0:]) != AESBlockSize {
		err = os.NewError("Unable to copy EIV")
		return
	}

	if copy(cs.DecryptIV[0:], div[0:]) != AESBlockSize {
		err = os.NewError("Unable to copy DIV")
		return
	}

	cs.cipher, err = aes.NewCipher(cs.RawKey[0:])
	if err != nil {
		return
	}

	return
}

func (cs *CryptState) Decrypt(src, dst []byte) (err os.Error) {
	if len(src) < 4 {
		err = os.NewError("Crypted length too short to decrypt")
		return
	}

	plain_len := len(src) - 4
	if len(dst) != plain_len {
		err = os.NewError("plain_len and src len mismatch")
		return
	}

	var saveiv [AESBlockSize]byte
	var tag [AESBlockSize]byte
	var ivbyte byte
	var restore bool
	lost := 0
	late := 0

	ivbyte = src[0]
	restore = false

	if copy(saveiv[0:], cs.DecryptIV[0:]) != AESBlockSize {
		err = os.NewError("Copy failed")
		return
	}

	if byte(cs.DecryptIV[0] + 1) == ivbyte {
		// In order as expected
		if ivbyte > cs.DecryptIV[0] {
			cs.DecryptIV[0] = ivbyte
		} else if ivbyte < cs.DecryptIV[0] {
			cs.DecryptIV[0] = ivbyte
			for i := 1; i < AESBlockSize; i++ {
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
			for i := 1; i < AESBlockSize; i++ {
				cs.DecryptIV[0] -= 1
				if cs.DecryptIV[0] > 0 {
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
			for i := 1; i < AESBlockSize; i++ {
				cs.DecryptIV[0] += 1
				if cs.DecryptIV[0] > 0 {
					break
				}
			}
		} else {
			err = os.NewError("No matching ivbyte")
			return
		}

		if cs.decryptHistory[cs.DecryptIV[0]] == cs.DecryptIV[0] {
			if copy(cs.DecryptIV[0:], saveiv[0:]) != AESBlockSize {
				err = os.NewError("Failed to copy AESBlockSize bytes")
				return
			}
		}
	}

	cs.OCBDecrypt(src[4:], dst[0:], cs.DecryptIV[0:], tag[0:])

	for i := 0; i < 3; i++ {
		if tag[i] != src[i+1] {
			if copy(cs.DecryptIV[0:], saveiv[0:]) != AESBlockSize {
				err = os.NewError("Error while trying to recover from error")
				return
			}
			err = os.NewError("tag mismatch")
			return
		}
	}

	cs.decryptHistory[cs.DecryptIV[0]] = cs.DecryptIV[0]

	if restore {
		if copy(cs.DecryptIV[0:], saveiv[0:]) != AESBlockSize {
			err = os.NewError("Error while trying to recover IV")
			return
		}
	}

	cs.Good += 1
	cs.Late += late
	cs.Lost += lost

	// restart timer

	return
}

func (cs *CryptState) Encrypt(src, dst []byte) {
	var tag [AESBlockSize]byte

	// First, increase our IV
	for i := 0; i < AESBlockSize; i++ {
		cs.EncryptIV[i] += 1;
		if cs.EncryptIV[i] > 0 {
			break;
		}
	}

	cs.OCBEncrypt(src, dst[4:], cs.EncryptIV[0:], tag[0:])

	dst[0] = cs.EncryptIV[0]
	dst[1] = tag[0];
	dst[2] = tag[1];
	dst[3] = tag[2];

	return
}

func zeros(block []byte) {
	for i := 0; i < AESBlockSize; i++ {
		block[i] = 0
	}
}

func xor(dst []byte, a []byte, b []byte) {
	for i := 0; i < AESBlockSize; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func times2(block []byte) {
	carry := (block[0] >> 7) & 0x1
	for i := 0; i < AESBlockSize-1; i++ {
		block[i] = (block[i] << 1) | ((block[i+1] >> 7) & 0x1)
	}
	block[AESBlockSize-1] = (block[AESBlockSize-1] << 1) ^ (carry * 135)
}

func times3(block []byte) {
	carry := (block[0] >> 7) & 0x1;
	for i := 0; i < AESBlockSize-1; i++ {
		block[i] ^= (block[i] << 1) | ((block[i+1] >> 7) & 0x1)
	}
	block[AESBlockSize-1] ^= ((block[AESBlockSize-1] << 1) ^ (carry * 135))
}

func (cs *CryptState) OCBEncrypt(src []byte, dst []byte, nonce []byte, tag []byte) (err os.Error) {
	var delta [AESBlockSize]byte
	var checksum [AESBlockSize]byte
	var tmp [AESBlockSize]byte
	var pad [AESBlockSize]byte
	off := 0

	cs.cipher.Encrypt(cs.EncryptIV[0:], delta[0:])
	zeros(checksum[0:])

	remain := len(src)
	for remain > AESBlockSize {
		times2(delta[0:])
		xor(tmp[0:], delta[0:], src[off:off+AESBlockSize])
		cs.cipher.Encrypt(tmp[0:], tmp[0:])
		xor(dst[off:off+AESBlockSize], delta[0:], tmp[0:])
		xor(checksum[0:], checksum[0:], src[off:off+AESBlockSize])
		remain -= AESBlockSize
		off += AESBlockSize
	}

	times2(delta[0:])
	zeros(tmp[0:])
	num := remain * 8
	tmp[AESBlockSize-2] = uint8((uint32(num) >> 8) & 0xff)
	tmp[AESBlockSize-1] = uint8(num & 0xff)
	xor(tmp[0:], tmp[0:], delta[0:])
	cs.cipher.Encrypt(tmp[0:], pad[0:])
	copied := copy(tmp[0:], src[off:])
	if copied != remain {
		err = os.NewError("Copy failed")
		return
	}
	if copy(tmp[copied:], pad[copied:]) != (AESBlockSize-remain) {
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
	cs.cipher.Encrypt(tmp[0:], tag[0:])

	return
}

func (cs *CryptState) OCBDecrypt(encrypted []byte, plain []byte, nonce []byte, tag []byte) (err os.Error) {
	var checksum [AESBlockSize]byte
	var delta [AESBlockSize]byte
	var tmp [AESBlockSize]byte
	var pad [AESBlockSize]byte
	off := 0

	cs.cipher.Encrypt(nonce[0:], delta[0:])
	zeros(checksum[0:])

	remain := len(encrypted)
	for remain > AESBlockSize {
		times2(delta[0:])
		xor(tmp[0:], delta[0:], encrypted[off:off+AESBlockSize])
		cs.cipher.Decrypt(tmp[0:], tmp[0:])
		xor(plain[off:off+AESBlockSize], delta[0:], tmp[0:])
		xor(checksum[0:], checksum[0:], plain[off:off+AESBlockSize])
		off += AESBlockSize
		remain -= AESBlockSize
	}

	times2(delta[0:])
	zeros(tmp[0:])
	num := remain * 8
	tmp[AESBlockSize-2] = uint8((uint32(num) >> 8) & 0xff)
	tmp[AESBlockSize-1] = uint8(num & 0xff)
	xor(tmp[0:], tmp[0:], delta[0:])
	cs.cipher.Encrypt(tmp[0:], pad[0:])
	for i := 0; i < AESBlockSize; i++ {
		tmp[i] = 0
	}
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
	cs.cipher.Encrypt(tmp[0:], tag[0:])

	return
}
