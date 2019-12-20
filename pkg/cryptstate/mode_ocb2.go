// Copyright (c) 2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package cryptstate

import (
	"crypto/aes"
	"crypto/cipher"

	"mumble.info/grumble/pkg/cryptstate/ocb2"
)

// ocb2Mode implements the OCB2-AES128 CryptoMode
type ocb2Mode struct {
	cipher cipher.Block
}

// NonceSize returns the nonce size to be used with OCB2-AES128.
func (ocb *ocb2Mode) NonceSize() int {
	return ocb2.NonceSize
}

// KeySize returns the key size to be used with OCB2-AES128.
func (ocb *ocb2Mode) KeySize() int {
	return aes.BlockSize
}

// Overhead returns the overhead that a ciphertext has over a plaintext.
// In the case of OCB2-AES128, the overhead is the authentication tag.
func (ocb *ocb2Mode) Overhead() int {
	return 3
}

// SetKey sets a new key. The key must have a length equal to KeySize().
func (ocb *ocb2Mode) SetKey(key []byte) {
	if len(key) != ocb.KeySize() {
		panic("cryptstate: invalid key length")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic("cryptstate: NewCipher returned unexpected " + err.Error())
	}
	ocb.cipher = cipher
}

// Encrypt encrypts a message using OCB2-AES128 and outputs it to dst.
func (ocb *ocb2Mode) Encrypt(dst []byte, src []byte, nonce []byte) {
	if len(dst) <= ocb.Overhead() {
		panic("cryptstate: bad dst")
	}

	tag := dst[0:3]
	dst = dst[3:]
	ocb2.Encrypt(ocb.cipher, dst, src, nonce, tag)
}

// Decrypt decrypts a message using OCB2-AES128 and outputs it to dst.
// Returns false if decryption failed (authentication tag mismatch).
func (ocb *ocb2Mode) Decrypt(dst []byte, src []byte, nonce []byte) bool {
	if len(src) <= ocb.Overhead() {
		panic("cryptstate: bad src")
	}

	tag := src[0:3]
	src = src[3:]
	return ocb2.Decrypt(ocb.cipher, dst, src, nonce, tag)
}
