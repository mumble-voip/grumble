// Copyright (c) 2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package cryptstate

import (
	"unsafe"

	"golang.org/x/crypto/nacl/secretbox"
)

// secretBoxMode implements the XSalsa20-Poly1305 CryptoMode
type secretBoxMode struct {
	key [32]byte
}

// NonceSize returns the nonce size to be used with XSalsa20-Poly1305.
func (sb *secretBoxMode) NonceSize() int {
	return 24
}

// KeySize returns the key size to be used with XSalsa20-Poly1305.
func (sb *secretBoxMode) KeySize() int {
	return 32
}

// Overhead returns the overhead that a ciphertext has over a plaintext.
// In the case of XSalsa20-Poly1305 the overhead is the authentication tag.
func (sb *secretBoxMode) Overhead() int {
	return secretbox.Overhead
}

// SetKey sets a new key. The key must have a length equal to KeySize().
func (sb *secretBoxMode) SetKey(key []byte) {
	if len(key) != sb.KeySize() {
		panic("cryptstate: invalid key length")
	}
	copy(sb.key[:], key)
}

// Encrypt encrypts a message using XSalsa20-Poly1305 and outputs it to dst.
func (sb *secretBoxMode) Encrypt(dst []byte, src []byte, nonce []byte) {
	if len(dst) <= sb.Overhead() {
		panic("cryptstate: bad dst")
	}

	if len(nonce) != 24 {
		panic("cryptstate: bad nonce length")
	}

	noncePtr := (*[24]byte)(unsafe.Pointer(&nonce[0]))
	secretbox.Seal(dst[0:0], src, noncePtr, &sb.key)
}

// Decrypt decrypts a message using XSalsa20-Poly1305 and outputs it to dst.
// Returns false if decryption failed (authentication tag mismatch).
func (sb *secretBoxMode) Decrypt(dst []byte, src []byte, nonce []byte) bool {
	if len(src) <= sb.Overhead() {
		panic("cryptstate: bad src")
	}

	if len(nonce) != 24 {
		panic("cryptstate: bad nonce length")
	}

	noncePtr := (*[24]byte)(unsafe.Pointer(&nonce[0]))
	_, ok := secretbox.Open(dst[0:0], src, noncePtr, &sb.key)
	return ok
}
