// Copyright (c) 2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package cryptstate

// nullMode implements the NULL CryptoMode
type nullMode struct{}

// NonceSize returns the nonce size to be used with NULL.
func (n *nullMode) NonceSize() int {
	return 1
}

// KeySize returns the key size to be used with NULL.
func (n *nullMode) KeySize() int {
	return 0
}

// Overhead returns the overhead that a ciphertext has over a plaintext.
func (n *nullMode) Overhead() int {
	return 0
}

// SetKey sets a new key. The key must have a length equal to KeySize().
func (n *nullMode) SetKey(key []byte) {
}

// Encrypt encrypts a message using NULL and outputs it to dst.
func (n *nullMode) Encrypt(dst []byte, src []byte, nonce []byte) {
	copy(dst, src)
}

// Decrypt decrypts a message using NULL and outputs it to dst.
func (n *nullMode) Decrypt(dst []byte, src []byte, nonce []byte) bool {
	copy(dst, src)
	return true
}
