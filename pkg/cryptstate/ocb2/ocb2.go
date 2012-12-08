// Copyright (c) 2010-2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// Package ocb2 implements the version 2 of the OCB authenticated-encryption algorithm.
// OCB2 is specified in http://www.cs.ucdavis.edu/~rogaway/papers/draft-krovetz-ocb-00.txt.
//
// Note that this implementation is limited to block ciphers with a block size of 128 bits.
//
// It should also be noted that OCB's author, Phil Rogaway <rogaway@cs.ucdavis.edu>, holds
// several US patents on the algorithm.  This should be considered before using this code
// in your own projects.  See OCB's FAQ for more info:
// http://www.cs.ucdavis.edu/~rogaway/ocb/ocb-faq.htm#patent:phil
//
// The Mumble Project has a license to use OCB mode in its BSD licensed code on a royalty
// free basis.
package ocb2

import (
	"crypto/cipher"
	"crypto/subtle"
)

const (
	// BlockSize defines the block size that this particular implementation
	// of OCB2 is made to work on.
	BlockSize = 16
	// TagSize specifies the length in bytes of a full OCB2 tag.
	// As per the specification, applications may truncate their
	// tags to a given length, but advocates that typical applications
	// should use a tag length of at least 8 bytes (64 bits).
	TagSize = BlockSize
	// NonceSize specifies the length in bytes of an OCB2 nonce.
	NonceSize = BlockSize
)

// zeros fills block with zero bytes.
func zeros(block []byte) {
	for i := range block {
		block[i] = 0
	}
}

// xor outputs the bitwise exclusive-or of a and b to dst.
func xor(dst []byte, a []byte, b []byte) {
	for i := 0; i < BlockSize; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

// times2 performs the times2 operation, defined as:
//
// times2(S)
//     S << 1 if S[1] = 0, and (S << 1) xor const(bitlength(S)) if S[1] = 1.
//
// where const(n) is defined as
//
// const(n)
//     The lexicographically first n-bit string C among all
//     strings that have a minimal possible number of "1"
//     bits and which name a polynomial x^n + C[1] *
//     x^{n-1} + ... + C[n-1] * x^1 + C[n] * x^0 that is
//     irreducible over the field with two elements.  In
//     particular, const(128) = num2str(135, 128).  For
//     other values of n, refer to a standard table of
//     irreducible polynomials [G. Seroussi,
//     "Table of low-weight binary irreducible polynomials",
//     HP Labs Technical Report HPL-98-135, 1998.].
//
// and num2str(x, n) is defined as
//
// num2str(x, n)
//     The n-bit binary representation of the integer x.
//     More formally, the n-bit string S where x = S[1] *
//     2^{n-1} + S[2] * 2^{n-2} + ... + S[n] * 2^{0}.  Only
//     used when 0 <= x < 2^n.
//
// For our 128-bit block size implementation, this means that
// the xor with const(bitlength(S)) if S[1] = 1 is implemented
// by simply xor'ing the last byte with the number 135 when
// S[1] = 1.
func times2(block []byte) {
	carry := (block[0] >> 7) & 0x1
	for i := 0; i < BlockSize-1; i++ {
		block[i] = (block[i] << 1) | ((block[i+1] >> 7) & 0x1)
	}
	block[BlockSize-1] = (block[BlockSize-1] << 1) ^ (carry * 135)
}

// times3 performs the times3 operation, defined as:
//
// times3(S)
//     times2(S) xor S
func times3(block []byte) {
	carry := (block[0] >> 7) & 0x1
	for i := 0; i < BlockSize-1; i++ {
		block[i] ^= (block[i] << 1) | ((block[i+1] >> 7) & 0x1)
	}
	block[BlockSize-1] ^= ((block[BlockSize-1] << 1) ^ (carry * 135))
}

// Encrypt encrypts the plaintext src and outputs the corresponding ciphertext into dst.
// Besides outputting a ciphertext into dst, Encrypt also outputs an authentication tag
// of ocb2.TagSize bytes into tag, which should be used to verify the authenticity of the
// message on the receiving side.
//
// To ensure both authenticity and secrecy of messages, each invocation to this function must
// be given an unique nonce of ocb2.NonceSize bytes.  The nonce need not be secret (it can be
// a counter), but it needs to be unique.
//
// The block cipher used in function must work on a block size equal to ocb2.BlockSize.
// The tag slice used in this function must have a length equal to ocb2.TagSize.
// The nonce slice used in this function must have a length equal to ocb2.NonceSize.
// If any of the above are violated, Encrypt will panic.
func Encrypt(cipher cipher.Block, dst []byte, src []byte, nonce []byte, tag []byte) {
	if cipher.BlockSize() != BlockSize {
		panic("ocb2: cipher blocksize is not equal to ocb2.BlockSize")
	}
	if len(nonce) != NonceSize {
		panic("ocb2: nonce length is not equal to ocb2.NonceSize")
	}

	var (
		checksum [BlockSize]byte
		delta    [BlockSize]byte
		tmp      [BlockSize]byte
		pad      [BlockSize]byte
		calcTag  [NonceSize]byte
		off      int
	)

	cipher.Encrypt(delta[0:], nonce[0:])
	zeros(checksum[0:])

	remain := len(src)
	for remain > BlockSize {
		times2(delta[0:])
		xor(tmp[0:], delta[0:], src[off:off+BlockSize])
		cipher.Encrypt(tmp[0:], tmp[0:])
		xor(dst[off:off+BlockSize], delta[0:], tmp[0:])
		xor(checksum[0:], checksum[0:], src[off:off+BlockSize])
		remain -= BlockSize
		off += BlockSize
	}

	times2(delta[0:])
	zeros(tmp[0:])
	num := remain * 8
	tmp[BlockSize-2] = uint8((uint32(num) >> 8) & 0xff)
	tmp[BlockSize-1] = uint8(num & 0xff)
	xor(tmp[0:], tmp[0:], delta[0:])
	cipher.Encrypt(pad[0:], tmp[0:])
	copied := copy(tmp[0:], src[off:])
	if copied != remain {
		panic("ocb2: copy failed")
	}
	if copy(tmp[copied:], pad[copied:]) != (BlockSize - remain) {
		panic("ocb2: copy failed")
	}
	xor(checksum[0:], checksum[0:], tmp[0:])
	xor(tmp[0:], pad[0:], tmp[0:])
	if copy(dst[off:], tmp[0:]) != remain {
		panic("ocb2: copy failed")
	}

	times3(delta[0:])
	xor(tmp[0:], delta[0:], checksum[0:])
	cipher.Encrypt(calcTag[0:], tmp[0:])
	copy(tag, calcTag[:])
}

// Decrypt takes a ciphertext, a nonce, and a tag as its input and outputs a decrypted
// plaintext (if successful) and a boolean flag that determines whether the function
// successfully decrypted the given ciphertext.
//
// Before using the decrpyted plaintext, the application
// should verify that the computed authentication tag matches the tag that was produced when
// encrypting the message (taking into consideration that OCB tags are allowed to be truncated
// to a length less than ocb.TagSize).
//
// The block cipher used in function must work on a block size equal to ocb2.BlockSize.
// The tag slice used in this function must have a length equal to ocb2.TagSize.
// The nonce slice used in this function must have a length equal to ocb2.NonceSize.
// If any of the above are violated, Encrypt will panic.
func Decrypt(cipher cipher.Block, plain []byte, encrypted []byte, nonce []byte, tag []byte) bool {
	if cipher.BlockSize() != BlockSize {
		panic("ocb2: cipher blocksize is not equal to ocb2.BlockSize")
	}
	if len(nonce) != NonceSize {
		panic("ocb2: nonce length is not equal to ocb2.NonceSize")
	}

	var (
		checksum [BlockSize]byte
		delta    [BlockSize]byte
		tmp      [BlockSize]byte
		pad      [BlockSize]byte
		calcTag  [NonceSize]byte
		off      int
	)

	cipher.Encrypt(delta[0:], nonce[0:])
	zeros(checksum[0:])

	remain := len(encrypted)
	for remain > BlockSize {
		times2(delta[0:])
		xor(tmp[0:], delta[0:], encrypted[off:off+BlockSize])
		cipher.Decrypt(tmp[0:], tmp[0:])
		xor(plain[off:off+BlockSize], delta[0:], tmp[0:])
		xor(checksum[0:], checksum[0:], plain[off:off+BlockSize])
		off += BlockSize
		remain -= BlockSize
	}

	times2(delta[0:])
	zeros(tmp[0:])
	num := remain * 8
	tmp[BlockSize-2] = uint8((uint32(num) >> 8) & 0xff)
	tmp[BlockSize-1] = uint8(num & 0xff)
	xor(tmp[0:], tmp[0:], delta[0:])
	cipher.Encrypt(pad[0:], tmp[0:])
	zeros(tmp[0:])
	copied := copy(tmp[0:remain], encrypted[off:off+remain])
	if copied != remain {
		panic("ocb2: copy failed")
	}
	xor(tmp[0:], tmp[0:], pad[0:])
	xor(checksum[0:], checksum[0:], tmp[0:])
	copied = copy(plain[off:off+remain], tmp[0:remain])
	if copied != remain {
		panic("ocb2: copy failed")
	}

	times3(delta[0:])
	xor(tmp[0:], delta[0:], checksum[0:])
	cipher.Encrypt(calcTag[0:], tmp[0:])

	// Compare the calculated tag with the expected tag. Truncate
	// the computed tag if necessary.
	if subtle.ConstantTimeCompare(calcTag[:len(tag)], tag) != 1 {
		return false
	}

	return true
}
