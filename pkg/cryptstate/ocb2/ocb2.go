// Package ocb2 implements the version 2 of the OCB authenticated-encryption algorithm.
// OCB2 is specified in http://www.cs.ucdavis.edu/~rogaway/papers/draft-krovetz-ocb-00.txt.
//
// It should be noted that OCB's author, Phil Rogaway <rogaway@cs.ucdavis.edu>, holds
// several US patents on the algorithm.  This should be considered before using this code
// in your own projects.  See OCB's FAQ for more info:
// http://www.cs.ucdavis.edu/~rogaway/ocb/ocb-faq.htm#patent:phil
//
// The Mumble Project has a license to use OCB mode in its BSD licensed code on a royalty
// free basis.
package ocb2

import (
	"crypto/aes"
	"crypto/cipher"
)

const (
	// TagSize specifies the length in bytes of a full OCB2 tag.
	// As per the specification, applications may truncate their
	// tags to a given length, but advocates that typical applications
	// should use a tag length of at least 8 bytes (64 bits).
	TagSize = aes.BlockSize
	// NonceSize specifies the length in bytes of an OCB2 nonce.
	NonceSize = aes.BlockSize
)

// zeros fills block with zero bytes.
func zeros(block []byte) {
	for i := range block {
		block[i] = 0
	}
}

// xor outputs the bitwise exclusive-or of a and b to dst.
func xor(dst []byte, a []byte, b []byte) {
	for i := 0; i < aes.BlockSize; i++ {
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
func times2(block []byte) {
	carry := (block[0] >> 7) & 0x1
	for i := 0; i < aes.BlockSize-1; i++ {
		block[i] = (block[i] << 1) | ((block[i+1] >> 7) & 0x1)
	}
	block[aes.BlockSize-1] = (block[aes.BlockSize-1] << 1) ^ (carry * 135)
}

// times3 performs the times3 operation, defined as:
//
// times3(S)
//     times2(S) xor S
func times3(block []byte) {
	carry := (block[0] >> 7) & 0x1
	for i := 0; i < aes.BlockSize-1; i++ {
		block[i] ^= (block[i] << 1) | ((block[i+1] >> 7) & 0x1)
	}
	block[aes.BlockSize-1] ^= ((block[aes.BlockSize-1] << 1) ^ (carry * 135))
}

// Encrypt encrypts the plaintext src and outputs the corresponding ciphertext into dst.
// Besides outputting a ciphertext into dst, Encrypt also outputs an authentication tag
// of ocb2.TagSize bytes into tag, which should be used to verify the authenticity of the
// message on the receiving side.
//
// To ensure both authenticity and secrecy of messages, each invocation to this function must
// be given an unique nonce of ocb2.NonceSize bytes.  The nonce need not be secret (it can be
// a counter), but it needs to be unique.
func Encrypt(cipher cipher.Block, dst []byte, src []byte, nonce []byte, tag []byte) {
	var delta [aes.BlockSize]byte
	var checksum [aes.BlockSize]byte
	var tmp [aes.BlockSize]byte
	var pad [aes.BlockSize]byte
	off := 0

	cipher.Encrypt(delta[0:], nonce[0:])
	zeros(checksum[0:])

	remain := len(src)
	for remain > aes.BlockSize {
		times2(delta[0:])
		xor(tmp[0:], delta[0:], src[off:off+aes.BlockSize])
		cipher.Encrypt(tmp[0:], tmp[0:])
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
	cipher.Encrypt(pad[0:], tmp[0:])
	copied := copy(tmp[0:], src[off:])
	if copied != remain {
		panic("ocb2: copy failed")
	}
	if copy(tmp[copied:], pad[copied:]) != (aes.BlockSize - remain) {
		panic("ocb2: copy failed")
	}
	xor(checksum[0:], checksum[0:], tmp[0:])
	xor(tmp[0:], pad[0:], tmp[0:])
	if copy(dst[off:], tmp[0:]) != remain {
		panic("ocb2: copy failed")
	}

	times3(delta[0:])
	xor(tmp[0:], delta[0:], checksum[0:])
	cipher.Encrypt(tag[0:], tmp[0:])
}

// Decrypt takes a ciphertext and a nonce as its input and outputs a decrypted plaintext
// and corresponding authentication tag.
//
// Before using the decrpyted plaintext, the application
// should verify that the computed authentication tag matches the tag that was produced when
// encrypting the message (taking into consideration that OCB tags are allowed to be truncated
// to a length less than ocb.TagSize).
func Decrypt(cipher cipher.Block, plain []byte, encrypted []byte, nonce []byte, tag []byte) {
	var checksum [aes.BlockSize]byte
	var delta [aes.BlockSize]byte
	var tmp [aes.BlockSize]byte
	var pad [aes.BlockSize]byte
	off := 0

	cipher.Encrypt(delta[0:], nonce[0:])
	zeros(checksum[0:])

	remain := len(encrypted)
	for remain > aes.BlockSize {
		times2(delta[0:])
		xor(tmp[0:], delta[0:], encrypted[off:off+aes.BlockSize])
		cipher.Decrypt(tmp[0:], tmp[0:])
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
	cipher.Encrypt(tag[0:], tmp[0:])
}