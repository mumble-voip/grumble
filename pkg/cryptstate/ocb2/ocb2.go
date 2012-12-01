package ocb2

import (
	"crypto/aes"
	"crypto/cipher"
)

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

func Encrypt(cipher cipher.Block, dst []byte, src []byte, nonce []byte, tag []byte) (err error) {
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

	return
}

func Decrypt(cipher cipher.Block, plain []byte, encrypted []byte, nonce []byte, tag []byte) (err error) {
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

	return
}