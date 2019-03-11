// Grumble - an implementation of Murmur in Go
// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package packetdata

import (
	"math"
)

type PacketData struct {
	Buf       []byte
	offset    int
	maxsize   int
	overshoot int
	ok        bool
}

func New(buf []byte) (pds *PacketData) {
	pds = new(PacketData)
	pds.Buf = buf
	pds.maxsize = len(buf)
	pds.ok = true
	return
}

func (pds *PacketData) IsValid() bool {
	return pds.ok
}

func (pds *PacketData) Skip(skip int) {
	if pds.Left() >= skip {
		pds.offset += skip
	} else {
		pds.ok = false
	}
}

// Left returns number of bytes remaining in
// the buffer.
func (pds *PacketData) Left() int {
	return int(pds.maxsize - pds.offset)
}

// Size returns the size of the currently-assembled data
// stream
func (pds *PacketData) Size() int {
	return pds.offset
}

// Get the next byte from the PacketData as a uint64
func (pds *PacketData) next() (ret uint64) {
	if pds.offset < pds.maxsize {
		ret = uint64(pds.Buf[pds.offset])
		pds.offset += 1
		return
	} else {
		pds.ok = false
	}
	return 0
}

// Next8 gets the next byte from the PacketData as a byte (uint8)
func (pds *PacketData) Next8() (ret uint8) {
	if pds.offset < pds.maxsize {
		ret = uint8(pds.Buf[pds.offset])
		pds.offset += 1
		return
	} else {
		pds.ok = false
	}
	return 0
}

// Put a byte (represented in an uint64) into the
// PacketData.
func (pds *PacketData) append(val uint64) {
	if val > 0xff {
		pds.ok = false
		return
	}

	if pds.offset < pds.maxsize {
		pds.Buf[pds.offset] = byte(val)
		pds.offset += 1
	} else {
		pds.ok = false
		pds.overshoot++
	}

}

// Add a variably-sized integer to the PacketData.
// The PacketData will figure out the most efficient
// encoding based on the binary representation of the value.
func (pds *PacketData) addVarint(val uint64) {
	i := val

	if (i&0x8000000000000000) != 0 && ^i < 0x100000000 {
		// Signed number
		i = ^i
		if i <= 0x3 {
			// Short for -1 to -4
			pds.append(0xfc | i)
		} else {
			pds.append(0xf8)
		}
	}
	if i < 0x80 {
		// Needs top bit clear
		pds.append(i)
	} else if i < 0x4000 {
		// Needs two top bits clear
		pds.append((i >> 8) | 0x80)
		pds.append(i & 0xff)
	} else if i < 0x10000000 {
		// Needs three top bits clear
		pds.append((i >> 16) | 0xc0)
		pds.append((i >> 8) & 0xff)
		pds.append(i & 0xff)
	} else if i < 0x100000000 {
		// Full 32 bit integer
		pds.append(0xf0)
		pds.append((i >> 24) & 0xff)
		pds.append((i >> 16) & 0xff)
		pds.append((i >> 8) & 0xff)
		pds.append(i & 0xff)
	} else {
		// 64 bit val
		pds.append(0xf4)
		pds.append((i >> 56) & 0xff)
		pds.append((i >> 48) & 0xff)
		pds.append((i >> 40) & 0xff)
		pds.append((i >> 32) & 0xff)
		pds.append((i >> 24) & 0xff)
		pds.append((i >> 16) & 0xff)
		pds.append((i >> 8) & 0xff)
		pds.append(i & 0xff)
	}
}

func (pds *PacketData) getVarint() (i uint64) {
	v := pds.next()

	if (v & 0x80) == 0x00 {
		i = (v & 0x7f)
	} else if (v & 0xc0) == 0x80 {
		i = (v&0x3f)<<8 | pds.next()
	} else if (v & 0xf0) == 0xf0 {
		switch v & 0xfc {
		case 0xf0:
			i = pds.next()<<24 | pds.next()<<16 | pds.next()<<8 | pds.next()
		case 0xf4:
			i = pds.next()<<56 | pds.next()<<48 | pds.next()<<40 | pds.next()<<32 | pds.next()<<24 | pds.next()<<16 | pds.next()<<8 | pds.next()
		case 0xf8:
			i = ^pds.getVarint()
		case 0xfc:
			i = ^(v & 0x03)
		default:
			pds.ok = false
			i = 0
		}
	} else if (v & 0xf0) == 0xe0 {
		i = (v&0x0f)<<24 | pds.next()<<16 | pds.next()<<8 | pds.next()
	} else if (v & 0xe0) == 0xc0 {
		i = (v&0x1f)<<16 | pds.next()<<8 | pds.next()
	}

	return
}

// GetUint64 reads a uint64 from the PacketData
func (pds *PacketData) GetUint64() uint64 {
	return pds.getVarint()
}

// PutUint64 writes a uint64 to the PacketData
func (pds *PacketData) PutUint64(val uint64) {
	pds.addVarint(val)
}

// GetUint32 reads a uint32 from the PacketData
func (pds *PacketData) GetUint32() uint32 {
	return uint32(pds.getVarint())
}

// PutUint32 writes a uint32 to the PacketData
func (pds *PacketData) PutUint32(val uint32) {
	pds.addVarint(uint64(val))
}

// GetUint16 reads a uint16 from the PacketData
func (pds *PacketData) GetUint16() uint16 {
	return uint16(pds.getVarint())
}

// PutUint16 writes a uint16 to the PacketData
func (pds *PacketData) PutUint16(val uint16) {
	pds.addVarint(uint64(val))
}

// GetUint8 reads a uint8 from the PacketData
func (pds *PacketData) GetUint8() uint8 {
	varint := pds.getVarint()
	return uint8(varint)
}

// PutUint8 writes a uint8 to the PacketData
func (pds *PacketData) PutUint8(val uint8) {
	pds.addVarint(uint64(val))
}

// GetInt64 reads a int64 from the PacketData
func (pds *PacketData) GetInt64() int64 {
	return int64(pds.getVarint())
}

// PutInt64 writes a int64 to the PacketData
func (pds *PacketData) PutInt64(val int64) {
	pds.addVarint(uint64(val))
}

// GetInt32 reads a int32 from the PacketData
func (pds *PacketData) GetInt32() int32 {
	return int32(pds.getVarint())
}

// PutInt32 writes a int32 to the PacketData
func (pds *PacketData) PutInt32(val int32) {
	pds.addVarint(uint64(val))
}

// GetInt16 reads a int16 from the PacketData
func (pds *PacketData) GetInt16() int16 {
	return int16(pds.getVarint())
}

// PutInt16 writes a int16 to the PacketData
func (pds *PacketData) PutInt16(val int16) {
	pds.addVarint(uint64(val))
}

// GetInt8 reads a int8 from the PacketData
func (pds *PacketData) GetInt8() int8 {
	return int8(pds.getVarint())
}

// PutInt8 writes a int8 to the PacketData
func (pds *PacketData) PutInt8(val int8) {
	pds.addVarint(uint64(val))
}

// GetFloat32 reads a float32 from the PacketData
func (pds *PacketData) GetFloat32() float32 {
	if pds.Left() < 4 {
		pds.ok = false
		return 0
	}

	var val uint32

	val = uint32(pds.Next8())<<24 | uint32(pds.Next8())<<16 | uint32(pds.Next8())<<8 | uint32(pds.Next8())
	return math.Float32frombits(val)
}

// PutFloat32 writes a float32 to the PacketData
func (pds *PacketData) PutFloat32(val float32) {
	bits := math.Float32bits(val)
	pds.append(uint64((bits >> 24) & 0xff))
	pds.append(uint64((bits >> 16) & 0xff))
	pds.append(uint64((bits >> 8) & 0xff))
	pds.append(uint64(bits & 0xff))
}

// GetFloat64 reads a float64 from the PacketData.
func (pds *PacketData) GetFloat64() float64 {
	if pds.Left() < 8 {
		pds.ok = false
		return 0
	}

	var val uint64
	val = uint64(pds.Next8())<<56 | uint64(pds.Next8())<<48 | uint64(pds.Next8())<<40 | uint64(pds.Next8())<<32 | uint64(pds.Next8())<<24 | uint64(pds.Next8())<<16 | uint64(pds.Next8())<<8 | uint64(pds.Next8())

	return math.Float64frombits(val)
}

// PutFloat64 writes a float64 to the PacketData
func (pds *PacketData) PutFloat64(val float64) {
	bits := math.Float64bits(val)
	pds.append((bits >> 56) & 0xff)
	pds.append((bits >> 48) & 0xff)
	pds.append((bits >> 40) & 0xff)
	pds.append((bits >> 32) & 0xff)
	pds.append((bits >> 24) & 0xff)
	pds.append((bits >> 16) & 0xff)
	pds.append((bits >> 8) & 0xff)
	pds.append(bits & 0xff)
}

// Copy a buffer out of the PacketData into dst.
func (pds *PacketData) CopyBytes(dst []byte) {
	if pds.Left() >= len(dst) {
		if copy(dst, pds.Buf[pds.offset:pds.offset+len(dst)]) != len(dst) {
			pds.ok = false
		}
	} else {
		pds.ok = false
	}
}

// Put a buffer src into the PacketData at the
// current offset.
func (pds *PacketData) PutBytes(src []byte) {
	if pds.Left() >= len(src) {
		if copy(pds.Buf[pds.offset:pds.offset+len(src)], src) != len(src) {
			pds.ok = false
		} else {
			pds.offset += len(src)
		}
	} else {
		pds.overshoot += len(src) - pds.Left()
		pds.ok = false
	}
}
