// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package freezer

import (
	"encoding/binary"
	"hash"
	"hash/crc32"
	"io"
	"math"

	"github.com/golang/protobuf/proto"
)

// Checks whether the error err is an EOF
// error.
func isEOF(err error) bool {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return true
	}
	return false
}

// Type Walker implements a method for
// iterating the transaction groups of an
// immutable Log.
type Walker struct {
	r io.Reader
}

// Type txReader imlpements a checksumming reader, intended
// for reading transaction groups of a Log.
//
// Besides auto-checksumming the read content, it also
// keeps track of the amount of consumed bytes.
type txReader struct {
	r        io.Reader
	crc32    hash.Hash32
	consumed int
}

// Create a new txReader for reading a transaction group
// from the log.
func newTxReader(r io.Reader) *txReader {
	txr := new(txReader)
	txr.r = r
	txr.crc32 = crc32.NewIEEE()
	return txr
}

// walkReader's Read method. Reads from walkReader's Reader
// and checksums while reading.
func (txr *txReader) Read(p []byte) (n int, err error) {
	n, err = txr.r.Read(p)
	if err != nil && err != io.EOF {
		return
	}
	txr.consumed += n

	_, crc32err := txr.crc32.Write(p)
	if crc32err != nil {
		return n, crc32err
	}

	return n, err
}

// Sum32 returns the IEEE-style CRC32 checksum
// of the data read by the walkReader.
func (txr *txReader) Sum32() uint32 {
	return txr.crc32.Sum32()
}

// Consumed returns the amount of bytes consumed by
// the walkReader.
func (txr *txReader) Consumed() int {
	return txr.consumed
}

// Create a new Walker that iterates over the log entries of a given Reader.
func NewReaderWalker(r io.Reader) (walker *Walker, err error) {
	walker = new(Walker)
	walker.r = r
	return walker, nil
}

// Next returns the next transaction group in the log as a slice of
// pointers to the protobuf-serialized log entries.
//
// This method will only attempt to serialize types with type identifiers
// that this package knows of. In case an unknown type identifier is found
// in a transaction group, it is silently ignored (it's skipped).
//
// On error, Next returns a nil slice and a non-nil err.
// When the end of the file is reached, Next returns nil, os.EOF.
func (walker *Walker) Next() (entries []interface{}, err error) {
	var (
		remainBytes uint32
		remainOps   uint32
		crcsum      uint32
		kind        uint16
		length      uint16
	)

	err = binary.Read(walker.r, binary.LittleEndian, &remainBytes)
	if isEOF(err) {
		return nil, io.EOF
	} else if err != nil {
		return nil, err
	}

	if remainBytes < 8 {
		return nil, ErrUnexpectedEndOfRecord
	}
	if remainBytes-8 > math.MaxUint8*math.MaxUint16 {
		return nil, ErrRecordTooBig
	}

	err = binary.Read(walker.r, binary.LittleEndian, &remainOps)
	if isEOF(err) {
		return nil, ErrUnexpectedEndOfRecord
	} else if err != nil {
		return nil, err
	}

	err = binary.Read(walker.r, binary.LittleEndian, &crcsum)
	if isEOF(err) {
		return nil, ErrUnexpectedEndOfRecord
	} else if err != nil {
		return nil, err
	}

	remainBytes -= 8
	reader := newTxReader(walker.r)

	for remainOps > 0 {
		err = binary.Read(reader, binary.LittleEndian, &kind)
		if isEOF(err) {
			break
		} else if err != nil {
			return nil, err
		}

		err = binary.Read(reader, binary.LittleEndian, &length)
		if isEOF(err) {
			break
		} else if err != nil {
			return nil, err
		}

		buf := make([]byte, length)
		_, err = io.ReadFull(reader, buf)
		if isEOF(err) {
			break
		} else if err != nil {
			return nil, err
		}

		switch typeKind(kind) {
		case ServerType:
			server := &Server{}
			err = proto.Unmarshal(buf, server)
			if isEOF(err) {
				break
			} else if err != nil {
				return nil, err
			}
			entries = append(entries, server)
		case ConfigKeyValuePairType:
			cfg := &ConfigKeyValuePair{}
			err = proto.Unmarshal(buf, cfg)
			if isEOF(err) {
				break
			} else if err != nil {
				return nil, err
			}
			entries = append(entries, cfg)
		case BanListType:
			banlist := &BanList{}
			err = proto.Unmarshal(buf, banlist)
			if isEOF(err) {
				break
			} else if err != nil {
				return nil, err
			}
			entries = append(entries, banlist)
		case UserType:
			user := &User{}
			err = proto.Unmarshal(buf, user)
			if isEOF(err) {
				break
			} else if err != nil {
				return nil, err
			}
			entries = append(entries, user)
		case UserRemoveType:
			userRemove := &UserRemove{}
			err = proto.Unmarshal(buf, userRemove)
			if isEOF(err) {
				break
			} else if err != nil {
				return nil, err
			}
			entries = append(entries, userRemove)
		case ChannelType:
			channel := &Channel{}
			err = proto.Unmarshal(buf, channel)
			if isEOF(err) {
				break
			} else if err != nil {
				return nil, err
			}
			entries = append(entries, channel)
		case ChannelRemoveType:
			channelRemove := &ChannelRemove{}
			err = proto.Unmarshal(buf, channelRemove)
			if isEOF(err) {
				break
			} else if err != nil {
				return nil, err
			}
			entries = append(entries, channelRemove)
		}

		remainOps -= 1
		continue
	}

	if isEOF(err) {
		return nil, ErrUnexpectedEndOfRecord
	}

	if reader.Consumed() != int(remainBytes) {
		return nil, ErrRemainingBytesForRecord
	}

	if reader.Sum32() != crcsum {
		return nil, ErrCRC32Mismatch
	}

	return entries, nil
}
