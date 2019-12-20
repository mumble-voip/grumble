// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// Package freezer implements a persistence layer for Grumble.
package freezer

// The freezer package exports types that can be persisted to disk,
// both as part of a full server snapshot, and as part of a log of state changes.
//
// The freezer package also implements an append-only log writer that can be used
// to serialize the freezer types to disk in atomic entities called transactions
// records.
//
// A Walker type that can be used to iterate over the  different transaction records
// of a log file is also provided.

import (
	"bytes"
	"encoding/binary"
	"hash"
	"hash/crc32"
	"io"
	"math"
	"os"

	"github.com/golang/protobuf/proto"
)

// Log implements an append-only log for flattened
// protobuf-encoded log entries.
//
// These log entries are typically state-change deltas
// for a Grumble server's main data strutures.
//
// The log supports atomic transactions. Transaction groups
// are persisted to disk with a checksum that covers the
// whole transaction group. In case of a failure, none of the
// entries of a transaction will be applied.
type Log struct {
	wc io.WriteCloser
}

// Type LogTx represents a transaction in the log.
// Transactions can be used to group several changes into an
// atomic entity in the log file.
type LogTx struct {
	log    *Log
	crc    hash.Hash32
	buf    *bytes.Buffer
	numops int
}

// Create a new log file
func NewLogFile(fn string) (*Log, error) {
	f, err := os.Create(fn)
	if err != nil {
		return nil, err
	}

	log := new(Log)
	log.wc = f

	return log, nil
}

// Close a Log
func (log *Log) Close() error {
	return log.wc.Close()
}

// Append a log entry
//
// This method implicitly creates a transaction
// group for this single Put operation. It is merely
// a convenience wrapper.
func (log *Log) Put(value interface{}) (err error) {
	tx := log.BeginTx()
	err = tx.Put(value)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Begin a transaction
func (log *Log) BeginTx() *LogTx {
	tx := &LogTx{}
	tx.log = log
	tx.buf = new(bytes.Buffer)
	tx.crc = crc32.NewIEEE()
	return tx
}

// Append a log entry to the transaction.
// The transaction's log entries will not be persisted to
// the log until the Commit has been called on the transaction.
func (tx *LogTx) Put(value interface{}) (err error) {
	var (
		buf  []byte
		kind typeKind
	)

	if tx.numops > 255 {
		return ErrTxGroupFull
	}

	switch val := value.(type) {
	case *Server:
		kind = ServerType
		buf, err = proto.Marshal(val)
	case *ConfigKeyValuePair:
		kind = ConfigKeyValuePairType
		buf, err = proto.Marshal(val)
	case *BanList:
		kind = BanListType
		buf, err = proto.Marshal(val)
	case *User:
		kind = UserType
		buf, err = proto.Marshal(val)
	case *UserRemove:
		kind = UserRemoveType
		buf, err = proto.Marshal(val)
	case *Channel:
		kind = ChannelType
		buf, err = proto.Marshal(val)
	case *ChannelRemove:
		kind = ChannelRemoveType
		buf, err = proto.Marshal(val)
	default:
		panic("Attempt to put an unknown type")
	}

	if err != nil {
		return err
	}

	if len(buf) > math.MaxUint16 {
		return ErrTxGroupValueTooBig
	}

	w := io.MultiWriter(tx.buf, tx.crc)

	err = binary.Write(w, binary.LittleEndian, uint16(kind))
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.LittleEndian, uint16(len(buf)))
	if err != nil {
		return err
	}

	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	tx.numops += 1

	return nil
}

// Commit all changes of the transaction to the log
// as a single atomic entry.
func (tx *LogTx) Commit() (err error) {
	buf := new(bytes.Buffer)

	err = binary.Write(buf, binary.LittleEndian, uint32(4+4+tx.buf.Len()))
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, uint32(tx.numops))
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, tx.crc.Sum32())
	if err != nil {
		return err
	}

	_, err = buf.Write(tx.buf.Bytes())
	if err != nil {
		return err
	}

	_, err = tx.log.wc.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}
