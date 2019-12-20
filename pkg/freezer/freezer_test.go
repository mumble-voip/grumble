// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package freezer

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"
	"os"
	"testing"

	"github.com/golang/protobuf/proto"
)

var testValues []proto.Message = []proto.Message{
	&ConfigKeyValuePair{Key: proto.String("Foo")},
	&BanList{Bans: []*Ban{&Ban{Mask: proto.Uint32(32)}}},
	&User{Id: proto.Uint32(0), Name: proto.String("SuperUser")},
	&UserRemove{Id: proto.Uint32(0)},
	&Channel{Id: proto.Uint32(0), Name: proto.String("RootChannel")},
	&ChannelRemove{Id: proto.Uint32(0)},
}

// Generate a byet slice representing an entry in a Tx record
func genTxValue(kind uint16, val []byte) (chunk []byte, crc32sum uint32, err error) {
	buf := new(bytes.Buffer)

	err = binary.Write(buf, binary.LittleEndian, kind)
	if err != nil {
		return nil, 0, err
	}

	err = binary.Write(buf, binary.LittleEndian, uint16(len(val)))
	if err != nil {
		return nil, 0, err
	}

	_, err = buf.Write(val)
	if err != nil {
		return nil, 0, err
	}

	summer := crc32.NewIEEE()
	_, err = summer.Write(val)
	if err != nil {
		return nil, 0, err
	}

	return buf.Bytes(), summer.Sum32(), nil
}

// Generate the header of a Tx record
func genTestCaseHeader(chunk []byte, numops uint32, crc32sum uint32) (r io.Reader, err error) {
	buf := new(bytes.Buffer)

	err = binary.Write(buf, binary.LittleEndian, uint32(4+4+len(chunk)))
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, numops)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, crc32sum)
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(chunk)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// Test that the Walker and the Writer agree on the
// protocol.
func TestCreation(t *testing.T) {
	l, err := NewLogFile("creation.log")
	if err != nil {
		t.Error(err)
		return
	}
	l.Close()
	os.Remove("creation.log")
}

func TestLogging(t *testing.T) {
	l, err := NewLogFile("logging.log")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.Remove("logging.log")

	for _, val := range testValues {
		err = l.Put(val)
		if err != nil {
			t.Fatal(err)
		}
	}

	err = l.Close()
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Open("logging.log")
	if err != nil {
		t.Fatal(err)
	}

	walker, err := NewReaderWalker(f)
	if err != nil {
		t.Error(err)
		return
	}

	i := 0
	for {
		entries, err := walker.Next()
		if err == io.EOF {
			err = f.Close()
			if err != nil {
				t.Fatal(err)
			}
			break
		} else if err != nil {
			t.Error(err)
			return
		}
		if len(entries) != 1 {
			t.Error("> 1 entry in log tx")
			return
		}
		val, ok := entries[0].(proto.Message)
		if !ok {
			t.Fatal("val does not implement proto.Message")
		}
		if !proto.Equal(val, testValues[i]) {
			t.Error("proto message mismatch")
		}
		i += 1
	}
}

// Check that we correctly catch CRC32 mismatches
func TestCRC32MismatchLog(t *testing.T) {
	chunk, _, err := genTxValue(0xff, []byte{0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		t.Error(err)
	}

	buf, err := genTestCaseHeader(chunk, 1, 0xcafebabe)
	if err != nil {
		t.Error(err)
	}

	walker, err := NewReaderWalker(buf)
	if err != nil {
		t.Error(err)
	}

	_, err = walker.Next()
	if err != ErrCRC32Mismatch {
		t.Errorf("exepcted CRC32 mismatch, got %v", err)
	}
	_, err = walker.Next()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

// Test that unknown TxGroup values are not attempted to be
// decoded.
func TestUnknownTypeDecode(t *testing.T) {
	buf, crc32sum, err := genTxValue(0xfa, []byte{0xfa, 0xfa, 0xfa})
	if err != nil {
		t.Error(err)
	}

	r, err := genTestCaseHeader(buf, 1, crc32sum)
	if err != nil {
		t.Error(err)
	}

	walker, err := NewReaderWalker(r)
	if err != nil {
		t.Error(err)
	}

	entries, err := walker.Next()
	// The bytes above should not decode to anything useful
	// (because they have an unknown type kind)
	if len(entries) != 0 && err != nil {
		t.Errorf("expected empty entries and non-nil err (got %v entries and %v)", len(entries), err)
	}
	_, err = walker.Next()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

// Test a TxRecord with some trailing bytes
func TestTrailingBytesTxRecord(t *testing.T) {
	buf, _, err := genTxValue(0xfa, []byte{0xff, 0xff, 0xff})
	// Add some trailing bytes to the tx record
	buf = append(buf, byte(0xff))
	buf = append(buf, byte(0xff))
	buf = append(buf, byte(0xff))

	summer := crc32.NewIEEE()
	_, err = summer.Write(buf)
	if err != nil {
		t.Error(err)
	}
	crc32sum := summer.Sum32()

	r, err := genTestCaseHeader(buf, 1, crc32sum)
	if err != nil {
		t.Error(err)
	}

	walker, err := NewReaderWalker(r)
	if err != nil {
		t.Error(err)
	}

	_, err = walker.Next()
	if err != ErrRemainingBytesForRecord {
		t.Error(err)
	}

	_, err = walker.Next()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

// Test that we check for TxRecords that are too big.
// A TxRecord can hold 255 entries, and each of those can be
// up to 16KB.
func TestTooBigTxRecord(t *testing.T) {
	bigValue := make([]byte, math.MaxUint16*math.MaxUint8+4)
	r, err := genTestCaseHeader(bigValue, 1, 0)
	if err != nil {
		t.Error(err)
	}

	walker, err := NewReaderWalker(r)
	if err != nil {
		t.Error(err)
	}

	_, err = walker.Next()
	if err != ErrRecordTooBig {
		t.Errorf("expected ErrRecordTooBig, got %v", err)
	}
}

// Test that we correctly enforce the 255 entry limit of TxGroups.
func TestTxGroupCapacityEnforcement(t *testing.T) {
	l, err := NewLogFile("capacity-enforcement.log")
	if err != nil {
		t.Error(err)
		return
	}
	defer l.Close()
	defer os.Remove("capacity-enforcement.log")

	tx := l.BeginTx()
	if err != nil {
		t.Error(err)
	}

	for i := 0; i <= 255; i++ {
		entry := testValues[i%len(testValues)]
		err = tx.Put(entry)
		if err != nil {
			t.Error(err)
		}
	}

	entry := testValues[0]
	err = tx.Put(entry)
	if err != ErrTxGroupFull {
		t.Error(err)
	}
}
