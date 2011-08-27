// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package freezer

import "os"

// Writer errors
var (
	ErrTxGroupFull = os.NewError("transction group is full")
	ErrTxGroupValueTooBig = os.NewError("value too big to put inside the txgroup")
)

// Walker errors
var (
	ErrUnexpectedEndOfRecord = os.NewError("unexpected end of record")
	ErrCRC32Mismatch = os.NewError("CRC32 mismatch")
	ErrRemainingBytesForRecord = os.NewError("remaining bytes in record")
	ErrRecordTooBig = os.NewError("the record in the file is too big")
)