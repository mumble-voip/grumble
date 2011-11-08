// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package freezer

import "errors"

// Writer errors
var (
	ErrTxGroupFull        = errors.New("transction group is full")
	ErrTxGroupValueTooBig = errors.New("value too big to put inside the txgroup")
)

// Walker errors
var (
	ErrUnexpectedEndOfRecord   = errors.New("unexpected end of record")
	ErrCRC32Mismatch           = errors.New("CRC32 mismatch")
	ErrRemainingBytesForRecord = errors.New("remaining bytes in record")
	ErrRecordTooBig            = errors.New("the record in the file is too big")
)
