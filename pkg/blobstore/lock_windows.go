// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package blobstore

import (
	"os"
	"syscall"
)

const (
	FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
)

// Acquire a lockfile at path.
func AcquireLockFile(path string) os.Error {
	handle, _ := syscall.CreateFile(syscall.StringToUTF16Ptr(path), syscall.GENERIC_WRITE, 0, nil, syscall.CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, 0)
	if handle < 0 {
		return ErrLocked
	}
	return nil
}

// Release the lockfile at path.
func ReleaseLockFile(path string) os.Error {
	// No-op because we use FLAG_DELETE_ON_CLOSE.
	return nil
}
