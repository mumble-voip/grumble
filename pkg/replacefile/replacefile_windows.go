// Copyright (c) 2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package replacefile

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procReplaceFileW = modkernel32.NewProc("ReplaceFileW")
)

// Define the syscall.Errno backed-errors here in order to get a cleaner
// godoc output.
var (
	win32_ERROR_UNABLE_TO_MOVE_REPLACEMENT   = syscall.Errno(0x498)
	win32_ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 = syscall.Errno(0x499)
	win32_ERROR_UNABLE_TO_REMOVE_REPLACED    = syscall.Errno(0x497)
)

var (
	ErrUnableToMoveReplacement  error = win32_ERROR_UNABLE_TO_MOVE_REPLACEMENT
	ErrUnableToMoveReplacement2 error = win32_ERROR_UNABLE_TO_MOVE_REPLACEMENT_2
	ErrUnableToRemoveReplaced   error = win32_ERROR_UNABLE_TO_REMOVE_REPLACED
)

func replaceFileW(replaced *uint16, replacement *uint16, backup *uint16, flags uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procReplaceFileW.Addr(), 6, uintptr(unsafe.Pointer(replaced)), uintptr(unsafe.Pointer(replacement)), uintptr(unsafe.Pointer(backup)), uintptr(flags), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// ReplaceFile calls through to the Win32 ReplaceFile API, which can be found at the following
// URL: http://msdn.microsoft.com/en-us/library/windows/desktop/aa365512(v=vs.85).aspx
func ReplaceFile(replaced string, replacement string, backup string, flags Flag) error {
	replacedPtr, err := syscall.UTF16PtrFromString(replaced)
	if err != nil {
		return err
	}

	replacementPtr, err := syscall.UTF16PtrFromString(replacement)
	if err != nil {
		return err
	}

	backupPtr, err := syscall.UTF16PtrFromString(backup)
	if err != nil {
		return err
	}

	return replaceFileW(replacedPtr, replacementPtr, backupPtr, uint32(flags))
}
