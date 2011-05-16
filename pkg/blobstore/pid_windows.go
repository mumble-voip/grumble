// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package blobstore

import (
	"syscall"
)

func getPid() uint64 {
	handle, _ := syscall.GetCurrentProcess()
	return uint64(handle)
}

func pidRunning(pid uint64) bool {
	var status uint32
	syscall.GetExitCodeProcess(uint32(pid), &status)
	return status == 259 // STILL_ACTIVE 
}
