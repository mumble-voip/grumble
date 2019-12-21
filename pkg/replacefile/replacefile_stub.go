// Copyright (c) 2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// +build !windows

package replacefile

import (
	"errors"
)

// The different types of errors that can happen if we're not on windows
var (
	errOnlyWindows                    = errors.New("replacefile: only implemented on Windows")
	ErrUnableToMoveReplacement  error = errOnlyWindows
	ErrUnableToMoveReplacement2 error = errOnlyWindows
	ErrUnableToRemoveReplaced   error = errOnlyWindows
)

// ReplaceFile tries to replace the file
func ReplaceFile(replaced string, replacement string, backup string, flags Flag) error {
	return errOnlyWindows
}
