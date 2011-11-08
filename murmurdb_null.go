// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import "errors"

const SQLiteSupport = false

func MurmurImport(filename string) (err error) {
	return errors.New("no sqlite support built in")
}
