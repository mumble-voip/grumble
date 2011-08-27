// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import "os"

const SQLiteSupport = false

func MurmurImport(filename string) (err os.Error) {
	return os.NewError("no sqlite support built in")
}