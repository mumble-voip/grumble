// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"os"
	"os/signal"
)

func SignalHandler() {
	for {
		sig := <-signal.Incoming
		if sig != os.SIGINT && sig != os.SIGTERM {
			continue
		}
		os.Exit(0)
	}
}
