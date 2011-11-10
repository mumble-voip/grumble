// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"fmt"
	"grumble/logtarget"
	"os"
	"os/signal"
)

func SignalHandler() {
	for {
		sig := <-signal.Incoming

		if sig == os.SIGUSR2 {
			err := logtarget.Target.Rotate()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to rotate log file: %v", err)
			}
			continue
		}
	
		if sig == os.SIGINT || sig == os.SIGTERM {
			os.Exit(0)
		}
	}
}
