// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// +build darwin freebsd linux netbsd openbsd

package main

import (
	"fmt"
	"github.com/mumble-voip/grumble/pkg/logtarget"
	"os"
	"os/signal"
	"syscall"
)

func SignalHandler() {
	sigchan := make(chan os.Signal, 10)
	signal.Notify(sigchan, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGINT)
	for sig := range sigchan {
		if sig == syscall.SIGUSR2 {
			err := logtarget.Target.Rotate()
			if err != nil {
				fmt.Fprintf(os.Stderr, "unable to rotate log file: %v", err)
			}
			continue
		}
		if sig == syscall.SIGINT || sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}
}
