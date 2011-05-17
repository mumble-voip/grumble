// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
)

func SignalHandler() {
	for {
		sig := <-signal.Incoming
		if sig != signal.SIGINT && sig != signal.SIGTERM {
			continue
		}
		for sid, s := range servers {
			err := s.FreezeToFile(filepath.Join(*datadir, fmt.Sprintf("%v", sid)))
			if err != nil {
				log.Printf("Unable to freeze server %v: %s", sid, err.String())
				continue
			}
			log.Printf("Server %v frozen", sid)
		}

		os.Exit(0)
	}
}
