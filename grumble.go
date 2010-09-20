// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"flag"
	"fmt"
	"os"
)

var help *bool = flag.Bool("help", false, "Show this help")
var port *int = flag.Int("port", 64738, "Default port to listen on")
var host *string = flag.String("host", "0.0.0.0", "Default host to listen on")

func usage() {
	fmt.Fprintf(os.Stderr, "usage: grumble [options]\n")
	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	if *help == true {
		usage()
		return
	}

	// Create our default server
	m, err := NewServer(*host, *port)
	if err != nil {
		return
	}

	// And launch it.
	go m.ListenAndMurmur()

	// Listen forever
	sleeper := make(chan int)
	zzz := <-sleeper
	if zzz > 0 {
	}
}
