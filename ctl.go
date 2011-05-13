// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"log"
	"os"
	"path/filepath"
	"rpc"
	"strconv"
)

var CtlUsage = `grumble ctl

	help
		Show this help

	start [id]
		Start a server

	stop [id]
		Stop a server

	setconf [id] [key] [value]
		Set a config value for server with id

	getconf [id] [key] [value]
		Get a config value for server with id
`

func GrumbleCtl(args []string) {
	log.SetFlags(0)

	if len(args) <= 1 || args[0] == "help" {
		log.Printf(CtlUsage)
		return
	}

	sid, _ := strconv.Atoi64(args[1])

	client, err := rpc.Dial("unix", filepath.Join(os.Getenv("HOME"), ".grumble", "ctl"))
	if err != nil {
		log.Fatalf("Could not connect to control socket: %v", err)
	}

	switch args[0] {
	case "start":
		err := client.Call("ctl.Start", sid, nil)
		if err != nil {
			log.Fatalf("Unable to start: %v", err)
		}
		log.Printf("[%v] Started", sid)
	case "stop":
		err := client.Call("ctl.Stop", sid, nil)
		if err != nil {
			log.Fatalf("Unable to stop: %v", err)
		}
		log.Printf("[%v] Stopped", sid)
	case "setconf":
		if len(args) < 4 {
			return
		}
		result := &ConfigValue{}
		err := client.Call("ctl.SetConfig", &ConfigValue{sid, args[2], args[3]}, result)
		if err != nil {
			log.Fatalf("Unable to set config: %v", err)
		}
		log.Printf("[%v] %v=%v", result.Id, result.Key, result.Value)
	case "getconf":
		if len(args) < 3 {
			return
		}
		result := &ConfigValue{}
		err := client.Call("ctl.GetConfig", &ConfigValue{sid, args[2], ""}, result)
		if err != nil {
			log.Fatalf("Unable to get config: %v", err)
		}
		log.Printf("[%v] %v=%v", result.Id, result.Key, result.Value)
	}
}
