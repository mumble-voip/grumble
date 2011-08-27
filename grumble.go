// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"flag"
	"fmt"
	"grumble/blobstore"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"rpc"
	"runtime"
)

func defaultGrumbleDir() string {
	dirname := ".grumble"
	if runtime.GOOS == "windows" {
		dirname = "grumble"
	}
	return filepath.Join(os.Getenv("HOME"), dirname)
}

func defaultDataDir() string {
	return filepath.Join(defaultGrumbleDir(), "data")
}

func defaultBlobDir() string {
	return filepath.Join(defaultGrumbleDir(), "blob")
}

func defaultCtlNet() string {
	if runtime.GOOS == "windows" {
		return "tcp"
	}
	return "unix"
}

func defaultCtlAddr() string {
	if runtime.GOOS == "windows" {
		return "localhost:5454"
	}
	return filepath.Join(defaultGrumbleDir(), ".ctl")
}

var help *bool = flag.Bool("help", false, "Show this help")
var datadir *string = flag.String("datadir", defaultDataDir(), "Directory to use for server storage")
var blobdir *string = flag.String("blobdir", defaultBlobDir(), "Directory to use for blob storage")
var ctlnet *string = flag.String("ctlnet", defaultCtlNet(), "Network to use for ctl socket")
var ctladdr *string = flag.String("ctladdr", defaultCtlAddr(), "Address to use for ctl socket")
var gencert *bool = flag.Bool("gencert", false, "Generate a self-signed certificate for use with Grumble")

var servers map[int64]*Server

func Usage() {
	fmt.Fprintf(os.Stderr, "usage: grumble [options]\n")
	fmt.Fprintf(os.Stderr, "remote control: grumble [options] ctl [ctlopts]\n")
	flag.PrintDefaults()
}

func main() {
	var err os.Error

	flag.Parse()
	if *help == true {
		Usage()
		return
	}

	for i, str := range os.Args {
		if str == "ctl" {
			GrumbleCtl(os.Args[i+1:])
			return
		}
	}

	log.SetPrefix("[G] ")
	log.Printf("Grumble")

	log.Printf("Using blob directory: %s", *blobdir)
	err = blobstore.Open(*blobdir, true)
	if err != nil {
		log.Fatalf("Unable to initialize blobstore: %v", err.String())
	}

	// Generate a cert?
	if *gencert {
		certfn := filepath.Join(*datadir, "cert")
		keyfn := filepath.Join(*datadir, "key")
		log.Printf("Generating 2048-bit RSA keypair for self-signed certificate...")

		err := GenerateSelfSignedCert(certfn, keyfn)
		if err != nil {
			log.Printf("Error: %v", err)
			return
		}

		log.Printf("Certificate output to %v", certfn)
		log.Printf("Private key output to %v", keyfn)

		log.Printf("Done generating certificate and private key.")
		log.Printf("Please restart Grumble to make use of the generated certificate and private key.")
		return
	}

	f, err := os.Open(*datadir)
	if err != nil {
		log.Fatalf("Murmur import failed: %s", err.String())
	}
	defer f.Close()

	names, err := f.Readdirnames(-1)
	if err != nil {
		log.Fatalf("Murmur import failed: %s", err.String())
	}

	servers = make(map[int64]*Server)
	for _, name := range names {
		if matched, _ := regexp.MatchString("^[0-9]+$", name); matched {
			log.Printf("Loading server %v", name)
			s, err := NewServerFromFrozen(name)
			if err != nil {
				log.Fatalf("Unable to load server: %v", err)
			}
			err = s.FreezeToFile()
			if err != nil {
				log.Fatalf("Unable to freeze server to disk: %v", err)
			}
			servers[s.Id] = s
			go s.ListenAndMurmur()
		}
	}

	if len(servers) == 0 {
		s, err := NewServer(1, "0.0.0.0", 64738)
		if err != nil {
			log.Fatalf("Couldn't start server: %s", err.String())
		}

		servers[s.Id] = s

		os.Mkdir(filepath.Join(*datadir, fmt.Sprintf("%v", 1)), 0750)
		s.FreezeToFile()

		go s.ListenAndMurmur()
	}

	if *ctlnet == "unix" {
		os.Remove(*ctladdr)
	}
	lis, err := net.Listen(*ctlnet, *ctladdr)
	if err != nil {
		log.Panicf("Unable to listen on ctl socket: %v", err)
	}

	ctl := &ControlRPC{}
	rpc.RegisterName("ctl", ctl)
	go rpc.Accept(lis)

	if len(servers) > 0 {
		go SignalHandler()
		select {}
	}
}
