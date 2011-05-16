// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"grumble/blobstore"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"log"
	"net"
	"sqlite"
	"path/filepath"
	"regexp"
	"rpc"
	"runtime"
	"time"
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
var sqlitedb *string = flag.String("murmurdb", "", "Path to murmur.sqlite to import server structure from")
var cleanup *bool = flag.Bool("clean", false, "Clean up existing data dir content before importing Murmur data")
var gencert *bool = flag.Bool("gencert", false, "Generate a self-signed certificate for use with Grumble")

var servers map[int64]*Server

func Usage() {
	fmt.Fprintf(os.Stderr, "usage: grumble [options]\n")
	fmt.Fprintf(os.Stderr, "remote control: grumble [options] ctl [ctlopts]\n")
	flag.PrintDefaults()
}

func MurmurImport(filename string) (err os.Error) {
	db, err := sqlite.Open(filename)
	if err != nil {
		panic(err.String())
	}

	stmt, err := db.Prepare("SELECT server_id FROM servers")
	if err != nil {
		panic(err.String())
	}

	var serverids []int64
	var sid int64
	for stmt.Next() {
		stmt.Scan(&sid)
		serverids = append(serverids, sid)
	}

	log.Printf("Found servers: %v (%v servers)", serverids, len(serverids))

	for _, sid := range serverids {
		m, err := NewServerFromSQLite(sid, db)
		if err != nil {
			return err
		}

		err = m.FreezeToFile(filepath.Join(*datadir, fmt.Sprintf("%v", sid)))
		if err != nil {
			return err
		}

		log.Printf("Successfully imported server %v", sid)
	}

	return
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

	// Should we import data from a Murmur SQLite file?
	if len(*sqlitedb) > 0 {
		f, err := os.Open(*datadir)
		if err != nil {
			log.Fatalf("Murmur import failed: %s", err.String())
		}
		defer f.Close()

		names, err := f.Readdirnames(-1)
		if err != nil {
			log.Fatalf("Murmur import failed: %s", err.String())
		}

		if !*cleanup && len(names) > 0 {
			log.Fatalf("Non-empty datadir. Refusing to import Murmur data.")
		}
		if *cleanup {
			log.Printf("Cleaning up existing data directory")
			for _, name := range names {
				if err := os.Remove(filepath.Join(*datadir, name)); err != nil {
					log.Fatalf("Unable to cleanup file: %s", name)
				}
			}
		}

		log.Printf("Importing Murmur data from '%s'", *sqlitedb)
		if err = MurmurImport(*sqlitedb); err != nil {
			log.Fatalf("Murmur import failed: %s", err.String())
		}

		log.Printf("Import from Murmur SQLite database succeeded.")
		log.Printf("Please restart Grumble to make use of the imported data.")

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
			s, err := NewServerFromFrozen(filepath.Join(*datadir, name))
			if err != nil {
				log.Fatalf("Unable to load server: %s", err.String())
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
		ticker := time.NewTicker(10e9) // 10 secs
		for {
			select {
			case <-ticker.C:
				for sid, server := range servers {
					err := server.FreezeToFile(filepath.Join(*datadir, fmt.Sprintf("%v", sid)))
					if err != nil {
						log.Printf("Unable to freeze server %v: %s", sid, err.String())
						continue
					}
				}

			case sig := <-signal.Incoming:
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

				return
			}
		}
	}
}
