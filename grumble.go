// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"flag"
	"fmt"
	"grumble/blobstore"
	"grumble/logtarget"
	"log"
	"os"
	"path/filepath"
	"regexp"
)

var servers map[int64]*Server

func main() {
	var err error

	flag.Parse()
	if Args.ShowHelp == true {
		Usage()
		return
	}

	err = logtarget.Target.OpenFile(Args.LogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open log file: %v", err)
		return
	}

	log.SetPrefix("[G] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(&logtarget.Target)

	log.Printf("Grumble")
	log.Printf("Using data directory: %s", Args.DataDir)

	// Open the blobstore
	blobDir := filepath.Join(Args.DataDir, "blob")
	err = os.Mkdir(blobDir, 0700)
	if err != nil {
		exists := false
		if e, ok := err.(*os.PathError); ok {
			if e.Err == os.EEXIST {
				exists = true	
			}
		}
		if !exists {
			log.Fatal("Unable to create blob directory: %v", err.Error())
		}
	}
	err = blobstore.Open(blobDir)
	if err != nil {
		log.Fatalf("Unable to initialize blobstore: %v", err.Error())
	}

	certFn := filepath.Join(Args.DataDir, "cert")
	keyFn := filepath.Join(Args.DataDir, "key")
	shouldRegen := false
	if Args.RegenKeys {
		shouldRegen = true
	} else {
		files := []string{certFn, keyFn}
		for _, fn := range files {
			_, err := os.Stat(fn)
			if err != nil {
				if e, ok := err.(*os.PathError); ok {
					if e.Err == os.ENOENT {
						shouldRegen = true
					}
				}
			}
		}
	}
	if shouldRegen {
		log.Printf("Generating 4096-bit RSA keypair for self-signed certificate...")

		err := GenerateSelfSignedCert(certFn, keyFn)
		if err != nil {
			log.Printf("Error: %v", err)
			return
		}

		log.Printf("Certificate output to %v", certFn)
		log.Printf("Private key output to %v", keyFn)
	}

	// Should we import data from a Murmur SQLite file?
	if SQLiteSupport && len(Args.SQLiteDB) > 0 {
		f, err := os.Open(Args.DataDir)
		if err != nil {
			log.Fatalf("Murmur import failed: %s", err.Error())
		}
		defer f.Close()

		names, err := f.Readdirnames(-1)
		if err != nil {
			log.Fatalf("Murmur import failed: %s", err.Error())
		}

		if !Args.CleanUp && len(names) > 0 {
			log.Fatalf("Non-empty datadir. Refusing to import Murmur data.")
		}
		if Args.CleanUp {
			log.Print("Cleaning up existing data directory")
			for _, name := range names {
				if err := os.RemoveAll(filepath.Join(Args.DataDir, name)); err != nil {
					log.Fatalf("Unable to cleanup file: %s", name)
				}
			}
		}

		log.Printf("Importing Murmur data from '%s'", Args.SQLiteDB)
		if err = MurmurImport(Args.SQLiteDB); err != nil {
			log.Fatalf("Murmur import failed: %s", err.Error())
		}

		log.Printf("Import from Murmur SQLite database succeeded.")
		log.Printf("Please restart Grumble to make use of the imported data.")

		return
	}

	f, err := os.Open(Args.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	names, err := f.Readdirnames(-1)
	if err != nil {
		log.Fatal(err)
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
			log.Fatalf("Couldn't start server: %s", err.Error())
		}

		servers[s.Id] = s

		os.Mkdir(filepath.Join(Args.DataDir, fmt.Sprintf("%v", 1)), 0750)
		s.FreezeToFile()
		go s.ListenAndMurmur()
	}

	go RunSSH()

	if len(servers) > 0 {
		go SignalHandler()
		select {}
	}
}