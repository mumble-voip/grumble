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

	// Open the data dir.  We need it later for looking up
	// the virtual server folders in the data dir.
	// We need it now to make sure the data dir actually exists.
	dataDir, err := os.Open(Args.DataDir)
	if err != nil {
		log.Fatalf("Unable to open data directory: %v", err)
		return
	}

	// Open the blobstore.  If the directory doesn't
	// already exist, create the directory and open
	// the blobstore.
	// The Open method of the blobstore performs simple
	// sanity checking of content of the blob directory,
	// and will return an error if something's amiss.
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

	// Check whether we should regenerate the default global keypair
	// and corresponding certificate.
	// These are used as the default certificate of all virtual servers
	// and the SSH admin console, but can be overridden using the "key"
	// and "cert" arguments to Grumble.
	certFn := filepath.Join(Args.DataDir, "cert.pem")
	keyFn := filepath.Join(Args.DataDir, "key.pem")
	shouldRegen := false
	if Args.RegenKeys {
		shouldRegen = true
	} else {
		// OK. Here's the idea:  We check for the existence of the cert.pem
		// and key.pem files in the data directory on launch. Although these
		// might be deleted later (and this check could be deemed useless),
		// it's simply here to be convenient for admins.
		hasKey := true
		hasCert := true
		_, err = os.Stat(certFn)
		if err != nil {
			if e, ok := err.(*os.PathError); ok {
				if e.Err == os.ENOENT {
					hasCert = false
				}
			}
		}
		_, err = os.Stat(keyFn)
		if err != nil {
			if e, ok := err.(*os.PathError); ok {
				if e.Err == os.ENOENT {
					hasKey = false
				}
			}
		}
		if !hasCert && !hasKey {
			shouldRegen = true
		} else if !hasCert || !hasKey {
			if !hasCert {
				log.Fatal("Grumble could not find its default certificate (cert.pem)")
			}
			if !hasKey {
				log.Fatal("Grumble could not find its default private key (key.pem)")
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

	// Run the SSH admin console.
	RunSSH()

	// Read all entries of the data directory.
	// We need these to load our virtual servers.
	names, err := dataDir.Readdirnames(-1)
	if err != nil {
		log.Fatal("Unable to read file from data directory: %v", err.Error())
	}
	// The data dir file descriptor.
	err = dataDir.Close()
	if err != nil {
		log.Fatalf("Unable to close data directory: %v", err.Error())
		return
	}

	// Look through the list of files in the data directory, and
	// load all virtual servers from disk.
	servers = make(map[int64]*Server)
	for _, name := range names {
		if matched, _ := regexp.MatchString("^[0-9]+$", name); matched {
			log.Printf("Loading server %v", name)
			s, err := NewServerFromFrozen(name)
			if err != nil {
				log.Fatalf("Unable to load server: %v", err.Error())
			}
			err = s.FreezeToFile()
			if err != nil {
				log.Fatalf("Unable to freeze server to disk: %v", err.Error())
			}
			servers[s.Id] = s
			err = s.Start()
			if err != nil {
				log.Printf("Unable to start server %v: %v", s.Id, err.Error())
			}
		}
	}

	// If no servers were found, create the default virtual server.
	if len(servers) == 0 {
		s, err := NewServer(1)
		if err != nil {
			log.Fatalf("Couldn't start server: %s", err.Error())
		}

		servers[s.Id] = s
		os.Mkdir(filepath.Join(Args.DataDir, fmt.Sprintf("%v", 1)), 0750)
		err = s.FreezeToFile()
		if err != nil {
			log.Fatalf("Unable to freeze newly created server to disk: %v", err.Error())
		}
		err = s.Start()
		if err != nil {
			log.Fatal("Unable to start newly created server: %v", err.Error())
		}
	}

	// If any servers were loaded, launch the signal
	// handler goroutine and sleep...
	if len(servers) > 0 {
		go SignalHandler()
		select {}
	}
}
