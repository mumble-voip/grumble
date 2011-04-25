// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"blobstore"
	"compress/gzip"
	"flag"
	"fmt"
	"gob"
	"io"
	"io/ioutil"
	"os"
	"log"
	"sqlite"
	"path/filepath"
	"regexp"
	"time"
)

var help *bool = flag.Bool("help", false, "Show this help")
var port *int = flag.Int("port", 64738, "Default port to listen on")
var host *string = flag.String("host", "0.0.0.0", "Default host to listen on")
var datadir *string = flag.String("datadir", "", "Directory to use for server storage")
var blobdir *string = flag.String("blobdir", "", "Directory to use for blob storage")
var sqlitedb *string = flag.String("murmurdb", "", "Path to murmur.sqlite to import server structure from")
var cleanup *bool = flag.Bool("clean", false, "Clean up existing data dir content before importing Murmur data")

var globalBlobstore *blobstore.BlobStore

func Usage() {
	fmt.Fprintf(os.Stderr, "usage: grumble [options]\n")
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

	var servers []int64
	var sid int64
	for stmt.Next() {
		stmt.Scan(&sid)
		servers = append(servers, sid)
	}

	log.Printf("Found servers: %v (%v servers)", servers, len(servers))

	for _, sid := range servers {
		m, err := NewServerFromSQLite(sid, db)
		if err != nil {
			return err
		}

		f, err := os.Create(filepath.Join(*datadir, fmt.Sprintf("%v", sid)))
		if err != nil {
			return err
		}

		zf, err := gzip.NewWriterLevel(f, gzip.BestCompression)

		fz, err := m.Freeze()
		if err != nil {
			return err
		}

		enc := gob.NewEncoder(zf)
		err = enc.Encode(fz)
		if err != nil {
			return err
		}

		zf.Close()
		f.Close()

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

	log.Printf("Grumble - Mumble server written in Go")

	if len(*datadir) == 0 {
		*datadir = filepath.Join(os.Getenv("HOME"), ".grumble", "data")
	}
	log.Printf("Using data directory: %s", *datadir)

	if len(*blobdir) == 0 {
		*blobdir = filepath.Join(os.Getenv("HOME"), ".grumble", "blob")
	}

	log.Printf("Using blob directory: %s", *blobdir)
	globalBlobstore, err = blobstore.NewBlobStore(*blobdir, true)
	if err != nil {
		log.Fatalf("Unable to initialize blobstore: %v", err.String())
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

	servers := make(map[int64]*Server)
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

	if len(servers) > 0 {
		ticker := time.NewTicker(10e9) // 10 secs
		for {
			select {
			case <-ticker.C:
				for sid, server := range servers {
					r := server.FreezeServer()
					if err != nil {
						log.Panicf("Unable to freeze server %v", sid)
					}
					f, err := ioutil.TempFile(*datadir, fmt.Sprintf("%v_", sid))
					if err != nil {
						log.Panicf("Unable to open file: %", err.String())
					}
					nwritten, err := io.Copy(f, r)
					if err != nil {
						log.Panicf("Unable to copy frozen server data: %v bytes, err=%v", nwritten, err)
					}
					err = r.Close()
					if err != nil {
						log.Panicf("Unable to freeze server: %v", err)
					}
					err = f.Sync()
					if err != nil {
						log.Panicf("Unable to sync frozen file: %v", err)
					}
					err = f.Close()
					if err != nil {
						log.Panicf("Unable to freeze server: %v", err)
					}
					err = os.Rename(f.Name(), filepath.Join(*datadir, fmt.Sprintf("%v", sid)))
					if err != nil {
						log.Panicf("Unable to freeze server: %v", err)
					}
				}
			}
		}
	}
}
