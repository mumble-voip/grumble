// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"mumble.info/grumble/pkg/blobstore"
	"mumble.info/grumble/pkg/logtarget"
	"mumble.info/grumble/pkg/serverconf"
)

var servers map[int64]*Server
var blobStore blobstore.BlobStore
var configFile *serverconf.ConfigFile

func main() {
	var err error

	flag.Parse()
	if Args.ShowHelp == true {
		Usage()
		return
	}
	if Args.ReadPass {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Failed to read password from stdin: %v", err)
		}
		Args.SuperUserPW = string(data)
	}
	if flag.NArg() > 0 && (Args.SuperUserPW != "" || Args.DisablePass) {
		Args.ServerId, err = strconv.ParseInt(flag.Arg(0), 10, 64)
		if err != nil {
			log.Fatalf("Failed to parse server id %v: %v", flag.Arg(0), err)
			return
		}
	}

	// Open the data dir to check whether it exists.
	dataDir, err := os.Open(Args.DataDir)
	if err != nil {
		log.Fatalf("Unable to open data directory (%v): %v", Args.DataDir, err)
		return
	}
	dataDir.Close()

	// Open the config file
	var configFn string
	if Args.ConfigPath != "" {
		configFn = Args.ConfigPath
	} else {
		configFn = filepath.Join(Args.DataDir, "grumble.ini")
	}
	if filepath.Ext(configFn) == ".ini" {
		// Create it if it doesn't exist
		configFd, err := os.OpenFile(configFn, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
		if err == nil {
			configFd.WriteString(serverconf.DefaultConfigFile)
			log.Fatalf("Default config written to %v\n", configFn)
			configFd.Close()
		} else if err != nil && !os.IsExist(err) {
			log.Fatalf("Unable to open config file (%v): %v", configFn, err)
			return
		}
	}
	configFile, err = serverconf.NewConfigFile(configFn)
	if err != nil {
		log.Fatalf("Unable to open config file (%v): %v", configFn, err)
		return
	}
	config := configFile.GlobalConfig()

	// Set up logging
	var logFn string
	if Args.LogPath != "" {
		logFn = Args.LogPath
	} else {
		logFn = config.PathValue("logfile", Args.DataDir)
	}
	logtarget.Default, err = logtarget.OpenFile(Args.LogPath, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open log file (%v): %v", logFn, err)
		return
	}
	log.SetPrefix("[G] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(logtarget.Default)
	log.Printf("Grumble")
	log.Printf("Using data directory: %s", Args.DataDir)

	// Warn on some unsupported configuration options for users migrating from Murmur
	if config.StringValue("database") != "" {
		log.Println("* Grumble does not yet support Murmur databases directly (see issue #21 on github).")
		if driver := config.StringValue("dbDriver"); driver == "QSQLITE" {
			log.Println("  To convert a previous SQLite database, use the --import-murmurdb flag.")
		}
	}
	if config.StringValue("sslDHParams") != "" {
		log.Println("* Go does not implement DHE modes in TLS, so the configured dhparams are ignored.")
	}
	if config.StringValue("ice") != "" {
		log.Println("* Grumble does not support ZeroC ICE.")
	}
	if config.StringValue("grpc") != "" {
		log.Println("* Grumble does not yet support gRPC (see issue #23 on github).")
	}

	// Open the blobstore.  If the directory doesn't
	// already exist, create the directory and open
	// the blobstore.
	// The Open method of the blobstore performs simple
	// sanity checking of content of the blob directory,
	// and will return an error if something's amiss.
	blobDir := filepath.Join(Args.DataDir, "blob")
	err = os.Mkdir(blobDir, 0700)
	if err != nil && !os.IsExist(err) {
		log.Fatalf("Unable to create blob directory (%v): %v", blobDir, err)
	}
	blobStore = blobstore.Open(blobDir)

	// Check whether we should regenerate the default global keypair
	// and corresponding certificate.
	// These are used as the default certificate of all virtual servers.
	certFn := config.PathValue("sslCert", Args.DataDir)
	keyFn := config.PathValue("sslKey", Args.DataDir)
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
		if err != nil && os.IsNotExist(err) {
			hasCert = false
		}
		_, err = os.Stat(keyFn)
		if err != nil && os.IsNotExist(err) {
			hasKey = false
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

	// Create the servers directory if it doesn't already
	// exist.
	serversDirPath := filepath.Join(Args.DataDir, "servers")
	err = os.Mkdir(serversDirPath, 0700)
	if err != nil && !os.IsExist(err) {
		log.Fatalf("Unable to create servers directory: %v", err)
	}

	// Read all entries of the servers directory.
	// We need these to load our virtual servers.
	serversDir, err := os.Open(serversDirPath)
	if err != nil {
		log.Fatalf("Unable to open the servers directory: %v", err.Error())
	}
	names, err := serversDir.Readdirnames(-1)
	if err != nil {
		log.Fatalf("Unable to read file from data directory: %v", err.Error())
	}
	// The servers dir file descriptor.
	err = serversDir.Close()
	if err != nil {
		log.Fatalf("Unable to close servers directory: %v", err.Error())
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

			// Check if SuperUser password should be updated.
			if Args.ServerId == 0 || Args.ServerId == s.Id {
				if Args.DisablePass {
					s.cfg.Reset("SuperUserPassword")
					log.Printf("Disabled SuperUser for server %v", name)
				} else if Args.SuperUserPW != "" {
					s.SetSuperUserPassword(Args.SuperUserPW)
					log.Printf("Set SuperUser password for server %v", name)
				}
			}

			err = s.FreezeToFile()
			if err != nil {
				log.Fatalf("Unable to freeze server to disk: %v", err.Error())
			}
			servers[s.Id] = s
		}
	}

	// If SuperUser password flags were passed, the servers should not start.
	if Args.SuperUserPW != "" || Args.DisablePass {
		if len(servers) == 0 {
			log.Fatalf("No servers found to set password for")
		}
		return
	}

	// If no servers were found, create the default virtual server.
	if len(servers) == 0 {
		s, err := NewServer(1, configFile.ServerConfig(1, nil))
		if err != nil {
			log.Fatalf("Couldn't start server: %s", err.Error())
		}

		servers[s.Id] = s
		os.Mkdir(filepath.Join(serversDirPath, fmt.Sprintf("%v", 1)), 0750)
		err = s.FreezeToFile()
		if err != nil {
			log.Fatalf("Unable to freeze newly created server to disk: %v", err.Error())
		}
	}

	// Launch the servers we found during launch...
	for _, server := range servers {
		err = server.Start()
		if err != nil {
			log.Printf("Unable to start server %v: %v", server.Id, err.Error())
		}
	}

	// If any servers were loaded, launch the signal
	// handler goroutine and sleep...
	if len(servers) > 0 {
		go SignalHandler()
		select {}
	}
}
