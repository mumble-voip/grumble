package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type args struct {
	ShowHelp     bool
	DataDir      string
	BlobDir      string
	CtlNet       string
	CtlAddr      string
	GenerateCert bool
	SQLiteDB     string
	CleanUp      bool
}

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

func Usage() {
	fmt.Fprintf(os.Stderr, "usage: grumble [options]\n")
	fmt.Fprintf(os.Stderr, "remote control: grumble [options] ctl [ctlopts]\n")
	flag.PrintDefaults()
}

var Args args

func init() {
	flag.BoolVar(&Args.ShowHelp, "help", false, "Show this help")
	flag.StringVar(&Args.DataDir, "datadir", defaultDataDir(), "Directory to use for server storage")
	flag.StringVar(&Args.BlobDir, "blobdir", defaultBlobDir(), "Directory to use for blob storage")
	flag.StringVar(&Args.CtlNet, "ctlnet", defaultCtlNet(), "Network to use for ctl socket")
	flag.StringVar(&Args.CtlAddr, "ctladdr", defaultCtlAddr(), "Address to use for ctl socket")
	flag.BoolVar(&Args.GenerateCert, "gencert", false, "Generate a self-signed certificate for use with Grumble")

	// SQLite related
	if SQLiteSupport {
		flag.StringVar(&Args.SQLiteDB, "murmurdb", "", "Path to a Murmur SQLite database to import from")
		flag.BoolVar(&Args.CleanUp, "cleanup", false, "Clean up Grumble's data directory on launch")
	}
}
