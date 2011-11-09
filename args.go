package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type args struct {
	ShowHelp  bool
	DataDir   string
	LogPath   string
	SshAddr   string
	RegenKeys bool
	SQLiteDB  string
	CleanUp   bool
}

func defaultDataDir() string {
	dirname := ".grumble"
	if runtime.GOOS == "windows" {
		dirname = "grumble"
	}
	return filepath.Join(os.Getenv("HOME"), dirname)
}

func defaultLogPath() string {
	return filepath.Join(defaultDataDir(), "grumble.log")
}

func Usage() {
	fmt.Fprintf(os.Stderr, "usage: grumble [options]\n")
	flag.PrintDefaults()
}

var Args args

func init() {
	flag.BoolVar(&Args.ShowHelp, "help", false, "Show this help listing")
	flag.StringVar(&Args.DataDir, "datadir", defaultDataDir(), "Directory to use for server storage")
	flag.StringVar(&Args.LogPath, "log", defaultLogPath(), "Log file path")
	flag.StringVar(&Args.SshAddr, "ssh", "localhost:46545", "Address to use for SSH admin prompt")
	flag.BoolVar(&Args.RegenKeys, "regenkeys", false, "Force Grumble to regenerate its global RSA keypair and certificate")

	// SQLite related
	if SQLiteSupport {
		flag.StringVar(&Args.SQLiteDB, "murmurdb", "", "Path to a Murmur SQLite database to import from")
		flag.BoolVar(&Args.CleanUp, "cleanup", false, "Clean up Grumble's data directory on launch")
	}
}
