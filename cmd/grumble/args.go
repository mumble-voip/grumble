package main

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"text/template"
)

type UsageArgs struct {
	Version        string
	BuildDate      string
	OS             string
	Arch           string
	DefaultDataDir string
}

var usageTmpl = `usage: grumble [options]

 grumble {{.Version}} ({{.BuildDate}})
 target: {{.OS}}, {{.Arch}}

 --help, --version
     Shows this help listing.

 --datadir <data-dir> (default: {{.DefaultDataDir}})
     Directory to use for server storage.

 --log <log-path> (default: $DATADIR/grumble.log)
     Log file path.

 --ini <config-path> (default: $DATADIR/grumble.ini)
     Config file path.

 --supw <password> [server-id]
     Set password for SuperUser account. Optionally takes
     the virtual server to modify as the first positional argument.

 --readsupw [server-id]
     Like --supw, but reads from stdin instead.

 --disablesu [server-id]
     Disables the SuperUser account. Optionally takes
     the virtual server to modify as the first positional argument.

 --regen-keys
     Force grumble to regenerate its global RSA
     keypair (and certificate).

     The global keypair lives in the root of the
     grumble data directory.

 --import-murmurdb <murmur-sqlite-path>
     Import a Murmur SQLite database into grumble.

     Use the --cleanup argument to force grumble to
     clean up its data directory when doing the
     import. This is *DESTRUCTIVE*! Use with care.
`

type args struct {
	ShowHelp    bool
	DataDir     string
	LogPath     string
	ConfigPath  string
	SuperUserPW string
	ReadPass    bool
	DisablePass bool
	RegenKeys   bool
	ServerId    int64
	SQLiteDB    string
	CleanUp     bool
}

func defaultDataDir() string {
	homedir := os.Getenv("HOME")
	dirname := ".grumble"
	if runtime.GOOS == "windows" {
		homedir = os.Getenv("USERPROFILE")
	}
	return filepath.Join(homedir, dirname)
}

func Usage() {
	t, err := template.New("usage").Parse(usageTmpl)
	if err != nil {
		panic("unable to parse usage template")
	}

	err = t.Execute(os.Stdout, UsageArgs{
		Version:        version,
		BuildDate:      buildDate,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		DefaultDataDir: defaultDataDir(),
	})
	if err != nil {
		panic("unable to execute usage template")
	}
}

var Args args

func init() {
	flag.Usage = Usage

	flag.BoolVar(&Args.ShowHelp, "version", false, "")
	flag.BoolVar(&Args.ShowHelp, "help", false, "")

	flag.StringVar(&Args.DataDir, "datadir", defaultDataDir(), "")
	flag.StringVar(&Args.LogPath, "log", "", "")
	flag.StringVar(&Args.ConfigPath, "ini", "", "")

	flag.StringVar(&Args.SuperUserPW, "supw", "", "")
	flag.BoolVar(&Args.ReadPass, "readsupw", false, "")
	flag.BoolVar(&Args.DisablePass, "disablesu", false, "")

	flag.BoolVar(&Args.RegenKeys, "regen-keys", false, "")

	flag.StringVar(&Args.SQLiteDB, "import-murmurdb", "", "")
	flag.BoolVar(&Args.CleanUp, "cleanup", false, "")
}
