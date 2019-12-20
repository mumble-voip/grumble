// Copyright (c) 2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/golang/protobuf/proto"
	"mumble.info/grumble/pkg/replacefile"
)

func (server *Server) freezeToFile() (err error) {
	// Close the log file, if it's open
	if server.freezelog != nil {
		err = server.freezelog.Close()
		if err != nil {
			return err
		}
		server.freezelog = nil
	}

	// Make sure the whole server is synced to disk
	fs, err := server.Freeze()
	if err != nil {
		return err
	}
	f, err := ioutil.TempFile(filepath.Join(Args.DataDir, "servers", strconv.FormatInt(server.Id, 10)), ".main.fz_")
	if err != nil {
		return err
	}
	buf, err := proto.Marshal(fs)
	if err != nil {
		return err
	}
	_, err = f.Write(buf)
	if err != nil {
		return err
	}
	err = f.Sync()
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}

	src := f.Name()
	dst := filepath.Join(Args.DataDir, "servers", strconv.FormatInt(server.Id, 10), "main.fz")
	backup := filepath.Join(Args.DataDir, "servers", strconv.FormatInt(server.Id, 10), "backup.fz")

	err = replacefile.ReplaceFile(dst, src, backup, replacefile.Flag(0))
	// If the dst file does not exist (as in, on first launch)
	// fall back to os.Rename. ReplaceFile does not work if the
	// dst file is not there.
	if os.IsNotExist(err) {
		err = os.Rename(src, dst)
		if err != nil {
			return err
		}
	}

	return nil
}
