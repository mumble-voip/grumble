// Copyright (c) 2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// +build !windows

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/golang/protobuf/proto"
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
	err = os.Rename(f.Name(), filepath.Join(Args.DataDir, "servers", strconv.FormatInt(server.Id, 10), "main.fz"))
	if err != nil {
		return err
	}

	return nil
}
