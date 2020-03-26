// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// Package logtarget implements a multiplexing logging target
package logtarget

import (
	"io"
	"os"
	"sync"
)

// LogTarget implements the io.Writer interface, allowing
// LogTarget to be registered with the regular Go log package.
// LogTarget multiplexes its incoming writes to multiple optional
// output writers, and one main output writer (the log file).
type LogTarget interface {
	io.Writer

	Rotate() error
}

type fileLogTarget struct {
	mu    sync.Mutex
	logfn string
	file  *os.File
}

var Default LogTarget

// OpenFile creates a LogTarget pointing to a log file
// and returns it.
// This method will open the file in append-only mode.
func OpenFile(fileName string) (t LogTarget, err error) {
	target := &fileLogTarget{}
	target.logfn = fileName
	target.file, err = os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0650)
	if err != nil {
		return nil, err
	}
	return target, nil
}

// Write writes a log message to all registered io.Writers
func (target *fileLogTarget) Write(in []byte) (int, error) {
	target.mu.Lock()
	defer target.mu.Unlock()

	if target.file == nil {
		panic("no log file opened")
	}

	n, err := os.Stderr.Write(in)
	if err != nil {
		return n, err
	}

	n, err = target.file.Write(in)
	if err != nil {
		return n, err
	}

	return len(in), nil
}

// Rotate rotates the current log file.
// This method holds a lock while rotating the log file,
// and all log writes will be held back until the rotation
// is complete.
func (target *fileLogTarget) Rotate() error {
	target.mu.Lock()
	defer target.mu.Unlock()

	// Close the existing log file
	err := target.file.Close()
	if err != nil {
		return err
	}

	target.file, err = os.OpenFile(target.logfn, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0650)
	if err != nil {
		return err
	}

	return nil
}
