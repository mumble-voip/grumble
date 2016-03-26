// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// Package logtarget implements a multiplexing logging target
package logtarget

import (
	"bytes"
	"os"
	"sync"
)

// LogTarget implements the io.Writer interface, allowing
// LogTarget to be registered with the regular Go log package.
// LogTarget multiplexes its incoming writes to multiple optional
// output writers, and one main output writer (the log file).
type LogTarget struct {
	mu     sync.Mutex
	logfn  string
	file   *os.File
	memLog *bytes.Buffer
}

var Target LogTarget

// Write writes a log message to all registered io.Writers
func (target *LogTarget) Write(in []byte) (int, error) {
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

// OpenFile opens the main log file for writing.
// This method will open the file in append-only mode.
func (target *LogTarget) OpenFile(fn string) (err error) {
	target.logfn = fn
	target.file, err = os.OpenFile(target.logfn, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0650)
	if err != nil {
		return err
	}
	return nil
}

// Rotate rotates the current log file.
// This method holds a lock while rotating the log file,
// and all log writes will be held back until the rotation
// is complete.
func (target *LogTarget) Rotate() error {
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
