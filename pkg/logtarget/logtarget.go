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

// logTarget is the default implementation of a log
// target. It can write to more than one writer at the same time
// but only rotate one file
type logTarget struct {
	mu    sync.Mutex
	logfn string
	file  *os.File
	w     io.Writer
	ws    []io.Writer
}

// Default is the default log target for the application
// It has to be initialized before used
var Default LogTarget

// OpenWriters returns a log target that will
// log to all the given writers at the same time
func OpenWriters(ws ...io.Writer) LogTarget {
	target := &logTarget{}
	target.w = io.MultiWriter(ws...)
	return target
}

// OpenFile creates a LogTarget pointing to a log file
// and returns it.
// This method will open the file in append-only mode.
// It also takes a variable number of writers that are
// other log targets
func OpenFile(fileName string, ws ...io.Writer) (t LogTarget, err error) {
	target := &logTarget{}
	target.logfn = fileName
	target.file, err = os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0650)
	if err != nil {
		return nil, err
	}
	target.ws = ws
	target.w = io.MultiWriter(append(ws, target.file)...)
	return target, nil
}

// Write writes a log message to all registered io.Writers
func (target *logTarget) Write(out []byte) (int, error) {
	target.mu.Lock()
	defer target.mu.Unlock()

	return target.w.Write(out)
}

// Rotate rotates the current log file, if one is opened.
// This method holds a lock while rotating the log file,
// and all log writes will be held back until the rotation
// is complete.
func (target *logTarget) Rotate() error {
	target.mu.Lock()
	defer target.mu.Unlock()

	if target.file == nil {
		return nil
	}

	// Close the existing log file
	err := target.file.Close()
	if err != nil {
		return err
	}

	target.file, err = os.OpenFile(target.logfn, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0650)
	if err != nil {
		return err
	}
	target.w = io.MultiWriter(append(target.ws, target.file)...)

	return nil
}
