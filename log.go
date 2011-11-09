package main

import (
	"bytes"
	"os"
	"sync"
)

type logTarget struct {
	mu       sync.Mutex
	logfn    string
	file     *os.File
	memLog   *bytes.Buffer
}

var LogTarget logTarget

func (target *logTarget) Write(in []byte) (int, error) {
	target.mu.Lock()
	defer target.mu.Unlock()

	return target.file.Write(in)
}

// Open a log file for writing.
// This method will open the file in append-only mode.
func (target *logTarget) OpenFile(fn string) (err error) {
	target.logfn = fn
	target.file, err = os.OpenFile(target.logfn, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0650)
	if err != nil {
		return err
	}
	return nil
}

// Perform a log rotation
func (target *logTarget) Rotate() error {
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
