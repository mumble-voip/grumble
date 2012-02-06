// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package blobstore

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"hash"
	"io"
)

// blobReader is based on the principles of the checksumReader from the archive/zip
// package of the Go standard library.

// ErrHashMismatch is returned if a blobReader has read a file whose computed hash
// did not match its key.
var ErrHashMismatch = errors.New("hash mismatch")

// blobReader reads a blob from disk, hashing all incoming data. On EOF, it checks
// whether the read data matches the key.
type blobReader struct {
	rc   io.ReadCloser
	sum  []byte
	hash hash.Hash
}

func newBlobReader(rc io.ReadCloser, key string) (br *blobReader, err error) {
	sum, err := hex.DecodeString(key)
	if err != nil {
		return
	}
	return &blobReader{rc, sum, sha1.New()}, nil
}

func (r *blobReader) Read(b []byte) (n int, err error) {
	n, err = r.rc.Read(b)
	r.hash.Write(b[:n])
	if err != io.EOF {
		return
	}
	if !bytes.Equal(r.sum, r.hash.Sum(nil)) {
		err = ErrHashMismatch
	}
	return
}

func (r *blobReader) Close() error {
	return r.rc.Close()
}
