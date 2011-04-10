// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package blobstore

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

// blobReader is based on the principles of the checksumReader from the archive/zip
// package of the Go standard library.

// ErrHashMismatch is returned if a blobReader has read a file whose computed hash
// did not match its key.
var ErrHashMismatch = os.NewError("hash mismatch")

// blobReader reads a blob from disk, hashing all incoming data. On EOF, it checks
// whether the read data matches the key.
type blobReader struct {
	rc   io.ReadCloser
	sum  []byte
	hash hash.Hash
}

func newBlobReader(rc io.ReadCloser, key string) (br *blobReader, err os.Error) {
	sum, err := hex.DecodeString(key)
	if err != nil {
		return
	}
	return &blobReader{rc, sum, sha1.New()}, nil
}

func (r *blobReader) Read(b []byte) (n int, err os.Error) {
	n, err = r.rc.Read(b)
	r.hash.Write(b[:n])
	if err != os.EOF {
		return
	}
	if !bytes.Equal(r.sum, r.hash.Sum()) {
		err = ErrHashMismatch
	}
	return
}

func (r *blobReader) Close() os.Error {
	return r.rc.Close()
}
