// Copyright (c) 2011-2013 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package blobstore

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"io"
)

// EOFHashMismatchError signals that a blobReader reached EOF, but that
// the calculated hash did not match the given blob key. This signals
// a successful read of the blob, but that the on-disk content is
// corrupted in some fashion.
type EOFHashMismatchError struct {
	// Sum represents that was calculated during the read operation.
	Sum []byte
}

func (hme EOFHashMismatchError) Error() string {
	return "blobstore: EOF hash mismatch"
}

// blobReader implements an io.ReadCloser that reads a blob from disk
// and hashes all incoming data to ensure integrity. On EOF, it matches
// its calculated hash with the given blob key in order to detect data
// corruption.
//
// If a mismatch is detected on EOF, the blobReader will return
// the error ErrEOFHashMismatch instead of a regular io.EOF error.
type blobReader struct {
	rc   io.ReadCloser
	sum  []byte
	hash hash.Hash
}

// newBlobReader returns a new blobReader reading from rc.
// The rc is expected to be a blobstore entry identified by
// the given key. (The blobstore is content addressible, and
// a blob's key represents the SHA1 of its content).
func newBlobReader(rc io.ReadCloser, key string) (*blobReader, error) {
	sum, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return &blobReader{rc, sum, sha1.New()}, nil
}

// Read implements the Read method of io.ReadCloser.
// This Read implementation passes on read calls to the
// wrapper io.ReadCloser and hashes all read content.
// When EOF is reached, the sum of the streaming hash
// hash is calculated and compared to the blob key given
// in newBlobReader. If the calculated hash does not match
// the blob key, the special error ErrEOFHashMismatch is
// returned to signal EOF, while also signalling a hash
// mismatch.
func (r *blobReader) Read(b []byte) (int, error) {
	n, err := r.rc.Read(b)
	_, werr := r.hash.Write(b[:n])
	if werr != nil {
		return 0, werr
	}
	if err != io.EOF {
		return n, err
	}
	// Match the calculated digest with the expected
	// digest on EOF.
	calcSum := r.hash.Sum(nil)
	if !bytes.Equal(r.sum, calcSum) {
		return 0, EOFHashMismatchError{Sum: calcSum}
	}
	return n, io.EOF
}

// Close implements the Close method of io.ReadCloser.
// This Close method simply closes the wrapped io.ReadCloser.
func (r *blobReader) Close() error {
	return r.rc.Close()
}
