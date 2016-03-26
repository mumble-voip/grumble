// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// This package implements a simple disk-persisted content-addressed blobstore.
package blobstore

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	// ErrNoSuchKey signals that a blob with the given key does
	// not exist in the BlobStore.
	ErrNoSuchKey = errors.New("blobstore: no such key")

	// ErrBadKey signals that the given key is not well formed.
	ErrBadKey = errors.New("blobstore: bad key")
)

// BlobStore represents a simple disk-persisted content addressible
// blob store that uses the file system for persistence.
//
// Blobs in the blobstore are indexed by their SHA1 hash.
//
// The BlobStore is backed by a directory on the filesystem. This
// directory contains subdirectories which contain keys (SHA1 hashes).
// Each subdirectory is named according to the first hex-encoded byte
// of the keys that subdirectory contains.
//
// For example, a file that has the content 'hello world' will have
// the SHA1 hash '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed'. If our
// blobstore's backing directory is called 'blobstore', the blob with
// only 'hello world' in it will be stored as follows:
//
//     blobstore/2a/2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
//
// The BlobStore is self-synchronizing, relying on the filesystem
// operations to ensure atomicity. Thus, accessing a single BlobStore
// from multiple goroutines should have no ill side effects.
type BlobStore struct {
	dir string
}

// Open opens an existing BlobStore. The path parameter must
// point to a directory that already exists for correct
// operation, however, the Open function does not check that
// this is the case.
func Open(path string) BlobStore {
	return BlobStore{dir: path}
}

// isValidKey checks whether key is a valid BlobStore key.
func isValidKey(key string) bool {
	// SHA1 digests are 40 bytes long when hex-encoded.
	if len(key) != 40 {
		return false
	}

	// Check whether the string is valid hex-encoding.
	_, err := hex.DecodeString(key)
	if err != nil {
		return false
	}

	return true
}

// extractKeyComponents returns the directory and the filename that the
// blob identified by key should be stored under in the BlobStore.
// This function also checks whether the key is valid. If not, it returns
// ErrBadKey.
func extractKeyComponents(key string) (dir string, fn string, err error) {
	if !isValidKey(key) {
		return "", "", ErrBadKey
	}
	return key[0:2], key, nil
}

// Get returns a byte slice containing the contents of
// the blob identified by key. If no such blob is found,
// Get returns ErrNoSuchKey.
func (bs BlobStore) Get(key string) ([]byte, error) {
	dir, fn, err := extractKeyComponents(key)
	if err != nil {
		return nil, err
	}

	blobfn := filepath.Join(bs.dir, dir, fn)
	f, err := os.Open(blobfn)
	if os.IsNotExist(err) {
		return nil, ErrNoSuchKey
	} else if err != nil {
		return nil, err
	}

	br, err := newBlobReader(f, key)
	if err != nil {
		f.Close()
		return nil, err
	}
	defer br.Close()

	buf, err := ioutil.ReadAll(br)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// Put puts the contents of blob into the BlobStore. If
// the blob was successfully stored, the returned key can
// be used to retrieve the buf from the BlobStore at a
// later time.
func (bs BlobStore) Put(buf []byte) (key string, err error) {
	// Calculate the key for the blob.  We can't really delay it more than this,
	// since we need to know the key for the blob to check whether it's already on
	// disk.
	h := sha1.New()
	_, err = h.Write(buf)
	if err != nil {
		return "", err
	}
	key = hex.EncodeToString(h.Sum(nil))

	// Get the components that make up the on-disk
	// path for the blob.
	dir, fn, err := extractKeyComponents(key)
	if err != nil {
		return "", err
	}

	blobdir := filepath.Join(bs.dir, dir)
	blobpath := filepath.Join(blobdir, fn)

	// Check if the blob already exists.
	_, err = os.Stat(blobpath)
	if err == nil {
		// The file already exists. Our job is done.
		return key, nil
	} else if os.IsNotExist(err) {
		// The blob does not exist on disk yet.
		// Fallthrough.
	} else if err != nil {
		return "", err
	}

	// Ensure that blobdir exist.
	err = os.Mkdir(blobdir, 0750)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	// Create a temporary file to write to.
	//
	// Once we're done, we can atomically rename the file
	// to the correct key.
	//
	// This method is racy: two callers can attempt to write
	// the same blob at the same time. This shouldn't affect
	// the consistency of the final blob, but worst case, we've
	// done some extra work.
	f, err := ioutil.TempFile(blobdir, fn)
	if err != nil {
		return "", err
	}

	tmpfn := f.Name()
	_, err = f.Write(buf)
	if err != nil {
		f.Close()
		return "", err
	}

	err = f.Sync()
	if err != nil {
		f.Close()
		return "", err
	}

	err = f.Close()
	if err != nil {
		return "", err
	}

	err = os.Rename(tmpfn, blobpath)
	if err != nil {
		os.Remove(tmpfn)
		return "", err
	}

	return key, nil
}
