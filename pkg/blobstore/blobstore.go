// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// This package implements a simple disk-persisted content-addressed
// blobstore.
package blobstore

import (
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

type BlobStore struct {
	dir     string
	lockfn  string
	makeall bool
}

const (
	win32AlreadyExists = 183
)

var (
	ErrLocked          = os.NewError("lockfile acquired by another process")
	ErrLockAcquirement = os.NewError("unable to acquire lockfile")
	ErrBadFile         = os.NewError("a bad file exists in the blobstore directory. unable to create container directores.")
	ErrNoSuchKey       = os.NewError("no such key")
	ErrInvalidKey      = os.NewError("invalid key")
)

var (
	defaultStore *BlobStore
	defaultMutex sync.Mutex
)

// Open an existing, or create a new BlobStore at path.
// Path must point to a directory, and must already exist.
// See NewBlobStore for more information.
func Open(path string, makeall bool) (err os.Error) {
	defaultMutex.Lock()
	defer defaultMutex.Unlock()

	if defaultStore != nil {
		panic("Default BlobStore already open")
	}

	defaultStore, err = NewBlobStore(path, makeall)
	return
}

// Close the open default BlobStore. This removes the lockfile allowing
// other processes to open the BlobStore.
func Close() (err os.Error) {
	if defaultStore == nil {
		panic("DefaultStore not open")
	}

	err = defaultStore.Close()
	if err != nil {
		return
	}

	defaultStore = nil
	return
}

// Lookup a blob by its key and return a buffer containing the contents
// of the blob.
func Get(key string) (buf []byte, err os.Error) {
	return defaultStore.Get(key)
}

// Store a blob. If the blob was successfully stored, the returned key
// can be used to retrieve the buf from the BlobStore.
func Put(buf []byte) (key string, err os.Error) {
	return defaultStore.Put(buf)
}


// Open an existing, or create a new BlobStore residing at path.
// Path must point to a directory, and must already exist.
//
// The makeall argument determines whether the BlobStore should
// create all possible blob-container directories a priori.
// This can take up a bit of disk space since the metadata for
// those directories can take up a lot of space. However, tt saves
// some I/O operations when writing blobs. (Since the BlobStore
// knows that all directories will exist, it does not need to check
// whether they do, and create them if they do not.).
func NewBlobStore(path string, makeall bool) (bs *BlobStore, err os.Error) {
	// Does the directory exist?
	dir, err := os.Open(path)
	if err != nil {
		return
	}
	dir.Close()

	// Try to acquire an exclusive lock on the blobstore.
	lockfn := filepath.Join(path, "lock")
	err = AcquireLockFile(lockfn)
	if err != nil {
		return nil, err
	}
	// Make sure to remove the lockfile if we return with an error.
	// It would be impossible for users to remove it (they wouldn't
	// know the filename.)
	defer func() {
		if err != nil {
			ReleaseLockFile(lockfn)
		}
	}()

	if makeall {
		for i := 0; i < 256; i++ {
			outer := filepath.Join(path, hex.EncodeToString([]byte{byte(i)}))
			err = os.Mkdir(outer, 0700)
			if e, ok := err.(*os.PathError); ok {
				if isExistError(e) {
					// The file alread exists. Stat it to check whether it is indeed
					// a directory.
					fi, err := os.Stat(outer)
					if err != nil {
						return nil, err
					}
					if !fi.IsDirectory() {
						return nil, ErrBadFile
					}
				} else if e.Error == os.ENOTDIR {
					return nil, ErrBadFile
				}
			} else if err != nil {
				return nil, err
			}
			for j := 0; j < 256; j++ {
				inner := filepath.Join(outer, hex.EncodeToString([]byte{byte(j)}))
				err = os.Mkdir(inner, 0700)
				if e, ok := err.(*os.PathError); ok {
					if isExistError(e) {
						// The file alread exists. Stat it to check whether it is indeed
						// a directory.
						fi, err := os.Stat(inner)
						if err != nil {
							return nil, err
						}
						if !fi.IsDirectory() {
							return nil, ErrBadFile
						}
					} else if e.Error == os.ENOTDIR {
						return nil, ErrBadFile
					}
				} else if err != nil {
					return nil, err
				}
			}
		}
	}

	bs = &BlobStore{
		dir:     path,
		lockfn:  lockfn,
		makeall: makeall,
	}
	return bs, nil
}

// Close an open BlobStore. This removes the lockfile allowing
// other processes to open the BlobStore.
func (bs *BlobStore) Close() (err os.Error) {
	return os.Remove(bs.lockfn)
}

// Checks that a given key is a valid key for the BlobStore.
// If it is, it returns the three components that make up the on-disk path
// the given key can be found or should be stored at.
func getKeyComponents(key string) (dir1, dir2, fn string, err os.Error) {
	// SHA1 digests are 40 bytes long when hex-encoded
	if len(key) != 40 {
		err = ErrInvalidKey
		return
	}
	// Check whether the string is valid hex-encoding.
	_, err = hex.DecodeString(key)
	if err != nil {
		err = ErrInvalidKey
		return
	}

	return key[0:2], key[2:4], key[4:], nil
}

// Lookup the path hat a key would have on disk.
// Returns an error if the key is not a valid BlobStore key.
func (bs *BlobStore) pathForKey(key string) (fn string, err os.Error) {
	dir1, dir2, rest, err := getKeyComponents(key)
	if err != nil {
		return
	}

	fn = filepath.Join(bs.dir, dir1, dir2, rest)
	return
}

// Lookup a blob by its key and return a buffer containing the contents
// of the blob.
func (bs *BlobStore) Get(key string) (buf []byte, err os.Error) {
	fn, err := bs.pathForKey(key)
	if err != nil {
		return
	}

	file, err := os.Open(fn)
	if e, ok := err.(*os.PathError); ok && (e.Error == os.ENOENT || e.Error == os.ENOTDIR) {
		err = ErrNoSuchKey
		return
	} else if err != nil {
		return
	}

	br, err := newBlobReader(file, key)
	if err != nil {
		file.Close()
		return
	}
	defer br.Close()

	buf, err = ioutil.ReadAll(br)
	if err != nil {
		return
	}

	return
}

// Store a blob. If the blob was successfully stored, the returned key
// can be used to retrieve the buf from the BlobStore.
func (bs *BlobStore) Put(buf []byte) (key string, err os.Error) {
	// Calculate the key for the blob.  We can't really delay it more than this,
	// since we need to know the key for the blob to check whether it's already on
	// disk.
	h := sha1.New()
	h.Write(buf)
	key = hex.EncodeToString(h.Sum())

	// Get the components that make up the on-disk
	// path for the blob.
	dir1, dir2, rest, err := getKeyComponents(key)
	if err != nil {
		return
	}

	blobpath := filepath.Join(bs.dir, dir1, dir2, rest)
	blobdir := filepath.Join(bs.dir, dir1, dir2)

	// Check if the blob already exists.
	file, err := os.Open(blobpath)
	if err == nil {
		// File exists. Job's done.
		file.Close()
		return
	} else {
		if e, ok := err.(*os.PathError); ok && (e.Error == os.ENOENT || e.Error == os.ENOTDIR) {
			// No such file exists on disk. Ready to rock!
		} else {
			return
		}
	}

	if !bs.makeall {
		// Make sure the leading directories exist...
		err = os.MkdirAll(filepath.ToSlash(blobdir), 0700)
		if err != nil {
			return
		}
	}

	// Create a temporary file to write to. Once we're done, we
	// can atomically rename the file to the correct key.
	file, err = ioutil.TempFile(blobdir, rest)
	if err != nil {
		return
	}

	tmpfn := file.Name()

	_, err = file.Write(buf)
	if err != nil {
		return
	}

	err = file.Sync()
	if err != nil {
		return "", err
	}

	err = file.Close()
	if err != nil {
		return "", err
	}

	err = os.Rename(tmpfn, blobpath)
	if err != nil {
		os.Remove(tmpfn)
		return
	}

	return key, nil
}

// Check whether an os.PathError is an EXIST error.
// On Unix, it checks for EEXIST. On Windows, it checks for EEXIST
// and Errno code 183 (ERROR_ALREADY_EXISTS)
func isExistError(err *os.PathError) (exists bool) {
	if e, ok := err.Error.(os.Errno); ok && e == win32AlreadyExists {
		exists = true
	}
	if err.Error == os.EEXIST {
		exists = true
	}
	return
}
