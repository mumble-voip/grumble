// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// This package implements a simple disk-persisted content-addressed
// blobstore.
package blobstore

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

type BlobStore struct {
	dir    string
	lockfn string
}

const (
	win32AlreadyExists = 183
)

var (
	ErrLocked          = errors.New("lockfile acquired by another process")
	ErrLockAcquirement = errors.New("unable to acquire lockfile")
	ErrBadFile         = errors.New("a bad file exists in the blobstore directory. unable to create container directores.")
	ErrNoSuchKey       = errors.New("no such key")
	ErrInvalidKey      = errors.New("invalid key")
)

var (
	defaultStore *BlobStore
	defaultMutex sync.Mutex
)

// Open an existing, or create a new BlobStore at path.
// Path must point to a directory, and must already exist.
// See NewBlobStore for more information.
func Open(path string) (err error) {
	defaultMutex.Lock()
	defer defaultMutex.Unlock()

	if defaultStore != nil {
		panic("Default BlobStore already open")
	}

	defaultStore, err = NewBlobStore(path)
	return
}

// Close the open default BlobStore. This removes the lockfile allowing
// other processes to open the BlobStore.
func Close() (err error) {
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
func Get(key string) (buf []byte, err error) {
	return defaultStore.Get(key)
}

// Store a blob. If the blob was successfully stored, the returned key
// can be used to retrieve the buf from the BlobStore.
func Put(buf []byte) (key string, err error) {
	return defaultStore.Put(buf)
}

// Open an existing, or create a new BlobStore residing at path.
// Path must point to a directory, and must already exist.
func NewBlobStore(path string) (bs *BlobStore, err error) {
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

	dirStructureExists := true
	// Check whether a 'blobstore' file exists in the directory.
	// The existence of the file signals that the directory already
	// has the correct hierarchy structure.
	bsf, err := os.Open(filepath.Join(path, "blobstore"))
	if err != nil {
		if e, ok := err.(*os.PathError); ok {
			if e.Err == os.ENOENT {
				dirStructureExists = false
			}
		}
	} else {
		bsf.Close()
	}

	if !dirStructureExists {
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
					if !fi.IsDir() {
						return nil, ErrBadFile
					}
				} else if e.Err == os.ENOTDIR {
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
						if !fi.IsDir() {
							return nil, ErrBadFile
						}
					} else if e.Err == os.ENOTDIR {
						return nil, ErrBadFile
					}
				} else if err != nil {
					return nil, err
				}
			}
		}

		// Add a blobstore file to signal that a correct directory
		// structure exists for this blobstore.
		bsf, err = os.Create(filepath.Join(path, "blobstore"))
		if err != nil {
			return nil, err
		}
		bsf.Close()
	}

	bs = &BlobStore{
		dir:    path,
		lockfn: lockfn,
	}
	return bs, nil
}

// Close an open BlobStore. This removes the lockfile allowing
// other processes to open the BlobStore.
func (bs *BlobStore) Close() (err error) {
	return os.Remove(bs.lockfn)
}

// Checks that a given key is a valid key for the BlobStore.
// If it is, it returns the three components that make up the on-disk path
// the given key can be found or should be stored at.
func getKeyComponents(key string) (dir1, dir2, fn string, err error) {
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
func (bs *BlobStore) pathForKey(key string) (fn string, err error) {
	dir1, dir2, rest, err := getKeyComponents(key)
	if err != nil {
		return
	}

	fn = filepath.Join(bs.dir, dir1, dir2, rest)
	return
}

// Lookup a blob by its key and return a buffer containing the contents
// of the blob.
func (bs *BlobStore) Get(key string) (buf []byte, err error) {
	fn, err := bs.pathForKey(key)
	if err != nil {
		return
	}

	file, err := os.Open(fn)
	if e, ok := err.(*os.PathError); ok && (e.Err == os.ENOENT || e.Err == os.ENOTDIR) {
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
func (bs *BlobStore) Put(buf []byte) (key string, err error) {
	// Calculate the key for the blob.  We can't really delay it more than this,
	// since we need to know the key for the blob to check whether it's already on
	// disk.
	h := sha1.New()
	h.Write(buf)
	key = hex.EncodeToString(h.Sum(nil))

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
		if e, ok := err.(*os.PathError); ok && (e.Err == os.ENOENT || e.Err == os.ENOTDIR) {
			// No such file exists on disk. Ready to rock!
		} else {
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
	if e, ok := err.Err.(syscall.Errno); ok && e == win32AlreadyExists {
		exists = true
	}
	if err.Err == os.EEXIST {
		exists = true
	}
	return
}
