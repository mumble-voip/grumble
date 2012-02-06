// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package blobstore

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestMakeAllCreateAll(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(dir)

	bs, err := NewBlobStore(dir)
	if err != nil {
		t.Error(err)
		return
	}
	defer bs.Close()

	// Check whether the blobstore created all the directories...
	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			dirname := filepath.Join(dir, hex.EncodeToString([]byte{byte(i)}), hex.EncodeToString([]byte{byte(j)}))
			fi, err := os.Stat(dirname)
			if err != nil {
				t.Fatal(err)
			}
			if !fi.IsDir() {
				t.Errorf("Not a directory")
			}
		}
	}
}

func TestAllInvalidFiles(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(dir)

	err = ioutil.WriteFile(filepath.Join(dir, "00"), []byte{0x0f, 0x00}, 0600)
	if err != nil {
		t.Error(err)
	}

	_, err = NewBlobStore(dir)
	if err == ErrBadFile {
		// Success
	} else if err != nil {
		t.Error(err)
	} else {
		t.Error("NewBlobStore returned without error")
	}
}

func TestAllInvalidFilesLevel2(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(dir)

	err = os.Mkdir(filepath.Join(dir, "00"), 0700)
	if err != nil {
		t.Error(err)
	}

	err = ioutil.WriteFile(filepath.Join(dir, "00", "00"), []byte{0x0f, 0x00}, 0600)
	if err != nil {
		t.Error(err)
	}

	_, err = NewBlobStore(dir)
	if err == ErrBadFile {
		// Success
	} else if err != nil {
		t.Error(err)
	} else {
		t.Error("NewBlobStore returned without error")
	}
}

func TestStoreRetrieve(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(dir)

	bs, err := NewBlobStore(dir)
	if err != nil {
		t.Error(err)
		return
	}
	defer bs.Close()

	data := []byte{0xde, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xbe, 0xef}

	key, err := bs.Put(data)
	if err != nil {
		t.Error(err)
		return
	}

	recv, err := bs.Get(key)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(recv, data) {
		t.Errorf("stored data and retrieved data does not match: %v vs. %v", recv, data)
	}
}

func TestReadNonExistantKey(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(dir)

	bs, err := NewBlobStore(dir)
	if err != nil {
		t.Error(err)
		return
	}
	defer bs.Close()

	h := sha1.New()
	h.Write([]byte{0x42})
	key := hex.EncodeToString(h.Sum(nil))
	buf, err := bs.Get(key)
	if err != ErrNoSuchKey {
		t.Error("Expected no such key %v, found it anyway. (buf=%v, err=%v)", key, buf, err)
		return
	}
}

func TestReadInvalidKeyLength(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)

	bs, err := NewBlobStore(dir)
	if err != nil {
		t.Error(err)
		return
	}
	defer bs.Close()

	key := ""
	for i := 0; i < 5; i++ {
		key += "0"
	}

	_, err = bs.Get(key)
	if err != ErrInvalidKey {
		t.Error("Expected invalid key for %v, got %v", key, err)
		return
	}
}

func TestReadInvalidKeyNonHex(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(dir)

	bs, err := NewBlobStore(dir)
	if err != nil {
		t.Error(err)
		return
	}
	defer bs.Close()

	key := ""
	for i := 0; i < 40; i++ {
		key += "i"
	}

	_, err = bs.Get(key)
	if err != ErrInvalidKey {
		t.Errorf("Expected invalid key for %v, got %v", key, err)
		return
	}
}

func TestDefaultBlobStore(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(dir)

	err = Open(dir)
	if err != nil {
		t.Error(err)
	}

	data := []byte{0xf, 0x0, 0x0, 0xb, 0xa, 0xf}

	key, err := Put(data)
	if err != nil {
		t.Error(err)
	}

	fetchedData, err := Get(key)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(fetchedData, data) {
		t.Errorf("stored data and retrieved data does not match: %v vs. %v", fetchedData, data)
	}
}
