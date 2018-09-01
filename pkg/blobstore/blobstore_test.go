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
	"testing"
)

func TestStoreRetrieve(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(dir)

	bs := Open(dir)

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

	bs := Open(dir)

	h := sha1.New()
	h.Write([]byte{0x42})
	key := hex.EncodeToString(h.Sum(nil))
	buf, err := bs.Get(key)
	if err != ErrNoSuchKey {
		t.Errorf("Expected no such key %v, found it anyway. (buf=%v, err=%v)", key, buf, err)
		return
	}
}

func TestReadInvalidKeyLength(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)

	bs := Open(dir)

	key := ""
	for i := 0; i < 5; i++ {
		key += "0"
	}

	_, err = bs.Get(key)
	if err != ErrBadKey {
		t.Errorf("Expected invalid key for %v, got %v", key, err)
		return
	}
}

func TestReadBadKeyNonHex(t *testing.T) {
	dir, err := ioutil.TempDir("", "blobstore")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(dir)

	bs := Open(dir)

	key := ""
	for i := 0; i < 40; i++ {
		key += "i"
	}

	_, err = bs.Get(key)
	if err != ErrBadKey {
		t.Errorf("Expected bad key for %v, got %v", key, err)
		return
	}
}
