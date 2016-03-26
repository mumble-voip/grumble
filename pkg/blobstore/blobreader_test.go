// Copyright (c) 2013 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package blobstore

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

type blobReaderTest struct {
	Key         string
	ExpectedSum string
	Data        string
}

var blobReaderTests = []blobReaderTest{
	{
		Key:         "a3da7877f94ad4cf58636a395fff77537cb8b919",
		ExpectedSum: "a3da7877f94ad4cf58636a395fff77537cb8b919",
		Data:        "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
	},
}

func TestBlobReader(t *testing.T) {
	for _, test := range blobReaderTests {
		rc := ioutil.NopCloser(bytes.NewBufferString(test.Data))
		br, err := newBlobReader(rc, test.Key)
		if err != nil {
			t.Errorf("unable to construct blob reader: %v", err)
			continue
		}
		_, err = io.Copy(ioutil.Discard, br)
		if err != nil {
			t.Errorf("got error: %v", err)
		}
	}
}
