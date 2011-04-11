// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"encoding/hex"
	"os"
)

// This file implements Server's handling of Users.
//
// Users are registered clients on the server.

type User struct {
	Id            uint32
	Name          string
	CertHash      string
	Email         string
	TextureBlob   string
	CommentBlob   string
	LastChannelId int
	LastActive    uint64
}

// Create a new User
func NewUser(id uint32, name string) (user *User, err os.Error) {
	if id < 0 {
		return nil, os.NewError("Invalid user id")
	}
	if len(name) == 0 || name == "SuperUser" {
		return nil, os.NewError("Invalid username")
	}

	return &User{
		Id:   id,
		Name: name,
	},nil
}

// Does the channel have comment?
func (user *User) HasComment() bool {
	return len(user.CommentBlob) > 0
}

// Get the hash of the user's comment blob as a byte slice for transmitting via a protobuf message.
// Returns nil if there is no such blob.
func (user *User) CommentBlobHashBytes() (buf []byte) {
	buf, err := hex.DecodeString(user.CommentBlob)
	if err != nil {
		return nil
	}
	return buf
}

// Does the user have a texture?
func (user *User) HasTexture() bool {
	return len(user.TextureBlob) > 0
}

// Get the hash of the user's texture blob as a byte slice for transmitting via a protobuf message.
// Returns nil if there is no such blob.
func (user *User) TextureBlobHashBytes() (buf []byte) {
	buf, err := hex.DecodeString(user.TextureBlob)
	if err != nil {
		return nil
	}
	return buf
}
