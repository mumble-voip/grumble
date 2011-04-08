// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
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
		Id: id,
		Name: name,
	}, nil
}
