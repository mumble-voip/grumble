// Copyright (c) 2013 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package acl

// User represents a user on a Mumble server.
// The User interface represents the method set that
// must be implemented in order to check a user's
// permissions in an ACL context.
type User interface {
	Session() uint32
	UserId() int

	CertHash() string
	Tokens() []string
	ACLContext() *Context
}

// Channel represents a Channel on a Mumble server.
type Channel interface {
	ChannelId() int
}
