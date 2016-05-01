// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"encoding/hex"
	"github.com/mumble-voip/grumble/pkg/acl"
)

// A Mumble channel
type Channel struct {
	Id       int
	Name     string
	Position int

	temporary bool
	clients   map[uint32]*Client
	parent    *Channel
	children  map[int]*Channel

	// ACL
	ACL acl.Context

	// Links
	Links map[int]*Channel

	// Blobs
	DescriptionBlob string
}

func NewChannel(id int, name string) (channel *Channel) {
	channel = new(Channel)
	channel.Id = id
	channel.Name = name
	channel.clients = make(map[uint32]*Client)
	channel.children = make(map[int]*Channel)
	channel.ACL.Groups = make(map[string]acl.Group)
	channel.Links = make(map[int]*Channel)
	return
}

// Add a child channel to a channel
func (channel *Channel) AddChild(child *Channel) {
	child.parent = channel
	child.ACL.Parent = &channel.ACL
	channel.children[child.Id] = child
}

// Remove a child channel from a parent
func (channel *Channel) RemoveChild(child *Channel) {
	child.parent = nil
	child.ACL.Parent = nil
	delete(channel.children, child.Id)
}

// Add client
func (channel *Channel) AddClient(client *Client) {
	channel.clients[client.Session()] = client
	client.Channel = channel
}

// Remove client
func (channel *Channel) RemoveClient(client *Client) {
	delete(channel.clients, client.Session())
	client.Channel = nil
}

// Does the channel have a description?
func (channel *Channel) HasDescription() bool {
	return len(channel.DescriptionBlob) > 0
}

// Get the channel's blob hash as a byte slice for sending via a protobuf message.
// Returns nil if there is no blob.
func (channel *Channel) DescriptionBlobHashBytes() (buf []byte) {
	buf, err := hex.DecodeString(channel.DescriptionBlob)
	if err != nil {
		return nil
	}
	return buf
}

// Returns a slice of all channels in this channel's
// link chain.
func (channel *Channel) AllLinks() (seen map[int]*Channel) {
	seen = make(map[int]*Channel)
	walk := []*Channel{channel}
	for len(walk) > 0 {
		current := walk[len(walk)-1]
		walk = walk[0 : len(walk)-1]
		for _, linked := range current.Links {
			if _, alreadySeen := seen[linked.Id]; !alreadySeen {
				seen[linked.Id] = linked
				walk = append(walk, linked)
			}
		}
	}
	return
}

// Returns a slice of all of this channel's subchannels.
func (channel *Channel) AllSubChannels() (seen map[int]*Channel) {
	seen = make(map[int]*Channel)
	walk := []*Channel{}
	if len(channel.children) > 0 {
		walk = append(walk, channel)
		for len(walk) > 0 {
			current := walk[len(walk)-1]
			walk = walk[0 : len(walk)-1]
			for _, child := range current.children {
				if _, alreadySeen := seen[child.Id]; !alreadySeen {
					seen[child.Id] = child
					walk = append(walk, child)
				}
			}
		}
	}
	return
}

// Checks whether the channel is temporary
func (channel *Channel) IsTemporary() bool {
	return channel.temporary
}

// Checks whether the channel is temporary
func (channel *Channel) IsEmpty() bool {
	return len(channel.clients) == 0
}
