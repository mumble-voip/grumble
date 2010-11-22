// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

// A Mumble channel
type Channel struct {
	Id          int
	Name        string
	Description string
	Temporary   bool
	Position    int

	clients map[uint32]*Client

	parent   *Channel
	children map[int]*Channel

	// ACL
	ACL        []*ChannelACL
	InheritACL bool

	// Groups
	Groups map[string]*Group
}

func NewChannel(id int, name string) (channel *Channel) {
	channel = new(Channel)
	channel.Id = id
	channel.Name = name
	channel.clients = make(map[uint32]*Client)
	channel.children = make(map[int]*Channel)
	channel.ACL = []*ChannelACL{}
	channel.Groups = map[string]*Group{}
	return
}

// Add a child channel to a channel
func (channel *Channel) AddChild(child *Channel) {
	child.parent = channel
	channel.children[child.Id] = child
}

// Remove a child channel from a parent
func (channel *Channel) RemoveChild(child *Channel) {
	child.parent = nil
	channel.children[child.Id] = nil, false
}

// Add client
func (channel *Channel) AddClient(client *Client) {
	channel.clients[client.Session] = client
	client.Channel = channel
}

// Remove client
func (channel *Channel) RemoveClient(client *Client) {
	channel.clients[client.Session] = nil, false
	client.Channel = nil
}
