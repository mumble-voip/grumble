// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"compress/gzip"
	"gob"
	"os"
)

type frozenServer struct {
	Id                int             "id"
	MaxUsers          int             "max_user"
	SuperUserPassword string          "super_user_password"
	Channels          []frozenChannel "channels"
	Users             []frozenUser    "users"
}

type frozenUser struct {
	Id            uint32 "id"
	Name          string "name"
	CertHash      string "cert_hash"
	Email         string "email"
	TextureBlob   string "texture_blob"
	CommentBlob   string "comment_blob"
	LastChannelId int    "last_channel_id"
	LastActive    uint64 "last_active"
}

type frozenChannel struct {
	Id              int           "id"
	Name            string        "name"
	ParentId        int           "parent_id"
	Position        int64         "position"
	InheritACL      bool          "inherit_acl"
	Links           []int         "links"
	ACL             []frozenACL   "acl"
	Groups          []frozenGroup "groups"
	DescriptionBlob string        "description_blob"
}

type frozenACL struct {
	UserId    int    "user_id"
	Group     string "group"
	ApplyHere bool   "apply_here"
	ApplySubs bool   "apply_subs"
	Allow     uint32 "allow"
	Deny      uint32 "deny"
}

type frozenGroup struct {
	Name        string "name"
	Inherit     bool   "inherit"
	Inheritable bool   "inheritable"
	Add         []int  "add"
	Remove      []int  "remove"
}

// Freeze a server
func (server *Server) Freeze() (fs frozenServer, err os.Error) {
	fs.Id = int(server.Id)
	fs.SuperUserPassword = server.superUserPassword
	fs.MaxUsers = server.MaxUsers

	channels := []frozenChannel{}
	for _, c := range server.Channels {
		fc, err := c.Freeze()
		if err != nil {
			return
		}
		channels = append(channels, fc)
	}
	fs.Channels = channels

	users := []frozenUser{}
	for _, u := range server.Users {
		fu, err := u.Freeze()
		if err != nil {
			return
		}
		users = append(users, fu)
	}
	fs.Users = users

	return
}

// Freeze a channel
func (channel *Channel) Freeze() (fc frozenChannel, err os.Error) {
	fc.Id = channel.Id
	fc.Name = channel.Name
	if channel.parent != nil {
		fc.ParentId = channel.parent.Id
	} else {
		fc.ParentId = -1
	}
	fc.Position = int64(channel.Position)
	fc.InheritACL = channel.InheritACL

	acls := []frozenACL{}
	for _, acl := range channel.ACL {
		facl, err := acl.Freeze()
		if err != nil {
			return
		}
		acls = append(acls, facl)
	}
	fc.ACL = acls

	groups := []frozenGroup{}
	for _, grp := range channel.Groups {
		fgrp, err := grp.Freeze()
		if err != nil {
			return
		}
		groups = append(groups, fgrp)
	}
	fc.Groups = groups

	links := []int{}
	for cid, _ := range channel.Links {
		links = append(links, cid)
	}
	fc.Links = links

	return
}

// Freeze a User
func (user *User) Freeze() (fu frozenUser, err os.Error) {
	fu.Id = user.Id
	fu.Name = user.Name
	fu.CertHash = user.CertHash
	fu.Email = user.Email
	fu.TextureBlob = user.TextureBlob
	fu.CommentBlob = user.CommentBlob
	fu.LastChannelId = user.LastChannelId
	fu.LastActive = user.LastActive

	return
}

// Freeze a ChannelACL
func (acl *ChannelACL) Freeze() (facl frozenACL, err os.Error) {
	facl.UserId = acl.UserId
	facl.Group = acl.Group
	facl.ApplyHere = acl.ApplyHere
	facl.ApplySubs = acl.ApplySubs
	facl.Allow = uint32(acl.Allow)
	facl.Deny = uint32(acl.Deny)

	return
}

// Freeze a Group
func (group *Group) Freeze() (fgrp frozenGroup, err os.Error) {
	fgrp.Name = group.Name
	fgrp.Inherit = group.Inherit
	fgrp.Inheritable = group.Inheritable
	fgrp.Add = group.AddUsers()
	fgrp.Remove = group.RemoveUsers()

	return
}

// Create a new Server from a frozen server
func NewServerFromFrozen(filename string) (s *Server, err os.Error) {
	descFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer descFile.Close()

	zr, err := gzip.NewReader(descFile)
	if err != nil {
		return nil, err
	}

	fs := new(frozenServer)
	decoder := gob.NewDecoder(zr)
	decoder.Decode(&fs)

	s, err = NewServer(int64(fs.Id), "", int(DefaultPort+fs.Id-1))
	if err != nil {
		return nil, err
	}

	s.superUserPassword = fs.SuperUserPassword

	// Add all channels, but don't hook up parent/child relationships
	// until all of them are loaded.
	for _, jc := range fs.Channels {
		c := NewChannel(jc.Id, jc.Name)
		c.Position = int(jc.Position)
		c.InheritACL = jc.InheritACL
		c.DescriptionHash = []byte{} // fixme

		for _, jacl := range jc.ACL {
			acl := NewChannelACL(c)
			acl.ApplyHere = jacl.ApplyHere
			acl.ApplySubs = jacl.ApplySubs
			acl.UserId = jacl.UserId
			acl.Group = jacl.Group
			acl.Deny = Permission(jacl.Deny)
			acl.Allow = Permission(jacl.Allow)
			c.ACL = append(c.ACL, acl)
		}
		for _, jgrp := range jc.Groups {
			g := NewGroup(c, jgrp.Name)
			g.Inherit = jgrp.Inherit
			g.Inheritable = jgrp.Inheritable
			for _, uid := range jgrp.Add {
				g.Add[uid] = true
			}
			for _, uid := range jgrp.Remove {
				g.Remove[uid] = true
			}
			c.Groups[g.Name] = g
		}

		s.Channels[c.Id] = c
	}

	// Hook up children with their parents.
	for _, jc := range fs.Channels {
		if jc.Id == 0 {
			continue
		}
		childChan, exists := s.Channels[jc.Id]
		if !exists {
			return nil, os.NewError("Non-existant child channel")
		}
		parentChan, exists := s.Channels[jc.ParentId]
		if !exists {
			return nil, os.NewError("Non-existant parent channel")
		}
		parentChan.AddChild(childChan)
	}

	s.root = s.Channels[0]

	// Add all users
	for _, ju := range fs.Users {
		u, err := NewUser(ju.Id, ju.Name)
		if err != nil {
			return nil, err
		}

		u.CertHash = ju.CertHash
		u.Email = ju.Email
		u.TextureBlob = ju.TextureBlob
		u.CommentBlob = ju.CommentBlob
		u.LastChannelId = ju.LastChannelId
		u.LastActive = ju.LastActive

		s.Users[u.Id] = u
		s.UserNameMap[u.Name] = u
		s.UserCertMap[u.CertHash] = u
	}

	return s, nil
}
