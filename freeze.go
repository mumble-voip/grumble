// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"compress/gzip"
	"fmt"
	"gob"
	"io"
	"io/ioutil"
	"os"
)

type frozenServer struct {
	Id       int               "id"
	Config   map[string]string "config"
	Channels []frozenChannel   "channels"
	Users    []frozenUser      "users"
}

type frozenUser struct {
	Id            uint32 "id"
	Name          string "name"
	Password      string "password"
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

// Freeze a server and write it to a file
func (server *Server) FreezeToFile(filename string) (err os.Error) {
	r := server.FreezeServer()
	if err != nil {
		return err
	}
	f, err := ioutil.TempFile(*datadir, fmt.Sprintf("%v_", server.Id))
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	if err != nil {
		return err
	}
	err = r.Close()
	if err != nil {
		return err
	}
	err = f.Sync()
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	err = os.Rename(f.Name(), filename)
	if err != nil {
		return err
	}

	return
}

// Freeze a server
func (server *Server) Freeze() (fs frozenServer, err os.Error) {
	fs.Id = int(server.Id)
	fs.Config = server.cfg

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
	fu.Password = user.Password
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

	s, err = NewServer(int64(fs.Id), "0.0.0.0", int(DefaultPort+fs.Id-1))
	if err != nil {
		return nil, err
	}

	if fs.Config != nil {
		s.cfg = fs.Config
	}

	// Add all channels, but don't hook up parent/child relationships
	// until all of them are loaded.
	for _, fc := range fs.Channels {
		c := NewChannel(fc.Id, fc.Name)
		c.Position = int(fc.Position)
		c.InheritACL = fc.InheritACL
		c.DescriptionBlob = fc.DescriptionBlob

		for _, facl := range fc.ACL {
			acl := NewChannelACL(c)
			acl.ApplyHere = facl.ApplyHere
			acl.ApplySubs = facl.ApplySubs
			acl.UserId = facl.UserId
			acl.Group = facl.Group
			acl.Deny = Permission(facl.Deny)
			acl.Allow = Permission(facl.Allow)
			c.ACL = append(c.ACL, acl)
		}
		for _, fgrp := range fc.Groups {
			g := NewGroup(c, fgrp.Name)
			g.Inherit = fgrp.Inherit
			g.Inheritable = fgrp.Inheritable
			for _, uid := range fgrp.Add {
				g.Add[uid] = true
			}
			for _, uid := range fgrp.Remove {
				g.Remove[uid] = true
			}
			c.Groups[g.Name] = g
		}

		s.Channels[c.Id] = c
	}

	// Hook up children with their parents.
	for _, fc := range fs.Channels {
		if fc.Id == 0 {
			continue
		}
		childChan, exists := s.Channels[fc.Id]
		if !exists {
			return nil, os.NewError("Non-existant child channel")
		}
		parentChan, exists := s.Channels[fc.ParentId]
		if !exists {
			return nil, os.NewError("Non-existant parent channel")
		}
		parentChan.AddChild(childChan)
	}

	s.root = s.Channels[0]

	// Add all users
	for _, fu := range fs.Users {
		u, err := NewUser(fu.Id, fu.Name)
		if err != nil {
			return nil, err
		}

		u.Password = fu.Password
		u.CertHash = fu.CertHash
		u.Email = fu.Email
		u.TextureBlob = fu.TextureBlob
		u.CommentBlob = fu.CommentBlob
		u.LastChannelId = fu.LastChannelId
		u.LastActive = fu.LastActive

		s.Users[u.Id] = u
		if u.Id > s.nextUserId {
			s.nextUserId = u.Id + 1
		}
		s.UserNameMap[u.Name] = u
		if len(u.CertHash) > 0 {
			s.UserCertMap[u.CertHash] = u
		}
	}

	return s, nil
}
