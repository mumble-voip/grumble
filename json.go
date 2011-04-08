package main

import (
	"json"
	"os"
	"compress/zlib"
)

type jsonServer struct {
	Id       int           "id"
	MaxUsers int           "max_user"
	Channels []jsonChannel "channels"
}

type jsonChannel struct {
	Id         int         "id"
	Name       string      "name"
	ParentId   int         "parent_id"
	Position   int64       "position"
	InheritACL bool        "inherit_acl"
	ACL        []jsonACL   "acl"
	Groups     []jsonGroup "groups"
	Description string     "description"
	DescriptionHash []byte "description_hash"
}

type jsonACL struct {
	UserId    int    "user_id"
	Group     string "group"
	ApplyHere bool   "apply_here"
	ApplySubs bool   "apply_subs"
	Allow     uint32 "allow"
	Deny      uint32 "deny"
}

type jsonGroup struct {
	Name        string "name"
	Inherit     bool   "inherit"
	Inheritable bool   "inheritable"
	Add         []int  "add"
	Remove      []int  "remove"
}

// Marshal a server into a JSON object
func (server *Server) MarshalJSON() (buf []byte, err os.Error) {
	obj := make(map[string]interface{})
	obj["id"] = server.Id
	obj["max_user"] = server.MaxUsers

	channels := []interface{}{}
	for _, c := range server.Channels {
		channels = append(channels, c)
	}
	obj["channels"] = channels

	return json.Marshal(obj)
}

// Marshal a Channel into a JSON object
func (channel *Channel) MarshalJSON() (buf []byte, err os.Error) {
	obj := make(map[string]interface{})

	obj["id"] = channel.Id
	obj["name"] = channel.Name
	if channel.parent != nil {
		obj["parent_id"] = channel.parent.Id
	} else {
		obj["parent_id"] = -1
	}

	obj["position"] = channel.Position
	obj["inherit_acl"] = channel.InheritACL
	obj["description"] = channel.Description
	obj["description_hash"] = channel.DescriptionHash

	obj["acl"] = channel.ACL

	groups := []*Group{}
	for _, grp := range channel.Groups {
		groups = append(groups, grp)
	}
	obj["groups"] = groups
	links := []int{}
	for cid, _ := range channel.Links {
		links = append(links, cid)
	}

	return json.Marshal(obj)
}

func (acl *ChannelACL) MarshalJSON() (buf []byte, err os.Error) {
	obj := make(map[string]interface{})
	obj["user_id"] = acl.UserId
	obj["group"] = acl.Group
	obj["apply_here"] = acl.ApplyHere
	obj["apply_subs"] = acl.ApplySubs
	obj["allow"] = acl.Allow
	obj["deny"] = acl.Deny

	return json.Marshal(obj)
}

func (group *Group) MarshalJSON() (buf []byte, err os.Error) {
	obj := make(map[string]interface{})
	obj["name"] = group.Name
	obj["inherit"] = group.Inherit
	obj["inheritable"] = group.Inheritable
	obj["add"] = group.AddUsers()
	obj["remove"] = group.RemoveUsers()

	return json.Marshal(obj)
}

// Create a new Server from a Grumble zlib-compressed JSON description
func NewServerFromGrumbleDesc(filename string) (s *Server, err os.Error) {
	descFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer descFile.Close()

	zr, err := zlib.NewReader(descFile)
	if err != nil {
		return nil, err
	}

	srv := new(jsonServer)
	decoder := json.NewDecoder(zr)
	decoder.Decode(&srv)

	s, err = NewServer(int64(srv.Id), "", int(DefaultPort+srv.Id-1))
	if err != nil {
		return nil, err
	}

	// Add all channels, but don't hook up parent/child relationships
	// until all of them are loaded.
	for _, jc := range srv.Channels {
		c := NewChannel(jc.Id, jc.Name)
		c.Position = int(jc.Position)
		c.InheritACL = jc.InheritACL
		c.Description = jc.Description
		c.DescriptionHash = jc.DescriptionHash

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
	for _, jc := range srv.Channels {
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

	return s, nil
}
