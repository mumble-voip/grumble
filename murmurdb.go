// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

// This file implements a Server that can be created from a Murmur SQLite file.
// This is read-only, so it's not generally useful.  It's meant as a convenient
// way to import a Murmur server into Grumble, to be able to dump the structure of the
// SQLite datbase into a format that Grumble can understand.

import (
	"os"
	"sqlite"
	"strconv"
)

const (
	ChannelInfoDescription int = iota
	ChannelInfoPosition
)

const (
	UserInfoName int = iota
	UserInfoEmail
	UserInfoComment
	UserInfoHash
	UserInfoPassword
	UserInfoLastActive
)

// Create a new Server from a Murmur SQLite database
func NewServerFromSQLite(id int64, db *sqlite.Conn) (s *Server, err os.Error) {
	s, err = NewServer(id, "", int(DefaultPort+id-1))
	if err != nil {
		return nil, err
	}

	err = populateChannelsFromDatabase(s, db, 0)
	if err != nil {
		return nil, err
	}

	err = populateChannelLinkInfo(s, db)
	if err != nil {
		return nil, err
	}

	err = populateUsers(s, db)
	if err != nil {
		return nil, err
	}

	return
}

// Populate the Server with Channels from the database.
func populateChannelsFromDatabase(server *Server, db *sqlite.Conn, parentId int) os.Error {
	parent, exists := server.Channels[parentId]
	if !exists {
		return os.NewError("Non-existant parent")
	}

	stmt, err := db.Prepare("SELECT channel_id, name, inheritacl FROM channels WHERE server_id=? AND parent_id=?")
	if err != nil {
		return err
	}

	err = stmt.Exec(server.Id, parentId)
	if err != nil {
		return err
	}

	for stmt.Next() {
		var (
			name    string
			chanid  int
			inherit bool
		)
		err = stmt.Scan(&chanid, &name, &inherit)
		if err != nil {
			return err
		}

		c := server.NewChannel(chanid, name)
		c.InheritACL = inherit
		parent.AddChild(c)
	}

	// Add channel_info
	for _, c := range parent.children {
		stmt, err = db.Prepare("SELECT value FROM channel_info WHERE server_id=? AND channel_id=? AND key=?")
		if err != nil {
			return err
		}

		// Fetch description
		if err := stmt.Exec(server.Id, c.Id, ChannelInfoDescription); err != nil {
			return err
		}
		for stmt.Next() {
			var description string
			err = stmt.Scan(&description)
			if err != nil {
				return err
			}

			key, err := globalBlobstore.Put([]byte(description))
			if err != nil {
				return err
			}
			c.DescriptionBlob = key
		}

		if err := stmt.Reset(); err != nil {
			return err
		}

		// Fetch position
		if err := stmt.Exec(server.Id, c.Id, ChannelInfoPosition); err != nil {
			return err
		}
		for stmt.Next() {
			var pos int
			if err := stmt.Scan(&pos); err != nil {
				return err
			}

			c.Position = pos
		}
	}

	// Add ACLs
	for _, c := range parent.children {
		stmt, err = db.Prepare("SELECT user_id, group_name, apply_here, apply_sub, grantpriv, revokepriv FROM acl WHERE server_id=? AND channel_id=? ORDER BY priority")
		if err != nil {
			return err
		}

		if err := stmt.Exec(server.Id, c.Id); err != nil {
			return err
		}

		for stmt.Next() {
			var (
				UserId    string
				Group     string
				ApplyHere bool
				ApplySub  bool
				Allow     int64
				Deny      int64
			)
			if err := stmt.Scan(&UserId, &Group, &ApplyHere, &ApplySub, &Allow, &Deny); err != nil {
				return err
			}

			acl := NewChannelACL(c)
			acl.ApplyHere = ApplyHere
			acl.ApplySubs = ApplySub
			if len(UserId) > 0 {
				acl.UserId, err = strconv.Atoi(UserId)
				if err != nil {
					return err
				}
			} else if len(Group) > 0 {
				acl.Group = Group
			} else {
				return os.NewError("Invalid ACL: Neither Group or UserId specified")
			}

			acl.Deny = Permission(Deny)
			acl.Allow = Permission(Allow)
			c.ACL = append(c.ACL, acl)
		}
	}

	// Add groups
	groups := make(map[int64]*Group)
	for _, c := range parent.children {
		stmt, err = db.Prepare("SELECT group_id, name, inherit, inheritable FROM groups WHERE server_id=? AND channel_id=?")
		if err != nil {
			return err
		}

		if err := stmt.Exec(server.Id, c.Id); err != nil {
			return err
		}

		for stmt.Next() {
			var (
				GroupId     int64
				Name        string
				Inherit     bool
				Inheritable bool
			)

			if err := stmt.Scan(&GroupId, &Name, &Inherit, &Inheritable); err != nil {
				return err
			}

			g := NewGroup(c, Name)
			g.Inherit = Inherit
			g.Inheritable = Inheritable
			c.Groups[g.Name] = g
			groups[GroupId] = g
		}
	}

	// Add group members
	for gid, grp := range groups {
		stmt, err = db.Prepare("SELECT user_id, addit FROM group_members WHERE server_id=? AND group_id=?")
		if err != nil {
			return err
		}

		if err := stmt.Exec(server.Id, gid); err != nil {
			return err
		}

		for stmt.Next() {
			var (
				UserId int64
				Add    bool
			)

			if err := stmt.Scan(&UserId, &Add); err != nil {
				return err
			}

			if Add {
				grp.Add[int(UserId)] = true
			} else {
				grp.Remove[int(UserId)] = true
			}
		}
	}

	// Add subchannels
	for id, _ := range parent.children {
		err = populateChannelsFromDatabase(server, db, id)
		if err != nil {
			return err
		}
	}

	return nil
}

// Link a Server's channels together
func populateChannelLinkInfo(server *Server, db *sqlite.Conn) (err os.Error) {
	stmt, err := db.Prepare("SELECT channel_id, link_id FROM channel_links WHERE server_id=?")
	if err != nil {
		return err
	}

	if err := stmt.Exec(server.Id); err != nil {
		return err
	}

	for stmt.Next() {
		var (
			ChannelId int
			LinkId    int
		)
		if err := stmt.Scan(&ChannelId, &LinkId); err != nil {
			return err
		}

		channel, exists := server.Channels[ChannelId]
		if !exists {
			return os.NewError("Attempt to perform link operation on non-existant channel.")
		}

		other, exists := server.Channels[LinkId]
		if !exists {
			return os.NewError("Attempt to perform link operation on non-existant channel.")
		}

		server.LinkChannels(channel, other)
	}

	return nil
}

func populateUsers(server *Server, db *sqlite.Conn) (err os.Error) {
	// Populate the server with regular user data
	stmt, err := db.Prepare("SELECT user_id, name, pw, lastchannel, texture, strftime('%s', last_active) FROM users WHERE server_id=?")
	if err != nil {
		return
	}

	err = stmt.Exec(server.Id)
	if err != nil {
		return
	}

	for stmt.Next() {
		var (
			UserId       int64
			UserName     string
			SHA1Password string
			LastChannel  int
			Texture      []byte
			LastActive   int64
		)

		err = stmt.Scan(&UserId, &UserName, &SHA1Password, &LastChannel, &Texture, &LastActive)
		if err != nil {
			continue
		}

		user, err := NewUser(uint32(UserId), UserName)
		if err != nil {
			return err
		}

		user.Password = "sha1$$" + SHA1Password

		key, err := globalBlobstore.Put(Texture)
		if err != nil {
			return err
		}
		user.TextureBlob = key

		user.LastActive = uint64(LastActive)
		user.LastChannelId = LastChannel

		server.Users[user.Id] = user
	}

	stmt, err = db.Prepare("SELECT key, value FROM user_info WHERE server_id=? AND user_id=?")
	if err != nil {
		return
	}

	// Populate users with any new-style UserInfo records
	for uid, user := range server.Users {
		err = stmt.Reset()
		if err != nil {
			return err
		}

		err = stmt.Exec(server.Id, uid)
		if err != nil {
			return err
		}

		for stmt.Next() {
			var (
				Key   int
				Value string
			)

			err = stmt.Scan(&Key, &Value)
			if err != nil {
				return err
			}

			switch Key {
			case UserInfoEmail:
				user.Email = Value
			case UserInfoComment:
				key, err := globalBlobstore.Put([]byte(Value))
				if err != nil {
					return err
				}
				user.CommentBlob = key
			case UserInfoHash:
				user.CertHash = Value
			case UserInfoLastActive:
				// not a kv-pair (trigger)
			case UserInfoPassword:
				// not a kv-pair
			case UserInfoName:
				// not a kv-pair
			}
		}
	}

	return
}
