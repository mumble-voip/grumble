// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

// This file implements a Server that can be created from a Murmur SQLite file.
// This is read-only, so it's not generally useful.  It's meant as a convenient
// way to import a Murmur server into Grumble, to be able to dump the structure of the
// SQLite datbase into a format that Grumble can understand.

import (
	"database/sql"
	"errors"
	"github.com/mumble-voip/grumble/pkg/acl"
	"github.com/mumble-voip/grumble/pkg/ban"
	"log"
	"net"
	"os"
	"path/filepath"
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

const SQLiteSupport = true

// Import the structure of an existing Murmur SQLite database.
func MurmurImport(filename string) (err error) {
	db, err := sql.Open("sqlite", filename)
	if err != nil {
		panic(err.Error())
	}

	rows, err := db.Query("SELECT server_id FROM servers")
	if err != nil {
		panic(err.Error())
	}

	var serverids []int64
	var sid int64
	for rows.Next() {
		err = rows.Scan(&sid)
		if err != nil {
			return err
		}
		serverids = append(serverids, sid)
	}

	log.Printf("Found servers: %v (%v servers)", serverids, len(serverids))

	for _, sid := range serverids {
		m, err := NewServerFromSQLite(sid, db)
		if err != nil {
			return err
		}

		err = os.Mkdir(filepath.Join(Args.DataDir, strconv.FormatInt(sid, 10)), 0750)
		if err != nil {
			return err
		}

		err = m.FreezeToFile()
		if err != nil {
			return err
		}

		log.Printf("Successfully imported server %v", sid)
	}

	return
}

// Create a new Server from a Murmur SQLite database
func NewServerFromSQLite(id int64, db *sql.DB) (s *Server, err error) {
	s, err = NewServer(id)
	if err != nil {
		return nil, err
	}

	err = populateChannelInfoFromDatabase(s, s.RootChannel(), db)
	if err != nil {
		return nil, err
	}

	err = populateChannelACLFromDatabase(s, s.RootChannel(), db)
	if err != nil {
		return nil, err
	}

	err = populateChannelGroupsFromDatabase(s, s.RootChannel(), db)
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

	err = populateBans(s, db)
	if err != nil {
		return nil, err
	}

	return
}

// Add channel metadata (channel_info table from SQLite) by reading the SQLite database.
func populateChannelInfoFromDatabase(server *Server, c *Channel, db *sql.DB) error {
	stmt, err := db.Prepare("SELECT value FROM channel_info WHERE server_id=? AND channel_id=? AND key=?")
	if err != nil {
		return err
	}

	// Fetch description
	rows, err := stmt.Query(server.Id, c.Id, ChannelInfoDescription)
	if err != nil {
		return err
	}
	for rows.Next() {
		var description string
		err = rows.Scan(&description)
		if err != nil {
			return err
		}

		if len(description) > 0 {
			key, err := blobStore.Put([]byte(description))
			if err != nil {
				return err
			}
			c.DescriptionBlob = key
		}
	}

	// Fetch position
	rows, err = stmt.Query(server.Id, c.Id, ChannelInfoPosition)
	if err != nil {
		return err
	}
	for rows.Next() {
		var pos int
		if err := rows.Scan(&pos); err != nil {
			return err
		}

		c.Position = pos
	}

	return nil
}

// Populate channel with its ACLs by reading the SQLite databse.
func populateChannelACLFromDatabase(server *Server, c *Channel, db *sql.DB) error {
	stmt, err := db.Prepare("SELECT user_id, group_name, apply_here, apply_sub, grantpriv, revokepriv FROM acl WHERE server_id=? AND channel_id=? ORDER BY priority")
	if err != nil {
		return err
	}

	rows, err := stmt.Query(server.Id, c.Id)
	if err != nil {
		return err
	}

	for rows.Next() {
		var (
			UserId    string
			Group     string
			ApplyHere bool
			ApplySub  bool
			Allow     int64
			Deny      int64
		)
		if err := rows.Scan(&UserId, &Group, &ApplyHere, &ApplySub, &Allow, &Deny); err != nil {
			return err
		}

		aclEntry := acl.ACL{}
		aclEntry.ApplyHere = ApplyHere
		aclEntry.ApplySubs = ApplySub
		if len(UserId) > 0 {
			aclEntry.UserId, err = strconv.Atoi(UserId)
			if err != nil {
				return err
			}
		} else if len(Group) > 0 {
			aclEntry.Group = Group
		} else {
			return errors.New("Invalid ACL: Neither Group or UserId specified")
		}

		aclEntry.Deny = acl.Permission(Deny)
		aclEntry.Allow = acl.Permission(Allow)
		c.ACL.ACLs = append(c.ACL.ACLs, aclEntry)
	}

	return nil
}

// Populate channel with groups by reading the SQLite database.
func populateChannelGroupsFromDatabase(server *Server, c *Channel, db *sql.DB) error {
	stmt, err := db.Prepare("SELECT group_id, name, inherit, inheritable FROM groups WHERE server_id=? AND channel_id=?")
	if err != nil {
		return err
	}

	rows, err := stmt.Query(server.Id, c.Id)
	if err != nil {
		return err
	}

	groups := make(map[int64]acl.Group)

	for rows.Next() {
		var (
			GroupId     int64
			Name        string
			Inherit     bool
			Inheritable bool
		)

		if err := rows.Scan(&GroupId, &Name, &Inherit, &Inheritable); err != nil {
			return err
		}

		g := acl.EmptyGroupWithName(Name)
		g.Inherit = Inherit
		g.Inheritable = Inheritable
		c.ACL.Groups[g.Name] = g
		groups[GroupId] = g
	}

	stmt, err = db.Prepare("SELECT user_id, addit FROM group_members WHERE server_id=? AND group_id=?")
	if err != nil {
		return err
	}

	for gid, grp := range groups {
		rows, err = stmt.Query(server.Id, gid)
		if err != nil {
			return err
		}

		for rows.Next() {
			var (
				UserId int64
				Add    bool
			)

			if err := rows.Scan(&UserId, &Add); err != nil {
				return err
			}

			if Add {
				grp.Add[int(UserId)] = true
			} else {
				grp.Remove[int(UserId)] = true
			}
		}
	}

	return nil
}

// Populate the Server with Channels from the database.
func populateChannelsFromDatabase(server *Server, db *sql.DB, parentId int) error {
	parent, exists := server.Channels[parentId]
	if !exists {
		return errors.New("Non-existant parent")
	}

	stmt, err := db.Prepare("SELECT channel_id, name, inheritacl FROM channels WHERE server_id=? AND parent_id=?")
	if err != nil {
		return err
	}

	rows, err := stmt.Query(server.Id, parentId)
	if err != nil {
		return err
	}

	for rows.Next() {
		var (
			name    string
			chanid  int
			inherit bool
		)
		err = rows.Scan(&chanid, &name, &inherit)
		if err != nil {
			return err
		}

		c := NewChannel(chanid, name)
		server.Channels[c.Id] = c
		c.ACL.InheritACL = inherit
		parent.AddChild(c)
	}

	// Add channel_info
	for _, c := range parent.children {
		err = populateChannelInfoFromDatabase(server, c, db)
		if err != nil {
			return err
		}
	}

	// Add ACLs
	for _, c := range parent.children {
		err = populateChannelACLFromDatabase(server, c, db)
		if err != nil {
			return err
		}
	}

	// Add groups
	for _, c := range parent.children {
		err = populateChannelGroupsFromDatabase(server, c, db)
		if err != nil {
			return err
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
func populateChannelLinkInfo(server *Server, db *sql.DB) (err error) {
	stmt, err := db.Prepare("SELECT channel_id, link_id FROM channel_links WHERE server_id=?")
	if err != nil {
		return err
	}

	rows, err := stmt.Query(server.Id)
	if err != nil {
		return err
	}

	for rows.Next() {
		var (
			ChannelId int
			LinkId    int
		)
		if err := rows.Scan(&ChannelId, &LinkId); err != nil {
			return err
		}

		channel, exists := server.Channels[ChannelId]
		if !exists {
			return errors.New("Attempt to perform link operation on non-existant channel.")
		}

		other, exists := server.Channels[LinkId]
		if !exists {
			return errors.New("Attempt to perform link operation on non-existant channel.")
		}

		server.LinkChannels(channel, other)
	}

	return nil
}

func populateUsers(server *Server, db *sql.DB) (err error) {
	// Populate the server with regular user data
	stmt, err := db.Prepare("SELECT user_id, name, pw, lastchannel, texture, strftime('%s', last_active) FROM users WHERE server_id=?")
	if err != nil {
		return
	}

	rows, err := stmt.Query(server.Id)
	if err != nil {
		return
	}

	for rows.Next() {
		var (
			UserId       int64
			UserName     string
			SHA1Password string
			LastChannel  int
			Texture      []byte
			LastActive   int64
		)

		err = rows.Scan(&UserId, &UserName, &SHA1Password, &LastChannel, &Texture, &LastActive)
		if err != nil {
			continue
		}

		if UserId == 0 {
			server.cfg.Set("SuperUserPassword", "sha1$$"+SHA1Password)
		}

		user, err := NewUser(uint32(UserId), UserName)
		if err != nil {
			return err
		}

		if len(Texture) > 0 {
			key, err := blobStore.Put(Texture)
			if err != nil {
				return err
			}
			user.TextureBlob = key
		}

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
		rows, err = stmt.Query(server.Id, uid)
		if err != nil {
			return err
		}

		for rows.Next() {
			var (
				Key   int
				Value string
			)

			err = rows.Scan(&Key, &Value)
			if err != nil {
				return err
			}

			switch Key {
			case UserInfoEmail:
				user.Email = Value
			case UserInfoComment:
				key, err := blobStore.Put([]byte(Value))
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

// Populate bans
func populateBans(server *Server, db *sql.DB) (err error) {
	stmt, err := db.Prepare("SELECT base, mask, name, hash, reason, start, duration FROM bans WHERE server_id=?")
	if err != nil {
		return
	}

	rows, err := stmt.Query(server.Id)
	if err != nil {
		return err
	}

	for rows.Next() {
		var (
			Ban       ban.Ban
			IP        []byte
			StartDate string
			Duration  int64
		)

		err = rows.Scan(&IP, &Ban.Mask, &Ban.Username, &Ban.CertHash, &Ban.Reason, &StartDate, &Duration)
		if err != nil {
			return err
		}

		if len(IP) == 16 && IP[10] == 0xff && IP[11] == 0xff {
			Ban.IP = net.IPv4(IP[12], IP[13], IP[14], IP[15])
		} else {
			Ban.IP = IP
		}

		Ban.SetISOStartDate(StartDate)
		Ban.Duration = uint32(Duration)

		server.Bans = append(server.Bans, Ban)
	}

	return
}
