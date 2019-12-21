// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"mumble.info/grumble/pkg/acl"
	"mumble.info/grumble/pkg/ban"
	"mumble.info/grumble/pkg/freezer"
	"mumble.info/grumble/pkg/mumbleproto"
	"mumble.info/grumble/pkg/serverconf"
)

// FreezeToFile will freeze a server to disk and closes the log file.
// This must be called from within the Server's synchronous handler.
func (server *Server) FreezeToFile() error {
	// See freeeze_{windows,unix}.go for real implementations.
	err := server.freezeToFile()
	if err != nil {
		return err
	}

	if server.running {
		// Re-open the freeze log.
		err = server.openFreezeLog()
		if err != nil {
			return err
		}
	}

	return nil
}

// Open a new freeze log.
func (server *Server) openFreezeLog() error {
	if server.freezelog != nil {
		err := server.freezelog.Close()
		if err != nil {
			return err
		}
		server.freezelog = nil
	}

	logfn := filepath.Join(Args.DataDir, "servers", strconv.FormatInt(server.ID, 10), "log.fz")
	err := os.Remove(logfn)
	if os.IsNotExist(err) {
		// fallthrough
	} else if err != nil {
		return err
	}

	server.freezelog, err = freezer.NewLogFile(logfn)
	if err != nil {
		return err
	}

	return nil
}

// Freeze a server to a flattened protobuf-based structure ready to
// persist to disk.
func (server *Server) Freeze() (fs *freezer.Server, err error) {
	fs = new(freezer.Server)

	// Freeze all config kv-pairs
	allCfg := server.cfg.GetAll()
	for k, v := range allCfg {
		fs.Config = append(fs.Config, &freezer.ConfigKeyValuePair{
			Key:   proto.String(k),
			Value: proto.String(v),
		})
	}

	// Freeze all bans
	server.banlock.RLock()
	fs.BanList = &freezer.BanList{}
	fs.BanList.Bans = make([]*freezer.Ban, len(server.Bans))
	for i := 0; i < len(server.Bans); i++ {
		fs.BanList.Bans[i] = FreezeBan(server.Bans[i])
	}
	server.banlock.RUnlock()

	// Freeze all channels
	channels := []*freezer.Channel{}
	for _, c := range server.Channels {
		fc, err := c.Freeze()
		if err != nil {
			return nil, err
		}
		channels = append(channels, fc)
	}
	fs.Channels = channels

	// Freeze all registered users
	users := []*freezer.User{}
	for _, u := range server.Users {
		fu, err := u.Freeze()
		if err != nil {
			return nil, err
		}
		users = append(users, fu)
	}
	fs.Users = users

	return fs, nil
}

// UnfreezeBanList will merge the contents of a freezer.BanList into the server's
// ban list.
func (server *Server) UnfreezeBanList(fblist *freezer.BanList) {
	server.Bans = nil
	for _, fb := range fblist.Bans {
		ban := ban.Ban{}

		ban.IP = fb.Ip
		if fb.Mask != nil {
			ban.Mask = int(*fb.Mask)
		}
		if fb.Username != nil {
			ban.Username = *fb.Username
		}
		if fb.CertHash != nil {
			ban.CertHash = *fb.CertHash
		}
		if fb.Reason != nil {
			ban.Reason = *fb.Reason
		}
		if fb.Start != nil {
			ban.Start = *fb.Start
		}
		if fb.Duration != nil {
			ban.Duration = *fb.Duration
		}

		server.Bans = append(server.Bans, ban)
	}
}

// FreezeBan will freeze a ban into a flattened protobuf-based struct
// ready to be persisted to disk.
func FreezeBan(ban ban.Ban) (fb *freezer.Ban) {
	fb = new(freezer.Ban)

	fb.Ip = ban.IP
	fb.Mask = proto.Uint32(uint32(ban.Mask))
	fb.Username = proto.String(ban.Username)
	fb.CertHash = proto.String(ban.CertHash)
	fb.Reason = proto.String(ban.Reason)
	fb.Start = proto.Int64(ban.Start)
	fb.Duration = proto.Uint32(ban.Duration)
	return
}

// Freeze a channel into a flattened protobuf-based struct
// ready to be persisted to disk.
func (channel *Channel) Freeze() (fc *freezer.Channel, err error) {
	fc = new(freezer.Channel)

	fc.Id = proto.Uint32(uint32(channel.ID))
	fc.Name = proto.String(channel.Name)
	if channel.parent != nil {
		fc.ParentId = proto.Uint32(uint32(channel.parent.ID))
	}
	fc.Position = proto.Int64(int64(channel.Position))
	fc.InheritACL = proto.Bool(channel.ACL.InheritACL)

	// Freeze the channel's ACLs
	acls := []*freezer.ACL{}
	for _, acl := range channel.ACL.ACLs {
		facl, err := FreezeACL(acl)
		if err != nil {
			return nil, err
		}
		acls = append(acls, facl)
	}
	fc.ACL = acls

	// Freeze the channel's groups
	groups := []*freezer.Group{}
	for _, grp := range channel.ACL.Groups {
		fgrp, err := FreezeGroup(grp)
		if err != nil {
			return nil, err
		}
		groups = append(groups, fgrp)
	}
	fc.Groups = groups

	// Add linked channels
	links := []uint32{}
	for cid := range channel.Links {
		links = append(links, uint32(cid))
	}
	fc.Links = links

	// Blobstore reference to the channel's description.
	fc.DescriptionBlob = proto.String(channel.DescriptionBlob)

	return
}

// Unfreeze unfreezes the contents of a freezer.Channel
// into a channel.
func (channel *Channel) Unfreeze(fc *freezer.Channel) {
	if fc.Name != nil {
		channel.Name = *fc.Name
	}
	if fc.Position != nil {
		channel.Position = int(*fc.Position)
	}
	if fc.InheritACL != nil {
		channel.ACL.InheritACL = *fc.InheritACL
	}
	if fc.DescriptionBlob != nil {
		channel.DescriptionBlob = *fc.DescriptionBlob
	}

	// Update ACLs
	if fc.ACL != nil {
		channel.ACL.ACLs = nil
		for _, facl := range fc.ACL {
			aclEntry := acl.ACL{}
			if facl.ApplyHere != nil {
				aclEntry.ApplyHere = *facl.ApplyHere
			}
			if facl.ApplySubs != nil {
				aclEntry.ApplySubs = *facl.ApplySubs
			}
			if facl.UserID != nil {
				aclEntry.UserID = int(*facl.UserID)
			} else {
				aclEntry.UserID = -1
			}
			if facl.Group != nil {
				aclEntry.Group = *facl.Group
			}
			if facl.Deny != nil {
				aclEntry.Deny = acl.Permission(*facl.Deny)
			}
			if facl.Allow != nil {
				aclEntry.Allow = acl.Permission(*facl.Allow)
			}
			channel.ACL.ACLs = append(channel.ACL.ACLs, aclEntry)
		}
	}

	// Update groups
	if fc.Groups != nil {
		channel.ACL.Groups = make(map[string]acl.Group)
		for _, fgrp := range fc.Groups {
			if fgrp.Name == nil {
				continue
			}
			g := acl.Group{}
			if fgrp.Inherit != nil {
				g.Inherit = *fgrp.Inherit
			}
			if fgrp.Inheritable != nil {
				g.Inheritable = *fgrp.Inheritable
			}
			for _, uid := range fgrp.Add {
				g.Add[int(uid)] = true
			}
			for _, uid := range fgrp.Remove {
				g.Remove[int(uid)] = true
			}
			channel.ACL.Groups[g.Name] = g
		}
	}

	// Hook up links, but make them point to the channel itself.
	// We can't be sure that the channels the links point to exist
	// yet, so we delay hooking up the map 'correctly' to later.
	if fc.Links != nil {
		channel.Links = make(map[int]*Channel)
		for _, link := range fc.Links {
			channel.Links[int(link)] = channel
		}
	}
}

// Freeze a User into a flattened protobuf-based structure
// ready to be persisted to disk.
func (user *User) Freeze() (fu *freezer.User, err error) {
	fu = new(freezer.User)

	fu.Id = proto.Uint32(user.ID)
	fu.Name = proto.String(user.Name)
	fu.CertHash = proto.String(user.CertHash)
	fu.Email = proto.String(user.Email)
	fu.TextureBlob = proto.String(user.TextureBlob)
	fu.CommentBlob = proto.String(user.CommentBlob)
	fu.LastChannelID = proto.Uint32(uint32(user.LastChannelID))
	fu.LastActive = proto.Uint64(user.LastActive)

	return
}

// Unfreeze will merge the contents of a frozen User into an existing user struct.
func (user *User) Unfreeze(fu *freezer.User) {
	if fu.Name != nil {
		user.Name = *fu.Name
	}
	if fu.CertHash != nil {
		user.CertHash = *fu.CertHash
	}
	if fu.Email != nil {
		user.Email = *fu.Email
	}
	if fu.TextureBlob != nil {
		user.TextureBlob = *fu.TextureBlob
	}
	if fu.CommentBlob != nil {
		user.CommentBlob = *fu.CommentBlob
	}
	if fu.LastChannelID != nil {
		user.LastChannelID = int(*fu.LastChannelID)
	}
	if fu.LastActive != nil {
		user.LastActive = *fu.LastActive
	}
}

// FreezeACL will freeze a ChannelACL into it a flattened protobuf-based structure
// ready to be persisted to disk.
func FreezeACL(aclEntry acl.ACL) (*freezer.ACL, error) {
	frozenACL := &freezer.ACL{}
	if aclEntry.UserID != -1 {
		frozenACL.UserID = proto.Uint32(uint32(aclEntry.UserID))
	} else {
		frozenACL.Group = proto.String(aclEntry.Group)
	}
	frozenACL.ApplyHere = proto.Bool(aclEntry.ApplyHere)
	frozenACL.ApplySubs = proto.Bool(aclEntry.ApplySubs)
	frozenACL.Allow = proto.Uint32(uint32(aclEntry.Allow))
	frozenACL.Deny = proto.Uint32(uint32(aclEntry.Deny))
	return frozenACL, nil
}

// FreezeGroup will freeze a Group into a flattened protobuf-based structure
// ready to be persisted to disk.
func FreezeGroup(group acl.Group) (*freezer.Group, error) {
	frozenGroup := &freezer.Group{}
	frozenGroup.Name = proto.String(group.Name)
	frozenGroup.Inherit = proto.Bool(group.Inherit)
	frozenGroup.Inheritable = proto.Bool(group.Inheritable)
	for _, id := range group.AddUsers() {
		frozenGroup.Add = append(frozenGroup.Add, uint32(id))
	}
	for _, id := range group.RemoveUsers() {
		frozenGroup.Remove = append(frozenGroup.Remove, uint32(id))
	}
	return frozenGroup, nil
}

// NewServerFromFrozen will create a new server from its on-disk representation.
//
// This will read a full serialized server (typically stored in
// a file called 'main.fz') from disk.  It will also check for
// a log file ('log.fz') and iterate through the entries of the log
// file and apply the updates incrementally to the server.
//
// Once both the full server and the log file has been merged together
// in memory, a new full seralized server will be written and synced to
// disk, and the existing log file will be removed.
func NewServerFromFrozen(name string) (s *Server, err error) {
	id, err := strconv.ParseInt(name, 10, 64)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(Args.DataDir, "servers", name)
	mainFile := filepath.Join(path, "main.fz")
	backupFile := filepath.Join(path, "backup.fz")
	logFn := filepath.Join(path, "log.fz")

	r, err := os.Open(mainFile)
	if os.IsNotExist(err) {
		err = os.Rename(backupFile, mainFile)
		if err != nil {
			return nil, err
		}
		r, err = os.Open(mainFile)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	defer r.Close()

	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal the server from it's frozen state
	fs := freezer.Server{}
	err = proto.Unmarshal(buf, &fs)
	if err != nil {
		return nil, err
	}

	// Create a config map from the frozen server.
	cfgMap := map[string]string{}
	for _, cfgEntry := range fs.Config {
		if cfgEntry.Key != nil && cfgEntry.Value != nil {
			cfgMap[*cfgEntry.Key] = *cfgEntry.Value
		}
	}

	s, err = NewServer(id)
	if err != nil {
		return nil, err
	}
	s.cfg = serverconf.New(cfgMap)

	// Unfreeze the server's frozen bans.
	s.UnfreezeBanList(fs.BanList)

	// Add all channels, but don't hook up parent/child relationships
	// until after we've walked the log file. No need to make it harder
	// than it really is.
	parents := make(map[uint32]uint32)
	for _, fc := range fs.Channels {
		// The frozen channel must contain an Id and a Name,
		// since the server's frozen channels are guaranteed to
		// not be deltas.
		if fc.Id == nil || fc.Name == nil {
			continue
		}

		// Create the channel on the server.
		// Update the server's nextChanId field if it needs to be,
		// to make sure the server doesn't re-use channel id's.
		c := NewChannel(int(*fc.Id), *fc.Name)
		if c.ID >= s.nextChanID {
			s.nextChanID = c.ID + 1
		}

		// Update the channel with the contents of the freezer.Channel.
		c.Unfreeze(fc)

		// Add the channel's id to the server's channel-id-map.
		s.Channels[c.ID] = c

		// Mark the channel's parent
		if fc.ParentId != nil {
			parents[*fc.Id] = *fc.ParentId
		} else {
			delete(parents, *fc.Id)
		}
	}

	// Add all users
	for _, fu := range fs.Users {
		if fu.Id == nil && fu.Name == nil {
			continue
		}
		u, err := NewUser(*fu.Id, *fu.Name)
		if err != nil {
			return nil, err
		}
		if u.ID >= s.nextUserID {
			s.nextUserID = u.ID + 1
		}

		// Merge the contents of the freezer.User into
		// the user struct.
		u.Unfreeze(fu)

		// Update the server's user maps to point correctly
		// to the new user.
		s.Users[u.ID] = u
		s.UserNameMap[u.Name] = u
		if len(u.CertHash) > 0 {
			s.UserCertMap[u.CertHash] = u
		}
	}

	// Attempt to walk the stored log file
	logFile, err := os.Open(logFn)
	walker, err := freezer.NewReaderWalker(logFile)
	if err != nil {
		return nil, err
	}

	for {
		values, err := walker.Next()
		if err == io.EOF {
			err = logFile.Close()
			if err != nil {
				return nil, err
			}
			break
		} else if err != nil {
			return nil, err
		}

		for _, val := range values {
			switch val.(type) {
			case *freezer.User:
				fu := val.(*freezer.User)
				// Check if it's a valid freezer.User message. It must at least
				// have the Id field filled out for us to be able to do anything
				// with it. Warn the admin if an illegal entry is encountered.
				if fu.Id == nil {
					log.Printf("Skipped User log entry: No id given.")
					continue
				}

				userID := *fu.Id

				// Determine whether the user already exists on the server or not.
				// If the user already exists, this log entry simply updates the
				// data for that user.
				// If the user doesn't exist, we create it with the data given in
				// this log entry.
				user, ok := s.Users[userID]
				if !ok {
					// If no name is given in the log entry, skip this entry.
					// Also, warn the admin.
					if fu.Name == nil {
						log.Printf("Skipped User creation log entry: No name given.")
						continue
					}
					// Create the new user and increment the UserID
					// counter for the server if needed.
					user, err = NewUser(userID, *fu.Name)
					if err != nil {
						return nil, err
					}
					if user.ID >= s.nextUserID {
						s.nextUserID = user.ID + 1
					}
				}

				// Merge the contents of the frozen.User into the
				// user struct.
				user.Unfreeze(fu)

				// Update the various user maps in the server to
				// be able to correctly look up the user.
				s.Users[user.ID] = user
				s.UserNameMap[user.Name] = user
				if len(user.CertHash) > 0 {
					s.UserCertMap[user.CertHash] = user
				}

			case *freezer.UserRemove:
				fu := val.(*freezer.UserRemove)
				// Check for an invalid message and warn if appropriate.
				if fu.Id == nil {
					log.Printf("Skipped UserRemove log entry: No id given.")
					continue
				}

				userID := *fu.Id

				// Does this user even exist?
				// Warn if we encounter an illegal delete op.
				user, ok := s.Users[userID]
				if ok {
					// Clear the server maps. That should do it.
					delete(s.Users, userID)
					delete(s.UserNameMap, user.Name)
					if len(user.CertHash) > 0 {
						delete(s.UserCertMap, user.CertHash)
					}
				} else {
					log.Printf("Skipped UserRemove log entry: No user for given id.")
					continue
				}

			case *freezer.Channel:
				fc := val.(*freezer.Channel)
				// Check whether the log entry is legal.
				if fc.Id == nil {
					log.Printf("Skipped Channel log entry: No id given.")
					continue
				}

				channelID := int(*fc.Id)

				channel, alreadyExists := s.Channels[channelID]
				if !alreadyExists {
					if fc.Name == nil {
						log.Printf("Skipped Channel creation log entry: No name given.")
						continue
					}
					// Add the channel and increment the server's
					// nextChanId field to a consistent state.
					channel = NewChannel(channelID, *fc.Name)
					if channel.ID >= s.nextChanID {
						s.nextChanID = channel.ID + 1
					}
				}

				// Unfreeze the contents of the frozen channel
				// into the existing or newly-created channel.
				channel.Unfreeze(fc)
				// Re-add it to the server's channel map (in case
				// the channel was newly-created)
				s.Channels[channelID] = channel

				// Mark the channel's parent
				if !alreadyExists {
					if fc.ParentId != nil {
						parents[*fc.Id] = *fc.ParentId
					} else {
						delete(parents, *fc.Id)
					}
				}

			case *freezer.ChannelRemove:
				fc := val.(*freezer.ChannelRemove)
				if fc.Id == nil {
					log.Printf("Skipped ChannelRemove log entry: No id given.")
					continue
				}
				s.Channels[int(*fc.Id)] = nil
				delete(parents, *fc.Id)

			case *freezer.BanList:
				fbl := val.(*freezer.BanList)
				s.UnfreezeBanList(fbl)

			case *freezer.ConfigKeyValuePair:
				fcfg := val.(*freezer.ConfigKeyValuePair)
				if fcfg.Key != nil {
					// It's an update operation
					if fcfg.Value != nil {
						s.cfg.Set(*fcfg.Key, *fcfg.Value)
						// It's a delete/reset operation.
					} else {
						s.cfg.Reset(*fcfg.Key)
					}
				}
			}
		}
	}

	// Hook up children with their parents
	for chanID, parentID := range parents {
		childChan, exists := s.Channels[int(chanID)]
		if !exists {
			return nil, errors.New("Non-existant child channel")
		}
		parentChan, exists := s.Channels[int(parentID)]
		if !exists {
			return nil, errors.New("Non-existant parent channel")
		}
		parentChan.AddChild(childChan)
	}

	// Hook up all channel links
	for _, channel := range s.Channels {
		if len(channel.Links) > 0 {
			links := channel.Links
			channel.Links = make(map[int]*Channel)
			for chanID := range links {
				targetChannel := s.Channels[chanID]
				if targetChannel != nil {
					s.LinkChannels(channel, targetChannel)
				}
			}
		}
	}

	return s, nil
}

// UpdateFrozenUser will update the datastore with the user's current state.
func (server *Server) UpdateFrozenUser(client *Client, state *mumbleproto.UserState) {
	// Full sync If there's no userstate messgae provided, or if there is one, and
	// it includes a registration operation.
	user := client.user
	nanos := time.Now().Unix()
	if state == nil || state.UserID != nil {
		fu, err := user.Freeze()
		if err != nil {
			server.Fatal(err)
		}
		fu.LastActive = proto.Uint64(uint64(nanos))
		err = server.freezelog.Put(fu)
		if err != nil {
			server.Fatal(err)
		}
	} else {
		fu := &freezer.User{}
		fu.Id = proto.Uint32(user.ID)
		if state.ChannelId != nil {
			fu.LastChannelID = proto.Uint32(uint32(client.Channel.ID))
		}
		if state.TextureHash != nil {
			fu.TextureBlob = proto.String(user.TextureBlob)
		}
		if state.CommentHash != nil {
			fu.CommentBlob = proto.String(user.CommentBlob)
		}
		fu.LastActive = proto.Uint64(uint64(nanos))
		err := server.freezelog.Put(fu)
		if err != nil {
			server.Fatal(err)
		}
	}
	server.numLogOps++
}

// UpdateFrozenUserLastChannel will update a user's last active channel
func (server *Server) UpdateFrozenUserLastChannel(client *Client) {
	if client.IsRegistered() {
		user := client.user

		fu := &freezer.User{}
		fu.Id = proto.Uint32(user.ID)
		fu.LastChannelID = proto.Uint32(uint32(client.Channel.ID))
		fu.LastActive = proto.Uint64(uint64(time.Now().Unix()))

		err := server.freezelog.Put(fu)
		if err != nil {
			server.Fatal(err)
		}

		server.numLogOps++
	}
}

// DeleteFrozenUser will mark a user as deleted in the datstore.
func (server *Server) DeleteFrozenUser(user *User) {
	err := server.freezelog.Put(&freezer.UserRemove{Id: proto.Uint32(user.ID)})
	if err != nil {
		server.Fatal(err)
	}
	server.numLogOps++
}

// UpdateFrozenChannel will, given a target channel and a ChannelState protocol message, create a freezer.Channel that
// only includes the values changed by the given ChannelState message.  When done, write that
// frozen.Channel to the datastore.
func (server *Server) UpdateFrozenChannel(channel *Channel, state *mumbleproto.ChannelState) {
	fc := &freezer.Channel{}
	fc.Id = proto.Uint32(uint32(channel.ID))
	if state.Name != nil {
		fc.Name = state.Name
	}
	if state.Parent != nil {
		fc.ParentId = state.Parent
	}
	if len(state.LinksAdd) > 0 || len(state.LinksRemove) > 0 {
		links := []uint32{}
		for cid := range channel.Links {
			links = append(links, uint32(cid))
		}
		fc.Links = links
	}
	if state.Position != nil {
		fc.Position = proto.Int64(int64(*state.Position))
	}
	if len(state.DescriptionHash) > 0 {
		fc.DescriptionBlob = proto.String(channel.DescriptionBlob)
	}
	err := server.freezelog.Put(fc)
	if err != nil {
		server.Fatal(err)
	}
	server.numLogOps++
}

// UpdateFrozenChannelACLs writes a channel's ACL and Group data to disk. Mumble doesn't support
// incremental ACL updates and as such we must write all ACLs and groups
// to the datastore on each change.
func (server *Server) UpdateFrozenChannelACLs(channel *Channel) {
	fc := &freezer.Channel{}

	fc.Id = proto.Uint32(uint32(channel.ID))
	fc.InheritACL = proto.Bool(channel.ACL.InheritACL)

	acls := []*freezer.ACL{}
	for _, aclEntry := range channel.ACL.ACLs {
		facl, err := FreezeACL(aclEntry)
		if err != nil {
			return
		}
		acls = append(acls, facl)
	}
	fc.ACL = acls

	groups := []*freezer.Group{}
	for _, grp := range channel.ACL.Groups {
		fgrp, err := FreezeGroup(grp)
		if err != nil {
			return
		}
		groups = append(groups, fgrp)
	}
	fc.Groups = groups

	err := server.freezelog.Put(fc)
	if err != nil {
		server.Fatal(err)
	}
	server.numLogOps++
}

// DeleteFrozenChannel will mark a channel as deleted in the datastore.
func (server *Server) DeleteFrozenChannel(channel *Channel) {
	err := server.freezelog.Put(&freezer.ChannelRemove{Id: proto.Uint32(uint32(channel.ID))})
	if err != nil {
		server.Fatal(err)
	}
	server.numLogOps++
}

// UpdateFrozenBans writes the server's banlist to the datastore.
func (server *Server) UpdateFrozenBans(bans []ban.Ban) {
	fbl := &freezer.BanList{}
	for _, ban := range server.Bans {
		fbl.Bans = append(fbl.Bans, FreezeBan(ban))
	}
	err := server.freezelog.Put(fbl)
	if err != nil {
		server.Fatal(err)
	}
	server.numLogOps++
}

// UpdateConfig writes an updated config value to the datastore.
func (server *Server) UpdateConfig(key, value string) {
	fcfg := &freezer.ConfigKeyValuePair{
		Key:   proto.String(key),
		Value: proto.String(value),
	}
	err := server.freezelog.Put(fcfg)
	if err != nil {
		server.Fatal(err)
	}
	server.numLogOps++
}

// ResetConfig writes to the freezelog that the config with key
// has been reset to its default value.
func (server *Server) ResetConfig(key string) {
	fcfg := &freezer.ConfigKeyValuePair{
		Key: proto.String(key),
	}
	err := server.freezelog.Put(fcfg)
	if err != nil {
		server.Fatal(err)
	}
	server.numLogOps++
}
