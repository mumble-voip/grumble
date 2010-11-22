// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"log"
	"mumbleproto"
	"goprotobuf.googlecode.com/hg/proto"
	"net"
	"cryptstate"
)

// These are the different kinds of messages
// that are defined for the Mumble protocol
const (
	MessageVersion = iota
	MessageUDPTunnel
	MessageAuthenticate
	MessagePing
	MessageReject
	MessageServerSync
	MessageChannelRemove
	MessageChannelState
	MessageUserRemove
	MessageUserState
	MessageBanList
	MessageTextMessage
	MessagePermissionDenied
	MessageACL
	MessageQueryUsers
	MessageCryptSetup
	MessageContextActionAdd
	MessageContextAction
	MessageUserList
	MessageVoiceTarget
	MessagePermissionQuery
	MessageCodecVersion
	MessageUserStats
	MessageRequestBlob
	MessageServerConfig
)

const (
	UDPMessageVoiceCELTAlpha = iota
	UDPMessagePing
	UDPMessageVoiceSpeex
	UDPMessageVoiceCELTBeta
)

type Message struct {
	buf []byte

	// Kind denotes a message kind for TCP packets. This field
	// is ignored for UDP packets.
	kind uint16

	// For UDP datagrams one of these fields have to be filled out.
	// If there is no connection established, address must be used.
	// If the datagram comes from an already-connected client, the
	// client field should point to that client.
	client  *Client
	address net.Addr
}

type VoiceBroadcast struct {
	// The client who is performing the broadcast
	client *Client
	// The VoiceTarget identifier.
	target byte
	// The voice packet itself.
	buf []byte
}

func (server *Server) handleCryptSetup(client *Client, msg *Message) {
	cs := &mumbleproto.CryptSetup{}
	err := proto.Unmarshal(msg.buf, cs)
	if err != nil {
		client.Panic(err.String())
		return
	}

	// No client nonce. This means the client
	// is requesting that we re-sync our nonces.
	if len(cs.ClientNonce) == 0 {
		log.Printf("Requested crypt-nonce resync")
		cs.ClientNonce = make([]byte, cryptstate.AESBlockSize)
		if copy(cs.ClientNonce, client.crypt.EncryptIV[0:]) != cryptstate.AESBlockSize {
			return
		}
		client.sendProtoMessage(MessageCryptSetup, cs)
	} else {
		log.Printf("Received client nonce")
		if len(cs.ClientNonce) != cryptstate.AESBlockSize {
			return
		}

		client.crypt.Resync += 1
		if copy(client.crypt.DecryptIV[0:], cs.ClientNonce) != cryptstate.AESBlockSize {
			return
		}
		log.Printf("Crypt re-sync successful")
	}
}

func (server *Server) handlePingMessage(client *Client, msg *Message) {
	ping := &mumbleproto.Ping{}
	err := proto.Unmarshal(msg.buf, ping)
	if err != nil {
		client.Panic(err.String())
		return
	}

	// Phony response for ping messages. We don't keep stats
	// for this yet.
	client.sendProtoMessage(MessagePing, &mumbleproto.Ping{
		Timestamp: ping.Timestamp,
		Good:      proto.Uint32(uint32(client.crypt.Good)),
		Late:      proto.Uint32(uint32(client.crypt.Late)),
		Lost:      proto.Uint32(uint32(client.crypt.Lost)),
		Resync:    proto.Uint32(uint32(client.crypt.Resync)),
	})
}

func (server *Server) handleChannelAddMessage(client *Client, msg *Message) {
}

func (server *Server) handleChannelRemoveMessage(client *Client, msg *Message) {
}

func (server *Server) handleChannelStateMessage(client *Client, msg *Message) {
}

func (server *Server) handleUserRemoveMessage(client *Client, msg *Message) {
}

func (server *Server) handleUserStateMessage(client *Client, msg *Message) {
	log.Printf("UserState!")
	userstate := &mumbleproto.UserState{}
	err := proto.Unmarshal(msg.buf, userstate)
	if err != nil {
		client.Panic(err.String())
	}

	if userstate.Session == nil {
		log.Printf("UserState without session.")
		return
	}

	actor := server.clients[client.Session]
	user := server.clients[*userstate.Session]

	log.Printf("actor = %v", actor)
	log.Printf("user = %v", user)

	userstate.Session = proto.Uint32(user.Session)
	userstate.Actor = proto.Uint32(actor.Session)

	// Has a channel ID
	if userstate.ChannelId != nil {
		// Destination channel
		dstChan, ok := server.channels[int(*userstate.ChannelId)]
		if !ok {
			return
		}

		// If the user and the actor aren't the same, check whether the actor has the 'move' permission
		// on the user's channel to move.
		if actor != user && !server.HasPermission(actor, user.Channel, MovePermission) {
			client.sendPermissionDenied(actor, user.Channel, MovePermission)
			return
		}

		// Check whether the actor has 'move' permissions on dstChan.  Check whether user has 'enter'
		// permissions on dstChan.
		if !server.HasPermission(actor, dstChan, MovePermission) && !server.HasPermission(user, dstChan, EnterPermission) {
			client.sendPermissionDenied(user, dstChan, EnterPermission)
			return
		}

		// Check whether the channel is full.
		// fixme(mkrautz): See above.
	}

	if userstate.Mute != nil || userstate.Deaf != nil || userstate.Suppress != nil || userstate.PrioritySpeaker != nil {
		// Disallow for SuperUser
		if user.UserId == 0 {
			client.sendPermissionDeniedType("SuperUser")
			return
		}

		// Check whether the actor has 'mutedeafen' permission on user's channel.
		if !server.HasPermission(actor, user.Channel, MuteDeafenPermission) {
			client.sendPermissionDenied(actor, user.Channel, MuteDeafenPermission)
			return
		}

		// Check if this was a suppress operation. Only the server can suppress users.
		if userstate.Suppress != nil {
			client.sendPermissionDenied(actor, user.Channel, MuteDeafenPermission)
			return
		}
	}

	// Comment set/clear
	if userstate.Comment != nil {
		comment := *userstate.Comment
		log.Printf("comment = %v", comment)

		// Clearing another user's comment.
		if user != actor {
			// Check if actor has 'move' permissions on the root channel. It is needed
			// to clear another user's comment.
			if !server.HasPermission(actor, server.root, MovePermission) {
				client.sendPermissionDenied(actor, server.root, MovePermission)
				return
			}

			// Only allow empty text.
			if len(comment) > 0 {
				return
			}
		}

		// Check if the text is allowed.

		// Only set the comment if it is different from the current
		// user comment.
	}

	// Texture change
	if userstate.Texture != nil {
		// Check the length of the texture
	}

	// Registration
	if userstate.UserId != nil {
		// If user == actor, check for 'selfregister' permission on root channel.
		// If user != actor, check for 'register' permission on root channel.
		permCheck := Permission(NonePermission)
		uid := *userstate.UserId
		if user == actor {
			permCheck = SelfRegisterPermission
		} else {
			permCheck = RegisterPermission
		}
		if uid >= 0 || !server.HasPermission(actor, server.root, SelfRegisterPermission) {
			client.sendPermissionDenied(actor, server.root, permCheck)
			return
		}

		// If user's hash is empty, deny...
		// fixme(mkrautz)
	}

	// Prevent self-targetting state changes to be applied to other users
	// That is, if actor != user, then:
	//   Discard message if it has any of the following things set:
	//      - SelfDeaf
	//      - SelfMute
	//      - Texture
	//      - PluginContext
	//      - PluginIdentity
	//      - Recording
	if actor != user && (userstate.SelfDeaf != nil || userstate.SelfMute != nil ||
		userstate.Texture != nil || userstate.PluginContext != nil || userstate.PluginIdentity != nil ||
		userstate.Recording != nil) {
		return
	}

}

func (server *Server) handleBanListMessage(client *Client, msg *Message) {
}

// Broadcast text messages
func (server *Server) handleTextMessage(client *Client, msg *Message) {
	txtmsg := &mumbleproto.TextMessage{}
	err := proto.Unmarshal(msg.buf, txtmsg)
	if err != nil {
		client.Panic(err.String())
		return
	}

	// fixme(mkrautz): Check text message length.
	// fixme(mkrautz): Sanitize text as well.

	users := make(map[uint32]*Client)

	// Tree
	for _, chanid := range txtmsg.TreeId {
		if channel, ok := server.channels[int(chanid)]; ok {
			if !server.HasPermission(client, channel, TextMessagePermission) {
				client.sendPermissionDenied(client, channel, TextMessagePermission)
			}
			for _, user := range channel.clients {
				users[user.Session] = user
			}
		}
	}

	// Direct-to-channel
	for _, chanid := range txtmsg.ChannelId {
		if channel, ok := server.channels[int(chanid)]; ok {
			if !server.HasPermission(client, channel, TextMessagePermission) {
				client.sendPermissionDenied(client, channel, TextMessagePermission)
				return
			}
			for _, user := range channel.clients {
				users[user.Session] = user
			}
		}
	}

	// Direct-to-users
	for _, session := range txtmsg.Session {
		if user, ok := server.clients[session]; ok {
			if !server.HasPermission(client, user.Channel, TextMessagePermission) {
				client.sendPermissionDenied(client, user.Channel, TextMessagePermission)
				return
			}
			users[session] = user
		}
	}

	// Remove ourselves
	users[client.Session] = nil, false

	for _, user := range users {
		user.sendProtoMessage(MessageTextMessage, &mumbleproto.TextMessage{
			Actor:   proto.Uint32(client.Session),
			Message: txtmsg.Message,
		})
	}
}

// ACL set/query
func (server *Server) handleAclMessage(client *Client, msg *Message) {
	acl := &mumbleproto.ACL{}
	err := proto.Unmarshal(msg.buf, acl)
	if err != nil {
		client.Panic(err.String())
	}

	// Look up the channel this ACL message operates on.
	channel, ok := server.channels[int(*acl.ChannelId)]
	if !ok {
		return
	}

	// Does the user have permission to update or look at ACLs?
	if !server.HasPermission(client, channel, WritePermission) && !(channel.parent != nil && server.HasPermission(client, channel.parent, WritePermission)) {
		client.sendPermissionDenied(client, channel, WritePermission)
		return
	}

	reply := &mumbleproto.ACL{}
	reply.ChannelId = proto.Uint32(uint32(channel.Id))

	channels := []*Channel{}
	users := map[int]bool{}

	// Query the current ACL state for the channel
	if acl.Query != nil && *acl.Query != false {
		reply.InheritAcls = proto.Bool(channel.InheritACL)
		// Walk the channel tree to get all relevant channels.
		// (Stop if we reach a channel that doesn't have the InheritACL flag set)
		iter := channel
		for iter != nil {
			channels = append([]*Channel{iter}, channels...)
			if iter == channel || iter.InheritACL {
				iter = iter.parent
			} else {
				iter = nil
			}
		}

		// Construct the protobuf ChanACL objects corresponding to the ACLs defined
		// in our channel list.
		reply.Acls = []*mumbleproto.ACL_ChanACL{}
		for _, iter := range channels {
			for _, chanacl := range iter.ACL {
				if iter == channel || chanacl.ApplySubs {
					mpacl := &mumbleproto.ACL_ChanACL{}
					mpacl.Inherited = proto.Bool(iter != channel)
					mpacl.ApplyHere = proto.Bool(chanacl.ApplyHere)
					mpacl.ApplySubs = proto.Bool(chanacl.ApplySubs)
					if chanacl.UserId >= 0 {
						mpacl.UserId = proto.Uint32(uint32(chanacl.UserId))
						users[chanacl.UserId] = true
					} else {
						mpacl.Group = proto.String(chanacl.Group)
					}
					mpacl.Grant = proto.Uint32(uint32(chanacl.Allow))
					mpacl.Deny = proto.Uint32(uint32(chanacl.Deny))
					reply.Acls = append(reply.Acls, mpacl)
				}
			}
		}

		parent := channel.parent
		allnames := channel.GroupNames()

		// Construct the protobuf ChanGroups that we send back to the client.
		// Also constructs a usermap that is a set user ids from the channel's groups.
		reply.Groups = []*mumbleproto.ACL_ChanGroup{}
		for name, _ := range allnames {
			group := channel.Groups[name]
			pgroup, ok := parent.Groups[name]
			if !ok {
				pgroup = nil
			}

			mpgroup := &mumbleproto.ACL_ChanGroup{}
			mpgroup.Name = proto.String(name)

			mpgroup.Inherit = proto.Bool(true)
			if group != nil {
				mpgroup.Inherit = proto.Bool(group.Inherit)
			}

			mpgroup.Inheritable = proto.Bool(true)
			if group != nil {
				mpgroup.Inheritable = proto.Bool(group.Inheritable)
			}

			mpgroup.Inherited = proto.Bool(pgroup != nil && pgroup.Inheritable)

			// Add the set of user ids that this group affects to the user map.
			// This is used later on in this function to send the client a QueryUsers
			// message that maps user ids to usernames.
			if group != nil {
				toadd := map[int]bool{}
				for uid, _ := range group.Add {
					users[uid] = true
					toadd[uid] = true
				}
				for uid, _ := range group.Remove {
					users[uid] = true
					toadd[uid] = false, false
				}
				for uid, _ := range toadd {
					mpgroup.Add = append(mpgroup.Add, uint32(uid))
				}
			}
			if pgroup != nil {
				for uid, _ := range pgroup.Members() {
					users[uid] = true
					mpgroup.InheritedMembers = append(mpgroup.InheritedMembers, uint32(uid))
				}
			}

			reply.Groups = append(reply.Groups, mpgroup)
		}

		if err := client.sendProtoMessage(MessageACL, reply); err != nil {
			client.Panic(err.String())
		}

		// Map the user ids in the user map to usernames of users.
		// fixme(mkrautz): This requires a persistent datastore, because it retrieves registered users.
		queryusers := &mumbleproto.QueryUsers{}
		for uid, _ := range users {
			queryusers.Ids = append(queryusers.Ids, uint32(uid))
			queryusers.Names = append(queryusers.Names, "Unknown")
		}
		if len(queryusers.Ids) > 0 {
			client.sendProtoMessage(MessageQueryUsers, reply)
		}

		// Set new groups and ACLs
	} else {

		// Get old temporary members
		oldtmp := map[string]map[int]bool{}
		for name, grp := range channel.Groups {
			oldtmp[name] = grp.Temporary
		}

		// Clear current ACLs and groups
		channel.ACL = []*ChannelACL{}
		channel.Groups = map[string]*Group{}

		// Add the received groups to the channel.
		channel.InheritACL = *acl.InheritAcls
		for _, pbgrp := range acl.Groups {
			changroup := NewGroup(channel, *pbgrp.Name)

			changroup.Inherit = *pbgrp.Inherit
			changroup.Inheritable = *pbgrp.Inheritable
			for _, uid := range pbgrp.Add {
				changroup.Add[int(uid)] = true
			}
			for _, uid := range pbgrp.Remove {
				changroup.Remove[int(uid)] = true
			}
			if temp, ok := oldtmp[*pbgrp.Name]; ok {
				changroup.Temporary = temp
			}

			channel.Groups[changroup.Name] = changroup
		}
		// Add the received ACLs to the channel.
		for _, pbacl := range acl.Acls {
			chanacl := NewChannelACL(channel)

			chanacl.ApplyHere = *pbacl.ApplyHere
			chanacl.ApplySubs = *pbacl.ApplySubs
			if pbacl.UserId != nil {
				chanacl.UserId = int(*pbacl.UserId)
			} else {
				chanacl.Group = *pbacl.Group
			}
			chanacl.Deny = Permission(*pbacl.Deny & AllPermissions)
			chanacl.Allow = Permission(*pbacl.Grant & AllPermissions)

			channel.ACL = append(channel.ACL, chanacl)
		}

		// Clear the server's ACL cache
		server.ClearACLCache()

		// Regular user?
		if (!server.HasPermission(client, channel, WritePermission) && client.UserId >= 0) || len(client.Hash) > 0 {
			chanacl := NewChannelACL(channel)

			chanacl.ApplyHere = true
			chanacl.ApplySubs = false
			if client.UserId >= 0 {
				chanacl.UserId = client.UserId
			} else {
				chanacl.Group = "$" + client.Hash
			}
			chanacl.UserId = client.UserId
			chanacl.Deny = Permission(NonePermission)
			chanacl.Allow = Permission(WritePermission | TraversePermission)

			channel.ACL = append(channel.ACL, chanacl)

			server.ClearACLCache()
		}

		// fixme(mkrautz): Sync channel to datastore
	}
}

// User query
func (server *Server) handleQueryUsers(client *Client, msg *Message) {
}

// User stats message. Shown in the Mumble client when a
// user right clicks a user and selects 'User Information'.
func (server *Server) handleUserStatsMessage(client *Client, msg *Message) {
	stats := &mumbleproto.UserStats{}
	err := proto.Unmarshal(msg.buf, stats)
	if err != nil {
		client.Panic(err.String())
	}

	log.Printf("UserStats")
}

// Permission query
func (server *Server) handlePermissionQuery(client *Client, msg *Message) {
	query := &mumbleproto.PermissionQuery{}
	err := proto.Unmarshal(msg.buf, query)
	if err != nil {
		client.Panic(err.String())
	}

	if query.ChannelId == nil {
		return
	}

	channel := server.channels[int(*query.ChannelId)]
	server.sendClientPermissions(client, channel)
}
