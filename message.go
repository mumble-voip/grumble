// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"crypto/aes"
	"crypto/tls"
	"mumbleproto"
	"goprotobuf.googlecode.com/hg/proto"
	"net"
	"fmt"
	"grumble/ban"
	"grumble/blobstore"
	"time"
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
		client.Printf("Requested crypt-nonce resync")
		cs.ClientNonce = make([]byte, aes.BlockSize)
		if copy(cs.ClientNonce, client.crypt.EncryptIV[0:]) != aes.BlockSize {
			return
		}
		client.sendProtoMessage(MessageCryptSetup, cs)
	} else {
		client.Printf("Received client nonce")
		if len(cs.ClientNonce) != aes.BlockSize {
			return
		}

		client.crypt.Resync += 1
		if copy(client.crypt.DecryptIV[0:], cs.ClientNonce) != aes.BlockSize {
			return
		}
		client.Printf("Crypt re-sync successful")
	}
}

func (server *Server) handlePingMessage(client *Client, msg *Message) {
	ping := &mumbleproto.Ping{}
	err := proto.Unmarshal(msg.buf, ping)
	if err != nil {
		client.Panic(err.String())
		return
	}

	if ping.Good != nil {
		client.crypt.RemoteGood = uint32(*ping.Good)
	}
	if ping.Late != nil {
		client.crypt.RemoteLate = *ping.Late
	}
	if ping.Lost != nil {
		client.crypt.RemoteLost = *ping.Lost
	}
	if ping.Resync != nil {
		client.crypt.RemoteResync = *ping.Resync
	}

	if ping.UdpPingAvg != nil {
		client.UdpPingAvg = *ping.UdpPingAvg
	}
	if ping.UdpPingVar != nil {
		client.UdpPingVar = *ping.UdpPingVar
	}
	if ping.UdpPackets != nil {
		client.UdpPackets = *ping.UdpPackets
	}

	if ping.TcpPingAvg != nil {
		client.TcpPingAvg = *ping.TcpPingAvg
	}
	if ping.TcpPingVar != nil {
		client.TcpPingVar = *ping.TcpPingVar
	}
	if ping.TcpPackets != nil {
		client.TcpPackets = *ping.TcpPackets
	}

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

// Handle channel state change.
func (server *Server) handleChannelStateMessage(client *Client, msg *Message) {
	chanstate := &mumbleproto.ChannelState{}
	err := proto.Unmarshal(msg.buf, chanstate)
	if err != nil {
		client.Panic(err.String())
		return
	}

	var channel *Channel
	var parent *Channel
	var ok bool

	// Lookup channel for channel ID
	if chanstate.ChannelId != nil {
		channel, ok = server.Channels[int(*chanstate.ChannelId)]
		if !ok {
			client.Panic("Invalid channel specified in ChannelState message")
			return
		}
	}

	// Lookup parent
	if chanstate.Parent != nil {
		parent, ok = server.Channels[int(*chanstate.Parent)]
		if !ok {
			client.Panic("Invalid parent channel specified in ChannelState message")
			return
		}
	}

	// The server can't receive links through the links field in the ChannelState message,
	// because clients are supposed to send modifications to a channel's link state through
	// the links_add and links_remove fields.
	// Make sure the links field is clear so we can transmit the channel's link state in our reply.
	chanstate.Links = nil

	var name string
	var description string

	// Extract the description and perform sanity checks.
	if chanstate.Description != nil {
		description = *chanstate.Description
		// fixme(mkrautz): Check length
	}

	// Extract the the name of channel and check whether it's valid.
	// A valid channel name is a name that:
	//  a) Isn't already used by a channel at the same level as the channel itself (that is, channels
	//     that have a common parent can't have the same name.
	//  b) A name must be a valid name on the server (it must pass the channel name regexp)
	if chanstate.Name != nil {
		name = *chanstate.Name

		// We don't allow renames for the root channel.
		if channel != nil && channel.Id != 0 {
			// Pick a parent. If the name change is part of a re-parent (a channel move),
			// we must evaluate the parent variable. Since we're explicitly exlcuding the root
			// channel from renames, channels that are the target of renames are guaranteed to have
			// a parent.
			evalp := parent
			if evalp == nil {
				evalp = channel.parent
			}
			for _, iter := range evalp.children {
				if iter.Name == name {
					client.sendPermissionDeniedType("ChannelName")
					return
				}
			}
		}
	}

	// If the channel does not exist already, the ChannelState message is a create operation.
	if channel == nil {
		if parent == nil || len(name) == 0 {
			return
		}

		// Check whether the client has permission to create the channel in parent.
		perm := Permission(NonePermission)
		if *chanstate.Temporary {
			perm = Permission(TempChannelPermission)
		} else {
			perm = Permission(MakeChannelPermission)
		}
		if !server.HasPermission(client, parent, perm) {
			client.sendPermissionDenied(client, parent, perm)
			return
		}

		// Only registered users can create channels.
		if !client.IsRegistered() && !client.HasCertificate() {
			client.sendPermissionDeniedTypeUser("MissingCertificate", client)
			return
		}

		// We can't add channels to a temporary channel
		if parent.Temporary {
			client.sendPermissionDeniedType("TemporaryChannel")
			return
		}

		key := ""
		if len(description) > 0 {
			key, err = blobstore.Put([]byte(description))
			if err != nil {
				server.Panicf("Blobstore error: %v", err.String())
			}
		}

		// Add the new channel
		channel = server.AddChannel(name)
		channel.DescriptionBlob = key
		channel.Temporary = *chanstate.Temporary
		channel.Position = int(*chanstate.Position)
		parent.AddChild(channel)

		// Add the creator to the channel's admin group
		if client.IsRegistered() {
			grp := NewGroup(channel, "admin")
			grp.Add[client.UserId()] = true
			channel.Groups["admin"] = grp
		}

		// If the client wouldn't have WritePermission in the just-created channel,
		// add a +write ACL for the user's hash.
		if !server.HasPermission(client, channel, WritePermission) {
			acl := NewChannelACL(channel)
			acl.ApplyHere = true
			acl.ApplySubs = true
			if client.IsRegistered() {
				acl.UserId = client.UserId()
			} else {
				acl.Group = "$" + client.CertHash
			}
			acl.Deny = Permission(NonePermission)
			acl.Allow = Permission(WritePermission | TraversePermission)

			channel.ACL = append(channel.ACL, acl)

			server.ClearACLCache()
		}

		chanstate.ChannelId = proto.Uint32(uint32(channel.Id))

		// Broadcast channel add
		server.broadcastProtoMessageWithPredicate(MessageChannelState, chanstate, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description if client knows how to handle blobs.
		if chanstate.Description != nil && channel.HasDescription() {
			chanstate.Description = nil
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		server.broadcastProtoMessageWithPredicate(MessageChannelState, chanstate, func(client *Client) bool {
			return client.Version >= 0x10202
		})

		// If it's a temporary channel, move the creator in there.
		if channel.Temporary {
			userstate := &mumbleproto.UserState{}
			userstate.Session = proto.Uint32(client.Session)
			userstate.ChannelId = proto.Uint32(uint32(channel.Id))
			server.userEnterChannel(client, channel, userstate)
			server.broadcastProtoMessage(MessageUserState, userstate)
		}
	} else {
		// Edit existing channel.
		// First, check whether the actor has the neccessary permissions.

		// Name change.
		if chanstate.Name != nil {
			// The client can only rename the channel if it has WritePermission in the channel.
			// Also, clients cannot change the name of the root channel.
			if !server.HasPermission(client, channel, WritePermission) || channel.Id == 0 {
				client.sendPermissionDenied(client, channel, WritePermission)
				return
			}
		}

		// Description change
		if chanstate.Description != nil {
			if !server.HasPermission(client, channel, WritePermission) {
				client.sendPermissionDenied(client, channel, WritePermission)
				return
			}
		}

		// Position change
		if chanstate.Position != nil {
			if !server.HasPermission(client, channel, WritePermission) {
				client.sendPermissionDenied(client, channel, WritePermission)
				return
			}
		}

		// Parent change (channel move)
		if parent != nil {
			// No-op?
			if parent == channel.parent {
				return
			}

			// Make sure that channel we're operating on is not a parent of the new parent.
			iter := parent
			for iter != nil {
				if iter == channel {
					client.Panic("Illegal channel reparent")
					return
				}
				iter = iter.parent
			}

			// A temporary channel must not have any subchannels, so deny it.
			if parent.Temporary {
				client.sendPermissionDeniedType("TemporaryChannel")
				return
			}

			// To move a channel, the user must have WritePermission in the channel
			if !server.HasPermission(client, channel, WritePermission) {
				client.sendPermissionDenied(client, channel, WritePermission)
				return
			}

			// And the user must also have MakeChannel permission in the new parent
			if !server.HasPermission(client, parent, MakeChannelPermission) {
				client.sendPermissionDenied(client, parent, MakeChannelPermission)
				return
			}

			// If a sibling of parent already has this name, don't allow it.
			for _, iter := range parent.children {
				if iter.Name == channel.Name {
					client.sendPermissionDeniedType("ChannelName")
					return
				}
			}
		}

		// Links
		linkadd := []*Channel{}
		linkremove := []*Channel{}
		if len(chanstate.LinksAdd) > 0 || len(chanstate.LinksRemove) > 0 {
			// Client must have permission to link
			if !server.HasPermission(client, channel, LinkChannelPermission) {
				client.sendPermissionDenied(client, channel, LinkChannelPermission)
				return
			}
			// Add any valid channels to linkremove slice
			for _, cid := range chanstate.LinksRemove {
				if iter, ok := server.Channels[int(cid)]; ok {
					linkremove = append(linkremove, iter)
				}
			}
			// Add any valid channels to linkadd slice
			for _, cid := range chanstate.LinksAdd {
				if iter, ok := server.Channels[int(cid)]; ok {
					if !server.HasPermission(client, iter, LinkChannelPermission) {
						client.sendPermissionDenied(client, iter, LinkChannelPermission)
						return
					}
					linkadd = append(linkadd, iter)
				}
			}
		}

		// Permission checks done!

		// Channel move
		if parent != nil {
			channel.parent.RemoveChild(channel)
			parent.AddChild(channel)
		}

		// Rename
		if chanstate.Name != nil {
			channel.Name = *chanstate.Name
		}

		// Description change
		if chanstate.Description != nil {
			key, err := blobstore.Put([]byte(*chanstate.Description))
			if err != nil {
				server.Panicf("Blobstore error: %v", err.String())
			}
			channel.DescriptionBlob = key
		}

		// Position change
		if chanstate.Position != nil {
			channel.Position = int(*chanstate.Position)
		}

		// Add links
		for _, iter := range linkadd {
			server.LinkChannels(channel, iter)
		}

		// Remove links
		for _, iter := range linkremove {
			server.UnlinkChannels(channel, iter)
		}

		// Broadcast the update
		server.broadcastProtoMessageWithPredicate(MessageChannelState, chanstate, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description blob when sending to 1.2.2 >= users. Only send the blob hash.
		if channel.HasDescription() {
			chanstate.Description = nil
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		server.broadcastProtoMessageWithPredicate(MessageChannelState, chanstate, func(client *Client) bool {
			return client.Version >= 0x10202
		})
	}
}

// Handle a user remove packet. This can either be a client disconnecting, or a
// user kicking or kick-banning another player.
func (server *Server) handleUserRemoveMessage(client *Client, msg *Message) {
	userremove := &mumbleproto.UserRemove{}
	err := proto.Unmarshal(msg.buf, userremove)
	if err != nil {
		client.Panic(err.String())
	}

	// Get the client to be removed.
	removeClient, ok := server.clients[*userremove.Session]
	if !ok {
		client.Panic("Invalid session in UserRemove message")
		return
	}

	isBan := false
	if userremove.Ban != nil {
		isBan = *userremove.Ban
	}

	// Check client's permissions
	perm := Permission(KickPermission)
	if isBan {
		perm = Permission(BanPermission)
	}
	if removeClient.IsSuperUser() || !server.HasPermission(client, server.root, perm) {
		client.sendPermissionDenied(client, server.root, perm)
		return
	}

	if isBan {
		ban := ban.Ban{}
		ban.IP = removeClient.conn.RemoteAddr().(*net.TCPAddr).IP
		ban.Mask = 128
		if userremove.Reason != nil {
			ban.Reason = *userremove.Reason
		}
		ban.Username = removeClient.ShownName()
		ban.CertHash = removeClient.CertHash
		ban.Start = time.Seconds()
		ban.Duration = 0

		server.banlock.Lock()
		server.Bans = append(server.Bans, ban)
		server.banlock.Unlock()
	}

	userremove.Actor = proto.Uint32(uint32(client.Session))
	if err = server.broadcastProtoMessage(MessageUserRemove, userremove); err != nil {
		server.Panicf("Unable to broadcast UserRemove message")
		return
	}

	if isBan {
		client.Printf("Kick-banned %v (%v)", removeClient.ShownName(), removeClient.Session)
	} else {
		client.Printf("Kicked %v (%v)", removeClient.ShownName(), removeClient.Session)
	}

	removeClient.ForceDisconnect()
}

// Handle user state changes
func (server *Server) handleUserStateMessage(client *Client, msg *Message) {
	userstate := &mumbleproto.UserState{}
	err := proto.Unmarshal(msg.buf, userstate)
	if err != nil {
		client.Panic(err.String())
	}

	actor, ok := server.clients[client.Session]
	if !ok {
		server.Panic("Client not found in server's client map.")
		return
	}
	target := actor
	if userstate.Session != nil {
		target, ok = server.clients[*userstate.Session]
		if !ok {
			client.Panic("Invalid session in UserState message")
			return
		}
	}

	userstate.Session = proto.Uint32(target.Session)
	userstate.Actor = proto.Uint32(actor.Session)

	// Does it have a channel ID?
	if userstate.ChannelId != nil {
		// Destination channel
		dstChan, ok := server.Channels[int(*userstate.ChannelId)]
		if !ok {
			return
		}

		// If the user and the actor aren't the same, check whether the actor has MovePermission on
		// the user's curent channel.
		if actor != target && !server.HasPermission(actor, target.Channel, MovePermission) {
			client.sendPermissionDenied(actor, target.Channel, MovePermission)
			return
		}

		// Check whether the actor has MovePermission on dstChan.  Check whether user has EnterPermission
		// on dstChan.
		if !server.HasPermission(actor, dstChan, MovePermission) && !server.HasPermission(target, dstChan, EnterPermission) {
			client.sendPermissionDenied(target, dstChan, EnterPermission)
			return
		}

		// fixme(mkrautz): Check whether the channel is full.
	}

	if userstate.Mute != nil || userstate.Deaf != nil || userstate.Suppress != nil || userstate.PrioritySpeaker != nil {
		// Disallow for SuperUser
		if target.IsSuperUser() {
			client.sendPermissionDeniedType("SuperUser")
			return
		}

		// Check whether the actor has 'mutedeafen' permission on user's channel.
		if !server.HasPermission(actor, target.Channel, MuteDeafenPermission) {
			client.sendPermissionDenied(actor, target.Channel, MuteDeafenPermission)
			return
		}

		// Check if this was a suppress operation. Only the server can suppress users.
		if userstate.Suppress != nil {
			client.sendPermissionDenied(actor, target.Channel, MuteDeafenPermission)
			return
		}
	}

	// Comment set/clear
	if userstate.Comment != nil {
		comment := *userstate.Comment

		// Clearing another user's comment.
		if target != actor {
			// Check if actor has 'move' permissions on the root channel. It is needed
			// to clear another user's comment.
			if !server.HasPermission(actor, server.root, MovePermission) {
				client.sendPermissionDenied(actor, server.root, MovePermission)
				return
			}

			// Only allow empty text.
			if len(comment) > 0 {
				client.Panic("Cannot clear another user's comment")
				return
			}
		}

		// todo(mkrautz): Check if the text is allowed.
	}

	// Texture change
	if userstate.Texture != nil {
		// Check the length of the texture
	}

	// Registration
	if userstate.UserId != nil {
		// If user == actor, check for SelfRegisterPermission on root channel.
		// If user != actor, check for RegisterPermission permission on root channel.
		perm := Permission(RegisterPermission)
		if actor == target {
			perm = Permission(SelfRegisterPermission)
		}

		if target.IsRegistered() || !server.HasPermission(actor, server.root, perm) {
			client.sendPermissionDenied(actor, server.root, perm)
			return
		}

		if len(target.CertHash) == 0 {
			client.sendPermissionDeniedTypeUser("MissingCertificate", target)
			return
		}
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
	if actor != target && (userstate.SelfDeaf != nil || userstate.SelfMute != nil ||
		userstate.Texture != nil || userstate.PluginContext != nil || userstate.PluginIdentity != nil ||
		userstate.Recording != nil) {
		client.Panic("Invalid UserState")
		return
	}

	broadcast := false

	if userstate.Texture != nil && target.user != nil {
		key, err := blobstore.Put(userstate.Texture)
		if err != nil {
			server.Panicf("Blobstore error: %v", err.String())
		}

		if target.user.TextureBlob != key {
			target.user.TextureBlob = key
		} else {
			userstate.Texture = nil
		}

		broadcast = true
	}

	if userstate.SelfDeaf != nil {
		target.SelfDeaf = *userstate.SelfDeaf
		if target.SelfDeaf {
			userstate.SelfDeaf = proto.Bool(true)
			target.SelfMute = true
		}
		broadcast = true
	}

	if userstate.SelfMute != nil {
		target.SelfMute = *userstate.SelfMute
		if !target.SelfMute {
			userstate.SelfDeaf = proto.Bool(false)
			target.SelfDeaf = false
		}
	}

	if userstate.PluginContext != nil {
		target.PluginContext = userstate.PluginContext
	}

	if userstate.PluginIdentity != nil {
		target.PluginIdentity = *userstate.PluginIdentity
	}

	if userstate.Comment != nil && target.user != nil {
		key, err := blobstore.Put([]byte(*userstate.Comment))
		if err != nil {
			server.Panicf("Blobstore error: %v", err.String())
		}

		if target.user.CommentBlob != key {
			target.user.CommentBlob = key
		} else {
			userstate.Comment = nil
		}

		broadcast = true
	}

	if userstate.Mute != nil || userstate.Deaf != nil || userstate.Suppress != nil || userstate.PrioritySpeaker != nil {
		if userstate.Deaf != nil {
			target.Deaf = *userstate.Deaf
			if target.Deaf {
				userstate.Mute = proto.Bool(true)
			}
		}
		if userstate.Mute != nil {
			target.Mute = *userstate.Mute
			if !target.Mute {
				userstate.Deaf = proto.Bool(false)
				target.Deaf = false
			}
		}
		if userstate.Suppress != nil {
			target.Suppress = *userstate.Suppress
		}
		if userstate.PrioritySpeaker != nil {
			target.PrioritySpeaker = *userstate.PrioritySpeaker
		}
		broadcast = true
	}

	if userstate.Recording != nil && *userstate.Recording != target.Recording {
		target.Recording = *userstate.Recording

		txtmsg := &mumbleproto.TextMessage{}
		txtmsg.TreeId = append(txtmsg.TreeId, uint32(0))
		if target.Recording {
			txtmsg.Message = proto.String(fmt.Sprintf("User '%s' started recording", target.ShownName()))
		} else {
			txtmsg.Message = proto.String(fmt.Sprintf("User '%s' stopped recording", target.ShownName()))
		}

		server.broadcastProtoMessageWithPredicate(MessageTextMessage, txtmsg, func(client *Client) bool {
			return client.Version < 0x10203
		})

		broadcast = true
	}

	userRegistrationChanged := false
	if userstate.UserId != nil {
		uid := server.RegisterClient(client)
		if uid > 0 {
			userstate.UserId = proto.Uint32(uid)
			client.user = server.Users[uid]
			userRegistrationChanged = true
		} else {
			userstate.UserId = nil
		}
		broadcast = true
	}

	if userstate.ChannelId != nil {
		channel, ok := server.Channels[int(*userstate.ChannelId)]
		if ok {
			server.userEnterChannel(target, channel, userstate)
			broadcast = true
		}
	}

	if broadcast {
		// This variable denotes the length of a zlib-encoded "old-style" texture.
		// Mumble and Murmur used qCompress and qUncompress from Qt to compress
		// textures that were sent over the wire. We can use this to determine
		// whether a texture is a "new style" or an "old style" texture.
		texture := userstate.Texture
		texlen := uint32(0)
		if texture != nil && len(texture) > 4 {
			texlen = uint32(texture[0])<<24 | uint32(texture[1])<<16 | uint32(texture[2])<<8 | uint32(texture[3])
		}
		if texture != nil && len(texture) > 4 && texlen != 600*60*4 {
			// The sent texture is a new-style texture.  Strip it from the message
			// we send to pre-1.2.2 clients.
			userstate.Texture = nil
			err := server.broadcastProtoMessageWithPredicate(MessageUserState, userstate, func(client *Client) bool {
				return client.Version < 0x10202
			})
			if err != nil {
				server.Panic("Unable to broadcast UserState")
			}
			// Re-add it to the message, so that 1.2.2+ clients *do* get the new-style texture.
			userstate.Texture = texture
		} else {
			// Old style texture.  We can send the message as-is.
			err := server.broadcastProtoMessageWithPredicate(MessageUserState, userstate, func(client *Client) bool {
				return client.Version < 0x10202
			})
			if err != nil {
				server.Panic("Unable to broadcast UserState")
			}
		}

		// If a texture hash is set on user, we transmit that instead of
		// the texture itself. This allows the client to intelligently fetch
		// the blobs that it does not already have in its local storage.
		if userstate.Texture != nil && target.user != nil && target.user.HasTexture() {
			userstate.Texture = nil
			userstate.TextureHash = target.user.TextureBlobHashBytes()
		} else if target.user == nil {
			userstate.Texture = nil
			userstate.TextureHash = nil
		}

		// Ditto for comments.
		if userstate.Comment != nil && target.user.HasComment() {
			userstate.Comment = nil
			userstate.CommentHash = target.user.CommentBlobHashBytes()
		} else if target.user == nil {
			userstate.Comment = nil
			userstate.CommentHash = nil
		}

		if userRegistrationChanged {
			server.ClearACLCache()
		}

		err := server.broadcastProtoMessageWithPredicate(MessageUserState, userstate, func(client *Client) bool {
			return client.Version >= 0x10203
		})
		if err != nil {
			server.Panic("Unable to broadcast UserState")
		}
	}
}

func (server *Server) handleBanListMessage(client *Client, msg *Message) {
	banlist := &mumbleproto.BanList{}
	err := proto.Unmarshal(msg.buf, banlist)
	if err != nil {
		client.Panic(err.String())
		return
	}

	if !server.HasPermission(client, server.root, BanPermission) {
		client.sendPermissionDenied(client, server.root, BanPermission)
	}

	if banlist.Query != nil && *banlist.Query != false {
		banlist.Reset()

		server.banlock.RLock()
		defer server.banlock.RUnlock()

		for _, ban := range server.Bans {
			entry := &mumbleproto.BanList_BanEntry{}
			entry.Address = ban.IP
			entry.Mask = proto.Uint32(uint32(ban.Mask))
			entry.Name = proto.String(ban.Username)
			entry.Hash = proto.String(ban.CertHash)
			entry.Reason = proto.String(ban.Reason)
			entry.Start = proto.String(ban.ISOStartDate())
			entry.Duration = proto.Uint32(ban.Duration)
			banlist.Bans = append(banlist.Bans, entry)
		}
		if err := client.sendProtoMessage(MessageBanList, banlist); err != nil {
			client.Panic("Unable to send BanList")
		}
	} else {
		server.banlock.Lock()
		defer server.banlock.Unlock()

		server.Bans = server.Bans[0:0]
		for _, entry := range banlist.Bans {
			ban := ban.Ban{}
			ban.IP = entry.Address
			ban.Mask = int(*entry.Mask)
			if entry.Name != nil {
				ban.Username = *entry.Name
			}
			if entry.Hash != nil {
				ban.CertHash = *entry.Hash
			}
			if entry.Reason != nil {
				ban.Reason = *entry.Reason
			}
			if entry.Start != nil {
				ban.SetISOStartDate(*entry.Start)
			}
			if entry.Duration != nil {
				ban.Duration = *entry.Duration
			}
			server.Bans = append(server.Bans, ban)
		}
		client.Printf("Banlist updated")
	}
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

	clients := make(map[uint32]*Client)

	// Tree
	for _, chanid := range txtmsg.TreeId {
		if channel, ok := server.Channels[int(chanid)]; ok {
			if !server.HasPermission(client, channel, TextMessagePermission) {
				client.sendPermissionDenied(client, channel, TextMessagePermission)
			}
			for _, target := range channel.clients {
				clients[target.Session] = target
			}
		}
	}

	// Direct-to-channel
	for _, chanid := range txtmsg.ChannelId {
		if channel, ok := server.Channels[int(chanid)]; ok {
			if !server.HasPermission(client, channel, TextMessagePermission) {
				client.sendPermissionDenied(client, channel, TextMessagePermission)
				return
			}
			for _, target := range channel.clients {
				clients[target.Session] = target
			}
		}
	}

	// Direct-to-clients
	for _, session := range txtmsg.Session {
		if target, ok := server.clients[session]; ok {
			if !server.HasPermission(client, target.Channel, TextMessagePermission) {
				client.sendPermissionDenied(client, target.Channel, TextMessagePermission)
				return
			}
			clients[session] = target
		}
	}

	// Remove ourselves
	clients[client.Session] = nil, false

	for _, target := range clients {
		target.sendProtoMessage(MessageTextMessage, &mumbleproto.TextMessage{
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
	channel, ok := server.Channels[int(*acl.ChannelId)]
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
			var (
				group  *Group
				pgroup *Group
			)
			group = channel.Groups[name]
			if parent != nil {
				pgroup = parent.Groups[name]
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
		queryusers := &mumbleproto.QueryUsers{}
		for uid, _ := range users {
			user, ok := server.Users[uint32(uid)]
			if !ok {
				client.Printf("Invalid user id in ACL")
				continue
			}
			queryusers.Ids = append(queryusers.Ids, uint32(uid))
			queryusers.Names = append(queryusers.Names, user.Name)
		}
		if len(queryusers.Ids) > 0 {
			client.sendProtoMessage(MessageQueryUsers, queryusers)
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
		if !server.HasPermission(client, channel, WritePermission) && client.IsRegistered() || client.HasCertificate() {
			chanacl := NewChannelACL(channel)

			chanacl.ApplyHere = true
			chanacl.ApplySubs = false
			if client.IsRegistered() {
				chanacl.UserId = client.UserId()
			} else if client.HasCertificate() {
				chanacl.Group = "$" + client.CertHash
			}
			chanacl.Deny = Permission(NonePermission)
			chanacl.Allow = Permission(WritePermission | TraversePermission)

			channel.ACL = append(channel.ACL, chanacl)

			server.ClearACLCache()
		}
	}
}

// User query
func (server *Server) handleQueryUsers(client *Client, msg *Message) {
	query := &mumbleproto.QueryUsers{}
	err := proto.Unmarshal(msg.buf, query)
	if err != nil {
		client.Panic(err.String())
	}

	reply := &mumbleproto.QueryUsers{}

	for _, id := range query.Ids {
		user, exists := server.Users[id]
		if exists {
			reply.Ids = append(reply.Ids, id)
			reply.Names = append(reply.Names, user.Name)
		}
	}

	for _, name := range query.Names {
		user, exists := server.UserNameMap[name]
		if exists {
			reply.Ids = append(reply.Ids, user.Id)
			reply.Names = append(reply.Names, name)
		}
	}

	if err := client.sendProtoMessage(MessageQueryUsers, reply); err != nil {
		client.Panic(err.String())
		return
	}
}

// User stats message. Shown in the Mumble client when a
// user right clicks a user and selects 'User Information'.
func (server *Server) handleUserStatsMessage(client *Client, msg *Message) {
	stats := &mumbleproto.UserStats{}
	err := proto.Unmarshal(msg.buf, stats)
	if err != nil {
		client.Panic(err.String())
	}

	if stats.Session == nil {
		return
	}

	target, exists := server.clients[*stats.Session]
	if !exists {
		return
	}

	extended := false
	// If a client is requesting a UserStats from itself, serve it the whole deal.
	if client == target {
		extended = true
	}
	// Otherwise, only send extended UserStats for people with +register permissions
	// on the root channel.
	if server.HasPermission(client, server.root, RegisterPermission) {
		extended = true
	}

	// If the client wasn't granted extended permissions, only allow it to query
	// users in channels it can enter.
	if !extended && !server.HasPermission(client, target.Channel, EnterPermission) {
		client.sendPermissionDenied(client, target.Channel, EnterPermission)
		return
	}

	details := extended
	local := extended || target.Channel == client.Channel

	if stats.StatsOnly != nil && *stats.StatsOnly == true {
		details = false
	}

	stats.Reset()
	stats.Session = proto.Uint32(target.Session)

	if details {
		if tlsconn := target.conn.(*tls.Conn); tlsconn != nil {
			state := tlsconn.ConnectionState()
			for i := len(state.PeerCertificates)-1; i >= 0; i-- {
				stats.Certificates = append(stats.Certificates, state.PeerCertificates[i].Raw)
			}
			// fixme(mkrautz): strong certificate checking
		}
	}

	if local {
		fromClient := &mumbleproto.UserStats_Stats{}
		fromClient.Good = proto.Uint32(target.crypt.Good)
		fromClient.Late = proto.Uint32(target.crypt.Late)
		fromClient.Lost = proto.Uint32(target.crypt.Lost)
		fromClient.Resync = proto.Uint32(target.crypt.Resync)
		stats.FromClient = fromClient

		fromServer := &mumbleproto.UserStats_Stats{}
		fromServer.Good = proto.Uint32(target.crypt.RemoteGood)
		fromServer.Late = proto.Uint32(target.crypt.RemoteLate)
		fromServer.Lost = proto.Uint32(target.crypt.RemoteLost)
		fromServer.Resync = proto.Uint32(target.crypt.RemoteResync)
		stats.FromServer = fromServer
	}

	stats.UdpPackets = proto.Uint32(target.UdpPackets)
	stats.TcpPackets = proto.Uint32(target.TcpPackets)
	stats.UdpPingAvg = proto.Float32(target.UdpPingAvg)
	stats.UdpPingVar = proto.Float32(target.UdpPingVar)
	stats.TcpPingAvg = proto.Float32(target.TcpPingAvg)
	stats.TcpPingVar = proto.Float32(target.TcpPingVar)

	if details {
		version := &mumbleproto.Version{}
		version.Version = proto.Uint32(target.Version)
		if len(target.ClientName) > 0 {
			version.Release = proto.String(target.ClientName)
		}
		if len(target.OSName) > 0 {
			version.Os = proto.String(target.OSName)
			if len(target.OSVersion) > 0 {
				version.OsVersion = proto.String(target.OSVersion)
			}
		}
		stats.Version = version
		stats.CeltVersions = target.codecs
		stats.Address = target.tcpaddr.IP
	}

	// fixme(mkrautz): we don't do bandwidth tracking yet

	if err := client.sendProtoMessage(MessageUserStats, stats); err != nil {
		client.Panic(err.String())
		return
	}
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

	channel := server.Channels[int(*query.ChannelId)]
	server.sendClientPermissions(client, channel)
}

// Request big blobs from the server
func (server *Server) handleRequestBlob(client *Client, msg *Message) {
	blobreq := &mumbleproto.RequestBlob{}
	err := proto.Unmarshal(msg.buf, blobreq)
	if err != nil {
		client.Panic(err.String())
		return
	}

	userstate := &mumbleproto.UserState{}

	// Request for user textures
	if len(blobreq.SessionTexture) > 0 {
		for _, sid := range blobreq.SessionTexture {
			if target, ok := server.clients[sid]; ok {
				if target.user == nil {
					continue
				}
				if target.user.HasTexture() {
					buf, err := blobstore.Get(target.user.TextureBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err.String())
					}
					userstate.Reset()
					userstate.Session = proto.Uint32(uint32(target.Session))
					userstate.Texture = buf
					if err := client.sendProtoMessage(MessageUserState, userstate); err != nil {
						client.Panic(err.String())
						return
					}
				}
			}
		}
	}

	// Request for user comments
	if len(blobreq.SessionComment) > 0 {
		for _, sid := range blobreq.SessionComment {
			if target, ok := server.clients[sid]; ok {
				if target.user == nil {
					continue
				}
				if target.user.HasComment() {
					buf, err := blobstore.Get(target.user.CommentBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err.String())
					}
					userstate.Reset()
					userstate.Session = proto.Uint32(uint32(target.Session))
					userstate.Comment = proto.String(string(buf))
					if err := client.sendProtoMessage(MessageUserState, userstate); err != nil {
						client.Panic(err.String())
						return
					}
				}
			}
		}
	}

	chanstate := &mumbleproto.ChannelState{}

	// Request for channel descriptions
	if len(blobreq.ChannelDescription) > 0 {
		for _, cid := range blobreq.ChannelDescription {
			if channel, ok := server.Channels[int(cid)]; ok {
				if channel.HasDescription() {
					chanstate.Reset()
					buf, err := blobstore.Get(channel.DescriptionBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err.String())
					}
					chanstate.ChannelId = proto.Uint32(uint32(channel.Id))
					chanstate.Description = proto.String(string(buf))
					if err := client.sendProtoMessage(MessageChannelState, chanstate); err != nil {
						client.Panic(err.String())
						return
					}
				}
			}
		}
	}
}

// User list query, user rename, user de-register
func (server *Server) handleUserList(client *Client, msg *Message) {
	userlist := &mumbleproto.UserList{}
	err := proto.Unmarshal(msg.buf, userlist)
	if err != nil {
		client.Panic(err.String())
		return
	}

	// Only users who are allowed to register other users can access the user list.
	if !server.HasPermission(client, server.root, RegisterPermission) {
		client.sendPermissionDenied(client, server.root, RegisterPermission)
		return
	}

	// Query user list
	if len(userlist.Users) == 0 {
		for uid, user := range server.Users {
			if uid == 0 {
				continue
			}
			userlist.Users = append(userlist.Users, &mumbleproto.UserList_User{
				UserId: proto.Uint32(uid),
				Name:   proto.String(user.Name),
			})
		}
		if err := client.sendProtoMessage(MessageUserList, userlist); err != nil {
			client.Panic(err.String())
			return
		}
		// Rename, registration removal
	} else {
		for _, listUser := range userlist.Users {
			uid := *listUser.UserId
			if uid == 0 {
				continue
			}
			// De-register a user
			if listUser.Name == nil {
				server.RemoveRegistration(uid)
				// Rename user
			} else {
				// todo(mkrautz): Validate name.
				user, ok := server.Users[uid]
				if ok {
					user.Name = *listUser.Name
				}
			}
		}
	}
}
