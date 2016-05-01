// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"crypto/aes"
	"crypto/tls"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/mumble-voip/grumble/pkg/acl"
	"github.com/mumble-voip/grumble/pkg/ban"
	"github.com/mumble-voip/grumble/pkg/freezer"
	"github.com/mumble-voip/grumble/pkg/mumbleproto"
	"net"
	"time"
)

type Message struct {
	buf    []byte
	kind   uint16
	client *Client
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
		client.Panic(err)
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
		client.sendMessage(cs)
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
		client.Panic(err)
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

	client.sendMessage(&mumbleproto.Ping{
		Timestamp: ping.Timestamp,
		Good:      proto.Uint32(uint32(client.crypt.Good)),
		Late:      proto.Uint32(uint32(client.crypt.Late)),
		Lost:      proto.Uint32(uint32(client.crypt.Lost)),
		Resync:    proto.Uint32(uint32(client.crypt.Resync)),
	})
}

func (server *Server) handleChannelRemoveMessage(client *Client, msg *Message) {
	chanremove := &mumbleproto.ChannelRemove{}
	err := proto.Unmarshal(msg.buf, chanremove)
	if err != nil {
		client.Panic(err)
		return
	}

	if chanremove.ChannelId == nil {
		return
	}

	channel, exists := server.Channels[int(*chanremove.ChannelId)]
	if !exists {
		return
	}

	if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
		client.sendPermissionDenied(client, channel, acl.WritePermission)
		return
	}

	// Update datastore
	if !channel.IsTemporary() {
		server.DeleteFrozenChannel(channel)
	}

	server.RemoveChannel(channel)
}

// Handle channel state change.
func (server *Server) handleChannelStateMessage(client *Client, msg *Message) {
	chanstate := &mumbleproto.ChannelState{}
	err := proto.Unmarshal(msg.buf, chanstate)
	if err != nil {
		client.Panic(err)
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
		description, err = server.FilterText(*chanstate.Description)
		if err != nil {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}
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
					client.sendPermissionDeniedType(mumbleproto.PermissionDenied_ChannelName)
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
		perm := acl.Permission(acl.NonePermission)
		if *chanstate.Temporary {
			perm = acl.Permission(acl.TempChannelPermission)
		} else {
			perm = acl.Permission(acl.MakeChannelPermission)
		}
		if !acl.HasPermission(&parent.ACL, client, perm) {
			client.sendPermissionDenied(client, parent, perm)
			return
		}

		// Only registered users can create channels.
		if !client.IsRegistered() && !client.HasCertificate() {
			client.sendPermissionDeniedTypeUser(mumbleproto.PermissionDenied_MissingCertificate, client)
			return
		}

		// We can't add channels to a temporary channel
		if parent.IsTemporary() {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TemporaryChannel)
			return
		}

		key := ""
		if len(description) > 0 {
			key, err = blobStore.Put([]byte(description))
			if err != nil {
				server.Panicf("Blobstore error: %v", err)
			}
		}

		// Add the new channel
		channel = server.AddChannel(name)
		channel.DescriptionBlob = key
		channel.temporary = *chanstate.Temporary
		channel.Position = int(*chanstate.Position)
		parent.AddChild(channel)

		// Add the creator to the channel's admin group
		if client.IsRegistered() {
			grp := acl.EmptyGroupWithName("admin")
			grp.Add[client.UserId()] = true
			channel.ACL.Groups["admin"] = grp
		}

		// If the client wouldn't have WritePermission in the just-created channel,
		// add a +write ACL for the user's hash.
		if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
			aclEntry := acl.ACL{}
			aclEntry.ApplyHere = true
			aclEntry.ApplySubs = true
			if client.IsRegistered() {
				aclEntry.UserId = client.UserId()
			} else {
				aclEntry.Group = "$" + client.CertHash()
			}
			aclEntry.Deny = acl.Permission(acl.NonePermission)
			aclEntry.Allow = acl.Permission(acl.WritePermission | acl.TraversePermission)

			channel.ACL.ACLs = append(channel.ACL.ACLs, aclEntry)

			server.ClearCaches()
		}

		chanstate.ChannelId = proto.Uint32(uint32(channel.Id))

		// Broadcast channel add
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description if client knows how to handle blobs.
		if chanstate.Description != nil && channel.HasDescription() {
			chanstate.Description = nil
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version >= 0x10202
		})

		// If it's a temporary channel, move the creator in there.
		if channel.IsTemporary() {
			userstate := &mumbleproto.UserState{}
			userstate.Session = proto.Uint32(client.Session())
			userstate.ChannelId = proto.Uint32(uint32(channel.Id))
			server.userEnterChannel(client, channel, userstate)
			server.broadcastProtoMessage(userstate)
		}
	} else {
		// Edit existing channel.
		// First, check whether the actor has the neccessary permissions.

		// Name change.
		if chanstate.Name != nil {
			// The client can only rename the channel if it has WritePermission in the channel.
			// Also, clients cannot change the name of the root channel.
			if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) || channel.Id == 0 {
				client.sendPermissionDenied(client, channel, acl.WritePermission)
				return
			}
		}

		// Description change
		if chanstate.Description != nil {
			if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
				client.sendPermissionDenied(client, channel, acl.WritePermission)
				return
			}
		}

		// Position change
		if chanstate.Position != nil {
			if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
				client.sendPermissionDenied(client, channel, acl.WritePermission)
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
			if parent.IsTemporary() {
				client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TemporaryChannel)
				return
			}

			// To move a channel, the user must have WritePermission in the channel
			if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
				client.sendPermissionDenied(client, channel, acl.WritePermission)
				return
			}

			// And the user must also have MakeChannel permission in the new parent
			if !acl.HasPermission(&parent.ACL, client, acl.MakeChannelPermission) {
				client.sendPermissionDenied(client, parent, acl.MakeChannelPermission)
				return
			}

			// If a sibling of parent already has this name, don't allow it.
			for _, iter := range parent.children {
				if iter.Name == channel.Name {
					client.sendPermissionDeniedType(mumbleproto.PermissionDenied_ChannelName)
					return
				}
			}
		}

		// Links
		linkadd := []*Channel{}
		linkremove := []*Channel{}
		if len(chanstate.LinksAdd) > 0 || len(chanstate.LinksRemove) > 0 {
			// Client must have permission to link
			if !acl.HasPermission(&channel.ACL, client, acl.LinkChannelPermission) {
				client.sendPermissionDenied(client, channel, acl.LinkChannelPermission)
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
					if !acl.HasPermission(&iter.ACL, client, acl.LinkChannelPermission) {
						client.sendPermissionDenied(client, iter, acl.LinkChannelPermission)
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
			if len(description) == 0 {
				channel.DescriptionBlob = ""
			} else {
				key, err := blobStore.Put([]byte(description))
				if err != nil {
					server.Panicf("Blobstore error: %v", err)
				}
				channel.DescriptionBlob = key
			}
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
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description blob when sending to 1.2.2 >= users. Only send the blob hash.
		if channel.HasDescription() {
			chanstate.Description = nil
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version >= 0x10202
		})
	}

	// Update channel in datastore
	if !channel.IsTemporary() {
		server.UpdateFrozenChannel(channel, chanstate)
	}
}

// Handle a user remove packet. This can either be a client disconnecting, or a
// user kicking or kick-banning another player.
func (server *Server) handleUserRemoveMessage(client *Client, msg *Message) {
	userremove := &mumbleproto.UserRemove{}
	err := proto.Unmarshal(msg.buf, userremove)
	if err != nil {
		client.Panic(err)
		return
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
	perm := acl.Permission(acl.KickPermission)
	if isBan {
		perm = acl.Permission(acl.BanPermission)
	}
	rootChan := server.RootChannel()
	if removeClient.IsSuperUser() || !acl.HasPermission(&rootChan.ACL, client, perm) {
		client.sendPermissionDenied(client, rootChan, perm)
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
		ban.CertHash = removeClient.CertHash()
		ban.Start = time.Now().Unix()
		ban.Duration = 0

		server.banlock.Lock()
		server.Bans = append(server.Bans, ban)
		server.UpdateFrozenBans(server.Bans)
		server.banlock.Unlock()
	}

	userremove.Actor = proto.Uint32(uint32(client.Session()))
	if err = server.broadcastProtoMessage(userremove); err != nil {
		server.Panicf("Unable to broadcast UserRemove message")
		return
	}

	if isBan {
		client.Printf("Kick-banned %v (%v)", removeClient.ShownName(), removeClient.Session())
	} else {
		client.Printf("Kicked %v (%v)", removeClient.ShownName(), removeClient.Session())
	}

	removeClient.ForceDisconnect()
}

// Handle user state changes
func (server *Server) handleUserStateMessage(client *Client, msg *Message) {
	userstate := &mumbleproto.UserState{}
	err := proto.Unmarshal(msg.buf, userstate)
	if err != nil {
		client.Panic(err)
		return
	}

	actor, ok := server.clients[client.Session()]
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

	userstate.Session = proto.Uint32(target.Session())
	userstate.Actor = proto.Uint32(actor.Session())

	// Does it have a channel ID?
	if userstate.ChannelId != nil {
		// Destination channel
		dstChan, ok := server.Channels[int(*userstate.ChannelId)]
		if !ok {
			return
		}

		// If the user and the actor aren't the same, check whether the actor has MovePermission on
		// the user's curent channel.
		if actor != target && !acl.HasPermission(&target.Channel.ACL, actor, acl.MovePermission) {
			client.sendPermissionDenied(actor, target.Channel, acl.MovePermission)
			return
		}

		// Check whether the actor has MovePermission on dstChan.  Check whether user has EnterPermission
		// on dstChan.
		if !acl.HasPermission(&dstChan.ACL, actor, acl.MovePermission) && !acl.HasPermission(&dstChan.ACL, target, acl.EnterPermission) {
			client.sendPermissionDenied(target, dstChan, acl.EnterPermission)
			return
		}

		maxChannelUsers := server.cfg.IntValue("MaxChannelUsers")
		if maxChannelUsers != 0 && len(dstChan.clients) >= maxChannelUsers {
			client.sendPermissionDeniedFallback(mumbleproto.PermissionDenied_ChannelFull,
				0x010201, "Channel is full")
			return
		}
	}

	if userstate.Mute != nil || userstate.Deaf != nil || userstate.Suppress != nil || userstate.PrioritySpeaker != nil {
		// Disallow for SuperUser
		if target.IsSuperUser() {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_SuperUser)
			return
		}

		// Check whether the actor has 'mutedeafen' permission on user's channel.
		if !acl.HasPermission(&target.Channel.ACL, actor, acl.MuteDeafenPermission) {
			client.sendPermissionDenied(actor, target.Channel, acl.MuteDeafenPermission)
			return
		}

		// Check if this was a suppress operation. Only the server can suppress users.
		if userstate.Suppress != nil {
			client.sendPermissionDenied(actor, target.Channel, acl.MuteDeafenPermission)
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
			rootChan := server.RootChannel()
			if !acl.HasPermission(&rootChan.ACL, actor, acl.MovePermission) {
				client.sendPermissionDenied(actor, rootChan, acl.MovePermission)
				return
			}

			// Only allow empty text.
			if len(comment) > 0 {
				client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
				return
			}
		}

		filtered, err := server.FilterText(comment)
		if err != nil {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}

		userstate.Comment = proto.String(filtered)
	}

	// Texture change
	if userstate.Texture != nil {
		maximg := server.cfg.IntValue("MaxImageMessageLength")
		if maximg > 0 && len(userstate.Texture) > maximg {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}
	}

	// Registration
	if userstate.UserId != nil {
		// If user == actor, check for SelfRegisterPermission on root channel.
		// If user != actor, check for RegisterPermission permission on root channel.
		perm := acl.Permission(acl.RegisterPermission)
		if actor == target {
			perm = acl.Permission(acl.SelfRegisterPermission)
		}

		rootChan := server.RootChannel()
		if target.IsRegistered() || !acl.HasPermission(&rootChan.ACL, actor, perm) {
			client.sendPermissionDenied(actor, rootChan, perm)
			return
		}

		if !target.HasCertificate() {
			client.sendPermissionDeniedTypeUser(mumbleproto.PermissionDenied_MissingCertificate, target)
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
		key, err := blobStore.Put(userstate.Texture)
		if err != nil {
			server.Panicf("Blobstore error: %v", err)
			return
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
		key, err := blobStore.Put([]byte(*userstate.Comment))
		if err != nil {
			server.Panicf("Blobstore error: %v", err)
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

		server.broadcastProtoMessageWithPredicate(txtmsg, func(client *Client) bool {
			return client.Version < 0x10203
		})

		broadcast = true
	}

	userRegistrationChanged := false
	if userstate.UserId != nil {
		uid, err := server.RegisterClient(target)
		if err != nil {
			client.Printf("Unable to register: %v", err)
			userstate.UserId = nil
		} else {
			userstate.UserId = proto.Uint32(uid)
			client.user = server.Users[uid]
			userRegistrationChanged = true
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
			err := server.broadcastProtoMessageWithPredicate(userstate, func(client *Client) bool {
				return client.Version < 0x10202
			})
			if err != nil {
				server.Panic("Unable to broadcast UserState")
			}
			// Re-add it to the message, so that 1.2.2+ clients *do* get the new-style texture.
			userstate.Texture = texture
		} else {
			// Old style texture.  We can send the message as-is.
			err := server.broadcastProtoMessageWithPredicate(userstate, func(client *Client) bool {
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
			server.ClearCaches()
		}

		err := server.broadcastProtoMessageWithPredicate(userstate, func(client *Client) bool {
			return client.Version >= 0x10203
		})
		if err != nil {
			server.Panic("Unable to broadcast UserState")
		}
	}

	if target.IsRegistered() {
		server.UpdateFrozenUser(target, userstate)
	}
}

func (server *Server) handleBanListMessage(client *Client, msg *Message) {
	banlist := &mumbleproto.BanList{}
	err := proto.Unmarshal(msg.buf, banlist)
	if err != nil {
		client.Panic(err)
		return
	}

	rootChan := server.RootChannel()
	if !acl.HasPermission(&rootChan.ACL, client, acl.BanPermission) {
		client.sendPermissionDenied(client, rootChan, acl.BanPermission)
		return
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
		if err := client.sendMessage(banlist); err != nil {
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

		server.UpdateFrozenBans(server.Bans)

		client.Printf("Banlist updated")
	}
}

// Broadcast text messages
func (server *Server) handleTextMessage(client *Client, msg *Message) {
	txtmsg := &mumbleproto.TextMessage{}
	err := proto.Unmarshal(msg.buf, txtmsg)
	if err != nil {
		client.Panic(err)
		return
	}

	filtered, err := server.FilterText(*txtmsg.Message)
	if err != nil {
		client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
		return
	}

	if len(filtered) == 0 {
		return
	}

	txtmsg.Message = proto.String(filtered)

	clients := make(map[uint32]*Client)

	// Tree
	for _, chanid := range txtmsg.TreeId {
		if channel, ok := server.Channels[int(chanid)]; ok {
			if !acl.HasPermission(&channel.ACL, client, acl.TextMessagePermission) {
				client.sendPermissionDenied(client, channel, acl.TextMessagePermission)
				return
			}
			for _, target := range channel.clients {
				clients[target.Session()] = target
			}
		}
	}

	// Direct-to-channel
	for _, chanid := range txtmsg.ChannelId {
		if channel, ok := server.Channels[int(chanid)]; ok {
			if !acl.HasPermission(&channel.ACL, client, acl.TextMessagePermission) {
				client.sendPermissionDenied(client, channel, acl.TextMessagePermission)
				return
			}
			for _, target := range channel.clients {
				clients[target.Session()] = target
			}
		}
	}

	// Direct-to-clients
	for _, session := range txtmsg.Session {
		if target, ok := server.clients[session]; ok {
			if !acl.HasPermission(&target.Channel.ACL, client, acl.TextMessagePermission) {
				client.sendPermissionDenied(client, target.Channel, acl.TextMessagePermission)
				return
			}
			clients[session] = target
		}
	}

	// Remove ourselves
	delete(clients, client.Session())

	for _, target := range clients {
		target.sendMessage(&mumbleproto.TextMessage{
			Actor:   proto.Uint32(client.Session()),
			Message: txtmsg.Message,
		})
	}
}

// ACL set/query
func (server *Server) handleAclMessage(client *Client, msg *Message) {
	pacl := &mumbleproto.ACL{}
	err := proto.Unmarshal(msg.buf, pacl)
	if err != nil {
		client.Panic(err)
		return
	}

	// Look up the channel this ACL message operates on.
	channel, ok := server.Channels[int(*pacl.ChannelId)]
	if !ok {
		return
	}

	// Does the user have permission to update or look at ACLs?
	if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) && !(channel.parent != nil && acl.HasPermission(&channel.parent.ACL, client, acl.WritePermission)) {
		client.sendPermissionDenied(client, channel, acl.WritePermission)
		return
	}

	reply := &mumbleproto.ACL{}
	reply.ChannelId = proto.Uint32(uint32(channel.Id))

	channels := []*Channel{}
	users := map[int]bool{}

	// Query the current ACL state for the channel
	if pacl.Query != nil && *pacl.Query != false {
		reply.InheritAcls = proto.Bool(channel.ACL.InheritACL)
		// Walk the channel tree to get all relevant channels.
		// (Stop if we reach a channel that doesn't have the InheritACL flag set)
		iter := channel
		for iter != nil {
			channels = append([]*Channel{iter}, channels...)
			if iter == channel || iter.ACL.InheritACL {
				iter = iter.parent
			} else {
				iter = nil
			}
		}

		// Construct the protobuf ChanACL objects corresponding to the ACLs defined
		// in our channel list.
		reply.Acls = []*mumbleproto.ACL_ChanACL{}
		for _, iter := range channels {
			for _, chanacl := range iter.ACL.ACLs {
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
		allnames := channel.ACL.GroupNames()

		// Construct the protobuf ChanGroups that we send back to the client.
		// Also constructs a usermap that is a set user ids from the channel's groups.
		reply.Groups = []*mumbleproto.ACL_ChanGroup{}
		for _, name := range allnames {
			var (
				group     acl.Group
				hasgroup  bool
				pgroup    acl.Group
				haspgroup bool
			)

			group, hasgroup = channel.ACL.Groups[name]
			if parent != nil {
				pgroup, haspgroup = parent.ACL.Groups[name]
			}

			mpgroup := &mumbleproto.ACL_ChanGroup{}
			mpgroup.Name = proto.String(name)

			mpgroup.Inherit = proto.Bool(true)
			if hasgroup {
				mpgroup.Inherit = proto.Bool(group.Inherit)
			}

			mpgroup.Inheritable = proto.Bool(true)
			if hasgroup {
				mpgroup.Inheritable = proto.Bool(group.Inheritable)
			}

			mpgroup.Inherited = proto.Bool(haspgroup && pgroup.Inheritable)

			// Add the set of user ids that this group affects to the user map.
			// This is used later on in this function to send the client a QueryUsers
			// message that maps user ids to usernames.
			if hasgroup {
				toadd := map[int]bool{}
				for uid, _ := range group.Add {
					users[uid] = true
					toadd[uid] = true
				}
				for uid, _ := range group.Remove {
					users[uid] = true
					delete(toadd, uid)
				}
				for uid, _ := range toadd {
					mpgroup.Add = append(mpgroup.Add, uint32(uid))
				}
			}
			if haspgroup {
				for uid, _ := range pgroup.MembersInContext(&parent.ACL) {
					users[uid] = true
					mpgroup.InheritedMembers = append(mpgroup.InheritedMembers, uint32(uid))
				}
			}

			reply.Groups = append(reply.Groups, mpgroup)
		}

		if err := client.sendMessage(reply); err != nil {
			client.Panic(err)
			return
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
			client.sendMessage(queryusers)
		}

		// Set new groups and ACLs
	} else {

		// Get old temporary members
		oldtmp := map[string]map[int]bool{}
		for name, grp := range channel.ACL.Groups {
			oldtmp[name] = grp.Temporary
		}

		// Clear current ACLs and groups
		channel.ACL.ACLs = []acl.ACL{}
		channel.ACL.Groups = map[string]acl.Group{}

		// Add the received groups to the channel.
		channel.ACL.InheritACL = *pacl.InheritAcls
		for _, pbgrp := range pacl.Groups {
			changroup := acl.EmptyGroupWithName(*pbgrp.Name)

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

			channel.ACL.Groups[changroup.Name] = changroup
		}
		// Add the received ACLs to the channel.
		for _, pbacl := range pacl.Acls {
			chanacl := acl.ACL{}
			chanacl.ApplyHere = *pbacl.ApplyHere
			chanacl.ApplySubs = *pbacl.ApplySubs
			if pbacl.UserId != nil {
				chanacl.UserId = int(*pbacl.UserId)
			} else {
				chanacl.Group = *pbacl.Group
			}
			chanacl.Deny = acl.Permission(*pbacl.Deny & acl.AllPermissions)
			chanacl.Allow = acl.Permission(*pbacl.Grant & acl.AllPermissions)

			channel.ACL.ACLs = append(channel.ACL.ACLs, chanacl)
		}

		// Clear the Server's caches
		server.ClearCaches()

		// Regular user?
		if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) && client.IsRegistered() || client.HasCertificate() {
			chanacl := acl.ACL{}
			chanacl.ApplyHere = true
			chanacl.ApplySubs = false
			if client.IsRegistered() {
				chanacl.UserId = client.UserId()
			} else if client.HasCertificate() {
				chanacl.Group = "$" + client.CertHash()
			}
			chanacl.Deny = acl.Permission(acl.NonePermission)
			chanacl.Allow = acl.Permission(acl.WritePermission | acl.TraversePermission)

			channel.ACL.ACLs = append(channel.ACL.ACLs, chanacl)

			server.ClearCaches()
		}

		// Update freezer
		server.UpdateFrozenChannelACLs(channel)
	}
}

// User query
func (server *Server) handleQueryUsers(client *Client, msg *Message) {
	query := &mumbleproto.QueryUsers{}
	err := proto.Unmarshal(msg.buf, query)
	if err != nil {
		client.Panic(err)
		return
	}

	server.Printf("in handleQueryUsers")

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

	if err := client.sendMessage(reply); err != nil {
		client.Panic(err)
		return
	}
}

// User stats message. Shown in the Mumble client when a
// user right clicks a user and selects 'User Information'.
func (server *Server) handleUserStatsMessage(client *Client, msg *Message) {
	stats := &mumbleproto.UserStats{}
	err := proto.Unmarshal(msg.buf, stats)
	if err != nil {
		client.Panic(err)
		return
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
	rootChan := server.RootChannel()
	if acl.HasPermission(&rootChan.ACL, client, acl.RegisterPermission) {
		extended = true
	}

	// If the client wasn't granted extended permissions, only allow it to query
	// users in channels it can enter.
	if !extended && !acl.HasPermission(&target.Channel.ACL, client, acl.EnterPermission) {
		client.sendPermissionDenied(client, target.Channel, acl.EnterPermission)
		return
	}

	details := extended
	local := extended || target.Channel == client.Channel

	if stats.StatsOnly != nil && *stats.StatsOnly == true {
		details = false
	}

	stats.Reset()
	stats.Session = proto.Uint32(target.Session())

	if details {
		if tlsconn := target.conn.(*tls.Conn); tlsconn != nil {
			state := tlsconn.ConnectionState()
			for i := len(state.PeerCertificates) - 1; i >= 0; i-- {
				stats.Certificates = append(stats.Certificates, state.PeerCertificates[i].Raw)
			}
			stats.StrongCertificate = proto.Bool(target.IsVerified())
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
		stats.Opus = proto.Bool(target.opus)
		stats.Address = target.tcpaddr.IP
	}

	// fixme(mkrautz): we don't do bandwidth tracking yet

	if err := client.sendMessage(stats); err != nil {
		client.Panic(err)
		return
	}
}

// Voice target message
func (server *Server) handleVoiceTarget(client *Client, msg *Message) {
	vt := &mumbleproto.VoiceTarget{}
	err := proto.Unmarshal(msg.buf, vt)
	if err != nil {
		client.Panic(err.Error())
		return
	}

	if vt.Id == nil {
		return
	}

	id := *vt.Id
	if id < 1 || id >= 0x1f {
		return
	}

	if len(vt.Targets) == 0 {
		delete(client.voiceTargets, id)
	}

	for _, target := range vt.Targets {
		newTarget := &VoiceTarget{}
		for _, session := range target.Session {
			newTarget.AddSession(session)
		}
		if target.ChannelId != nil {
			chanid := *target.ChannelId
			group := ""
			links := false
			subchannels := false
			if target.Group != nil {
				group = *target.Group
			}
			if target.Links != nil {
				links = *target.Links
			}
			if target.Children != nil {
				subchannels = *target.Children
			}
			newTarget.AddChannel(chanid, subchannels, links, group)
		}
		if newTarget.IsEmpty() {
			delete(client.voiceTargets, id)
		} else {
			client.voiceTargets[id] = newTarget
		}
	}
}

// Permission query
func (server *Server) handlePermissionQuery(client *Client, msg *Message) {
	query := &mumbleproto.PermissionQuery{}
	err := proto.Unmarshal(msg.buf, query)
	if err != nil {
		client.Panic(err)
		return
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
		client.Panic(err)
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
					buf, err := blobStore.Get(target.user.TextureBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err)
						return
					}
					userstate.Reset()
					userstate.Session = proto.Uint32(uint32(target.Session()))
					userstate.Texture = buf
					if err := client.sendMessage(userstate); err != nil {
						client.Panic(err)
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
					buf, err := blobStore.Get(target.user.CommentBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err)
						return
					}
					userstate.Reset()
					userstate.Session = proto.Uint32(uint32(target.Session()))
					userstate.Comment = proto.String(string(buf))
					if err := client.sendMessage(userstate); err != nil {
						client.Panic(err)
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
					buf, err := blobStore.Get(channel.DescriptionBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err)
						return
					}
					chanstate.ChannelId = proto.Uint32(uint32(channel.Id))
					chanstate.Description = proto.String(string(buf))
					if err := client.sendMessage(chanstate); err != nil {
						client.Panic(err)
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
		client.Panic(err)
		return
	}

	// Only users who are allowed to register other users can access the user list.
	rootChan := server.RootChannel()
	if !acl.HasPermission(&rootChan.ACL, client, acl.RegisterPermission) {
		client.sendPermissionDenied(client, rootChan, acl.RegisterPermission)
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
		if err := client.sendMessage(userlist); err != nil {
			client.Panic(err)
			return
		}
		// Rename, registration removal
	} else {
		if len(userlist.Users) > 0 {
			tx := server.freezelog.BeginTx()
			for _, listUser := range userlist.Users {
				uid := *listUser.UserId
				if uid == 0 {
					continue
				}
				user, ok := server.Users[uid]
				if ok {
					if listUser.Name == nil {
						// De-register
						server.RemoveRegistration(uid)
						err := tx.Put(&freezer.UserRemove{Id: listUser.UserId})
						if err != nil {
							server.Fatal(err)
						}
					} else {
						// Rename user
						// todo(mkrautz): Validate name.
						user.Name = *listUser.Name
						err := tx.Put(&freezer.User{Id: listUser.UserId, Name: listUser.Name})
						if err != nil {
							server.Fatal(err)
						}
					}
				}
			}
			err := tx.Commit()
			if err != nil {
				server.Fatal(err)
			}
		}
	}
}
