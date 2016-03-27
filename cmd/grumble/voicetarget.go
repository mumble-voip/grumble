// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import "github.com/mumble-voip/grumble/pkg/acl"

// A VoiceTarget holds information about a single
// VoiceTarget entry of a Client.
type VoiceTarget struct {
	sessions []uint32
	channels []voiceTargetChannel

	directCache       map[uint32]*Client
	fromChannelsCache map[uint32]*Client
}

type voiceTargetChannel struct {
	id          uint32
	subChannels bool
	links       bool
	onlyGroup   string
}

// Add's a client's session to the VoiceTarget
func (vt *VoiceTarget) AddSession(session uint32) {
	vt.sessions = append(vt.sessions, session)
}

// Add a channel to the VoiceTarget.
// If subchannels is true, any sent voice packets will also be sent to all subchannels.
// If links is true, any sent voice packets will also be sent to all linked channels.
// If group is a non-empty string, any sent voice packets will only be broadcast to members
// of that group who reside in the channel (or its children or linked channels).
func (vt *VoiceTarget) AddChannel(id uint32, subchannels bool, links bool, group string) {
	vt.channels = append(vt.channels, voiceTargetChannel{
		id:          id,
		subChannels: subchannels,
		links:       links,
		onlyGroup:   group,
	})
}

// Checks whether the VoiceTarget is empty (has no targets)
func (vt *VoiceTarget) IsEmpty() bool {
	return len(vt.sessions) == 0 && len(vt.channels) == 0
}

// Clear the VoiceTarget's cache.
func (vt *VoiceTarget) ClearCache() {
	vt.directCache = nil
	vt.fromChannelsCache = nil
}

// Send the contents of the VoiceBroadcast to all targets specified in the
// VoiceTarget.
func (vt *VoiceTarget) SendVoiceBroadcast(vb *VoiceBroadcast) {
	buf := vb.buf
	client := vb.client
	server := client.server

	direct := vt.directCache
	fromChannels := vt.fromChannelsCache

	if direct == nil || fromChannels == nil {
		direct = make(map[uint32]*Client)
		fromChannels = make(map[uint32]*Client)

		for _, vtc := range vt.channels {
			channel := server.Channels[int(vtc.id)]
			if channel == nil {
				continue
			}

			if !vtc.subChannels && !vtc.links && vtc.onlyGroup == "" {
				if acl.HasPermission(&channel.ACL, client, acl.WhisperPermission) {
					for _, target := range channel.clients {
						fromChannels[target.Session()] = target
					}
				}
			} else {
				server.Printf("%v", vtc)
				newchans := make(map[int]*Channel)
				if vtc.links {
					newchans = channel.AllLinks()
				} else {
					newchans[channel.Id] = channel
				}
				if vtc.subChannels {
					subchans := channel.AllSubChannels()
					for k, v := range subchans {
						newchans[k] = v
					}
				}
				for _, newchan := range newchans {
					if acl.HasPermission(&newchan.ACL, client, acl.WhisperPermission) {
						for _, target := range newchan.clients {
							if vtc.onlyGroup == "" || acl.GroupMemberCheck(&newchan.ACL, &newchan.ACL, vtc.onlyGroup, target) {
								fromChannels[target.Session()] = target
							}
						}
					}
				}
			}
		}

		for _, session := range vt.sessions {
			target := server.clients[session]
			if target != nil {
				if _, alreadyInFromChannels := fromChannels[target.Session()]; !alreadyInFromChannels {
					direct[target.Session()] = target
				}
			}
		}

		// Make sure we don't send to ourselves.
		delete(direct, client.Session())
		delete(fromChannels, client.Session())

		if vt.directCache == nil {
			vt.directCache = direct
		}

		if vt.fromChannelsCache == nil {
			vt.fromChannelsCache = fromChannels
		}
	}

	kind := buf[0] & 0xe0

	if len(fromChannels) > 0 {
		for _, target := range fromChannels {
			buf[0] = kind | 2
			err := target.SendUDP(buf)
			if err != nil {
				target.Panicf("Unable to send UDP packet: %v", err.Error())
			}
		}
	}

	if len(direct) > 0 {
		for _, target := range direct {
			buf[0] = kind | 2
			target.SendUDP(buf)
			err := target.SendUDP(buf)
			if err != nil {
				target.Panicf("Unable to send UDP packet: %v", err.Error())
			}
		}
	}
}
