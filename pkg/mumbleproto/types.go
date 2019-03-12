// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package mumbleproto

const (
	MessageVersion uint16 = iota
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
	MessageContextActionModify
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
	UDPMessageVoiceOpus
)

// MessageType returns the numeric value identifying the message type of msg on the wire.
func MessageType(msg interface{}) uint16 {
	switch msg.(type) {
	case *Version:
		return MessageVersion
	case *UDPTunnel:
	case []byte:
		return MessageUDPTunnel
	case *Authenticate:
		return MessageAuthenticate
	case *Ping:
		return MessagePing
	case *Reject:
		return MessageReject
	case *ServerSync:
		return MessageServerSync
	case *ChannelRemove:
		return MessageChannelRemove
	case *ChannelState:
		return MessageChannelState
	case *UserRemove:
		return MessageUserRemove
	case *UserState:
		return MessageUserState
	case *BanList:
		return MessageBanList
	case *TextMessage:
		return MessageTextMessage
	case *PermissionDenied:
		return MessagePermissionDenied
	case *ACL:
		return MessageACL
	case *QueryUsers:
		return MessageQueryUsers
	case *CryptSetup:
		return MessageCryptSetup
	case *ContextActionModify:
		return MessageContextActionModify
	case *ContextAction:
		return MessageContextAction
	case *UserList:
		return MessageUserList
	case *VoiceTarget:
		return MessageVoiceTarget
	case *PermissionQuery:
		return MessagePermissionQuery
	case *CodecVersion:
		return MessageCodecVersion
	case *UserStats:
		return MessageUserStats
	case *RequestBlob:
		return MessageRequestBlob
	case *ServerConfig:
		return MessageServerConfig
	}
	panic("unknown type")
}
