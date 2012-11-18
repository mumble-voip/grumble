// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

const (
	// Per-channel permissions
	NonePermission        = 0x0
	WritePermission       = 0x1
	TraversePermission    = 0x2
	EnterPermission       = 0x4
	SpeakPermission       = 0x8
	MuteDeafenPermission  = 0x10
	MovePermission        = 0x20
	MakeChannelPermission = 0x40
	LinkChannelPermission = 0x80
	WhisperPermission     = 0x100
	TextMessagePermission = 0x200
	TempChannelPermission = 0x400

	// Root channel only
	KickPermission         = 0x10000
	BanPermission          = 0x20000
	RegisterPermission     = 0x40000
	SelfRegisterPermission = 0x80000

	// Extra flags
	CachedPermission = 0x8000000
	AllPermissions   = 0xf07ff
)

type Permission uint32

// Check whether the given flags are set on perm
func (perm Permission) IsSet(check Permission) bool {
	return perm&check == check
}

// Check whether the Permission is marked as cached
// (i.e. that it was read from an ACLCache)
func (perm Permission) IsCached() bool {
	return perm.IsSet(CachedPermission)
}

// Clear a flag in the Permission
func (perm Permission) ClearFlag(flag Permission) {
	perm &= ^flag
}

// Clear the cache bit in the Permission
func (perm Permission) ClearCacheBit() {
	perm.ClearFlag(CachedPermission)
}

// A channel-to-permission mapping used in the ACLCache
type ChannelCache map[int]Permission

// The ACLCache maps a user id to a ChannelCache map.
// The ChannelCache map maps a channel to its permissions.
type ACLCache map[uint32]ChannelCache

// Creates a new ACLCache
func NewACLCache() ACLCache {
	return make(map[uint32]ChannelCache)
}

// Store a client's permissions for a particular channel. When the permissions are stored,
// the permission will have the CachedPermission flag added to it.
func (cache ACLCache) StorePermission(client *Client, channel *Channel, perm Permission) {
	chancache, ok := cache[client.Session]
	if !ok {
		chancache = make(map[int]Permission)
		cache[client.Session] = chancache
	}
	chancache[channel.Id] = perm | CachedPermission
}

// Get a client's permissions for a partcular channel. NonePermission will be returned
// on error. To determine whether the returned value was retrieved from the cache, the
// caller must call IsCached() on the returned permission.
func (cache ACLCache) GetPermission(client *Client, channel *Channel) (perm Permission) {
	chancache, ok := cache[client.Session]
	perm = Permission(NonePermission)
	if !ok {
		return
	}
	perm, ok = chancache[channel.Id]
	if !ok {
		perm = Permission(NonePermission)
		return
	}
	return
}

// An ACL as defined on a channel.
// An ACL can be defined for either a user or a group.
type ChannelACL struct {
	// The channel that the ChannelACL is defined on.
	Channel *Channel

	// The user id that this ACL applied to. If this
	// field is -1, the ACL is a group ACL.
	UserId int
	// The group that this ACL applies to.
	Group string

	// The ApplyHere flag determines whether the ACL
	// should apply to the current channel.
	ApplyHere bool
	// The ApplySubs flag determines whethr the ACL
	// should apply to subchannels.
	ApplySubs bool

	// The allowed permission flags.
	Allow Permission
	// The allowed permission flags. The Deny flags override
	// permissions set in Allow.
	Deny Permission
}

// Returns true if the ACL is defined on a user
// (as opposed to a group)
func (acl ChannelACL) IsUserACL() bool {
	return acl.UserId != -1
}

// Returns true if the ACL is defined on a channel
// (as opposed to a user)
func (acl ChannelACL) IsChannelACL() bool {
	return !acl.IsUserACL()
}

// Create a new ACL for channel. Does not add it to the channel's
// ACL list. This must be done manually.
func NewChannelACL(channel *Channel) *ChannelACL {
	return &ChannelACL{
		Channel: channel,
		UserId:  -1,
	}
}

// Check whether client has permission perm on channel. Perm *must* be a single permission,
// and not a combination of permissions.
func (server *Server) HasPermission(client *Client, channel *Channel, perm Permission) (ok bool) {
	// SuperUser can't speak or whisper, but everything else is OK	
	if client.IsSuperUser() {
		if perm == SpeakPermission || perm == WhisperPermission {
			return false
		}
		return true
	}

	// First, try to look in the server's ACLCache.
	granted := Permission(NonePermission)
	cached := server.aclcache.GetPermission(client, channel)
	if cached.IsCached() {
		granted = cached
		// The +write permission implies all permissions except for +speak and +whisper.
		// For more information regarding this check, please see the comment regarding a simmilar
		// check at the bottom of this function.
		if perm != SpeakPermission && perm != WhisperPermission {
			return (granted & (perm | WritePermission)) != NonePermission
		} else {
			return (granted & perm) != NonePermission
		}
	}

	// Default permissions
	def := Permission(TraversePermission | EnterPermission | SpeakPermission | WhisperPermission | TextMessagePermission)
	granted = def

	channels := []*Channel{}
	iter := channel
	for iter != nil {
		channels = append([]*Channel{iter}, channels...)
		iter = iter.parent
	}

	traverse := true
	write := false

	for _, iter := range channels {
		// If the channel does not inherit any ACLs, use the default permissions.
		if !iter.InheritACL {
			granted = def
		}
		// Iterate through ACLs that are defined on iter. Note: this does not include
		// ACLs that iter has inherited from a parent (unless there is also a group on
		// iter with the same name, that changes the permissions a bit!)
		for _, acl := range iter.ACL {
			// Determine whether the ACL applies to client.  If it is
			// a user ACL and the user id of the ACL matches client, we're good to go.
			//
			// If it's a group ACL, we have to parse and interpret the group string in the
			// current context to determine membership. For that we use GroupMemberCheck.
			matchUser := acl.IsUserACL() && acl.UserId == client.UserId()
			matchGroup := GroupMemberCheck(channel, iter, acl.Group, client)
			if matchUser || matchGroup {
				if acl.Allow.IsSet(TraversePermission) {
					traverse = true
				}
				if acl.Deny.IsSet(TraversePermission) {
					traverse = false
				}
				if acl.Allow.IsSet(WritePermission) {
					write = true
				}
				if acl.Deny.IsSet(WritePermission) {
					write = false
				}
				if (channel == iter && acl.ApplyHere) || (channel != iter && acl.ApplySubs) {
					granted |= acl.Allow
					granted &= ^acl.Deny
				}
			}
		}
		// If traverse is not set and the user doesn't have write permissions
		// on the channel, the user will not have any permissions.
		// This is because -traverse removes all permissions, and +write grants
		// all permissions.
		if !traverse && !write {
			granted = NonePermission
			break
		}
	}

	// Cache the result
	server.aclcache.StorePermission(client, channel, granted)

	// The +write permission implies all permissions except for +speak and +whisper.
	// This means that if the user has WritePermission, we should return true for all
	// permissions exccept SpeakPermission and WhisperPermission.
	if perm != SpeakPermission && perm != WhisperPermission {
		return (granted & (perm | WritePermission)) != NonePermission
	} else {
		return (granted & perm) != NonePermission
	}

	return false
}
