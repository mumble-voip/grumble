// Copyright (c) 2010-2013 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package acl

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

// Permission represents a permission in Mumble's ACL system.
type Permission uint32

// Check whether the given flags are set on perm
func (perm Permission) isSet(check Permission) bool {
	return perm&check == check
}

// IsCached checks whether the ACL has its cache bit set,
// signalling that it was returned from an ACLCache.
func (perm Permission) IsCached() bool {
	return perm.isSet(CachedPermission)
}

// Clean returns a Permission that has its cache bit cleared.
func (perm Permission) Clean() Permission {
	return perm ^ Permission(CachedPermission)
}

// An ACL as defined in an ACL context.
// An ACL can be defined for either a user or a group.
type ACL struct {
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

// IsUserACL returns true if the ACL is defined for a user,
// as opposed to a group.
func (acl *ACL) IsUserACL() bool {
	return acl.UserId != -1
}

// IsChannelACL returns true if the ACL is defined for a group,
// as opposed to a user.
func (acl *ACL) IsChannelACL() bool {
	return !acl.IsUserACL()
}

// HasPermission checks whether the given user has permission perm in the given context.
// The permission perm must be a single permission and not a combination of permissions.
func HasPermission(ctx *Context, user User, perm Permission) bool {
	// We can't check permissions on a nil ctx.
	if ctx == nil {
		panic("acl: HasPermission got nil context")
	}

	// SuperUser can't speak or whisper, but everything else is OK
	if user.UserId() == 0 {
		if perm == SpeakPermission || perm == WhisperPermission {
			return false
		}
		return true
	}

	// Default permissions
	defaults := Permission(TraversePermission | EnterPermission | SpeakPermission | WhisperPermission | TextMessagePermission)
	granted := defaults
	contexts := buildChain(ctx)
	origCtx := ctx

	traverse := true
	write := false

	for _, ctx := range contexts {
		// If the context does not inherit any ACLs, use the default permissions.
		if !ctx.InheritACL {
			granted = defaults
		}
		// Iterate through ACLs that are defined on ctx. Note: this does not include
		// ACLs that iter has inherited from a parent (unless there is also a group on
		// iter with the same name, that changes the permissions a bit!)
		for _, acl := range ctx.ACLs {
			// Determine whether the ACL applies to user.
			// If it is a user ACL and the user id of the ACL
			// matches user's id, we're good to go.
			//
			// If it's a group ACL, we have to parse and interpret
			// the group string in the current context to determine
			// membership. For that we use GroupMemberCheck.
			matchUser := acl.IsUserACL() && acl.UserId == user.UserId()
			matchGroup := GroupMemberCheck(origCtx, ctx, acl.Group, user)
			if matchUser || matchGroup {
				if acl.Allow.isSet(TraversePermission) {
					traverse = true
				}
				if acl.Deny.isSet(TraversePermission) {
					traverse = false
				}
				if acl.Allow.isSet(WritePermission) {
					write = true
				}
				if acl.Deny.isSet(WritePermission) {
					write = false
				}
				if (origCtx == ctx && acl.ApplyHere) || (origCtx != ctx && acl.ApplySubs) {
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
