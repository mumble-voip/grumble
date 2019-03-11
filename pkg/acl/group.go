// Copyright (c) 2010-2013 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.
package acl

import (
	"log"
	"strconv"
	"strings"
)

// Group represents a Group in an Context.
type Group struct {
	// The name of this group
	Name string

	// The inherit flag means that this group will inherit group
	// members from its parent.
	Inherit bool

	// The inheritable flag means that subchannels can
	// inherit the members of this group.
	Inheritable bool

	// Group adds permissions to these users
	Add map[int]bool
	// Group removes permissions from these users
	Remove map[int]bool
	// Temporary add (authenticators)
	Temporary map[int]bool
}

// EmptyGroupWithName creates a new Group with the given name.
func EmptyGroupWithName(name string) Group {
	grp := Group{}
	grp.Name = name
	grp.Add = make(map[int]bool)
	grp.Remove = make(map[int]bool)
	grp.Temporary = make(map[int]bool)
	return grp
}

// AddContains checks whether the Add set contains id.
func (group *Group) AddContains(id int) (ok bool) {
	_, ok = group.Add[id]
	return
}

// AddUsers gets the list of user ids in the Add set.
func (group *Group) AddUsers() []int {
	users := []int{}
	for uid, _ := range group.Add {
		users = append(users, uid)
	}
	return users
}

// RemoveContains checks whether the Remove set contains id.
func (group *Group) RemoveContains(id int) (ok bool) {
	_, ok = group.Remove[id]
	return
}

// RemoveUsers gets the list of user ids in the Remove set.
func (group *Group) RemoveUsers() []int {
	users := []int{}
	for uid, _ := range group.Remove {
		users = append(users, uid)
	}
	return users
}

// TemporaryContains checks whether the Temporary set contains id.
func (group *Group) TemporaryContains(id int) (ok bool) {
	_, ok = group.Temporary[id]
	return
}

// MembersInContext gets the set of user id's from the group in the given context.
// This includes group members that have been inherited from an ancestor context.
func (group *Group) MembersInContext(ctx *Context) map[int]bool {
	groups := []Group{}
	members := map[int]bool{}

	// Walk a group's context chain, starting with the context the group
	// is defined on, followed by its parent contexts.
	origCtx := ctx
	for ctx != nil {
		curgroup, ok := ctx.Groups[group.Name]
		if ok {
			// If the group is not inheritable, and we're looking at an
			// ancestor group, we've looked in all the groups we should.
			if ctx != origCtx && !curgroup.Inheritable {
				break
			}
			// Add the group to the list of groups to be considered
			groups = append([]Group{curgroup}, groups...)
			// If this group does not inherit from groups in its ancestors, stop looking
			// for more ancestor groups.
			if !curgroup.Inherit {
				break
			}
		}
		ctx = ctx.Parent
	}

	for _, curgroup := range groups {
		for uid, _ := range curgroup.Add {
			members[uid] = true
		}
		for uid, _ := range curgroup.Remove {
			delete(members, uid)
		}
	}

	return members
}

// GroupMemberCheck checks whether a user is a member
// of the group as defined in the given context.
//
// The 'current' context is the context that group
// membership is currently being evaluated for.
//
// The 'acl' context is the context of the ACL that
// that group membership is being evaluated for.
//
// The acl context will always be either equal to
// current, or be an ancestor.
func GroupMemberCheck(current *Context, acl *Context, name string, user User) (ok bool) {
	valid := true
	invert := false
	token := false
	hash := false

	// Returns the 'correct' return value considering the value
	// of the invert flag.
	defer func() {
		if valid && invert {
			ok = !ok
		}
	}()

	channel := current

	for {
		// Empty group name are not valid.
		if len(name) == 0 {
			valid = false
			return false
		}
		// Invert
		if name[0] == '!' {
			invert = true
			name = name[1:]
			continue
		}
		// Evaluate in ACL context (not current channel)
		if name[0] == '~' {
			channel = acl
			name = name[1:]
			continue
		}
		// Token
		if name[0] == '#' {
			token = true
			name = name[1:]
			continue
		}
		// Hash
		if name[0] == '$' {
			hash = true
			name = name[1:]
			continue
		}
		break
	}

	if token {
		// The user is part of this group if the remaining name is part of
		// his access token list. The name check is case-insensitive.
		for _, token := range user.Tokens() {
			if strings.ToLower(name) == strings.ToLower(token) {
				return true
			}
		}
		return false
	} else if hash {
		// The client is part of this group if the remaining name matches the
		// client's cert hash.
		if strings.ToLower(name) == strings.ToLower(user.CertHash()) {
			return true
		}
		return false
	} else if name == "none" {
		// None
		return false
	} else if name == "all" {
		// Everyone
		return true
	} else if name == "auth" {
		// The user is part of the auth group is he is authenticated. That is,
		// his UserId is >= 0.
		return user.UserId() >= 0
	} else if name == "strong" {
		// The user is part of the strong group if he is authenticated to the server
		// via a strong certificate (i.e. non-self-signed, trusted by the server's
		// trusted set of root CAs).
		log.Printf("GroupMemberCheck: Implement strong certificate matching")
		return false
	} else if name == "in" {
		// Is the user in the currently evaluated channel?
		return user.ACLContext() == channel
	} else if name == "out" {
		// Is the user not in the currently evaluated channel?
		return user.ACLContext() != channel
	} else if name == "sub" {
		// fixme(mkrautz): The sub group implementation below hasn't been thoroughly
		// tested yet. It might be a bit buggy!

		// Strip away the "sub," part of the name
		name = name[4:]

		mindesc := 1
		maxdesc := 1000
		minpath := 0

		// Parse the groupname to extract the values we should use
		// for minpath (first argument), mindesc (second argument),
		// and maxdesc (third argument).
		args := strings.SplitN(name, ",", 3)
		nargs := len(args)
		if nargs == 3 {
			if len(args[2]) > 0 {
				if result, err := strconv.Atoi(args[2]); err == nil {
					maxdesc = result
				}
			}
		}
		if nargs >= 2 {
			if len(args[1]) > 0 {
				if result, err := strconv.Atoi(args[1]); err == nil {
					mindesc = result
				}
			}
		}
		if nargs >= 1 {
			if len(args[0]) > 0 {
				if result, err := strconv.Atoi(args[0]); err == nil {
					minpath = result
				}
			}
		}

		// Build a context chain starting from the
		// user's current context.
		userChain := buildChain(user.ACLContext())
		// Build a chain of contexts, starting from
		// the 'current' context. This is the context
		// that group membership is checked against,
		// notwithstanding the ~ group operator.
		groupChain := buildChain(current)

		// Find the index of the context that the group
		// is currently being evaluated on. This can be
		// either the 'acl' context or 'current' context
		// depending on the ~ group operator.
		cofs := indexOf(groupChain, current)
		if cofs == -1 {
			valid = false
			return false
		}

		// Add the first parameter of our sub group to cofs
		// to get our base context.
		cofs += minpath
		// Check that the minpath parameter that was given
		// is a valid index for groupChain.
		if cofs >= len(groupChain) {
			valid = false
			return false
		} else if cofs < 0 {
			cofs = 0
		}

		// If our base context is not in the userChain, the
		// group does not apply to the user.
		if indexOf(userChain, groupChain[cofs]) == -1 {
			return false
		}

		// Down here, we're certain that the userChain
		// includes the base context somewhere in its
		// chain. We must now determine if the path depth
		// makes the user a member of the group.
		mindepth := cofs + mindesc
		maxdepth := cofs + maxdesc
		pdepth := len(userChain) - 1
		return pdepth >= mindepth && pdepth <= maxdepth

	} else {
		// Non-magic groups
		groups := []Group{}

		iter := channel
		for iter != nil {
			if group, ok := iter.Groups[name]; ok {
				// Skip non-inheritable groups if we're in parents
				// of our evaluated context.
				if iter != channel && !group.Inheritable {
					break
				}
				// Prepend group
				groups = append([]Group{group}, groups...)
				// If this group does not inherit from groups in its ancestors, stop looking
				// for more ancestor groups.
				if !group.Inherit {
					break
				}
			}
			iter = iter.Parent
		}

		isMember := false
		for _, group := range groups {
			if group.AddContains(user.UserId()) || group.TemporaryContains(user.UserId()) || group.TemporaryContains(-int(user.Session())) {
				isMember = true
			}
			if group.RemoveContains(user.UserId()) {
				isMember = false
			}
		}
		return isMember
	}

	return false
}

// GroupNames gets the list of group names for the given ACL context.
//
// This function walks the through the context chain to figure
// out all groups that affect the given context whilst considering
// group inheritance.
func (ctx *Context) GroupNames() []string {
	names := map[string]bool{}
	origCtx := ctx
	contexts := []*Context{}

	// Walk through the whole context chain and all groups in it.
	for _, ctx := range contexts {
		for _, group := range ctx.Groups {
			// A non-inheritable group in parent. Discard it.
			if ctx != origCtx && !group.Inheritable {
				delete(names, group.Name)
				// An inheritable group. Add it to the list.
			} else {
				names[group.Name] = true
			}
		}
	}

	// Convert to slice
	stringNames := make([]string, 0, len(names))
	for name, ok := range names {
		if ok {
			stringNames = append(stringNames, name)
		}
	}
	return stringNames
}
