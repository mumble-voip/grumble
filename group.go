// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"log"
	"strings"
	"strconv"
)

type Group struct {
	// The channel that this group resides in
	Channel *Channel

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

// Create a new group for channel with name. Does not add it to the channels
// group list.
func NewGroup(channel *Channel, name string) *Group {
	grp := &Group{}
	grp.Channel = channel
	grp.Name = name
	grp.Add = make(map[int]bool)
	grp.Remove = make(map[int]bool)
	grp.Temporary = make(map[int]bool)
	return grp
}

// Check whether the Add set contains id.
func (group *Group) AddContains(id int) (ok bool) {
	_, ok = group.Add[id]
	return
}

// Get the list of user ids in the Add set.
func (group *Group) AddUsers() []int {
	users := []int{}
	for uid, _ := range group.Add {
		users = append(users, uid)
	}
	return users
}

// Check whether the Remove set contains id.
func (group *Group) RemoveContains(id int) (ok bool) {
	_, ok = group.Remove[id]
	return
}

// Get the list of user ids in the Remove set.
func (group *Group) RemoveUsers() []int {
	users := []int{}
	for uid, _ := range group.Remove {
		users = append(users, uid)
	}
	return users
}

// Check whether the Temporary set contains id.
func (group *Group) TemporaryContains(id int) (ok bool) {
	_, ok = group.Temporary[id]
	return
}

// Get the set of user id's from the group. This includes group
// members that have been inherited from an ancestor.
func (group *Group) Members() map[int]bool {
	groups := []*Group{}
	members := map[int]bool{}

	// The channel that the group is defined on.
	channel := group.Channel

	// Walk a group's channel tree, starting with the channel the group
	// is defined on, followed by its parent channels.
	iter := group.Channel
	for iter != nil {
		curgroup := iter.Groups[group.Name]
		if curgroup != nil {
			// If the group is not inheritable, and we're looking at an
			// ancestor group, we've looked in all the groups we should.
			if iter != channel && !curgroup.Inheritable {
				break
			}
			// Add the group to the list of groups to be considered
			groups = append([]*Group{curgroup}, groups...)
			// If this group does not inherit from groups in its ancestors, stop looking
			// for more ancestor groups.
			if !curgroup.Inherit {
				break
			}
		}
		iter = iter.parent
	}

	for _, curgroup := range groups {
		for uid, _ := range curgroup.Add {
			members[uid] = true
		}
		for uid, _ := range curgroup.Remove {
			members[uid] = false, false
		}
	}

	return members
}

// Checks whether a user is a member of the group as defined on channel.
// The channel current is the channel that group membership is currently being evaluated for.
// The channel aclchan is the channel that the group is defined on. This means that current inherits
// the group from an acl in aclchan.
//
// The channel aclchan will always be either equal to current, or be an ancestor.
func GroupMemberCheck(current *Channel, aclchan *Channel, name string, client *Client) (ok bool) {
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
			channel = aclchan
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
		// his access token list.
		log.Printf("GroupMemberCheck: Implement token matching")
		return false
	} else if hash {
		// The user is part of this group if the remaining name matches his
		// cert hash.
		log.Printf("GroupMemberCheck: Implement hash matching")
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
		return client.IsRegistered()
	} else if name == "strong" {
		// The user is part of the strong group if he is authenticated to the server
		// via a strong certificate (i.e. non-self-signed, trusted by the server's
		// trusted set of root CAs).
		log.Printf("GroupMemberCheck: Implement strong certificate matching")
		return false
	} else if name == "in" {
		// Is the user in the currently evaluated channel?
		return client.Channel == channel
	} else if name == "out" {
		// Is the user not in the currently evaluated channel?
		return client.Channel != channel
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
		args := strings.Split(name, ",", 3)
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

		// Build a chain of channels, starting from the client's current channel.
		playerChain := []*Channel{}
		iter := client.Channel
		for iter != nil {
			playerChain = append([]*Channel{iter}, playerChain...)
			iter = iter.parent
		}
		// Build a chain of channels, starting from the channel current. This is
		// the channel that group membership is checked against, notwithstanding
		// the ~ group operator.
		groupChain := []*Channel{}
		iter = current
		for iter != nil {
			groupChain = append([]*Channel{iter}, groupChain...)
			iter = iter.parent
		}

		// Helper function that finds the given channel in the channels slice.
		// Returns -1 if the given channel was not found in the slice.
		indexOf := func(channels []*Channel, channel *Channel) int {
			for i, iter := range channels {
				if iter == channel {
					return i
				}
			}
			return -1
		}

		// Find the index of channel that the group is currently being evaluated on.
		// This can be either aclchan or current depending on the ~ group operator.
		cofs := indexOf(groupChain, channel)
		if cofs == -1 {
			valid = false
			return false
		}

		// Add the first parameter of our sub group to cofs to get our 'base' channel.
		cofs += minpath
		// Check that the minpath parameter that was given is a valid index for groupChain.
		if cofs >= len(groupChain) {
			valid = false
			return false
		} else if cofs < 0 {
			cofs = 0
		}

		// If our 'base' channel is not in the playerChain, the group does not apply to the client.
		if indexOf(playerChain, groupChain[cofs]) == -1 {
			return false
		}

		// Down here, we're certain that the playerChain includes the base channel
		// *somewhere*. We must now determine if the path depth makes the user a
		// member of the group.
		mindepth := cofs + mindesc
		maxdepth := cofs + maxdesc
		pdepth := len(playerChain) - 1
		return pdepth >= mindepth && pdepth <= maxdepth

	} else {
		// Non-magic groups
		groups := []*Group{}

		iter := channel
		for iter != nil {
			if group, ok := iter.Groups[name]; ok {
				// Skip non-inheritable groups if we're in parents
				// of our evaluated channel.
				if iter != channel && !group.Inheritable {
					break
				}
				// Prepend group
				groups = append([]*Group{group}, groups...)
				// If this group does not inherit from groups in its ancestors, stop looking
				// for more ancestor groups.
				if !group.Inherit {
					break
				}
			}
			iter = iter.parent
		}

		isMember := false
		for _, group := range groups {
			if group.AddContains(client.UserId()) || group.TemporaryContains(client.UserId()) || group.TemporaryContains(-int(client.Session)) {
				isMember = true
			}
			if group.RemoveContains(client.UserId()) {
				isMember = false
			}
		}
		return isMember
	}

	return false
}

// Get the list of group names in a particular channel.
// This function walks the through the channel and all its
// parent channels to figure out all groups that affect
// the channel while considering group inheritance.
func (channel *Channel) GroupNames() map[string]bool {
	names := map[string]bool{}

	// Construct a list of channels. Fartherst away ancestors
	// are put in front of the list, allowing us to linearly
	// iterate the list to determine inheritance.
	channels := []*Channel{}
	iter := channel
	for iter != nil {
		channels = append([]*Channel{iter}, channels...)
		iter = iter.parent
	}

	// Walk through all channels and groups in them.
	for _, iter := range channels {
		for _, group := range iter.Groups {
			// A non-inheritable group in parent. Discard it.
			if channel != iter && !group.Inheritable {
				names[group.Name] = false, false
				// An inheritable group. Add it to the list.
			} else {
				names[group.Name] = true
			}
		}
	}
	return names
}
