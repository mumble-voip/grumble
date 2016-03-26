// Copyright (c) 2010-2013 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package acl

// Context represents a context in which ACLs can
// be understood. Typically embedded into a type
// that represents a Mumble channel.
type Context struct {
	// Parent points to the context's parent.
	// May be nil if the Context does not have a parent.
	Parent *Context

	// ACLs is the Context's list of ACL entries.
	ACLs []ACL

	// Groups is the Context's representation of groups.
	// It is indexed by the Group's name.
	Groups map[string]Group

	// InheritACL determines whether this context should
	// inherit ACLs from its parent.
	InheritACL bool
}

// indexOf finds the index of the context ctx in the context chain contexts.
// Returns -1 if the given context was not found in the context chain.
func indexOf(contexts []*Context, ctx *Context) int {
	for i, iter := range contexts {
		if iter == ctx {
			return i
		}
	}
	return -1
}

// buildChain walks from the context ctx back through all of its parents,
// collecting them all in a slice. The first element of the returned
// slice is the final ancestor (it has a nil Parent).
func buildChain(ctx *Context) []*Context {
	chain := []*Context{}
	for ctx != nil {
		chain = append([]*Context{ctx}, chain...)
		ctx = ctx.Parent
	}
	return chain
}
