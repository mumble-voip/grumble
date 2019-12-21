// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package freezer

type typeKind uint32

// The different types of data that can be frozen
const (
	ServerType typeKind = iota
	ConfigKeyValuePairType
	BanListType
	UserType
	UserRemoveType
	ChannelType
	ChannelRemoveType
)
