// Copyright (c) 2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package replacefile

type Flag uint32

const (
	IgnoreMergeErrors Flag = 0x2
	IgnoreACLErrors   Flag = 0x4
)
