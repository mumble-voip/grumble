// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package ban

import (
	"net"
	"time"
)

const (
	ISODate = "2006-01-02T15:04:05"
)

type Ban struct {
	IP       net.IP
	Mask     int
	Username string
	CertHash string
	Reason   string
	Start    int64
	Duration uint32
}

// Create a net.IPMask from a specified amount of mask bits
func (ban Ban) IPMask() (mask net.IPMask) {
	allbits := ban.Mask
	for i := 0; i < 16; i++ {
		bits := allbits
		if bits > 0 {
			if bits > 8 {
				bits = 8
			}
			mask = append(mask, byte((1<<uint(bits))-1))
		} else {
			mask = append(mask, byte(0))
		}
		allbits -= 8
	}
	return
}

// Match checks whether an IP matches a Ban
func (ban Ban) Match(ip net.IP) bool {
	banned := ban.IP.Mask(ban.IPMask())
	masked := ip.Mask(ban.IPMask())
	return banned.Equal(masked)
}

// Set Start date from an ISO 8601 date (in UTC)
func (ban *Ban) SetISOStartDate(isodate string) {
	startTime, err := time.Parse(ISODate, isodate)
	if err != nil {
		ban.Start = 0
	} else {
		ban.Start = startTime.Unix()
	}
}

// ISOStartDate returns the currently set start date as an ISO 8601-formatted
// date (in UTC).
func (ban Ban) ISOStartDate() string {
	startTime := time.Unix(ban.Start, 0).UTC()
	return startTime.Format(ISODate)
}

// IsExpired checks whether a ban has expired
func (ban Ban) IsExpired() bool {
	// ∞-case
	if ban.Duration == 0 {
		return false
	}

	// Expiry check
	expiryTime := ban.Start + int64(ban.Duration)
	if time.Now().Unix() > expiryTime {
		return true
	}
	return false
}
