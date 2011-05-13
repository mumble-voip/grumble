// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package serverconf

import (
	"strconv"
)

var defaultCfg = map[string]string{
	"MaxBandwidth":          "72000",
	"MaxUsers":              "1000",
	"MaxUsersPerChannel":    "0",
	"MaxTextMessageLength":  "5000",
	"MaxImageMessageLength": "131072",
	"AllowHTML":             "true",
	"DefaultChannel":        "0",
	"RememberChannel":       "true",
	"WelcomeText":           "Welcome to this server running <b>Grumble</b>.",
	"SendVersion":           "true",
}

type Config map[string]string

func (cfg Config) Set(key string, value string) {
	cfg[key] = value
}

func (cfg Config) StringValue(key string) (value string) {
	value, exists := cfg[key]
	if exists {
		return value
	}

	value, exists = defaultCfg[key]
	if exists {
		return value
	}

	return ""
}

func (cfg Config) IntValue(key string) (intval int) {
	str := cfg.StringValue(key)
	intval, _ = strconv.Atoi(str)
	return
}

func (cfg Config) Uint32Value(key string) (uint32val uint32) {
	str := cfg.StringValue(key)
	uintval, _ := strconv.Atoui(str)
	return uint32(uintval)
}

func (cfg Config) BoolValue(key string) (boolval bool) {
	str := cfg.StringValue(key)
	boolval, _ = strconv.Atob(str)
	return
}

func (cfg Config) Reset(key string) {
	cfg[key] = "", false
}
