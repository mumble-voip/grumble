package serverconf

import (
	"gopkg.in/ini.v1"
)

type inicfg struct {
	file *ini.File
}

func newinicfg(path string) (*inicfg, error) {
	file, err := ini.LoadSources(ini.LoadOptions{AllowBooleanKeys: true, UnescapeValueDoubleQuotes: true}, path)
	if err != nil {
		return nil, err
	}
	file.BlockMode = false // read only, avoid locking
	return &inicfg{file}, nil
}

func (f *inicfg) GlobalMap() map[string]string {
	return f.file.Section("").KeysHash()
}

// todo(rubenseyer): not all of these even work.. make sure to implement them
var DefaultConfigFile = `# Grumble configuration file.
#
# The commented out settings represent the defaults.
# Options here may be overridden by virtual server specific configuration.
# Make sure to enclose values containing # or ; in double quotes or backticks.

# Address to bind the listeners to.
#Address = 0.0.0.0

# Port is the port to bind the native Mumble protocol to.
# WebPort is the port to bind the WebSocket Mumble protocol to.
# They are incremented for each virtual server.
#Port = 64738
#WebPort = 443

# "Message of the day" HTML string sent to connecting clients.
#WelcomeText = "Welcome to this server running <b>Grumble</b>."

# Maximum bandwidth (in bits per second) per client for voice.
# Grumble does not yet enforce this limit, but some clients nicely follow it.
#MaxBandwidth = 72000

# Maximum number of concurrent clients.
#MaxUsers = 1000
#MaxUsersPerChannel = 0

#MaxTextMessageLength = 5000
#MaxImageMessageLength = 131072
#AllowHTML

# DefaultChannel is the channel (by ID) new users join.
# The root channel is the default.
#DefaultChannel = 0 

# Whether users will rejoin the last channel they were in.
#RememberChannel

# Whether to include server version and server os in ping response.
#SendVersion
#SendOSInfo

# Path to the log file (relative to the data directory).
#LogPath = grumble.log

# Path to TLS certificate and key (relative to the data directory).
# The certificate needs to have the entire chain concatenated to be validate.
# If these paths do not exist, Grumble will autogenerate a certificate.
#CertPath = cert.pem
#KeyPath = key.pem

# Options for public server registration.
# All of these have to be set to make the server public.
# RegisterName additionally sets the name of the root channel.
# RegisterPassword is a simple, arbitrary secret to guard your registration. Don't lose it.
#RegisterName = 
#RegisterHost =
#RegisterPassword =
#RegisterWebUrl =
`
