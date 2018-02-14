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

var DefaultConfigFile = `# Grumble configuration file.
#
# The commented out settings represent the defaults.
# Options here may be overridden by virtual server specific configuration.
# Make sure to enclose values containing # or ; in double quotes or backticks.

# Address to bind the listeners to.
#host = 0.0.0.0

# port is the port to bind the native Mumble protocol to.
# webport is the port to bind the WebSocket Mumble protocol to.
# They are incremented for each virtual server (if set globally).
#port = 64738
#webport = 443

# Whether to disable web server.
#nowebserver

# "Message of the day" HTML string sent to connecting clients.
#welcometext = "Welcome to this server running <b>Grumble</b>."

# Password to join the server.
#serverpassword =

# Maximum bandwidth (in bits per second) per client for voice.
# Grumble does not yet enforce this limit, but some clients nicely follow it.
#bandwidth = 72000

# Maximum number of concurrent clients.
#users = 1000
#usersperchannel = 0

#textmessagelength = 5000
#imagemessagelength = 131072
#allowhtml

# The default channel is the channel (by ID) new users join.
# The root channel (ID = 0) is the default.
#defaultchannel = 0 

# Whether users will rejoin the last channel they were in.
#rememberchannel

# Whether to include server OS info in ping response.
#sendversion

# Whether to respond to pings from the Connect dialog.
#allowping

# Path to the log file (relative to the data directory).
#logfile = grumble.log

# Path to TLS certificate and key (relative to the data directory).
# The certificate needs to have the entire chain concatenated to be valid.
# If these paths do not exist, Grumble will autogenerate a certificate.
#sslCert = cert.pem
#sslKey = key.pem

# Options for public server registration.
# All of these have to be set to make the server public.
# registerName additionally sets the name of the root channel.
# registerPassword is a simple, arbitrary secret to guard your registration. Don't lose it.
#registerName = 
#registerHostname =
#registerPassword =
#registerUrl =
`
