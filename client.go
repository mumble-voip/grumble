// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"net"
	"bufio"
	"log"
	"os"
	"encoding/binary"
	"goprotobuf.googlecode.com/hg/proto"
	"mumbleproto"
	"cryptstate"
	"packetdatastream"
)

// A client connection
type Client struct {
	// Connection-related
	tcpaddr *net.TCPAddr
	udpaddr *net.UDPAddr
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	state   int
	server  *Server

	msgchan chan *Message
	udprecv chan []byte

	disconnected bool

	crypt  *cryptstate.CryptState
	codecs []int32
	udp    bool

	// Personal
	UserId          int
	Session         uint32
	Username        string
	Hash            string
	Tokens          []string
	Channel         *Channel
	SelfMute        bool
	SelfDeaf        bool
	Mute            bool
	Deaf            bool
	Suppress        bool
	PrioritySpeaker bool
	Recording       bool
	PluginContext   []byte
	PluginIdentity  string
}

// Something invalid happened on the wire.
func (client *Client) Panic(reason string) {
	log.Printf("Client panic: %s", reason)
	client.Disconnect()
}

// Internal disconnect function
func (client *Client) disconnect(kicked bool) {
	if !client.disconnected {
		client.disconnected = true
		close(client.udprecv)
		close(client.msgchan)

		client.conn.Close()
		client.server.RemoveClient(client, kicked)
	}
}

// Disconnect a client (client disconnected)
func (client *Client) Disconnect() {
	client.disconnect(false)
}

// Disconnect a client (kick/ban)
func (client *Client) ForceDisconnect() {
	client.disconnect(true)
}

// Read a protobuf message from a client
func (client *Client) readProtoMessage() (msg *Message, err os.Error) {
	var length uint32
	var kind uint16

	// Read the message type (16-bit big-endian unsigned integer)
	err = binary.Read(client.reader, binary.BigEndian, &kind)
	if err != nil {
		client.Panic("Unable to read packet kind")
		return
	}

	// Read the message length (32-bit big-endian unsigned integer)
	err = binary.Read(client.reader, binary.BigEndian, &length)
	if err != nil {
		client.Panic("Unable to read packet length")
		return
	}

	buf := make([]byte, length)
	_, err = client.reader.Read(buf)
	if err != nil {
		client.Panic("Unable to read packet content")
		return
	}

	msg = &Message{
		buf:    buf,
		kind:   kind,
		client: client,
	}

	return
}

// Send a protobuf-encoded message
func (c *Client) sendProtoMessage(kind uint16, msg interface{}) (err os.Error) {
	d, err := proto.Marshal(msg)
	if err != nil {
		return
	}

	c.msgchan <- &Message{
		buf:  d,
		kind: kind,
	}

	return
}

// Send permission denied by type
func (c *Client) sendPermissionDeniedType(kind string) {
	val, ok := mumbleproto.PermissionDenied_DenyType_value[kind]
	if ok {
		d, err := proto.Marshal(&mumbleproto.PermissionDenied{
			Type: mumbleproto.NewPermissionDenied_DenyType(val),
		})
		if err != nil {
			c.Panic(err.String())
			return
		}
		c.msgchan <- &Message{
			buf:  d,
			kind: MessagePermissionDenied,
		}
	} else {
		log.Printf("Unknown permission denied type.")
	}
}

// Send permission denied by who, what, where
func (c *Client) sendPermissionDenied(who *Client, where *Channel, what Permission) {
	d, err := proto.Marshal(&mumbleproto.PermissionDenied{
		Permission: proto.Uint32(uint32(what)),
		ChannelId:  proto.Uint32(uint32(where.Id)),
		Session:    proto.Uint32(who.Session),
		Type:       mumbleproto.NewPermissionDenied_DenyType(mumbleproto.PermissionDenied_Permission),
	})
	if err != nil {
		c.Panic(err.String())
	}
	c.msgchan <- &Message{
		buf:  d,
		kind: MessagePermissionDenied,
	}
}

// Send permission denied fallback
func (c *Client) sendPermissionDeniedFallback(kind string, version uint32, text string) {
	// fixme(mkrautz): Do fallback kind of stuff...
	c.sendPermissionDeniedType(kind)
}

// UDP receiver.
func (client *Client) udpreceiver() {
	for buf := range client.udprecv {
		// Channel close.
		if len(buf) == 0 {
			return
		}

		kind := (buf[0] >> 5) & 0x07

		switch kind {
		case UDPMessageVoiceSpeex:
			fallthrough
		case UDPMessageVoiceCELTAlpha:
			fallthrough
		case UDPMessageVoiceCELTBeta:
			kind := buf[0] & 0xe0
			target := buf[0] & 0x1f
			var counter uint8
			outbuf := make([]byte, 1024)

			incoming := packetdatastream.New(buf[1 : 1+(len(buf)-1)])
			outgoing := packetdatastream.New(outbuf[1 : 1+(len(outbuf)-1)])
			_ = incoming.GetUint32()

			for {
				counter = incoming.Next8()
				incoming.Skip(int(counter & 0x7f))
				if !((counter&0x80) != 0 && incoming.IsValid()) {
					break
				}
			}

			outgoing.PutUint32(client.Session)
			outgoing.PutBytes(buf[1 : 1+(len(buf)-1)])
			outbuf[0] = kind

			// VoiceTarget
			if target != 0x1f {
				client.server.voicebroadcast <- &VoiceBroadcast{
					client: client,
					buf:    outbuf[0 : 1+outgoing.Size()],
					target: target,
				}
				// Server loopback
			} else {
				client.sendUdp(&Message{
					buf:    outbuf[0 : 1+outgoing.Size()],
					client: client,
				})
			}

		case UDPMessagePing:
			client.server.udpsend <- &Message{
				buf:    buf,
				client: client,
			}
		}
	}
}

func (client *Client) sendUdp(msg *Message) {
	if client.udp {
		log.Printf("Sent UDP!")
		client.server.udpsend <- msg
	} else {
		log.Printf("Sent TCP!")
		msg.kind = MessageUDPTunnel
		client.msgchan <- msg
	}
}


//
// Sender Goroutine
//
func (client *Client) sender() {
	for msg := range client.msgchan {
		// Check for channel close.
		if len(msg.buf) == 0 {
			return
		}

		// First, we write out the message type as a big-endian uint16
		err := binary.Write(client.writer, binary.BigEndian, msg.kind)
		if err != nil {
			client.Panic("Unable to write message type to client")
			return
		}

		// Then the length of the protobuf message
		err = binary.Write(client.writer, binary.BigEndian, uint32(len(msg.buf)))
		if err != nil {
			client.Panic("Unable to write message length to client")
			return
		}

		// At last, write the buffer itself
		_, err = client.writer.Write(msg.buf)
		if err != nil {
			client.Panic("Unable to write message content to client")
			return
		}

		// Flush the write buffer
		err = client.writer.Flush()
		if err != nil {
			client.Panic("Unable to flush client write buffer")
			return
		}
	}
}

// Receiver Goroutine
func (client *Client) receiver() {
	for {
		// The version handshake is done. Forward this message to the synchronous request handler.
		if client.state == StateClientAuthenticated || client.state == StateClientSentVersion {
			// Try to read the next message in the pool
			msg, err := client.readProtoMessage()
			if err != nil {
				if err == os.EOF {
					log.Printf("Client disconnected.")
					client.Disconnect()
				} else {
					log.Printf("Client error.")
				}
				return
			}
			// Special case UDPTunnel messages. They're high priority and shouldn't
			// go through our synchronous path.
			if msg.kind == MessageUDPTunnel {
				client.udp = false
				client.udprecv <- msg.buf
			} else {
				client.server.incoming <- msg
			}
		}

		// The client has just connected. Before it sends its authentication
		// information we must send it our version information so it knows
		// what version of the protocol it should speak.
		if client.state == StateClientConnected {
			client.sendProtoMessage(MessageVersion, &mumbleproto.Version{
				Version: proto.Uint32(0x10203),
				Release: proto.String("1.2.2"),
			})
			// fixme(mkrautz): Re-add OS information... Does it break anything? It seems like
			// the client discards the version message if there is no OS information in it.
			client.state = StateServerSentVersion
			continue
		} else if client.state == StateServerSentVersion {
			msg, err := client.readProtoMessage()
			if err != nil {
				if err == os.EOF {
					log.Printf("Client disconnected.")
					client.Disconnect()
				} else {
					log.Printf("Client error.")
				}
				return
			}

			version := &mumbleproto.Version{}
			err = proto.Unmarshal(msg.buf, version)
			if err != nil {
				client.Panic("Unable to unmarshal client version packet.")
				return
			}

			// Don't really do anything with it...

			client.state = StateClientSentVersion
		}
	}
}

func (client *Client) sendChannelList() {
	client.sendChannelTree(client.server.root)
}

func (client *Client) sendChannelTree(channel *Channel) {
	// Start at the root channel.
	log.Printf("sending channel ID=%i, NAME=%s", channel.Id, channel.Name)
	chanstate := &mumbleproto.ChannelState{
		ChannelId:   proto.Uint32(uint32(channel.Id)),
		Name:        proto.String(channel.Name),
		Description: proto.String(channel.Description),
	}
	if channel.parent != nil {
		chanstate.Parent = proto.Uint32(uint32(channel.parent.Id))
	}

	err := client.sendProtoMessage(MessageChannelState, chanstate)
	if err != nil {
		client.Panic(err.String())
	}

	for _, subchannel := range channel.children {
		client.sendChannelTree(subchannel)
	}
}

// Send the userlist to a client.
func (client *Client) sendUserList() {
	server := client.server
	for _, client := range server.clients {
		err := client.sendProtoMessage(MessageUserState, &mumbleproto.UserState{
			Session:   proto.Uint32(client.Session),
			Name:      proto.String(client.Username),
			ChannelId: proto.Uint32(0),
		})
		if err != nil {
			log.Printf("Unable to send UserList")
			continue
		}
	}
}
