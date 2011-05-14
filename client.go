// Copyright (c) 2010-2011 The Grumble Authors
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
	"grumble/blobstore"
	"grumble/cryptstate"
	"io"
	"packetdatastream"
	"time"
)

// A client connection
type Client struct {
	// Logging
	*log.Logger
	lf *clientLogForwarder

	// Connection-related
	tcpaddr *net.TCPAddr
	udpaddr *net.UDPAddr
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	state   int
	server  *Server

	msgchan     chan *Message
	udprecv     chan []byte
	doneSending chan bool

	disconnected bool

	lastResync int64
	crypt      *cryptstate.CryptState
	codecs     []int32
	udp        bool

	// Ping stats
	UdpPingAvg float32
	UdpPingVar float32
	UdpPackets uint32
	TcpPingAvg float32
	TcpPingVar float32
	TcpPackets uint32

	// If the client is a registered user on the server,
	// the user field will point to the registration record.
	user *User

	// The clientReady channel signals the client's reciever routine that
	// the client has been successfully authenticated and that it has been
	// sent the necessary information to be a participant on the server.
	// When this signal is received, the client has transitioned into the
	// 'ready' state.
	clientReady chan bool

	// Version
	Version    uint32
	ClientName string
	OSName     string
	OSVersion  string

	// Personal
	Username        string
	Session         uint32
	CertHash        string
	Email           string
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

// Is the client a registered user?
func (client *Client) IsRegistered() bool {
	return client.user != nil
}

// Does the client have a certificate?
func (client *Client) HasCertificate() bool {
	return len(client.CertHash) > 0
}

// Is the client the SuperUser?
func (client *Client) IsSuperUser() bool {
	if client.user == nil {
		return false
	}
	return client.user.Id == 0
}

// Get the User ID of this client.
// Returns -1 if the client is not a registered user.
func (client *Client) UserId() int {
	if client.user == nil {
		return -1
	}
	return int(client.user.Id)
}

// Get the client's shown name.
func (client *Client) ShownName() string {
	if client.IsSuperUser() {
		return "SuperUser"
	}
	if client.IsRegistered() {
		return client.user.Name
	}
	return client.Username
}

// Log a panic and disconnect the client.
func (client *Client) Panic(v ...interface{}) {
	client.Print(v)
	client.Disconnect()
}

// Log a formatted panic and disconnect the client.
func (client *Client) Panicf(format string, v ...interface{}) {
	client.Printf(format, v)
	client.Disconnect()
}

// Internal disconnect function
func (client *Client) disconnect(kicked bool) {
	if !client.disconnected {
		client.disconnected = true
		close(client.udprecv)

		// If the client paniced during authentication, before reaching
		// the ready state, the receiver goroutine will be waiting for
		// a signal telling it that the client is ready to receive 'real'
		// messages from the server.
		//
		// In case of a premature disconnect, close the channel so the
		// receiver routine can exit correctly.
		if client.state == StateClientSentVersion || client.state == StateClientAuthenticated {
			close(client.clientReady)
		}

		// Cleanly shut down the sender goroutine. This should be non-blocking
		// since we're writing to a bufio.Writer.
		// todo(mkrautz): Check whether that's the case? We do a flush, so maybe not.
		client.msgchan <- nil
		<-client.doneSending
		close(client.msgchan)

		client.Printf("Disconnected")

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

// Reject an authentication attempt
func (client *Client) RejectAuth(kind, reason string) {
	var reasonString *string = nil
	if len(reason) > 0 {
		reasonString = proto.String(reason)
	}

	client.sendProtoMessage(MessageReject, &mumbleproto.Reject{
		Type:   mumbleproto.NewReject_RejectType(mumbleproto.Reject_RejectType_value[kind]),
		Reason: reasonString,
	})

	client.ForceDisconnect()
}

// Read a protobuf message from a client
func (client *Client) readProtoMessage() (msg *Message, err os.Error) {
	var (
		length uint32
		kind   uint16
	)

	// Read the message type (16-bit big-endian unsigned integer)
	err = binary.Read(client.reader, binary.BigEndian, &kind)
	if err != nil {
		return
	}

	// Read the message length (32-bit big-endian unsigned integer)
	err = binary.Read(client.reader, binary.BigEndian, &length)
	if err != nil {
		return
	}

	buf := make([]byte, length)
	_, err = io.ReadFull(client.reader, buf)
	if err != nil {
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
	c.sendPermissionDeniedTypeUser(kind, nil)
}

// Send permission denied by type (and user)
func (c *Client) sendPermissionDeniedTypeUser(kind string, user *Client) {
	val, ok := mumbleproto.PermissionDenied_DenyType_value[kind]
	if ok {
		pd := &mumbleproto.PermissionDenied{}
		pd.Type = mumbleproto.NewPermissionDenied_DenyType(val)
		if user != nil {
			pd.Session = proto.Uint32(uint32(user.Session))
		}
		d, err := proto.Marshal(pd)
		if err != nil {
			c.Panicf("%v", err)
			return
		}
		c.msgchan <- &Message{
			buf:  d,
			kind: MessagePermissionDenied,
		}
	} else {
		c.Panicf("Unknown permission denied type.")
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
		c.Panicf(err.String())
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
		// Received a zero-valued buffer. This means that the udprecv
		// channel was closed, so exit cleanly.
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
		client.Printf("Sent UDP!")
		client.server.udpsend <- msg
	} else {
		client.Printf("Sent TCP!")
		msg.kind = MessageUDPTunnel
		client.msgchan <- msg
	}
}

// Send a Message to the client.  The Message in msg to the client's
// buffered writer and flushes it when done.
//
// This method should only be called from within the client's own
// sender goroutine, since it serializes access to the underlying
// buffered writer.
func (client *Client) sendMessage(msg *Message) os.Error {
	// Write message kind
	err := binary.Write(client.writer, binary.BigEndian, msg.kind)
	if err != nil {
		return err
	}

	// Message length
	err = binary.Write(client.writer, binary.BigEndian, uint32(len(msg.buf)))
	if err != nil {
		return err
	}

	// Message buffer itself
	_, err = client.writer.Write(msg.buf)
	if err != nil {
		return err
	}

	// Flush it, no need to keep it in the buffer for any longer.
	err = client.writer.Flush()
	if err != nil {
		return err
	}

	return nil
}

// Sender Goroutine.  The sender goroutine will initiate shutdown
// if it receives a nil Message.
//
// On shutdown, it will send a true boolean value on the client's
// doneSending channel.  This allows the client to send all the messages
// that remain in it's buffer when the server has to force a disconnect.
func (client *Client) sender() {
	defer func() {
		client.doneSending <- true
	}()

	for msg := range client.msgchan {
		if msg == nil {
			return
		}

		err := client.sendMessage(msg)
		if err != nil {
			// fixme(mkrautz): This is a deadlock waiting to happen.
			client.Panicf("Unable to send message to client")
			return
		}
	}
}

// Receiver Goroutine
func (client *Client) receiver() {
	for {
		// The version handshake is done, the client has been authenticated and it has received
		// all necessary information regarding the server.  Now we're ready to roll!
		if client.state == StateClientReady {
			// Try to read the next message in the pool
			msg, err := client.readProtoMessage()
			if err != nil {
				if err == os.EOF {
					client.Disconnect()
				} else {
					client.Panicf("%v", err)
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

		// The client has responded to our version query. It will try to authenticate.
		if client.state == StateClientSentVersion {
			// Try to read the next message in the pool
			msg, err := client.readProtoMessage()
			if err != nil {
				if err == os.EOF {
					client.Disconnect()
				} else {
					client.Panicf("%v", err)
				}
				return
			}

			client.clientReady = make(chan bool)
			go client.server.handleAuthenticate(client, msg)
			<-client.clientReady

			// It's possible that the client has disconnected in the meantime.
			// In that case, step out of the receiver, since there's nothing left
			// to receive.
			if client.disconnected {
				return
			}

			close(client.clientReady)
			client.clientReady = nil
		}

		// The client has just connected. Before it sends its authentication
		// information we must send it our version information so it knows
		// what version of the protocol it should speak.
		if client.state == StateClientConnected {
			client.sendProtoMessage(MessageVersion, &mumbleproto.Version{
				Version: proto.Uint32(0x10203),
				Release: proto.String("Grumble"),
			})
			// fixme(mkrautz): Re-add OS information... Does it break anything? It seems like
			// the client discards the version message if there is no OS information in it.
			client.state = StateServerSentVersion
			continue
		} else if client.state == StateServerSentVersion {
			msg, err := client.readProtoMessage()
			if err != nil {
				if err == os.EOF {
					client.Disconnect()
				} else {
					client.Panicf("%v", err)
				}
				return
			}

			version := &mumbleproto.Version{}
			err = proto.Unmarshal(msg.buf, version)
			if err != nil {
				client.Panicf("%v", err)
				return
			}

			if version.Version != nil {
				client.Version = *version.Version
			} else {
				client.Version = 0x10200
			}

			if version.Release != nil {
				client.ClientName = *version.Release
			}

			if version.Os != nil {
				client.OSName = *version.Os
			}

			if version.OsVersion != nil {
				client.OSVersion = *version.OsVersion
			}

			client.Printf("version = 0x%x", client.Version)
			client.Printf("os = %s %s", client.OSName, client.OSVersion)
			client.Printf("client = %s", client.ClientName)

			client.state = StateClientSentVersion
		}
	}
}

func (client *Client) sendChannelList() {
	client.sendChannelTree(client.server.root)
}

func (client *Client) sendChannelTree(channel *Channel) {
	chanstate := &mumbleproto.ChannelState{
		ChannelId: proto.Uint32(uint32(channel.Id)),
		Name:      proto.String(channel.Name),
	}
	if channel.parent != nil {
		chanstate.Parent = proto.Uint32(uint32(channel.parent.Id))
	}

	if channel.HasDescription() {
		if client.Version >= 0x10202 {
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		} else {
			buf, err := blobstore.Get(channel.DescriptionBlob)
			if err != nil {
				panic("Blobstore error.")
			}
			chanstate.Description = proto.String(string(buf))
		}
	}

	if channel.Temporary {
		chanstate.Temporary = proto.Bool(true)
	}

	chanstate.Position = proto.Int32(int32(channel.Position))

	links := []uint32{}
	for cid, _ := range channel.Links {
		links = append(links, uint32(cid))
	}
	chanstate.Links = links

	err := client.sendProtoMessage(MessageChannelState, chanstate)
	if err != nil {
		client.Panicf("%v", err)
	}

	for _, subchannel := range channel.children {
		client.sendChannelTree(subchannel)
	}
}

// Try to do a crypto resync
func (client *Client) cryptResync() {
	goodElapsed := time.Seconds() - client.crypt.LastGoodTime
	if goodElapsed > 5 {
		requestElapsed := time.Seconds() - client.lastResync
		if requestElapsed > 5 {
			client.lastResync = time.Seconds()
			cryptsetup := &mumbleproto.CryptSetup{}
			err := client.sendProtoMessage(MessageCryptSetup, cryptsetup)
			if err != nil {
				client.Panicf("%v", err)
			}
		}
	}
}
